// Edge Function: admin-reset-password
//
// Lets an approved `smat` set a NEW password for another user, without ever
// seeing their current one. This requires the Supabase service_role key,
// which must never reach the browser — that key exists ONLY inside this
// function's environment (set via `supabase secrets set`), never in the repo
// or client code.
//
// Security design (two separate clients, on purpose):
//   1. `callerClient` is built with the caller's own JWT + the public anon
//      key. It respects RLS, so `.from("profiles").select(...)` only ever
//      returns the CALLER's own row (see policy `profiles_select_self`).
//      This is how we verify "is the caller an approved smat" without any
//      elevated privilege.
//   2. Only after that check passes do we build `adminClient` with the
//      service_role key, and use it exclusively to call the Auth Admin API.
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const PASSWORD_RE = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,}$/;

// Required so the browser's CORS preflight (OPTIONS) succeeds and every
// response (including errors) is readable by the calling page — otherwise
// the browser blocks the request before our logic ever runs.
const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
};

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", ...corsHeaders },
  });
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response(null, { headers: corsHeaders });
  if (req.method !== "POST") return json({ error: "Method not allowed" }, 405);

  const supabaseUrl = Deno.env.get("SUPABASE_URL")!;
  const anonKey = Deno.env.get("SUPABASE_ANON_KEY")!;
  const serviceRoleKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
  const authHeader = req.headers.get("Authorization") ?? "";

  try {
    const callerClient = createClient(supabaseUrl, anonKey, {
      global: { headers: { Authorization: authHeader } },
    });

    const { data: userData, error: userErr } = await callerClient.auth.getUser();
    if (userErr || !userData?.user) {
      return json({ error: "Unauthorized" }, 401);
    }

    const { data: callerProfile, error: profileErr } = await callerClient
      .from("profiles")
      .select("role, status")
      .eq("id", userData.user.id)
      .single();

    if (
      profileErr ||
      !callerProfile ||
      callerProfile.role !== "smat" ||
      callerProfile.status !== "approved"
    ) {
      return json({ error: "Forbidden — smat only" }, 403);
    }

    const body = await req.json().catch(() => null);
    const targetUserId = body?.target_user_id;
    const newPassword = body?.new_password;

    if (!targetUserId || typeof newPassword !== "string") {
      return json({ error: "Missing target_user_id or new_password" }, 400);
    }
    if (!PASSWORD_RE.test(newPassword)) {
      return json(
        { error: "Password must be at least 8 characters and include an uppercase letter, a lowercase letter and a digit." },
        400,
      );
    }

    const adminClient = createClient(supabaseUrl, serviceRoleKey);
    const { error: updateErr } = await adminClient.auth.admin.updateUserById(targetUserId, {
      password: newPassword,
    });

    if (updateErr) return json({ error: updateErr.message }, 500);

    return json({ success: true });
  } catch (e) {
    return json({ error: String(e) }, 500);
  }
});
