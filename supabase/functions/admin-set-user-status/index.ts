// Edge Function: admin-set-user-status
//
// Lets an approved `smat` move a user between 'approved' and 'disabled'.
// This exists as an Edge Function (not a plain table UPDATE) because status
// changes must also be reflected at the Supabase Auth layer:
//   - 'disabled' also bans the user via the Admin API, so their session
//     cannot be refreshed and they cannot sign in again — our Postgres RLS
//     already blocks all their data access the instant `status` changes,
//     but RLS has no effect on native Auth calls (e.g. changing one's own
//     password), so the ban closes that separate gap.
//   - 'approved' also lifts any existing ban — required when re-enabling a
//     previously-disabled user, otherwise they'd stay locked out at the Auth
//     layer even though our own `profiles.status` says they're fine again.
//
// role assignment is unrelated to this and still happens via a normal
// smat-only table UPDATE (covered by the `profiles_smat_all` RLS policy) —
// this function only touches `status` and the Auth ban state.
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const ALLOWED_STATUSES = ["approved", "disabled"];

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
    const newStatus = body?.status;

    if (!targetUserId || !ALLOWED_STATUSES.includes(newStatus)) {
      return json({ error: "target_user_id and status ('approved'|'disabled') are required" }, 400);
    }

    // Use callerClient (the smat's own JWT) so RLS (profiles_smat_all) and
    // the prevent_profile_privilege_escalation trigger see the real caller —
    // adminClient's service_role request has no auth.uid(), which would make
    // has_role('smat') resolve to false inside the trigger and block this.
    const { error: statusErr } = await callerClient
      .from("profiles")
      .update({ status: newStatus })
      .eq("id", targetUserId);

    if (statusErr) return json({ error: statusErr.message }, 500);

    // Only the Auth Admin API call below requires service_role.
    const adminClient = createClient(supabaseUrl, serviceRoleKey);
    const banDuration = newStatus === "disabled" ? "876000h" : "none"; // ~100y ban, or lift it
    const { error: banErr } = await adminClient.auth.admin.updateUserById(targetUserId, {
      ban_duration: banDuration,
    });

    if (banErr) {
      return json(
        { warning: `profiles.status set to '${newStatus}', but syncing the Auth ban failed: ${banErr.message}` },
        207,
      );
    }

    return json({ success: true });
  } catch (e) {
    return json({ error: String(e) }, 500);
  }
});
