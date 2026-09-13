// Edge Function: admin-delete-user
//
// Permanently deletes a user (the auth.users row). This cascades through
// profiles -> instructor_profiles/trainee_profiles -> instructor_trainees
// per their ON DELETE CASCADE foreign keys. It deliberately does NOT touch
// public.feedbacks: feedbacks.trainee_id / feedbacks.instructor_id are
// ON DELETE RESTRICT by design (audit trail), so if the target has any
// feedback rows the whole delete fails atomically at the database level and
// this function returns a clear, actionable message instead of a raw
// Postgres error — it never deletes or reassigns feedbacks itself.
//
// Security design mirrors admin-reset-password / admin-set-user-status:
//   1. `callerClient` (anon key + caller's JWT, RLS-scoped) verifies the
//      caller is an approved smat, by reading only their own profiles row.
//   2. `adminClient` (service_role, kept only as a Function secret) is used
//      only after that check passes, and only for the privileged operations
//      below (reading the target's role, then deleting them).
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

// A user must currently hold one of these roles to be eligible for
// permanent deletion — never smat, never kahad, and never a pending user
// (whose role is null anyway, so it wouldn't match either way).
const DELETABLE_ROLES = ["trainee", "instructor"];

const HAS_FEEDBACKS_MESSAGE =
  "לא ניתן למחוק את המשתמש מכיוון שקיימים משובים הקשורים אליו. אם חשוב לשמור את היסטוריית המידע, מומלץ להשתמש בהשבתה במקום מחיקה. ניתן למחוק את המשובים בנפרד ואז לנסות שוב.";

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
    const callerId = userData.user.id;

    const { data: callerProfile, error: profileErr } = await callerClient
      .from("profiles")
      .select("role, status")
      .eq("id", callerId)
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
    if (!targetUserId) return json({ error: "Missing target_user_id" }, 400);

    if (targetUserId === callerId) {
      return json({ error: "לא ניתן למחוק את המשתמש המחובר בעצמו" }, 400);
    }

    const adminClient = createClient(supabaseUrl, serviceRoleKey);

    // Re-check the TARGET's role independently — never trust that the
    // client only offered a deletable user; this is the real gate.
    const { data: targetProfile, error: targetErr } = await adminClient
      .from("profiles")
      .select("role, status")
      .eq("id", targetUserId)
      .single();

    if (targetErr || !targetProfile) {
      return json({ error: "המשתמש המבוקש לא נמצא" }, 404);
    }
    if (!DELETABLE_ROLES.includes(targetProfile.role)) {
      return json({ error: "ניתן למחוק לצמיתות רק משתמשים עם תפקיד חניך או מדריך" }, 403);
    }

    // Deterministic pre-check: feedbacks.trainee_id / feedbacks.instructor_id
    // are ON DELETE RESTRICT, so a related row would block the deletion
    // below. Checking directly here — rather than trying to recognize this
    // case from the error auth.admin.deleteUser() returns — is the reliable
    // path: GoTrue wraps ANY database error during user deletion in the
    // generic message "Database error deleting user", never surfacing the
    // underlying Postgres "foreign key"/"violates" text, so pattern-matching
    // on that text (kept below only as a fallback) cannot be trusted alone.
    const { data: relatedFeedbacks, error: fbErr } = await adminClient
      .from("feedbacks")
      .select("id")
      .or(`trainee_id.eq.${targetUserId},instructor_id.eq.${targetUserId}`)
      .limit(1);

    if (fbErr) return json({ error: fbErr.message }, 500);
    if (relatedFeedbacks && relatedFeedbacks.length > 0) {
      return json({ error: HAS_FEEDBACKS_MESSAGE }, 409);
    }

    const { error: deleteErr } = await adminClient.auth.admin.deleteUser(targetUserId);

    if (deleteErr) {
      const msg = (deleteErr.message || "").toLowerCase();
      // Kept as a secondary safety net only (e.g. a feedback inserted in the
      // brief window between the pre-check above and this call) — the
      // pre-check above is the primary, reliable detection.
      if (
        msg.includes("foreign key") ||
        msg.includes("violates") ||
        msg.includes("feedbacks") ||
        msg.includes("database error deleting user")
      ) {
        return json({ error: HAS_FEEDBACKS_MESSAGE }, 409);
      }
      return json({ error: deleteErr.message }, 500);
    }

    return json({ success: true });
  } catch (e) {
    return json({ error: String(e) }, 500);
  }
});
