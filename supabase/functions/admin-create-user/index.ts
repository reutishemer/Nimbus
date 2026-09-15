// Edge Function: admin-create-user
//
// Lets an approved `smat` create a brand-new user directly - already
// `status: 'approved'` with the chosen role, no separate approval step
// needed. Mirrors admin-delete-user / admin-set-user-status /
// admin-reset-password exactly:
//   1. `callerClient` (anon key + caller's JWT, RLS-scoped) verifies the
//      caller is an approved smat, by reading only their own profiles row.
//   2. `adminClient` (service_role, kept only as a Function secret) is used
//      only after that check passes, and only for the Auth Admin API call
//      that creates the user - it never writes to `profiles`/
//      `trainee_profiles`/`instructor_profiles` directly (see below).
//
// Username/email convention matches auth.js exactly: Supabase Auth is
// email-based, so a username maps deterministically to a synthetic,
// never-emailed address ("<username>@nimbus.local").
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const EMAIL_DOMAIN = "@nimbus.local";
const USERNAME_RE = /^[a-z0-9_]{3,20}$/;
const PASSWORD_RE = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,}$/;

// Deliberately excludes "manager" - not a role this system supports yet.
const ALLOWED_ROLES = ["smat", "instructor", "trainee", "kahad"];
const VALID_POPULATIONS = ["airCrew", "controllers", "scouts"];

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

    const { data: callerProfile, error: callerProfileErr } = await callerClient
      .from("profiles")
      .select("role, status")
      .eq("id", userData.user.id)
      .single();

    if (
      callerProfileErr ||
      !callerProfile ||
      callerProfile.role !== "smat" ||
      callerProfile.status !== "approved"
    ) {
      return json({ error: "Forbidden — smat only" }, 403);
    }

    const body = await req.json().catch(() => null);
    const username = typeof body?.username === "string" ? body.username.trim().toLowerCase() : "";
    const password = body?.password;
    const fullName = typeof body?.full_name === "string" ? body.full_name.trim() : "";
    const role = body?.role;

    // All validation happens here, server-side - the UI's own checks are
    // just for a responsive form, never trusted as the real gate.
    if (!USERNAME_RE.test(username)) {
      return json({ error: "שם משתמש חייב להכיל 3–20 תווים: אותיות אנגליות קטנות, ספרות וקו תחתון בלבד." }, 400);
    }
    if (typeof password !== "string" || !PASSWORD_RE.test(password)) {
      return json({ error: "הסיסמה חייבת להכיל לפחות 8 תווים, כולל אות גדולה, אות קטנה ומספר." }, 400);
    }
    if (!fullName) {
      return json({ error: "יש למלא שם מלא." }, 400);
    }
    if (!ALLOWED_ROLES.includes(role)) {
      return json({ error: "תפקיד לא חוקי." }, 400);
    }

    let course = "";
    let population = "";
    let traineeClass = "";
    let populations: string[] = [];

    if (role === "trainee") {
      course = typeof body?.course === "string" ? body.course.trim() : "";
      population = typeof body?.population === "string" ? body.population : "";
      traineeClass = typeof body?.class === "string" ? body.class.trim() : "";
      if (!course || !population || !traineeClass) {
        return json({ error: "יש למלא קורס, אוכלוסייה ומחזור." }, 400);
      }
      if (!VALID_POPULATIONS.includes(population)) {
        return json({ error: "אוכלוסייה לא חוקית." }, 400);
      }
    } else if (role === "instructor") {
      populations = Array.isArray(body?.populations) ? body.populations : [];
      if (!populations.length) {
        return json({ error: "יש לבחור לפחות אוכלוסייה אחת." }, 400);
      }
      if (!populations.every((p: unknown) => typeof p === "string" && VALID_POPULATIONS.includes(p))) {
        return json({ error: "אוכלוסייה לא חוקית." }, 400);
      }
    }

    const adminClient = createClient(supabaseUrl, serviceRoleKey);
    const email = username + EMAIL_DOMAIN;

    const { data: created, error: createErr } = await adminClient.auth.admin.createUser({
      email,
      password,
      email_confirm: true,
      user_metadata: { username, full_name: fullName },
    });

    if (createErr) {
      const msg = (createErr.message || "").toLowerCase();
      if (msg.includes("already") || msg.includes("registered") || msg.includes("exists")) {
        return json({ error: "שם המשתמש הזה כבר תפוס." }, 409);
      }
      return json({ error: createErr.message }, 500);
    }

    const newUserId = created?.user?.id;
    if (!newUserId) {
      return json({ error: "יצירת המשתמש נכשלה - לא התקבל מזהה." }, 500);
    }

    // From here on, the auth user exists - any failure below triggers a
    // best-effort rollback (delete the auth user) so we never leave a
    // half-created user behind. Uses callerClient (the smat's own JWT), never
    // adminClient, to write profiles/trainee_profiles/instructor_profiles -
    // adminClient's service_role request has no auth.uid(), which would make
    // has_role('smat') resolve to false inside the prevent_profile_privilege_
    // escalation trigger and block this (same reasoning as
    // admin-set-user-status).
    //
    // This assumes the same DB trigger that creates a `profiles` row on a
    // self-service signup also fires for an Admin-API-created auth user
    // (both are inserts into auth.users) - not verified against the live
    // trigger definition here (no direct SQL/DB access from this tool), only
    // against observed app behavior. Needs confirming with a real test after
    // deploying this function.
    const { error: profileUpdateErr } = await callerClient
      .from("profiles")
      .update({ role, status: "approved" })
      .eq("id", newUserId);

    if (profileUpdateErr) {
      await adminClient.auth.admin.deleteUser(newUserId).catch(() => {});
      return json({ error: "יצירת פרופיל המשתמש נכשלה: " + profileUpdateErr.message }, 500);
    }

    if (role === "trainee") {
      const { error: tErr } = await callerClient
        .from("trainee_profiles")
        .upsert({ profile_id: newUserId, course, population, class: traineeClass }, { onConflict: "profile_id" });
      if (tErr) {
        await adminClient.auth.admin.deleteUser(newUserId).catch(() => {});
        return json({ error: "יצירת פרטי החניך נכשלה: " + tErr.message }, 500);
      }
    } else if (role === "instructor") {
      const { error: iErr } = await callerClient
        .from("instructor_profiles")
        .upsert({ profile_id: newUserId, populations }, { onConflict: "profile_id" });
      if (iErr) {
        await adminClient.auth.admin.deleteUser(newUserId).catch(() => {});
        return json({ error: "יצירת פרטי המדריך נכשלה: " + iErr.message }, 500);
      }
    }

    return json({ success: true, user_id: newUserId });
  } catch (e) {
    return json({ error: String(e) }, 500);
  }
});
