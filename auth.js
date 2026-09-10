// Nimbus Auth module.
//
// Supabase Auth is email-based; this app authenticates with username+password
// instead. Each username maps deterministically to a synthetic, never-emailed
// address ("<username>@nimbus.local") so we never need a lookup step before
// login. Real passwords are handled entirely by Supabase Auth (GoTrue) — this
// file never stores or sees a password hash.
//
// Depends on window.nimbusSupabase (see supabaseClient.js).
(function () {
  "use strict";

  var EMAIL_DOMAIN = "@nimbus.local";
  var USERNAME_RE = /^[a-z0-9_]{3,20}$/;
  var PASSWORD_RE = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,}$/;

  function normalizeUsername(raw) {
    return String(raw || "").trim().toLowerCase();
  }

  function usernameToEmail(username) {
    return normalizeUsername(username) + EMAIL_DOMAIN;
  }

  function validateUsername(username) {
    var u = normalizeUsername(username);
    if (!USERNAME_RE.test(u)) {
      return "שם משתמש חייב להכיל 3–20 תווים: אותיות אנגליות קטנות, ספרות וקו תחתון בלבד.";
    }
    return null;
  }

  function validatePassword(password) {
    if (!PASSWORD_RE.test(password || "")) {
      return "הסיסמה חייבת להכיל לפחות 8 תווים, כולל אות גדולה, אות קטנה ומספר.";
    }
    return null;
  }

  function translateAuthError(error) {
    var msg = (error && error.message) || "";
    if (/already registered/i.test(msg)) return "שם המשתמש הזה כבר תפוס.";
    if (/invalid login credentials/i.test(msg)) return "שם משתמש או סיסמה שגויים.";
    if (/banned|blocked/i.test(msg)) return "החשבון הזה חסום.";
    if (/password/i.test(msg)) return "הסיסמה לא עומדת בדרישות האבטחה.";
    return "אירעה שגיאה: " + msg;
  }

  function client() {
    if (!window.nimbusSupabase) {
      throw new Error("[Nimbus/Auth] window.nimbusSupabase is not initialized — check supabase-config.js");
    }
    return window.nimbusSupabase;
  }

  async function signUp(username, password, fullName) {
    var uErr = validateUsername(username);
    if (uErr) return { error: uErr };
    var pErr = validatePassword(password);
    if (pErr) return { error: pErr };
    var u = normalizeUsername(username);
    var name = String(fullName || "").trim();
    var res = await client().auth.signUp({
      email: usernameToEmail(u),
      password: password,
      options: { data: { username: u, full_name: name } }
    });
    if (res.error) return { error: translateAuthError(res.error) };
    return { data: res.data };
  }

  async function signIn(username, password) {
    var u = normalizeUsername(username);
    var res = await client().auth.signInWithPassword({
      email: usernameToEmail(u),
      password: password
    });
    if (res.error) return { error: translateAuthError(res.error) };
    return { data: res.data };
  }

  async function signOut() {
    await client().auth.signOut();
  }

  async function changeOwnPassword(newPassword) {
    var pErr = validatePassword(newPassword);
    if (pErr) return { error: pErr };
    var res = await client().auth.updateUser({ password: newPassword });
    if (res.error) return { error: translateAuthError(res.error) };
    return { data: res.data };
  }

  // Returns the current session plus the matching profiles row (role/status),
  // or {session:null, profile:null} if nobody is logged in.
  async function getSessionProfile() {
    var sessionRes = await client().auth.getSession();
    var session = sessionRes.data && sessionRes.data.session;
    if (!session) return { session: null, profile: null };
    var profileRes = await client()
      .from("profiles")
      .select("id, full_name, role, status, username")
      .eq("id", session.user.id)
      .single();
    if (profileRes.error) {
      return { session: session, profile: null, error: profileRes.error.message };
    }
    return { session: session, profile: profileRes.data };
  }

  function onAuthStateChange(cb) {
    return client().auth.onAuthStateChange(cb);
  }

  window.NimbusAuth = {
    normalizeUsername: normalizeUsername,
    validateUsername: validateUsername,
    validatePassword: validatePassword,
    signUp: signUp,
    signIn: signIn,
    signOut: signOut,
    changeOwnPassword: changeOwnPassword,
    getSessionProfile: getSessionProfile,
    onAuthStateChange: onAuthStateChange
  };
})();
