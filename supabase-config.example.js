// Copy this file to supabase-config.js and fill in your real values.
// supabase-config.js is listed in .gitignore — it is never committed.
//
// Get these from your Supabase project: Settings -> API.
// Only the "Publishable" (anon/public) key belongs here — never the
// Secret key. The publishable key is safe to expose in client-side code;
// access control is enforced separately via Row Level Security policies.
//
// Names match the VITE_SUPABASE_* convention (see .env.example) in case
// this project migrates to a Vite build later.
window.NIMBUS_SUPABASE_CONFIG = {
  url: "VITE_SUPABASE_URL", // e.g. https://xxxxxxxxxxxx.supabase.co
  publishableKey: "VITE_SUPABASE_PUBLISHABLE_KEY",
};
