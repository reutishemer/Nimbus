// Nimbus Supabase client module.
//
// This project has no build step, so the Supabase JS library is loaded from
// a CDN <script> tag (see the <helmet> block in Nimbus.dc.html) and this
// file wires it up using the connection details from supabase-config.js
// (see supabase-config.example.js). Nothing in the app calls this yet —
// this is preparation only.
//
// Usage once wired up elsewhere: window.nimbusSupabase
(function () {
  "use strict";

  const config = window.NIMBUS_SUPABASE_CONFIG;

  if (!config || !config.url || !config.publishableKey ||
      config.url === "VITE_SUPABASE_URL" ||
      config.publishableKey === "VITE_SUPABASE_PUBLISHABLE_KEY") {
    console.warn(
      "[Nimbus/Supabase] supabase-config.js is missing or not filled in. " +
      "Copy supabase-config.example.js to supabase-config.js and set your " +
      "Supabase Project URL and Publishable Key."
    );
    window.nimbusSupabase = null;
    return;
  }

  if (!window.supabase || typeof window.supabase.createClient !== "function") {
    console.warn("[Nimbus/Supabase] supabase-js did not load from the CDN.");
    window.nimbusSupabase = null;
    return;
  }

  window.nimbusSupabase = window.supabase.createClient(
    config.url,
    config.publishableKey
  );
})();
