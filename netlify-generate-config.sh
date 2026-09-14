#!/bin/sh
# Generates supabase-config.js on Netlify from environment variables, so the
# real file (gitignored, never committed) never needs to exist in the repo.
# Runs as the Netlify "build command" for this buildless project - plain
# POSIX shell only, no npm/node/dependencies required. Also runnable locally
# (e.g. in Git Bash on Windows) for testing.
#
# Required environment variables (set in Netlify: Site settings -> Environment
# variables - never committed to git):
#   SUPABASE_URL              - the Supabase project URL
#   SUPABASE_PUBLISHABLE_KEY  - the Supabase anon/publishable key (safe for
#                                client-side code; RLS is the real boundary)
set -e

if [ -z "$SUPABASE_URL" ] || [ -z "$SUPABASE_PUBLISHABLE_KEY" ]; then
  echo "ERROR: SUPABASE_URL and/or SUPABASE_PUBLISHABLE_KEY environment variables are not set." >&2
  echo "Set them in Netlify: Site settings -> Environment variables, then redeploy." >&2
  exit 1
fi

cat > supabase-config.js <<EOF
// Auto-generated at build time by netlify-generate-config.sh from Netlify
// environment variables. Not committed to git - see .gitignore.
window.NIMBUS_SUPABASE_CONFIG = {
  url: "$SUPABASE_URL",
  publishableKey: "$SUPABASE_PUBLISHABLE_KEY",
};
EOF

echo "supabase-config.js generated."
