#!/bin/sh
set -e

# Generate a static JWT for demo/portfolio auth.
# If JWT_SECRET is not set, generate-jwt.mjs exits cleanly and
# VITE_STATIC_TOKEN remains empty — the frontend falls back to
# mock data or sessionStorage auth.
JWT=$(node scripts/generate-jwt.mjs)
export VITE_STATIC_TOKEN="$JWT"

tsc -b && vite build && node scripts/trim-demo-findings.js
