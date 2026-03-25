#!/bin/sh
set -e

JWT=$(node scripts/generate-jwt.mjs)
VITE_STATIC_TOKEN="$JWT" npx vite build
