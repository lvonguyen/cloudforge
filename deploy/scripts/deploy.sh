#!/usr/bin/env bash
# deploy/scripts/deploy.sh
# Usage: ./deploy.sh --env dev --provider gcp [--execute]
#
# Dry-run by default. Pass --execute to actually apply.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

ENV="${ENV:-dev}"
PROVIDER="${PROVIDER:-gcp}"
EXECUTE=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --env)      ENV="$2";      shift 2 ;;
        --provider) PROVIDER="$2"; shift 2 ;;
        --execute)  EXECUTE=true;  shift ;;
        *) echo "[!] Unknown: $1"; exit 1 ;;
    esac
done

echo "[*] Cloud Aegis Deploy"
echo "    Environment : ${ENV}"
echo "    Provider    : ${PROVIDER}"
echo "    Execute     : ${EXECUTE}"
echo ""

# Step 1: Always run policy check first
"${SCRIPT_DIR}/plan-with-policy.sh" --env "${ENV}" --provider "${PROVIDER}"
PLAN_EXIT=$?

if [[ ${PLAN_EXIT} -eq 1 ]]; then
    echo "[-] Deploy aborted: policy violations must be resolved."
    exit 1
fi

if [[ "${EXECUTE}" != "true" ]]; then
    echo "[*] Dry-run complete. Pass --execute to apply."
    exit 0
fi

# Step 2: Apply
TERRAFORM_DIR="${SCRIPT_DIR}/../terraform"
ENV_DIR="${TERRAFORM_DIR}/environments/${ENV}"
PLAN_FILE="${TMPDIR:-/tmp}/aegis-plan-${ENV}.tfplan"

echo "[>] Applying..."
terraform -chdir="${ENV_DIR}" apply "${PLAN_FILE}"
echo "[+] Deploy complete."
