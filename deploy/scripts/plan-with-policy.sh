#!/usr/bin/env bash
# deploy/scripts/plan-with-policy.sh
# Usage: ./plan-with-policy.sh [--env dev|staging|prod] [--provider gcp|aws|azure]
#
# Runs: terraform plan → JSON export → conftest evaluate against Rego policies
# Exit codes: 0 = pass, 1 = policy violations (blocks CI), 2 = warnings only
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TERRAFORM_DIR="${SCRIPT_DIR}/../terraform"
POLICY_DIR="${TERRAFORM_DIR}/policies"

ENV="${ENV:-dev}"
PROVIDER="${PROVIDER:-gcp}"
PLAN_FILE="${TMPDIR:-/tmp}/aegis-plan-${ENV}.tfplan"
PLAN_JSON="${TMPDIR:-/tmp}/aegis-plan-${ENV}.json"

# ─── Argument Parsing ─────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case $1 in
        --env)      ENV="$2";      shift 2 ;;
        --provider) PROVIDER="$2"; shift 2 ;;
        --help)
            echo "Usage: $0 [--env dev|staging|prod] [--provider gcp|aws|azure]"
            exit 0
            ;;
        *) echo "[!] Unknown argument: $1"; exit 1 ;;
    esac
done

ENV_DIR="${TERRAFORM_DIR}/environments/${ENV}"
if [[ ! -d "${ENV_DIR}" ]]; then
    echo "[!] Environment directory not found: ${ENV_DIR}"
    exit 1
fi

# ─── Dependency Check ─────────────────────────────────────────────────────────
for tool in terraform conftest jq; do
    if ! command -v "${tool}" &>/dev/null; then
        echo "[!] Required tool not found: ${tool}"
        echo "    Install: https://developer.hashicorp.com/terraform | https://www.conftest.dev | https://jqlang.org"
        exit 1
    fi
done

echo "[*] CloudForge Policy-Gated Plan"
echo "    Environment : ${ENV}"
echo "    Provider    : ${PROVIDER}"
echo "    Policy dir  : ${POLICY_DIR}"
echo ""

# ─── Step 1: Terraform Init + Plan ───────────────────────────────────────────
echo "[>] Step 1: terraform init"
terraform -chdir="${ENV_DIR}" init -input=false -backend=false 2>&1 | tail -5

echo "[>] Step 2: terraform plan → ${PLAN_FILE}"
terraform -chdir="${ENV_DIR}" plan \
    -var="cloud_provider=${PROVIDER}" \
    -input=false \
    -out="${PLAN_FILE}" 2>&1

# ─── Step 2: Export Plan to JSON ─────────────────────────────────────────────
echo "[>] Step 3: export plan JSON → ${PLAN_JSON}"
terraform -chdir="${ENV_DIR}" show -json "${PLAN_FILE}" > "${PLAN_JSON}"

RESOURCE_COUNT=$(jq '.resource_changes | length' "${PLAN_JSON}")
echo "    Resources in plan: ${RESOURCE_COUNT}"

# ─── Step 3: conftest Evaluation ─────────────────────────────────────────────
echo ""
echo "[>] Step 4: conftest evaluate"
echo "    Policies: $(ls "${POLICY_DIR}"/*.rego | xargs -I{} basename {})"
echo ""

CONFTEST_EXIT=0
conftest test "${PLAN_JSON}" \
    --policy "${POLICY_DIR}" \
    --namespace "terraform" \
    --output table \
    2>&1 || CONFTEST_EXIT=$?

echo ""

# ─── Step 4: Gate on Exit Code ───────────────────────────────────────────────
if [[ ${CONFTEST_EXIT} -eq 0 ]]; then
    echo "[+] All policy checks PASSED. Safe to apply."
    echo "    Run: terraform -chdir=${ENV_DIR} apply ${PLAN_FILE}"
    exit 0
elif [[ ${CONFTEST_EXIT} -eq 2 ]]; then
    echo "[!] Policy checks passed with WARNINGS. Review above before applying."
    exit 2
else
    echo "[-] Policy VIOLATIONS detected. Resolve before applying."
    echo ""
    echo "    Common remediation paths:"
    echo "    - SECURITY-*: Review encryption/public IP/TLS settings in module variables"
    echo "    - COST-*:     Downsize instance type or submit exception via CloudForge UI"
    echo "    - NAMING-*:   Ensure resource names follow {project}-{env}-{service}"
    echo "    - NETWORK-*:  Restrict security group CIDRs; move databases to private subnets"
    echo "    - AI-GOV-*:   Set AI_MODEL to approved model; add observability env vars"
    exit 1
fi
