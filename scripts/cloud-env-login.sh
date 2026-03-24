#!/usr/bin/env bash
# cloud-env-login.sh — Authenticate to all HAEA cloud environments
#
# Usage:
#   ./scripts/cloud-env-login.sh          # Login to all (interactive)
#   ./scripts/cloud-env-login.sh aws      # AWS SSO only (all 4 orgs + personal)
#   ./scripts/cloud-env-login.sh gcp      # GCP only
#   ./scripts/cloud-env-login.sh az       # Azure only
#   ./scripts/cloud-env-login.sh status   # Check auth status across all clouds
#   ./scripts/cloud-env-login.sh discover # Discover all accounts/projects/subs

set -euo pipefail

# ─── Colors ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'; BLUE='\033[0;34m'
NC='\033[0m'
ok() { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
fail() { echo -e "${RED}[-]${NC} $1"; }
info() { echo -e "${BLUE}[*]${NC} $1"; }

# ─── AWS SSO Sessions ────────────────────────────────────────────────────────
AWS_SSO_SESSIONS=(
  "haea-sso|HMA Legacy|haea-aws-sso.awsapps.com|haea-sso"
  "haea-kna|KNA|d-9267fb4f9b.awsapps.com|haea-kna-readonly"
  "haea-hkna|HMNA|d-92678cbdc7.awsapps.com|haea-hmna-readonly"
  "haea-hmgna|HMGNA|d-92678d8f7b.awsapps.com|haea-hmgna-readonly"
  "lvn-sso|Personal|d-9267d171b2.awsapps.com|lvn-personal"
)

# ─── AWS Login ────────────────────────────────────────────────────────────────
aws_login() {
  info "AWS SSO — 4 HAEA orgs + personal"
  for entry in "${AWS_SSO_SESSIONS[@]}"; do
    IFS='|' read -r session label portal profile <<< "$entry"
    echo -n "  $label ($session): "
    if aws sts get-caller-identity --profile "$profile" --output json >/dev/null 2>&1; then
      ok "already authenticated"
    else
      warn "logging in..."
      aws sso login --sso-session "$session" 2>&1 | tail -1
      if aws sts get-caller-identity --profile "$profile" --output json >/dev/null 2>&1; then
        ok "authenticated"
      else
        fail "login failed — check browser"
      fi
    fi
  done
}

# ─── GCP Login ────────────────────────────────────────────────────────────────
gcp_login() {
  info "GCP — autoeveramerica.com org"
  if gcloud auth print-access-token >/dev/null 2>&1; then
    local account
    account=$(gcloud config get account 2>/dev/null)
    ok "already authenticated as $account"
  else
    warn "logging in..."
    gcloud auth login --update-adc 2>&1
    if gcloud auth print-access-token >/dev/null 2>&1; then
      ok "authenticated"
    else
      fail "login failed"
    fi
  fi
}

# ─── Azure Login ──────────────────────────────────────────────────────────────
az_login() {
  info "Azure — HMGNA tenant (bd29b3ab-aaa2-425a-b882-9e7f73283ca6)"
  if az account show --output json >/dev/null 2>&1; then
    local name tenant
    name=$(az account show --query "user.name" -o tsv 2>/dev/null)
    tenant=$(az account show --query "tenantDisplayName" -o tsv 2>/dev/null)
    ok "already authenticated as $name ($tenant)"
  else
    warn "logging in to HMGNA tenant..."
    az login --tenant bd29b3ab-aaa2-425a-b882-9e7f73283ca6 2>&1
    if az account show --output json >/dev/null 2>&1; then
      ok "authenticated"
    else
      fail "login failed"
    fi
  fi
}

# ─── Status Check ─────────────────────────────────────────────────────────────
status() {
  echo ""
  info "=== Cloud Environment Auth Status ==="
  echo ""

  # AWS
  info "AWS SSO Sessions:"
  for entry in "${AWS_SSO_SESSIONS[@]}"; do
    IFS='|' read -r session label portal profile <<< "$entry"
    echo -n "  $label ($profile): "
    if aws sts get-caller-identity --profile "$profile" --output json >/dev/null 2>&1; then
      local arn
      arn=$(aws sts get-caller-identity --profile "$profile" --query "Arn" --output text 2>/dev/null)
      ok "$arn"
    else
      fail "not authenticated"
    fi
  done

  echo ""

  # GCP
  info "GCP:"
  echo -n "  autoeveramerica.com: "
  if gcloud auth print-access-token >/dev/null 2>&1; then
    local gcp_account gcp_project
    gcp_account=$(gcloud config get account 2>/dev/null)
    gcp_project=$(gcloud config get project 2>/dev/null || echo "none")
    ok "$gcp_account (project: $gcp_project)"
  else
    fail "not authenticated"
  fi

  echo ""

  # Azure
  info "Azure:"
  echo -n "  HMGNA tenant: "
  if az account show --output json >/dev/null 2>&1; then
    local az_name az_tenant az_sub
    az_name=$(az account show --query "user.name" -o tsv 2>/dev/null)
    az_tenant=$(az account show --query "tenantDisplayName" -o tsv 2>/dev/null)
    az_sub=$(az account show --query "name" -o tsv 2>/dev/null)
    ok "$az_name ($az_tenant, sub: $az_sub)"
  else
    fail "not authenticated"
  fi

  echo ""
}

# ─── Discover ─────────────────────────────────────────────────────────────────
discover() {
  info "=== Account/Project/Subscription Discovery ==="
  echo ""

  # AWS — list accounts per SSO session
  for entry in "${AWS_SSO_SESSIONS[@]}"; do
    IFS='|' read -r session label portal profile <<< "$entry"
    [[ "$session" == "lvn-sso" ]] && continue  # skip personal
    info "AWS $label ($session):"
    local token_file
    token_file=$(python3 -c "
import json,glob,os,sys
portal='$portal'
for f in sorted(glob.glob(os.path.expanduser('~/.aws/sso/cache/*.json')), key=os.path.getmtime, reverse=True):
  try:
    d=json.load(open(f))
    if 'accessToken' in d and portal in d.get('startUrl',''):
      print(d['accessToken'].replace(chr(10),''), end=''); sys.exit(0)
  except: pass
" 2>/dev/null)
    if [[ -n "$token_file" ]]; then
      local count
      count=$(aws sso list-accounts --region us-west-2 --access-token "$token_file" --query "length(accountList)" --output text 2>/dev/null || echo "ERR")
      if [[ "$count" == "ERR" || "$count" == "0" ]]; then
        # Fallback: count profiles using this session
        local profile_count
        profile_count=$(grep -c "sso_session = $session" ~/.aws/config 2>/dev/null || echo "0")
        warn "token-based discovery unavailable — $profile_count profiles configured for this session"
      else
        ok "$count accounts visible"
      fi
    else
      fail "no SSO token — run login first"
    fi
  done

  echo ""

  # GCP
  info "GCP (autoeveramerica.com):"
  if gcloud auth print-access-token >/dev/null 2>&1; then
    local gcp_count
    gcp_count=$(gcloud projects list --format="value(projectId)" 2>/dev/null | wc -l | tr -d ' ')
    ok "$gcp_count projects"
  else
    fail "not authenticated"
  fi

  echo ""

  # Azure
  info "Azure (HMGNA):"
  if az account show >/dev/null 2>&1; then
    local az_count
    az_count=$(az account list --all --query "length([?tenantId=='bd29b3ab-aaa2-425a-b882-9e7f73283ca6'])" --output tsv 2>/dev/null)
    ok "$az_count subscriptions"
  else
    fail "not authenticated"
  fi

  echo ""
}

# ─── Main ─────────────────────────────────────────────────────────────────────
case "${1:-all}" in
  aws)      aws_login ;;
  gcp)      gcp_login ;;
  az|azure) az_login ;;
  status)   status ;;
  discover) discover ;;
  all)
    aws_login
    echo ""
    gcp_login
    echo ""
    az_login
    echo ""
    status
    ;;
  *)
    echo "Usage: $0 {all|aws|gcp|az|status|discover}"
    exit 1
    ;;
esac
