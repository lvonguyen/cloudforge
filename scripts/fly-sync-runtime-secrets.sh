#!/usr/bin/env bash
set -euo pipefail

SCRIPT_NAME="$(basename "$0")"

APP="${FLY_APP:-cloudforge-api}"
CONTEXT="${CLOUDFORGE_CONTEXT:-personal}"
APPLY=false
INCLUDE_INTEGRATIONS=false
INCLUDE_POSTGRES=false
INCLUDE_THREAT_INTEL=false

FLY_API_TOKEN_REF="${FLY_API_TOKEN_REF:-}"
AEGIS_JWT_SECRET_REF="${AEGIS_JWT_SECRET_REF:-}"
AEGIS_DATABASE_URL_REF="${AEGIS_DATABASE_URL_REF:-}"
ASANA_PAT_REF="${ASANA_PAT_REF:-}"
JIRA_API_TOKEN_REF="${JIRA_API_TOKEN_REF:-}"
ASANA_WEBHOOK_TOKEN_REF="${ASANA_WEBHOOK_TOKEN_REF:-}"
GREYNOISE_API_KEY_REF="${GREYNOISE_API_KEY_REF:-}"
HIBP_API_KEY_REF="${HIBP_API_KEY_REF:-}"
OTX_API_KEY_REF="${OTX_API_KEY_REF:-}"
THREATFOX_AUTH_KEY_REF="${THREATFOX_AUTH_KEY_REF:-}"

ASANA_WORKSPACE_GID="${ASANA_WORKSPACE_GID:-1212540665692548}"
ASANA_DEFAULT_PROJECT_GID="${ASANA_DEFAULT_PROJECT_GID:-1213803357058798}"
JIRA_URL="${JIRA_URL:-https://lvn-jira-dev.atlassian.net}"
JIRA_USERNAME="${JIRA_USERNAME:-liem@pvdsolutions.io}"
JIRA_PROJECT_KEY="${JIRA_PROJECT_KEY:-CVRT}"
FINDINGS_SOURCE="${FINDINGS_SOURCE:-mock}"
SECGRAPH_AUTO_TICKETS="${SECGRAPH_AUTO_TICKETS:-false}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m'

ok() { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
fail() { echo -e "${RED}[-]${NC} $1" >&2; exit 1; }
info() { echo -e "${BLUE}[*]${NC} $1"; }

usage() {
  cat <<EOF
Usage: ${SCRIPT_NAME} [options]

Sync runtime secrets from 1Password into Fly.io for the active demo API.
Dry-run is the default; pass --apply to execute.

Options:
  --app <name>                 Fly app name (default: ${APP})
  --context <personal|haea>    Secret default context (default: ${CONTEXT})
  --include-integrations       Sync Asana/Jira runtime config and tokens
  --include-postgres           Sync AEGIS_DATABASE_URL plus D19 runtime flags
  --include-threat-intel       Sync threat-intel provider keys
  --apply                      Resolve op:// refs and run fly secrets set
  --dry-run                    Print the plan only (default)
  --help                       Show this help

1Password ref overrides:
  FLY_API_TOKEN_REF            Personal default: op://Development/flyio-org-deploy-token/credential
  AEGIS_JWT_SECRET_REF         Personal default: op://Development/aegis-personal-jwt-secret/credential
  AEGIS_DATABASE_URL_REF       Personal default: op://Development/4uvialfye3icuwak32yblswaam/credential
  ASANA_PAT_REF                Personal default: op://Development/lvnio-asana-dev-token/credential
  JIRA_API_TOKEN_REF           Personal default: op://Development/lvn-pvd-dev-jira-token/credential
  ASANA_WEBHOOK_TOKEN_REF      Optional
  GREYNOISE_API_KEY_REF        Personal default: op://Development/glzdciaetfnrafvhntwe6enymu/credential
  HIBP_API_KEY_REF             Personal default: op://Development/itrqxidqwvzwviz357fqtpcdi4/credential
  OTX_API_KEY_REF              Personal default: op://Development/dy5ds2uttd35prezcbyb4753ra/credential
  THREATFOX_AUTH_KEY_REF       Personal default: op://Development/qxi4xw27nzkw6diikdug4arose/wvvuolayxv6m7b75ldy4c52aiu

Plain env overrides:
  ASANA_WORKSPACE_GID
  ASANA_DEFAULT_PROJECT_GID
  JIRA_URL
  JIRA_USERNAME
  JIRA_PROJECT_KEY
  FINDINGS_SOURCE              Default: mock. Set to postgres only after schema + seed are loaded.
  SECGRAPH_AUTO_TICKETS

Examples:
  ${SCRIPT_NAME} --include-integrations --include-threat-intel

  AEGIS_DATABASE_URL_REF='op://Development/4uvialfye3icuwak32yblswaam/credential' \\
  ${SCRIPT_NAME} --include-integrations --include-threat-intel --include-postgres --apply

  FINDINGS_SOURCE=postgres \\
  AEGIS_DATABASE_URL_REF='op://Development/4uvialfye3icuwak32yblswaam/credential' \\
  ${SCRIPT_NAME} --include-integrations --include-threat-intel --include-postgres --apply
EOF
}

apply_context_defaults() {
  case "${CONTEXT}" in
    personal)
      if [[ -z "${FLY_API_TOKEN_REF}" ]]; then
        FLY_API_TOKEN_REF='op://Development/flyio-org-deploy-token/credential'
      fi
      if [[ -z "${AEGIS_JWT_SECRET_REF}" ]]; then
        AEGIS_JWT_SECRET_REF='op://Development/aegis-personal-jwt-secret/credential'
      fi
      if [[ -z "${AEGIS_DATABASE_URL_REF}" ]]; then
        AEGIS_DATABASE_URL_REF='op://Development/4uvialfye3icuwak32yblswaam/credential'
      fi
      if [[ -z "${ASANA_PAT_REF}" ]]; then
        ASANA_PAT_REF='op://Development/lvnio-asana-dev-token/credential'
      fi
      if [[ -z "${JIRA_API_TOKEN_REF}" ]]; then
        JIRA_API_TOKEN_REF='op://Development/lvn-pvd-dev-jira-token/credential'
      fi
      if [[ -z "${ASANA_WEBHOOK_TOKEN_REF}" ]]; then
        ASANA_WEBHOOK_TOKEN_REF='op://Development/aegis-asana-webhook-secret/credential'
      fi
      if [[ -z "${GREYNOISE_API_KEY_REF}" ]]; then
        GREYNOISE_API_KEY_REF='op://Development/glzdciaetfnrafvhntwe6enymu/credential'
      fi
      if [[ -z "${HIBP_API_KEY_REF}" ]]; then
        HIBP_API_KEY_REF='op://Development/itrqxidqwvzwviz357fqtpcdi4/credential'
      fi
      if [[ -z "${OTX_API_KEY_REF}" ]]; then
        OTX_API_KEY_REF='op://Development/dy5ds2uttd35prezcbyb4753ra/credential'
      fi
      if [[ -z "${THREATFOX_AUTH_KEY_REF}" ]]; then
        THREATFOX_AUTH_KEY_REF='op://Development/qxi4xw27nzkw6diikdug4arose/wvvuolayxv6m7b75ldy4c52aiu'
      fi
      ;;
    haea)
      :
      ;;
    *)
      fail "unsupported context: ${CONTEXT}"
      ;;
  esac
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --app)
      APP="$2"
      shift 2
      ;;
    --context)
      CONTEXT="$2"
      shift 2
      ;;
    --include-integrations)
      INCLUDE_INTEGRATIONS=true
      shift
      ;;
    --include-postgres)
      INCLUDE_POSTGRES=true
      shift
      ;;
    --include-threat-intel)
      INCLUDE_THREAT_INTEL=true
      shift
      ;;
    --apply)
      APPLY=true
      shift
      ;;
    --dry-run)
      APPLY=false
      shift
      ;;
    --help)
      usage
      exit 0
      ;;
    *)
      fail "unknown argument: $1"
      ;;
  esac
done

apply_context_defaults

if [[ -z "${AEGIS_JWT_SECRET_REF}" ]]; then
  fail "AEGIS_JWT_SECRET_REF is required for context '${CONTEXT}'"
fi

if [[ "${INCLUDE_POSTGRES}" == "true" && -z "${AEGIS_DATABASE_URL_REF}" ]]; then
  fail "AEGIS_DATABASE_URL_REF is required when --include-postgres is set"
fi

if [[ "${INCLUDE_INTEGRATIONS}" == "true" && -z "${ASANA_PAT_REF}" ]]; then
  fail "ASANA_PAT_REF is required when --include-integrations is set"
fi

if [[ "${INCLUDE_INTEGRATIONS}" == "true" && -z "${JIRA_API_TOKEN_REF}" ]]; then
  fail "JIRA_API_TOKEN_REF is required when --include-integrations is set"
fi

if [[ "${INCLUDE_THREAT_INTEL}" == "true" && -z "${GREYNOISE_API_KEY_REF}" ]]; then
  fail "GREYNOISE_API_KEY_REF is required when --include-threat-intel is set"
fi

if [[ "${INCLUDE_THREAT_INTEL}" == "true" && -z "${HIBP_API_KEY_REF}" ]]; then
  fail "HIBP_API_KEY_REF is required when --include-threat-intel is set"
fi

if [[ "${INCLUDE_THREAT_INTEL}" == "true" && -z "${OTX_API_KEY_REF}" ]]; then
  fail "OTX_API_KEY_REF is required when --include-threat-intel is set"
fi

secret_names=()
secret_refs=()
plain_names=()
plain_values=()

add_secret_ref() {
  secret_names+=("$1")
  secret_refs+=("$2")
}

add_plain_value() {
  plain_names+=("$1")
  plain_values+=("$2")
}

add_secret_ref "AEGIS_JWT_SECRET" "${AEGIS_JWT_SECRET_REF}"

if [[ "${INCLUDE_POSTGRES}" == "true" ]]; then
  add_secret_ref "AEGIS_DATABASE_URL" "${AEGIS_DATABASE_URL_REF}"
  add_plain_value "FINDINGS_SOURCE" "${FINDINGS_SOURCE}"
  add_plain_value "SECGRAPH_AUTO_TICKETS" "${SECGRAPH_AUTO_TICKETS}"
fi

if [[ "${INCLUDE_INTEGRATIONS}" == "true" ]]; then
  add_secret_ref "ASANA_PAT" "${ASANA_PAT_REF}"
  add_secret_ref "JIRA_API_TOKEN" "${JIRA_API_TOKEN_REF}"
  add_plain_value "ASANA_WORKSPACE_GID" "${ASANA_WORKSPACE_GID}"
  add_plain_value "ASANA_DEFAULT_PROJECT_GID" "${ASANA_DEFAULT_PROJECT_GID}"
  add_plain_value "JIRA_URL" "${JIRA_URL}"
  add_plain_value "JIRA_USERNAME" "${JIRA_USERNAME}"
  add_plain_value "JIRA_PROJECT_KEY" "${JIRA_PROJECT_KEY}"

  if [[ -n "${ASANA_WEBHOOK_TOKEN_REF}" ]]; then
    add_secret_ref "ASANA_WEBHOOK_TOKEN" "${ASANA_WEBHOOK_TOKEN_REF}"
  fi
fi

if [[ "${INCLUDE_THREAT_INTEL}" == "true" ]]; then
  add_secret_ref "GREYNOISE_API_KEY" "${GREYNOISE_API_KEY_REF}"
  add_secret_ref "HIBP_API_KEY" "${HIBP_API_KEY_REF}"
  add_secret_ref "OTX_API_KEY" "${OTX_API_KEY_REF}"
  if [[ -n "${THREATFOX_AUTH_KEY_REF}" ]]; then
    add_secret_ref "THREATFOX_AUTH_KEY" "${THREATFOX_AUTH_KEY_REF}"
  fi
fi

load_op_service_account_token() {
  if [[ -n "${OP_SERVICE_ACCOUNT_TOKEN:-}" ]]; then
    return
  fi

  local token_file
  token_file="${HOME}/.config/op/sa-token"
  if [[ -r "${token_file}" ]]; then
    export OP_SERVICE_ACCOUNT_TOKEN
    OP_SERVICE_ACCOUNT_TOKEN="$(tr -d '\r\n' < "${token_file}")"
  fi
}

resolve_op_ref() {
  local ref="$1"
  local value
  if ! value="$(op read "${ref}")"; then
    fail "failed to resolve 1Password ref: ${ref}"
  fi
  if [[ -z "${value}" ]]; then
    fail "1Password ref resolved to an empty value: ${ref}"
  fi
  printf '%s' "${value}"
}

detect_fly_bin() {
  if command -v fly >/dev/null 2>&1; then
    printf 'fly'
    return
  fi
  if command -v flyctl >/dev/null 2>&1; then
    printf 'flyctl'
    return
  fi
  fail "Fly CLI not found. Install 'fly' or 'flyctl' first."
}

echo ""
info "Fly runtime secret sync"
echo "    App                 : ${APP}"
echo "    Context             : ${CONTEXT}"
echo "    Integrations        : ${INCLUDE_INTEGRATIONS}"
echo "    Postgres config     : ${INCLUDE_POSTGRES}"
echo "    Threat intel        : ${INCLUDE_THREAT_INTEL}"
echo "    Apply               : ${APPLY}"
echo ""

echo "Secret refs:"
for i in "${!secret_names[@]}"; do
  echo "  - ${secret_names[$i]} <- ${secret_refs[$i]}"
done

if [[ ${#plain_names[@]} -gt 0 ]]; then
  echo ""
  echo "Plain runtime values:"
  for i in "${!plain_names[@]}"; do
    echo "  - ${plain_names[$i]}=${plain_values[$i]}"
  done
fi

echo ""
if [[ "${APPLY}" != "true" ]]; then
  info "Dry-run only. Re-run with --apply to push these values to Fly."
  exit 0
fi

command -v op >/dev/null 2>&1 || fail "1Password CLI not found. Install 'op' first."
load_op_service_account_token

local_fly_bin="$(detect_fly_bin)"

if [[ -z "${FLY_API_TOKEN:-}" && -n "${FLY_API_TOKEN_REF}" ]]; then
  export FLY_API_TOKEN
  FLY_API_TOKEN="$(resolve_op_ref "${FLY_API_TOKEN_REF}")"
fi

fly_args=()
for i in "${!secret_names[@]}"; do
  resolved_value="$(resolve_op_ref "${secret_refs[$i]}")"
  fly_args+=("${secret_names[$i]}=${resolved_value}")
done

for i in "${!plain_names[@]}"; do
  fly_args+=("${plain_names[$i]}=${plain_values[$i]}")
done

info "Applying $((${#fly_args[@]})) runtime values via ${local_fly_bin} secrets set"
"${local_fly_bin}" secrets set "${fly_args[@]}" -a "${APP}"
ok "Fly runtime secrets updated for ${APP}"
