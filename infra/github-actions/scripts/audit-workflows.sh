#!/usr/bin/env bash
# Read-only GitHub Actions inventory collector.
# Enumerates active repositories, default-branch workflows, jobs, runner
# declarations, triggers, permissions, environments, and name-only
# secret/variable references. Query names/metadata only.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
LIB="${ROOT}/infra/github-actions/scripts/lib/audit_workflows.py"
DEFAULT_OUTPUT="${ROOT}/infra/github-actions/inventory"
DEFAULT_HOST_EVIDENCE="${ROOT}/infra/github-actions/inventory/evidence/hosts-2026-08-19.json"

ORG="Ken-Technology"
OFFLINE=0
FIXTURE_DIR=""
OUTPUT_DIR="${DEFAULT_OUTPUT}"
COLLECT_DIR=""
KEEP_COLLECT=0

# gh may emit ANSI-colored JSON when a TTY or color.ui=always is set.
# Inventory files must stay parseable and must never include styled dumps.
export NO_COLOR=1
export CLICOLOR=0
export CLICOLOR_FORCE=0
export GH_FORCE_TTY=0
export GH_PAGER=cat
export TERM="${TERM:-dumb}"

# Explicit denylist against secret-value endpoints and accidental value output.
# The collector may list secret *names*. It must never fetch or print values.
SECRET_VALUE_DENYLIST=(
  "gh secret get"
  "gh variable get"
  "op item get"
  "op read "
  "op://.*password"
  "/actions/secrets/.*/"
  "/actions/variables/.*/"
  "/environments/.*/secrets/.\\+"
  "/orgs/.*/actions/secrets/.\\+"
  "secrets/.*/value"
  "--jq .value"
  "--jq .secret"
  "jq -r .value"
)

usage() {
  cat <<'EOF'
Usage: audit-workflows.sh [--org NAME] [--output-dir DIR] [--offline --fixture-dir DIR]
                          [--collect-dir DIR] [--keep-collect]

Read-only. Live mode uses gh + jq. Offline mode consumes a fixture tree so
tests do not depend on GitHub.
EOF
}

die() {
  printf 'audit-workflows: %s\n' "$*" >&2
  exit 1
}

guard_command() {
  local rendered="$*"
  local item
  for item in "${SECRET_VALUE_DENYLIST[@]}"; do
    if [[ "${rendered}" =~ ${item} ]]; then
      die "blocked by SECRET_VALUE_DENYLIST: ${item}"
    fi
  done
}

safe_gh() {
  guard_command gh "$@"
  gh "$@" | strip_ansi
}

strip_ansi() {
  python3 -c 'import re,sys; sys.stdout.write(re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", sys.stdin.read()))'
}

json_file() {
  local path="$1"
  shift
  mkdir -p "$(dirname "${path}")"
  if ! "$@" | strip_ansi >"${path}"; then
    die "command failed writing ${path}"
  fi
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --org)
      ORG="$2"
      shift 2
      ;;
    --output-dir)
      OUTPUT_DIR="$2"
      shift 2
      ;;
    --offline)
      OFFLINE=1
      shift
      ;;
    --fixture-dir)
      FIXTURE_DIR="$2"
      shift 2
      ;;
    --collect-dir)
      COLLECT_DIR="$2"
      KEEP_COLLECT=1
      shift 2
      ;;
    --keep-collect)
      KEEP_COLLECT=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      usage
      exit 2
      ;;
  esac
done

[[ -f "${LIB}" ]] || die "missing parser ${LIB}"
mkdir -p "${OUTPUT_DIR}"

if [[ "${OFFLINE}" -eq 1 ]]; then
  [[ -n "${FIXTURE_DIR}" && -d "${FIXTURE_DIR}" ]] || die "--offline requires --fixture-dir"
  python3 "${LIB}" "${FIXTURE_DIR}" "${OUTPUT_DIR}"
  exit 0
fi

command -v gh >/dev/null || die "gh is required for live collection"
command -v jq >/dev/null || die "jq is required for live collection"
command -v python3 >/dev/null || die "python3 is required to parse workflow YAML"

if [[ -z "${COLLECT_DIR}" ]]; then
  COLLECT_DIR="$(mktemp -d "${TMPDIR:-/tmp}/ken-actions-audit.XXXXXX")"
fi
mkdir -p "${COLLECT_DIR}"

cleanup() {
  if [[ "${KEEP_COLLECT}" -eq 0 && -n "${COLLECT_DIR}" && -d "${COLLECT_DIR}" ]]; then
    rm -rf "${COLLECT_DIR}"
  fi
}
trap cleanup EXIT

printf '{"collected_at":"%s","organization":"%s","mode":"live","policy":"names only"}\n' \
  "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${ORG}" >"${COLLECT_DIR}/collection-meta.json"

json_file "${COLLECT_DIR}/org.json" safe_gh api "orgs/${ORG}" --jq '{login:.login,plan:{name:(.plan.name // "free")},id:.id}'
json_file "${COLLECT_DIR}/repos.json" safe_gh repo list "${ORG}" --limit 100 \
  --json name,visibility,isArchived,defaultBranchRef,url \
  --jq '[.[] | select(.isArchived == false)]'

json_file "${COLLECT_DIR}/runners.json" safe_gh api --paginate "orgs/${ORG}/actions/runners?per_page=100"
json_file "${COLLECT_DIR}/runner-groups.json" safe_gh api --paginate "orgs/${ORG}/actions/runner-groups?per_page=100"

# Name-only org secret/variable lists. Never retrieve a value.
json_file "${COLLECT_DIR}/org-secrets.json" safe_gh secret list --org "${ORG}" --json name,updatedAt
if ! safe_gh variable list --org "${ORG}" --json name >"${COLLECT_DIR}/org-variables.json"; then
  echo '[]' >"${COLLECT_DIR}/org-variables.json"
fi

if safe_gh api "orgs/${ORG}/settings/billing/budgets" --jq '{raw:true}' >/dev/null 2>&1; then
  safe_gh api "orgs/${ORG}/settings/billing/budgets" >"${COLLECT_DIR}/budgets-raw.json" || true
fi
python3 - "${COLLECT_DIR}/budgets-raw.json" "${COLLECT_DIR}/budgets.json" <<'PY'
import json
import sys
from pathlib import Path

src = Path(sys.argv[1])
dst = Path(sys.argv[2])
payload = {}
if src.exists():
    try:
        payload = json.loads(src.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        payload = {}
budgets = payload.get("budgets") or payload.get("items") or []
overage = 0
prevent = True
for item in budgets:
    product = str(item.get("product") or item.get("budget_product") or "").lower()
    if "action" in product:
        overage = item.get("budget_amount") or item.get("amount") or 0
        prevent = bool(item.get("prevent_further_usage", True))
out = {
    "actions_overage_budget_usd": overage,
    "prevent_further_usage": prevent,
}
dst.write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")
PY

if [[ -f "${DEFAULT_HOST_EVIDENCE}" ]]; then
  cp "${DEFAULT_HOST_EVIDENCE}" "${COLLECT_DIR}/hosts.json"
fi
if [[ -f "${ROOT}/infra/github-actions/inventory/evidence/grok-runners.json" ]]; then
  cp "${ROOT}/infra/github-actions/inventory/evidence/grok-runners.json" "${COLLECT_DIR}/grok-runners.json"
fi
if [[ -f "${ROOT}/infra/github-actions/inventory/evidence/worldstream-runners.json" ]]; then
  cp "${ROOT}/infra/github-actions/inventory/evidence/worldstream-runners.json" "${COLLECT_DIR}/worldstream-runners.json"
fi
if [[ -f "${ROOT}/infra/github-actions/inventory/evidence/onepassword-vaults.json" ]]; then
  cp "${ROOT}/infra/github-actions/inventory/evidence/onepassword-vaults.json" "${COLLECT_DIR}/onepassword-vaults.json"
fi
if [[ -f "${ROOT}/infra/github-actions/inventory/evidence/blacksmith-billing.json" ]]; then
  cp "${ROOT}/infra/github-actions/inventory/evidence/blacksmith-billing.json" "${COLLECT_DIR}/blacksmith-billing.json"
fi

while IFS= read -r repo; do
  [[ -n "${repo}" ]] || continue
  printf 'audit-workflows: collecting %s (names/metadata only)\n' "${repo}" >&2
  repo_dir="${COLLECT_DIR}/repos/${repo}"
  mkdir -p "${repo_dir}/workflows" "${repo_dir}/environments" "${repo_dir}/environment-secrets"
  branch="$(jq -r --arg n "${repo}" '.[] | select(.name==$n) | .defaultBranchRef.name // "main"' "${COLLECT_DIR}/repos.json")"
  visibility="$(jq -r --arg n "${repo}" '.[] | select(.name==$n) | .visibility' "${COLLECT_DIR}/repos.json")"
  sha="$(safe_gh api "repos/${ORG}/${repo}/commits/${branch}" --jq .sha | strip_ansi)"
  printf '{"name":"%s","visibility":"%s","archived":false,"default_branch":"%s","default_sha":"%s"}\n' \
    "${repo}" "${visibility}" "${branch}" "${sha}" >"${repo_dir}/meta.json"

  if tree_json="$(safe_gh api "repos/${ORG}/${repo}/git/trees/${branch}?recursive=1" | strip_ansi)"; then
    printf '%s\n' "${tree_json}" >"${repo_dir}/tree.json"
    while IFS= read -r wf; do
      [[ -n "${wf}" ]] || continue
      dest="${repo_dir}/workflows/$(basename "${wf}")"
      safe_gh api -H "Accept: application/vnd.github.raw" \
        "repos/${ORG}/${repo}/contents/${wf}?ref=${branch}" >"${dest}"
    done < <(printf '%s\n' "${tree_json}" | jq -r '.tree[]? | select(.type=="blob") | .path | select(test("^\\.github/workflows/[^/]+\\.(yml|yaml)$"))')
  fi

  # Name-only repository secret and variable lists.
  safe_gh secret list --repo "${ORG}/${repo}" --json name,updatedAt >"${repo_dir}/secrets.json" || echo '[]' >"${repo_dir}/secrets.json"
  safe_gh variable list --repo "${ORG}/${repo}" --json name >"${repo_dir}/variables.json" || echo '[]' >"${repo_dir}/variables.json"

  if envs_json="$(safe_gh api "repos/${ORG}/${repo}/environments" --jq . 2>/dev/null)"; then
    printf '%s\n' "${envs_json}" >"${repo_dir}/environments.json"
    while IFS= read -r env_name; do
      [[ -n "${env_name}" ]] || continue
      encoded="$(python3 -c 'import sys,urllib.parse; print(urllib.parse.quote(sys.argv[1]))' "${env_name}")"
      safe_gh api "repos/${ORG}/${repo}/environments/${encoded}" >"${repo_dir}/environments/${env_name}.json" || true
      if python3 - "${repo_dir}/environments/${env_name}.json" <<'PY'
import json
import sys
from pathlib import Path
path = Path(sys.argv[1])
try:
    data = json.loads(path.read_text(encoding="utf-8"))
except Exception:
    sys.exit(1)
policy = data.get("deployment_branch_policy") or {}
sys.exit(0 if policy.get("custom_branch_policies") else 1)
PY
      then
        safe_gh api "repos/${ORG}/${repo}/environments/${encoded}/deployment-branch-policies" \
          >"${repo_dir}/environments/${env_name}.branches.json" || echo '[]' >"${repo_dir}/environments/${env_name}.branches.json"
      fi
      safe_gh secret list --repo "${ORG}/${repo}" --env "${env_name}" --json name,updatedAt \
        >"${repo_dir}/environment-secrets/${env_name}.json" || echo '[]' >"${repo_dir}/environment-secrets/${env_name}.json"
    done < <(printf '%s\n' "${envs_json}" | jq -r '.environments[]?.name // empty')
  fi
done < <(jq -r '.[].name' "${COLLECT_DIR}/repos.json")

python3 "${LIB}" "${COLLECT_DIR}" "${OUTPUT_DIR}"
