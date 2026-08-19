#!/usr/bin/env bash
# Static assertions for Ken-SRE GitHub Actions inventory, labels, and later
# platform files. Subcommands are additive so later tasks can extend this
# runner without rewriting Task 2 inventory checks.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
GA_ROOT="${ROOT}/infra/github-actions"
INV="${GA_ROOT}/inventory"
AUDIT="${GA_ROOT}/scripts/audit-workflows.sh"
FIXTURE_DIR="${GA_ROOT}/tests/fixtures/offline-org"
FAILED=0
RAN=0

pass() {
  RAN=$((RAN + 1))
  printf '  PASS  %s\n' "$1"
}

fail() {
  RAN=$((RAN + 1))
  FAILED=$((FAILED + 1))
  printf '  FAIL  %s\n' "$1"
}

require_file() {
  local path="$1"
  if [[ -f "${path}" ]]; then
    pass "exists ${path#"${ROOT}/"}"
  else
    fail "missing ${path#"${ROOT}/"}"
  fi
}

assert_eq() {
  local label="$1" expected="$2" actual="$3"
  if [[ "${expected}" == "${actual}" ]]; then
    pass "${label} == ${expected}"
  else
    fail "${label}: expected ${expected}, got ${actual}"
  fi
}

assert_ge() {
  local label="$1" minimum="$2" actual="$3"
  if [[ "${actual}" =~ ^[0-9]+$ ]] && (( actual >= minimum )); then
    pass "${label} >= ${minimum} (${actual})"
  else
    fail "${label}: expected >= ${minimum}, got ${actual}"
  fi
}

python_inventory() {
  python3 - "$@" <<'PY'
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    sys.stderr.write("PyYAML is required for inventory assertions\n")
    sys.exit(2)

inv = Path(sys.argv[1])
cmd = sys.argv[2]
repos_path = inv / "repositories.yaml"
runners_path = inv / "runners.yaml"
secrets_path = inv / "secrets.yaml"

def load(path):
    if not path.exists():
        print(f"MISSING:{path.name}")
        sys.exit(3)
    with path.open(encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}

if cmd == "repo-counts":
    data = load(repos_path)
    repos = data.get("repositories") or []
    private = [r for r in repos if str(r.get("visibility", "")).lower() == "private"]
    public = [r for r in repos if str(r.get("visibility", "")).lower() == "public"]
    archived = [r for r in repos if r.get("archived") is True]
    names = [r.get("name") for r in repos]
    print(f"count={len(repos)}")
    print(f"private={len(private)}")
    print(f"public={len(public)}")
    print(f"archived={len(archived)}")
    print(f"unique={len(set(names))}")
    print(f"declared_active={data.get('counts', {}).get('active_repositories')}")
    print(f"declared_private={data.get('counts', {}).get('private_repositories')}")
    print(f"declared_public={data.get('counts', {}).get('public_repositories')}")
    print(f"plan={((data.get('organization_plan') or {}).get('name') or '').lower()}")
    print(f"minutes={((data.get('organization_plan') or {}).get('private_hosted_minutes_allowance'))}")
    print(f"overage={((data.get('organization_plan') or {}).get('actions_overage_budget_usd'))}")
    print(f"prevent={((data.get('organization_plan') or {}).get('prevent_further_usage'))}")
elif cmd == "classification":
    data = load(repos_path)
    missing = []
    missing_target = []
    grok_gate_wrong = []
    grok_review_wrong = []
    preprod_wrong = []
    unflagged_combined = []
    jobs = 0
    classified = 0
    for repo in data.get("repositories") or []:
        visibility = str(repo.get("visibility", "")).lower()
        for wf in repo.get("workflows") or []:
            path = wf.get("path") or ""
            grok_workflow = path.endswith("grok-pr-review.yml") or path.endswith("grok-pr-review.yaml")
            for job in wf.get("jobs") or []:
                jobs += 1
                classification = job.get("classification") or job.get("target_runner_class")
                if classification:
                    classified += 1
                else:
                    missing.append(f"{repo.get('name')}:{path}#{job.get('id')}")
                runs_on = job.get("runs_on")
                if isinstance(runs_on, list):
                    runs_on_s = "[" + ", ".join(str(x) for x in runs_on) + "]"
                else:
                    runs_on_s = str(runs_on or "")
                needs_target = (
                    "blacksmith" in runs_on_s.lower()
                    or "ken-ci" in runs_on_s
                    or "ubuntu-" in runs_on_s
                    or "self-hosted" in runs_on_s
                    or "${{" in runs_on_s
                )
                if needs_target and not job.get("target_runner_class"):
                    missing_target.append(f"{repo.get('name')}:{path}#{job.get('id')}")
                if grok_workflow and job.get("id") == "gate":
                    cls = str(job.get("classification") or "")
                    if "grok-review" not in cls:
                        grok_gate_wrong.append(f"{repo.get('name')}:{path}#{job.get('id')}->{cls}")
                if grok_workflow and job.get("id") == "review":
                    target = str(job.get("target_runs_on") or job.get("target_runner_class") or "")
                    if "grok-review" not in target:
                        grok_review_wrong.append(f"{repo.get('name')}:{path}#{job.get('id')}->{target}")
                env_name = ""
                env = job.get("environment")
                if isinstance(env, dict):
                    env_name = str(env.get("name") or "")
                else:
                    env_name = str(env or job.get("environment_name") or "")
                if repo.get("name") == "ken-backend" and path.endswith("deploy.yml") and job.get("id") == "deploy":
                    if env_name != "Preprod" or job.get("production_impact") is not True:
                        preprod_wrong.append(
                            f"env={env_name} production_impact={job.get('production_impact')}"
                        )
                if job.get("combined_build_and_deploy") is True:
                    flags = job.get("flags") or []
                    if "COMBINED_BUILD_AND_DEPLOY" not in flags:
                        unflagged_combined.append(f"{repo.get('name')}:{path}#{job.get('id')}")
                if visibility == "private" and "ubuntu-" in runs_on_s and "matrix" not in runs_on_s:
                    flags = job.get("flags") or []
                    if "PRIVATE_UBUNTU_HOSTED" not in flags and job.get("id"):
                        pass
    print(f"jobs={jobs}")
    print(f"classified={classified}")
    print(f"missing={len(missing)}")
    print(f"missing_target={len(missing_target)}")
    print(f"grok_gate_wrong={len(grok_gate_wrong)}")
    print(f"grok_review_wrong={len(grok_review_wrong)}")
    print(f"preprod_wrong={len(preprod_wrong)}")
    print(f"unflagged_combined={len(unflagged_combined)}")
    if missing[:5]:
        print("missing_sample=" + ";".join(missing[:5]))
    if missing_target[:5]:
        print("missing_target_sample=" + ";".join(missing_target[:5]))
    if grok_gate_wrong:
        print("grok_gate_sample=" + ";".join(grok_gate_wrong[:5]))
    if grok_review_wrong:
        print("grok_review_sample=" + ";".join(grok_review_wrong[:5]))
    if preprod_wrong:
        print("preprod_sample=" + ";".join(preprod_wrong))
elif cmd == "runners-target":
    data = load(runners_path)
    target = data.get("target") or {}
    ci = target.get("ci_runners") or target.get("ci") or {}
    deploy = target.get("deploy_runners") or target.get("deploy") or {}
    names = []
    if isinstance(ci, dict):
        names.extend(ci.get("names") or [])
        ci_count = ci.get("count")
    else:
        ci_count = None
    if isinstance(deploy, dict):
        names.extend(deploy.get("names") or [])
        deploy_count = deploy.get("count")
    else:
        deploy_count = None
    extras = [n for n in names if n in {"ken-ci-standard-09", "ken-ci-standard-10"}]
    registered_extras = extras[:]
    if isinstance(ci, dict):
        reserved = ci.get("reserved_disabled") or []
        registered_extras = [n for n in extras if n not in reserved]
    grok = ((data.get("preserved") or {}).get("grok_review") or {})
    print(f"ci_count={ci_count}")
    print(f"deploy_count={deploy_count}")
    print(f"registered_extras={len(registered_extras)}")
    print(f"grok_count={grok.get('count')}")
    print(f"snapshot_time={((data.get('current') or {}).get('snapshot_time') or data.get('snapshot_time') or '')}")
    print(f"plan={((data.get('organization_plan') or {}).get('name') or '').lower()}")
    print(f"minutes={((data.get('organization_plan') or {}).get('private_hosted_minutes_allowance'))}")
    print(f"overage={((data.get('organization_plan') or {}).get('actions_overage_budget_usd'))}")
    print(f"blacksmith_offline_recorded={((data.get('current') or {}).get('blacksmith_offline_count') is not None)}")
elif cmd == "secrets-policy":
    data = load(secrets_path)
    entries = data.get("secrets") or data.get("entries") or []
    missing_rot = []
    github_token_rot = []
    missing_auth = []
    for item in entries:
        name = item.get("github_secret_name") or item.get("name")
        if not name:
            continue
        if name == "GITHUB_TOKEN":
            if item.get("rotation_required") is True:
                github_token_rot.append(name)
            continue
        readable = item.get("source_readable")
        authority = item.get("source_authority")
        if not authority:
            missing_auth.append(f"{item.get('repository')}:{name}")
        if readable is not True and item.get("rotation_required") is not True:
            missing_rot.append(f"{item.get('repository')}:{name}")
    print(f"entries={len(entries)}")
    print(f"missing_rotation={len(missing_rot)}")
    print(f"missing_authority={len(missing_auth)}")
    print(f"github_token_rotation={len(github_token_rot)}")
    if missing_rot[:5]:
        print("missing_rotation_sample=" + ";".join(missing_rot[:5]))
elif cmd == "environments":
    data = load(repos_path)
    named = 0
    missing_fields = []
    required = ("required_reviewers", "prevent_self_review", "wait_timer", "deployment_branches")
    for repo in data.get("repositories") or []:
        for wf in repo.get("workflows") or []:
            for job in wf.get("jobs") or []:
                env = job.get("environment")
                env_name = job.get("environment_name")
                if isinstance(env, dict):
                    env_name = env.get("name") or env_name
                    record = env
                elif env:
                    record = job.get("environment_protection") or {}
                    env_name = env
                else:
                    continue
                if not env_name:
                    continue
                named += 1
                for field in required:
                    if isinstance(record, dict) and field in record:
                        continue
                    if field in job:
                        continue
                    missing_fields.append(f"{repo.get('name')}:{wf.get('path')}#{job.get('id')}:{field}")
    print(f"named_environments={named}")
    print(f"missing_fields={len(missing_fields)}")
    if missing_fields[:8]:
        print("missing_fields_sample=" + ";".join(missing_fields[:8]))
else:
    sys.stderr.write(f"unknown inventory query {cmd}\n")
    sys.exit(2)
PY
}

scan_secret_values() {
  local path="$1"
  python3 - "$path" <<'PY'
import re
import sys
from pathlib import Path

root = Path(sys.argv[1])
patterns = [
    re.compile(r"-----BEGIN [A-Z0-9 ]+PRIVATE KEY-----"),
    re.compile(r"\bghp_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bgho_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bxai-[A-Za-z0-9]{20,}\b"),
]
placeholder = re.compile(r"\b(TBD|TODO|FIXME|implement later|fill in details)\b", re.I)
hits = []
placeholders = []
for path in sorted(root.rglob("*")):
    if not path.is_file():
        continue
    if path.suffix.lower() not in {".yaml", ".yml", ".md", ".sh", ".json"}:
        continue
    text = path.read_text(encoding="utf-8", errors="replace")
    rel = str(path)
    for rx in patterns:
        if rx.search(text):
            hits.append(f"{path.name}:{rx.pattern}")
    if "inventory" in rel or path.name in {"review-ledger.md", "cutover.md"}:
        for match in placeholder.finditer(text):
            placeholders.append(f"{path.name}:{match.group(0)}")
print(f"secret_hits={len(hits)}")
print(f"placeholders={len(placeholders)}")
if hits:
    print("secret_sample=" + ";".join(hits[:5]))
if placeholders:
    print("placeholder_sample=" + ";".join(placeholders[:5]))
PY
}

audit_denylist_ok() {
  python3 - "${AUDIT}" <<'PY'
import re
import sys
from pathlib import Path

text = Path(sys.argv[1]).read_text(encoding="utf-8")
needles = [
    "SECRET_VALUE_DENYLIST",
    "/actions/secrets/",
    "gh secret get",
    "op item get",
    "op read",
]
missing = [n for n in needles if n not in text]
if "query names/metadata only" not in text.lower() and "names only" not in text.lower() and "name-only" not in text.lower():
    missing.append("name-only policy comment")
print("missing=" + ",".join(missing))
print(f"ok={int(not missing)}")
PY
}

test_inventory_files() {
  echo "== inventory files =="
  require_file "${INV}/repositories.yaml"
  require_file "${INV}/runners.yaml"
  require_file "${INV}/secrets.yaml"
  require_file "${AUDIT}"
  require_file "${GA_ROOT}/runbooks/review-ledger.md"
}

test_repo_counts() {
  echo "== repository counts and billing =="
  if [[ ! -f "${INV}/repositories.yaml" ]]; then
    fail "repositories.yaml missing; cannot assert counts"
    return
  fi
  local out
  out="$(python_inventory "${INV}" repo-counts)"
  local count private public archived unique plan minutes overage prevent
  count="$(printf '%s\n' "${out}" | awk -F= '/^count=/{print $2}')"
  private="$(printf '%s\n' "${out}" | awk -F= '/^private=/{print $2}')"
  public="$(printf '%s\n' "${out}" | awk -F= '/^public=/{print $2}')"
  archived="$(printf '%s\n' "${out}" | awk -F= '/^archived=/{print $2}')"
  unique="$(printf '%s\n' "${out}" | awk -F= '/^unique=/{print $2}')"
  plan="$(printf '%s\n' "${out}" | awk -F= '/^plan=/{print $2}')"
  minutes="$(printf '%s\n' "${out}" | awk -F= '/^minutes=/{print $2}')"
  overage="$(printf '%s\n' "${out}" | awk -F= '/^overage=/{print $2}')"
  prevent="$(printf '%s\n' "${out}" | awk -F= '/^prevent=/{print $2}')"
  assert_eq "active repositories" "25" "${count}"
  assert_eq "private repositories" "22" "${private}"
  assert_eq "public repositories" "3" "${public}"
  assert_eq "archived repositories" "0" "${archived}"
  assert_eq "unique repository names" "25" "${unique}"
  assert_eq "organization plan" "free" "${plan}"
  assert_eq "private hosted minutes allowance" "2000" "${minutes}"
  assert_eq "actions overage budget" "0" "${overage}"
  assert_eq "prevent further usage" "True" "${prevent}"
  if printf '%s\n' "${out}" | grep -q '3000'; then
    fail "inventory hard-codes a 3000-minute Team assumption"
  else
    pass "no 3000-minute Team assumption in count fields"
  fi
}

test_classification() {
  echo "== job classification =="
  if [[ ! -f "${INV}/repositories.yaml" ]]; then
    fail "repositories.yaml missing; cannot assert classification"
    return
  fi
  local out
  out="$(python_inventory "${INV}" classification)"
  local jobs classified missing missing_target grok_gate grok_review preprod combined
  jobs="$(printf '%s\n' "${out}" | awk -F= '/^jobs=/{print $2}')"
  classified="$(printf '%s\n' "${out}" | awk -F= '/^classified=/{print $2}')"
  missing="$(printf '%s\n' "${out}" | awk -F= '/^missing=/{print $2}')"
  missing_target="$(printf '%s\n' "${out}" | awk -F= '/^missing_target=/{print $2}')"
  grok_gate="$(printf '%s\n' "${out}" | awk -F= '/^grok_gate_wrong=/{print $2}')"
  grok_review="$(printf '%s\n' "${out}" | awk -F= '/^grok_review_wrong=/{print $2}')"
  preprod="$(printf '%s\n' "${out}" | awk -F= '/^preprod_wrong=/{print $2}')"
  combined="$(printf '%s\n' "${out}" | awk -F= '/^unflagged_combined=/{print $2}')"
  assert_ge "inventoried jobs" "1" "${jobs:-0}"
  assert_eq "unclassified jobs" "0" "${missing:-1}"
  assert_eq "Blacksmith/legacy jobs missing target class" "0" "${missing_target:-1}"
  assert_eq "Grok gate jobs classified outside grok-review" "0" "${grok_gate:-1}"
  assert_eq "Grok review jobs remapped away from grok-review" "0" "${grok_review:-1}"
  assert_eq "ken-backend Preprod production-impact errors" "0" "${preprod:-1}"
  assert_eq "combined build+deploy jobs missing flag" "0" "${combined:-1}"
  if [[ "${classified}" == "${jobs}" ]]; then
    pass "every job is classified (${jobs})"
  else
    fail "classified ${classified} of ${jobs} jobs"
    printf '%s\n' "${out}" | sed -n '/_sample=/p'
  fi
}

test_runners() {
  echo "== target runner pools =="
  if [[ ! -f "${INV}/runners.yaml" ]]; then
    fail "runners.yaml missing; cannot assert runner pools"
    return
  fi
  local out
  out="$(python_inventory "${INV}" runners-target)"
  assert_eq "target CI runners" "10" "$(printf '%s\n' "${out}" | awk -F= '/^ci_count=/{print $2}')"
  assert_eq "target deploy runners" "2" "$(printf '%s\n' "${out}" | awk -F= '/^deploy_count=/{print $2}')"
  assert_eq "registered CI extras 09/10" "0" "$(printf '%s\n' "${out}" | awk -F= '/^registered_extras=/{print $2}')"
  assert_eq "preserved grok-review runners" "6" "$(printf '%s\n' "${out}" | awk -F= '/^grok_count=/{print $2}')"
  assert_eq "runner inventory plan" "free" "$(printf '%s\n' "${out}" | awk -F= '/^plan=/{print $2}')"
  assert_eq "runner inventory minutes" "2000" "$(printf '%s\n' "${out}" | awk -F= '/^minutes=/{print $2}')"
  assert_eq "runner inventory overage" "0" "$(printf '%s\n' "${out}" | awk -F= '/^overage=/{print $2}')"
  local snapshot
  snapshot="$(printf '%s\n' "${out}" | awk -F= '/^snapshot_time=/{print $2}')"
  if [[ -n "${snapshot}" ]]; then
    pass "current runner snapshot_time recorded (${snapshot})"
  else
    fail "current runner snapshot_time missing"
  fi
  local recorded
  recorded="$(printf '%s\n' "${out}" | awk -F= '/^blacksmith_offline_recorded=/{print $2}')"
  assert_eq "blacksmith offline count recorded as snapshot" "True" "${recorded}"
}

test_secrets_and_environments() {
  echo "== secret names and environment protection =="
  if [[ ! -f "${INV}/secrets.yaml" ]]; then
    fail "secrets.yaml missing; cannot assert secret map"
  else
    local out
    out="$(python_inventory "${INV}" secrets-policy)"
    assert_ge "secret-name entries" "1" "$(printf '%s\n' "${out}" | awk -F= '/^entries=/{print $2}')"
    assert_eq "secrets missing rotation_required" "0" "$(printf '%s\n' "${out}" | awk -F= '/^missing_rotation=/{print $2}')"
    assert_eq "secrets missing source_authority" "0" "$(printf '%s\n' "${out}" | awk -F= '/^missing_authority=/{print $2}')"
    assert_eq "GITHUB_TOKEN marked rotation_required" "0" "$(printf '%s\n' "${out}" | awk -F= '/^github_token_rotation=/{print $2}')"
  fi
  if [[ -f "${INV}/repositories.yaml" ]]; then
    local env_out
    env_out="$(python_inventory "${INV}" environments)"
    assert_ge "named environments inventoried" "1" "$(printf '%s\n' "${env_out}" | awk -F= '/^named_environments=/{print $2}')"
    assert_eq "environment protection fields missing" "0" "$(printf '%s\n' "${env_out}" | awk -F= '/^missing_fields=/{print $2}')"
  fi
}

test_secret_scan() {
  echo "== no-secret-value / placeholder scan =="
  local out
  out="$(scan_secret_values "${GA_ROOT}")"
  assert_eq "secret-value pattern hits" "0" "$(printf '%s\n' "${out}" | awk -F= '/^secret_hits=/{print $2}')"
  assert_eq "placeholder hits in inventory/runbooks" "0" "$(printf '%s\n' "${out}" | awk -F= '/^placeholders=/{print $2}')"
}

test_audit_tool() {
  echo "== audit script contract =="
  if [[ ! -x "${AUDIT}" && ! -f "${AUDIT}" ]]; then
    fail "audit-workflows.sh missing"
    return
  fi
  if bash -n "${AUDIT}"; then
    pass "audit-workflows.sh bash -n"
  else
    fail "audit-workflows.sh bash -n"
  fi
  if bash -n "${GA_ROOT}/tests/test-config.sh"; then
    pass "test-config.sh bash -n"
  else
    fail "test-config.sh bash -n"
  fi
  local deny
  deny="$(audit_denylist_ok)"
  assert_eq "secret-value denylist present" "1" "$(printf '%s\n' "${deny}" | awk -F= '/^ok=/{print $2}')"
  if [[ -d "${FIXTURE_DIR}" ]]; then
    local tmp
    tmp="$(mktemp -d)"
    if bash "${AUDIT}" --offline --fixture-dir "${FIXTURE_DIR}" --output-dir "${tmp}" >/tmp/ken-audit-offline.log 2>&1; then
      pass "audit-workflows.sh offline fixture run"
      if [[ -f "${tmp}/repositories.yaml" ]]; then
        pass "offline audit wrote repositories.yaml"
      else
        fail "offline audit did not write repositories.yaml"
      fi
    else
      fail "audit-workflows.sh offline fixture run"
    fi
    rm -rf "${tmp}"
  else
    fail "offline fixture directory missing"
  fi
}

test_review_ledger() {
  echo "== review ledger =="
  local ledger="${GA_ROOT}/runbooks/review-ledger.md"
  if [[ ! -f "${ledger}" ]]; then
    fail "review-ledger.md missing"
    return
  fi
  local accepted
  accepted="$(grep -c '^### Finding ' "${ledger}" || true)"
  assert_eq "accepted Grok findings recorded" "11" "${accepted}"
  if grep -E 'ghp_|gho_|BEGIN .*PRIVATE KEY' "${ledger}" >/dev/null; then
    fail "review-ledger.md contains credential-shaped text"
  else
    pass "review-ledger.md has no credential-shaped text"
  fi
}

run_inventory() {
  test_inventory_files
  test_repo_counts
  test_classification
  test_runners
  test_secrets_and_environments
  test_secret_scan
  test_audit_tool
  test_review_ledger
  echo
  if (( FAILED == 0 )); then
    echo "inventory: ${RAN} assertions passed"
    return 0
  fi
  echo "inventory: ${FAILED} failed / ${RAN} assertions"
  return 1
}

usage() {
  cat <<'EOF'
Usage: bash infra/github-actions/tests/test-config.sh [inventory|runners|all]
EOF
}

cmd="${1:-inventory}"
case "${cmd}" in
  inventory)
    run_inventory
    ;;
  runners)
    echo "runners: not implemented in Task 2; use inventory assertions for target pool counts"
    exit 2
    ;;
  all)
    run_inventory
    ;;
  -h|--help)
    usage
    ;;
  *)
    usage
    exit 2
    ;;
esac
