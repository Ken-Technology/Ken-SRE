#!/usr/bin/env bash
# Thin inventory entry point. Parser/classifier behavior lives in
# test_audit_workflows.py.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
GA_ROOT="${ROOT}/infra/github-actions"
INV="${GA_ROOT}/inventory"
AUDIT="${GA_ROOT}/scripts/audit-workflows.sh"
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

run_inventory() {
  echo "== files =="
  require_file "${INV}/repositories.yaml"
  require_file "${INV}/runners.yaml"
  require_file "${INV}/secrets.yaml"
  require_file "${INV}/input-manifest.yaml"
  require_file "${AUDIT}"
  require_file "${GA_ROOT}/runbooks/review-ledger.md"
  require_file "${GA_ROOT}/tests/test_audit_workflows.py"

  echo "== python collector/classifier =="
  if (cd "${ROOT}" && python3 -m unittest infra.github-actions.tests.test_audit_workflows -q); then
    pass "focused Python collector tests"
  else
    fail "focused Python collector tests"
  fi

  echo "== inventory semantics =="
  if python3 - "${INV}" "${GA_ROOT}" <<'PY'
import re
import sys
from pathlib import Path

import yaml

inv = Path(sys.argv[1])
ga = Path(sys.argv[2])
repos = yaml.safe_load((inv / "repositories.yaml").read_text())
runners = yaml.safe_load((inv / "runners.yaml").read_text())
secrets = yaml.safe_load((inv / "secrets.yaml").read_text())
manifest = yaml.safe_load((inv / "input-manifest.yaml").read_text())
failed = []

def check(cond, msg):
    if not cond:
        failed.append(msg)

check(repos["counts"]["active_repositories"] == 25, "active != 25")
check(repos["counts"]["private_repositories"] == 22, "private != 22")
check(repos["counts"]["public_repositories"] == 3, "public != 3")
check(str(repos["organization_plan"]["name"]).lower() == "free", "plan is not free")
check(repos["organization_plan"]["private_hosted_minutes_allowance"] == 2000, "minutes != 2000")
check(repos["organization_plan"]["actions_overage_budget_usd"] == 0, "overage != 0")
check(runners["target"]["ci"]["count"] == 10, "ci count != 10")
check(runners["target"]["deploy"]["count"] == 2, "deploy count != 2")
check(runners["preserved"]["grok_review"]["count"] == 6, "grok != 6")
check("ken-ci-standard-09" not in (runners["target"]["ci"].get("names") or []), "09 registered")
check((runners["current"].get("runners") or []), "current runners list empty")
check("previous_month" in runners["billing"] and "current_unbilled" in runners["billing"], "billing sides missing")
check(runners["billing"]["current_unbilled"]["amount_usd"] is None, "invented current unbilled amount")
check(manifest.get("input_hash"), "missing input hash")

want = {
    ("ken-agents", ".github/workflows/eval-weekly.yml", "scoreboard"),
    ("ken-agents", ".github/workflows/prompt-parity.yml", "parity"),
    ("ken-ai-mcp", ".github/workflows/contracts-drift.yml", "drift-check"),
    ("ken-website", ".github/workflows/beehiiv-sync.yml", "sync"),
}
seen = set()
for repo in repos["repositories"]:
    vis = str(repo.get("visibility") or "").lower()
    for wf in repo.get("workflows") or []:
        for job in wf.get("jobs") or []:
            key = (repo["name"], wf["path"], job["id"])
            if key in want:
                seen.add(key)
                if not str(job.get("target_runner_class") or "").startswith("ken-deploy"):
                    failed.append(f"{key} not routed to ken-deploy")
            if vis == "private":
                runs = str(job.get("runs_on") or "")
                if re.search(r"(^|[,\s\[])ubuntu-(latest|[0-9]{2}\.[0-9]{2})($|[,\s\]])", runs) and "blacksmith" not in runs.lower() and "self-hosted" not in runs:
                    if "PRIVATE_UBUNTU_HOSTED" not in (job.get("flags") or []):
                        failed.append(f"{key} missing PRIVATE_UBUNTU_HOSTED")
            if job.get("deploys_or_publishes"):
                target = job.get("target") or {}
                if not (
                    target.get("action_types")
                    or target.get("endpoint_expressions")
                    or target.get("host_secret_names")
                    or target.get("host_variable_names")
                    or target.get("registry_or_package")
                    or target.get("unknown_reason")
                ):
                    failed.append(f"{key} deploy/publish missing structured target")
            if repo["name"] == "ken-analytics" and wf["path"].endswith("deploy-production.yml") and job["id"] == "validate":
                if job.get("classification") != "standard-ci":
                    failed.append("ken-analytics validate is not standard-ci")
            if repo["name"] == "ken-backend" and str(wf["path"]).endswith("deploy.yml") and job["id"] == "deploy":
                env = job.get("environment") or {}
                if env.get("name") != "Preprod" or job.get("production_impact") is not True:
                    failed.append("ken-backend Preprod is not production-impact")
check(seen == want, f"missing scheduled-secret jobs: {want - seen}")

for entry in secrets.get("entries") or []:
    if entry.get("github_secret_name") == "GITHUB_TOKEN":
        if entry.get("target_vault") is not None or entry.get("rotation_required") is True or entry.get("consumer") is not None:
            failed.append(f"GITHUB_TOKEN override {entry.get('repository')}:{entry.get('workflow')}")
    if entry.get("github_secret_name") == "OP_SERVICE_ACCOUNT_TOKEN" and "ken-ci" in str(entry.get("consumer") or ""):
        failed.append("OP_SERVICE_ACCOUNT_TOKEN consumer is ken-ci")
    if entry.get("github_secret_name") != "GITHUB_TOKEN" and not entry.get("source_authority"):
        failed.append(f"missing authority {entry.get('repository')}:{entry.get('github_secret_name')}")

ledger = (ga / "runbooks/review-ledger.md").read_text()
check(len(re.findall(r"^### Finding ", ledger, re.M)) == 11, "review ledger != 11 findings")

secret_rx = [
    re.compile(r"-----BEGIN [A-Z0-9 ]+PRIVATE KEY-----"),
    re.compile(r"\bghp_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bgho_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
]
placeholder = re.compile(r"\b(TBD|TODO|FIXME|implement later|fill in details)\b", re.I)
for path in ga.rglob("*"):
    if not path.is_file() or path.suffix.lower() not in {".yaml", ".yml", ".md", ".sh", ".json", ".py"}:
        continue
    text = path.read_text(encoding="utf-8", errors="replace")
    for rx in secret_rx:
        if rx.search(text):
            failed.append(f"secret-shaped {path.name}")
    if "inventory" in str(path) or path.name in {"review-ledger.md", "cutover.md"}:
        if placeholder.search(text):
            failed.append(f"placeholder {path.name}")

if failed:
    print("SEMANTIC_FAIL")
    for item in failed:
        print(item)
    sys.exit(1)
print("SEMANTIC_OK")
PY
  then
    pass "inventory semantic assertions"
  else
    fail "inventory semantic assertions"
  fi

  echo "== shell syntax =="
  if bash -n "${AUDIT}" && bash -n "${GA_ROOT}/tests/test-config.sh"; then
    pass "bash -n"
  else
    fail "bash -n"
  fi
  if grep -q 'SECRET_VALUE_DENYLIST' "${AUDIT}" && grep -q 'gh secret get' "${AUDIT}"; then
    pass "secret-value denylist present"
  else
    fail "secret-value denylist present"
  fi

  echo
  if (( FAILED == 0 )); then
    echo "inventory: ${RAN} assertions passed"
    return 0
  fi
  echo "inventory: ${FAILED} failed / ${RAN} assertions"
  return 1
}

cmd="${1:-inventory}"
case "${cmd}" in
  inventory|all)
    run_inventory
    ;;
  runners)
    echo "runners: Task 5 owns runner-service tests"
    exit 2
    ;;
  -h|--help)
    echo "Usage: bash infra/github-actions/tests/test-config.sh [inventory|all]"
    ;;
  *)
    echo "Usage: bash infra/github-actions/tests/test-config.sh [inventory|all]"
    exit 2
    ;;
esac
