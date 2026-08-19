#!/usr/bin/env bash
# Thin inventory entry point. Parser/classifier behavior lives in
# test_audit_workflows.py.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
GA_ROOT="${ROOT}/infra/github-actions"
INV="${GA_ROOT}/inventory"
AUDIT="${GA_ROOT}/scripts/audit-workflows.sh"
HOST_PROVISION="${GA_ROOT}/scripts/provision-host.sh"
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
                if job.get("deploys_or_publishes"):
                    failed.append(f"{key} schedule marked deploys_or_publishes")
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
            if repo["name"] == "ken-analytics" and wf["path"].endswith("deploy-production.yml") and job["id"] in {"validate", "no_stack_yet"}:
                if job.get("classification") != "standard-ci" or job.get("deploys_or_publishes"):
                    failed.append(f"ken-analytics {job['id']} is not standard-ci")
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

run_host() {
  local test_dir fake_ssh output status log
  test_dir="$(mktemp -d)"
  trap 'rm -rf "${test_dir}"' RETURN
  fake_ssh="${test_dir}/ssh"
  log="${test_dir}/ssh.log"

  cat >"${fake_ssh}" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
phase="${*: -1}"
printf '%s\n' "${phase}" >>"${FAKE_SSH_LOG:?}"
remote_script="$(mktemp)"
trap 'rm -f "${remote_script}"' EXIT
cat >"${remote_script}"
bash -n "${remote_script}"

if [[ "${phase}" == "preflight" ]]; then
  root_free=32212254720
  data_free=1073741824000
  memory_available=161061273600
  data_mount=/mnt/data
  data_options=rw,relatime
  kvm=1
  grok_total=6
  grok_active=6
  case "${FAKE_SSH_PROFILE:-good}" in
    root-low) root_free=991952896 ;;
    data-low) data_free=536870912000 ;;
    memory-low) memory_available=68719476736 ;;
    wrong-mount) data_mount=/ ;;
    read-only-data) data_options=ro,relatime ;;
    no-kvm) kvm=0 ;;
    grok-unhealthy) grok_active=5 ;;
  esac
  cat <<EOF
ROOT_FREE_BYTES=${root_free}
ROOT_FREE_INODES=4000000
DATA_MOUNT=${data_mount}
DATA_OPTIONS=${data_options}
DATA_FREE_BYTES=${data_free}
DATA_FREE_INODES=8000000
MEM_AVAILABLE_BYTES=${memory_available}
KVM_DEVICE_READY=${kvm}
GROK_RUNNERS_TOTAL=${grok_total}
GROK_RUNNERS_ACTIVE=${grok_active}
EOF
  exit 0
fi

if [[ "${phase}" == "apply" ]]; then
  if [[ "${FAKE_SSH_PROFILE:-good}" == "bad-apply-readback" ]]; then
    echo 'APPLY_STATUS=incomplete'
    exit 0
  fi
  cat <<'EOF'
ROOT_FREE_AFTER_BYTES=30064771072
DATA_FREE_AFTER_BYTES=1063004405760
MEM_AVAILABLE_AFTER_BYTES=158913789952
GROK_RUNNERS_TOTAL_AFTER=6
GROK_RUNNERS_ACTIVE_AFTER=6
PROTECTED_STATE_OK=1
LIBVIRTD_ACTIVE=1
POOL_READY=1
KEN_CI_NET_READY=1
KEN_DEPLOY_NET_READY=1
APPLY_STATUS=ok
EOF
  exit 0
fi

echo "unexpected phase: ${phase}" >&2
exit 64
SH
  chmod +x "${fake_ssh}"

  exercise() {
    local profile="$1"
    shift
    set +e
    output="$(FAKE_SSH_LOG="${log}" FAKE_SSH_PROFILE="${profile}" PROVISION_HOST_SSH_BIN="${fake_ssh}" bash "${HOST_PROVISION}" "$@" 2>&1)"
    status=$?
    set -e
  }

  expect_failure() {
    local profile="$1" expected="$2"
    exercise "${profile}" --dry-run root@167.235.8.250
    if (( status != 0 )) && grep -Fq "${expected}" <<<"${output}" && ! grep -Fxq apply "${log}"; then
      pass "host gate rejects ${profile} before apply"
    else
      fail "host gate did not reject ${profile} safely"
      printf '%s\n' "${output}"
    fi
    : >"${log}"
  }

  echo "== host preflight boundaries =="
  expect_failure root-low "root filesystem free space"
  expect_failure data-low "/mnt/data free space"
  expect_failure memory-low "host MemAvailable"
  expect_failure wrong-mount "dedicated /mnt/data mount"
  expect_failure read-only-data "/mnt/data is not read-write"
  expect_failure no-kvm "/dev/kvm is not ready"
  expect_failure grok-unhealthy "all 6 Grok runners"

  echo "== host dry run =="
  exercise good --dry-run root@167.235.8.250
  if (( status == 0 )) &&
    grep -Fq "/mnt/data/libvirt/images" <<<"${output}" &&
    grep -Fq "ken-ci-net" <<<"${output}" &&
    grep -Fq "ken-deploy-net" <<<"${output}" &&
    grep -Fq "qemu-kvm" <<<"${output}" &&
    [[ "$(grep -Fxc preflight "${log}")" == 1 ]] &&
    ! grep -Fxq apply "${log}"; then
    pass "dry run reports the approved plan without apply"
  else
    fail "dry run did not preserve the no-mutation boundary"
    printf '%s\n' "${output}"
  fi

  echo "== host apply readback =="
  : >"${log}"
  exercise good root@167.235.8.250
  if (( status == 0 )) && [[ "$(grep -Fxc preflight "${log}")" == 1 ]] && [[ "$(grep -Fxc apply "${log}")" == 1 ]] && grep -Fq "Host provisioning verified" <<<"${output}"; then
    pass "apply requires preflight then complete readback"
  else
    fail "apply sequencing or readback validation failed"
    printf '%s\n' "${output}"
  fi

  : >"${log}"
  exercise bad-apply-readback root@167.235.8.250
  if (( status != 0 )) && grep -Fq "apply readback is incomplete" <<<"${output}"; then
    pass "incomplete apply readback fails closed"
  else
    fail "incomplete apply readback was accepted"
    printf '%s\n' "${output}"
  fi

  echo "== host shell syntax =="
  if bash -n "${HOST_PROVISION}"; then
    pass "provision-host bash -n"
  else
    fail "provision-host bash -n"
  fi

  echo
  if (( FAILED == 0 )); then
    echo "host: ${RAN} assertions passed"
    return 0
  fi
  echo "host: ${FAILED} failed / ${RAN} assertions"
  return 1
}

cmd="${1:-inventory}"
case "${cmd}" in
  inventory)
    run_inventory
    ;;
  host)
    run_host
    ;;
  all)
    run_inventory
    run_host
    ;;
  runners)
    echo "runners: Task 5 owns runner-service tests"
    exit 2
    ;;
  -h|--help)
    echo "Usage: bash infra/github-actions/tests/test-config.sh [inventory|host|all]"
    ;;
  *)
    echo "Usage: bash infra/github-actions/tests/test-config.sh [inventory|host|all]"
    exit 2
    ;;
esac
