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
  local test_dir fake_ssh fake_bin output status ssh_log command_log state_root data_root escape_root
  test_dir="$(mktemp -d)"
  test_dir="$(cd "${test_dir}" && pwd -P)"
  trap 'rm -rf "${test_dir}"' RETURN
  fake_ssh="${test_dir}/ssh"
  fake_bin="${test_dir}/bin"
  ssh_log="${test_dir}/ssh.log"
  command_log="${test_dir}/commands.log"
  state_root="${test_dir}/state"
  data_root="${test_dir}/data"
  escape_root="${test_dir}/escape"
  mkdir -p "${fake_bin}" "${state_root}" "${data_root}" "${escape_root}"
  ln -s "$(command -v jq)" "${fake_bin}/jq"

  cat >"${fake_ssh}" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
phase=''
remote_argument=''
args=("$@")
for ((i=0; i<${#args[@]}; i++)); do
  if [[ "${args[i]}" == -- ]]; then
    phase="${args[i+1]:-}"
    remote_argument="${args[i+2]:-}"
    break
  fi
done
[[ -n "${phase}" ]] || { echo 'missing remote phase' >&2; exit 64; }
printf '%s\n' "${phase}" >>"${FAKE_SSH_LOG:?}"
remote_script="${FAKE_STATE_ROOT:?}/remote-script.sh"
cat >"${remote_script}"
bash -n "${remote_script}"
export PATH="${FAKE_BIN:?}:/usr/bin:/bin"
export PROVISION_HOST_DATA_ROOT="${FAKE_DATA_ROOT:?}"
if [[ "${FAKE_SSH_PROFILE:-good}" == no-kvm ]]; then
  export PROVISION_HOST_KVM_DEVICE="${FAKE_STATE_ROOT}/missing-kvm"
else
  export PROVISION_HOST_KVM_DEVICE=/dev/null
fi
export PROVISION_HOST_STATE_PARENT="${FAKE_STATE_ROOT}"
export FAKE_REMOTE_PHASE="${phase}"
bash "${remote_script}" "${phase}" "${remote_argument}"
SH
  chmod +x "${fake_ssh}"

  cat >"${fake_bin}/df" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
printf 'df %s\n' "$*" >>"${FAKE_COMMAND_LOG:?}"
if [[ " $* " == *' -P '* && "$*" == *--output=* ]]; then
  echo 'df: options -P and --output are mutually exclusive' >&2
  exit 1
fi
path="${*: -1}"
if [[ "$*" == *iavail* ]]; then
  value=4000000
  [[ "${path}" == "${FAKE_DATA_ROOT}" ]] && value=8000000
  printf 'IAvail\n%s\n' "${value}"
  exit 0
fi
value=32212254720
[[ "${path}" == "${FAKE_DATA_ROOT}" ]] && value=1073741824000
case "${FAKE_SSH_PROFILE:-good}:${FAKE_REMOTE_PHASE:-}" in
  root-low:*) [[ "${path}" == / ]] && value=991952896 ;;
  data-low:*) [[ "${path}" == "${FAKE_DATA_ROOT}" ]] && value=536870912000 ;;
esac
printf 'Avail\n%s\n' "${value}"
SH

  cat >"${fake_bin}/free" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
value=161061273600
case "${FAKE_SSH_PROFILE:-good}:${FAKE_REMOTE_PHASE:-}" in
  memory-low:*) value=68719476736 ;;
  memory-after-low:apply)
    [[ -e "${FAKE_STATE_ROOT}/packages-installed" ]] && value=68719476736
    ;;
esac
printf '              total        used        free      shared  buff/cache   available\n'
printf 'Mem:   206158430208 10000000000 10000000000 0 0 %s\n' "${value}"
SH

  cat >"${fake_bin}/findmnt" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
printf 'findmnt %s\n' "$*" >>"${FAKE_COMMAND_LOG:?}"
field=''
target="${*: -1}"
args=("$@")
for ((i=0; i<${#args[@]}; i++)); do
  [[ "${args[i]}" == -o ]] && field="${args[i+1]}"
done
case "${field}" in
  TARGET)
    if [[ "${FAKE_SSH_PROFILE:-good}:${FAKE_REMOTE_PHASE:-}" == wrong-mount:* ]]; then
      echo /
    elif [[ "${FAKE_SSH_PROFILE:-good}:${FAKE_REMOTE_PHASE:-}" == mount-drift:apply ]]; then
      echo /
    else
      echo "${FAKE_DATA_ROOT}"
    fi
    ;;
  OPTIONS)
    if [[ "${FAKE_SSH_PROFILE:-good}:${FAKE_REMOTE_PHASE:-}" == read-only-data:* || "${FAKE_SSH_PROFILE:-good}:${FAKE_REMOTE_PHASE:-}" == mount-drift:apply ]]; then
      echo ro,relatime
    else
      echo rw,relatime
    fi
    ;;
  SOURCE)
    if [[ "${FAKE_SSH_PROFILE:-good}" == storage-mount-drift && "${target}" == *'/seed' ]]; then
      echo /dev/fake-root
    else
      echo /dev/fake-data
    fi
    ;;
  *) echo "unsupported findmnt invocation: $*" >&2; exit 64 ;;
esac
SH

  cat >"${fake_bin}/readlink" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
mode="${1:-}"
[[ "${mode}" == -m || "${mode}" == -e ]] || { echo "unsupported readlink invocation: $*" >&2; exit 64; }
shift
[[ "${1:-}" == -- ]] && shift
path="${1:?}"
if [[ "${mode}" == -e && ! -e "${path}" ]]; then
  exit 1
fi
python3 -c 'import os, sys; print(os.path.realpath(sys.argv[1]))' "${path}"
SH

  cat >"${fake_bin}/systemctl" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
printf 'systemctl %s\n' "$*" >>"${FAKE_COMMAND_LOG:?}"
case "${1:-}" in
  cat) exit 0 ;;
  is-active)
    [[ "${FAKE_SSH_PROFILE:-good}" == grok-unhealthy && "${*: -1}" == *ken-search* ]] && exit 3
    exit 0
    ;;
  enable) exit 0 ;;
  show)
    cat <<EOF
Id=${2:-unit}
LoadState=loaded
ActiveState=active
SubState=running
MainPID=4242
EOF
    ;;
  *) exit 0 ;;
esac
SH

  cat >"${fake_bin}/apt-get" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
printf 'apt-get %s\n' "$*" >>"${FAKE_COMMAND_LOG:?}"
if [[ "${1:-}" == -s ]]; then
  echo '0 upgraded, 0 newly installed, 0 to remove'
  exit 0
fi
if [[ "${1:-}" == install ]]; then
  touch "${FAKE_STATE_ROOT}/packages-installed"
  if [[ "${FAKE_SSH_PROFILE:-good}" != missing-dnsmasq ]]; then
    for pkg in "$@"; do
      if [[ "${pkg}" == dnsmasq-base ]]; then
        printf '%s\n' '#!/usr/bin/env bash' 'exit 0' >"${FAKE_BIN}/dnsmasq"
        chmod +x "${FAKE_BIN}/dnsmasq"
      fi
    done
  fi
fi
SH

  cat >"${fake_bin}/install" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
printf 'install %s\n' "$*" >>"${FAKE_COMMAND_LOG:?}"
for arg in "$@"; do
  [[ "${arg}" == -* || "${arg}" == 0755 ]] && continue
  /bin/mkdir -p "${arg}"
done
SH

  cat >"${fake_bin}/ip" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
printf 'ip %s\n' "$*" >>"${FAKE_COMMAND_LOG:?}"
if [[ "$*" == *'route show'* ]]; then
  case "${FAKE_SSH_PROFILE:-good}" in
    route-conflict) echo '192.168.210.0/24 dev eth0 proto kernel' ;;
    existing-running|preexisting-inactive)
      echo '192.168.210.0/24 dev virbr-ci proto kernel'
      echo '192.168.211.0/24 dev virbr-deploy proto kernel'
      ;;
    partial-preexisting) echo '192.168.210.0/24 dev virbr-ci proto kernel' ;;
    *) echo '10.0.0.0/8 dev eth0 proto kernel' ;;
  esac
  exit 0
fi
if [[ "$*" == *'link show'* ]]; then
  bridge="${*: -1}"
  case "${FAKE_SSH_PROFILE:-good}:${bridge}" in
    bridge-conflict:virbr-ci|existing-running:virbr-ci|existing-running:virbr-deploy|preexisting-inactive:virbr-ci|preexisting-inactive:virbr-deploy|partial-preexisting:virbr-ci)
      echo "9: ${bridge}: <BROADCAST> mtu 1500"
      exit 0
      ;;
  esac
  exit 1
fi
exit 0
SH

  cat >"${fake_bin}/docker" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
printf 'docker %s\n' "$*" >>"${FAKE_COMMAND_LOG:?}"
if [[ "${1:-}" == network && "${2:-}" == ls ]]; then
  echo network-1
elif [[ "${1:-}" == network && "${2:-}" == inspect ]]; then
  if [[ "${FAKE_SSH_PROFILE:-good}" == docker-conflict ]]; then
    subnet=192.168.211.0/24
  else
    subnet=172.17.0.0/16
  fi
  if [[ "$*" == *--format* ]]; then
    echo "${subnet}"
  else
    printf '[{"IPAM":{"Config":[{"Subnet":"%s"}]}}]\n' "${subnet}"
  fi
elif [[ "${1:-}" == ps && "$*" == *-q* ]]; then
  echo container-1
elif [[ "${1:-}" == inspect ]]; then
  if [[ "$*" == *--format* ]]; then
    if [[ "${FAKE_SSH_PROFILE:-good}" == docker-no-health && "$*" == *'.State.Health'* ]]; then
      echo 'template parsing error: template: :1:180: executing "" at <.State.Health>: map has no entry for key "Health"' >&2
      exit 64
    fi
    if [[ "${2:-}" == network-1 || "${*: -1}" == network-1 ]]; then
      echo 172.17.0.0/16
      exit 0
    fi
  fi
  started=2026-08-19T00:00:00Z
  restarts=0
  if [[ "${FAKE_SSH_PROFILE:-good}" == docker-restarted && -e "${FAKE_STATE_ROOT}/packages-installed" ]]; then
    started=2026-08-19T01:00:00Z
    restarts=1
  fi
  if [[ "$*" == *--format* ]]; then
    printf 'container-1|/search|elasticsearch:8|running|%s|%s|healthy\n' "${started}" "${restarts}"
  elif [[ "${*: -1}" == network-1 ]]; then
    printf '[{"IPAM":{"Config":[{"Subnet":"172.17.0.0/16"}]}}]\n'
  elif [[ "${FAKE_SSH_PROFILE:-good}" == docker-no-health ]]; then
    printf '[{"Id":"container-1","Name":"/search","Config":{"Image":"elasticsearch:8","Env":["SNAPSHOT_SECRET_CANARY=must-not-leak"]},"State":{"Status":"running","StartedAt":"%s"},"RestartCount":%s}]\n' "${started}" "${restarts}"
  else
    printf '[{"Id":"container-1","Name":"/search","Config":{"Image":"elasticsearch:8","Env":["SNAPSHOT_SECRET_CANARY=must-not-leak"]},"State":{"Status":"running","StartedAt":"%s","Health":{"Status":"healthy"}},"RestartCount":%s}]\n' "${started}" "${restarts}"
  fi
else
  exit 64
fi
SH

  cat >"${fake_bin}/virsh" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
printf 'virsh %s\n' "$*" >>"${FAKE_COMMAND_LOG:?}"
state="${FAKE_STATE_ROOT:?}"
exists() { [[ -e "${state}/$1.$2.exists" ]]; }
flag() { cat "${state}/$1.$2.$3" 2>/dev/null || echo 0; }
set_flag() { printf '%s\n' "$4" >"${state}/$1.$2.$3"; }
pool_info() {
  exists pool "$1" || exit 1
  [[ "$(flag pool "$1" active)" == 1 ]] && pool_state=running || pool_state=inactive
  [[ "$(flag pool "$1" auto)" == 1 ]] && auto=yes || auto=no
  printf 'Name: %s\nState: %s\nPersistent: yes\nAutostart: %s\n' "$1" "${pool_state}" "${auto}"
}
net_info() {
  if [[ "$1" == default ]]; then
    printf 'Name: default\nActive: yes\nPersistent: yes\nAutostart: yes\n'
    return
  fi
  exists net "$1" || exit 1
  [[ "$(flag net "$1" active)" == 1 ]] && active=yes || active=no
  [[ "$(flag net "$1" auto)" == 1 ]] && auto=yes || auto=no
  printf 'Name: %s\nActive: %s\nPersistent: yes\nAutostart: %s\n' "$1" "${active}" "${auto}"
}
net_xml() {
  name="$1"
  if [[ "${name}" == default ]]; then
    address=192.168.122.1; netmask=255.255.255.0; bridge=virbr0; start=192.168.122.2; end=192.168.122.254
  elif [[ "${name}" == conflict-net ]]; then
    address=192.168.210.99; netmask=255.255.255.0; bridge=virbr-other; start=192.168.210.100; end=192.168.210.200
  elif [[ "${name}" == ken-ci-net ]]; then
    address=192.168.210.1; bridge=virbr-ci; start=192.168.210.10; end=192.168.210.254
    [[ "${FAKE_SSH_PROFILE:-good}" == wrong-prefix ]] && netmask=255.255.0.0 || netmask=255.255.255.0
  else
    address=192.168.211.1; netmask=255.255.255.0; bridge=virbr-deploy; start=192.168.211.10; end=192.168.211.254
  fi
  extra=''
  case "${FAKE_SSH_PROFILE:-good}:${name}" in
    extra-network-ip:ken-ci-net)
      extra="<ip address='172.30.0.1' netmask='255.255.255.0'/>"
      ;;
    extra-network-route:ken-ci-net)
      extra="<route address='172.31.0.0' prefix='16' gateway='192.168.210.2'/>"
      ;;
  esac
  cat <<EOF
<network><name>${name}</name><forward mode='nat'/><bridge name='${bridge}' stp='on' delay='0'/><ip address='${address}' netmask='${netmask}'><dhcp><range start='${start}' end='${end}'/></dhcp></ip>${extra}</network>
EOF
}
case "${1:-}" in
  pool-info) pool_info "$2" ;;
  pool-dumpxml) printf '<pool><target><path>%s/libvirt/images</path></target></pool>\n' "${FAKE_DATA_ROOT}" ;;
  pool-define-as)
    touch "${state}/pool.ken-actions.exists"
    set_flag pool ken-actions active 0
    set_flag pool ken-actions auto 0
    ;;
  pool-autostart)
    value=1; [[ "${3:-}" == --disable ]] && value=0
    set_flag pool "$2" auto "${value}"
    ;;
  pool-start)
    [[ "$(flag pool "$2" active)" == 0 ]] || { echo 'already active' >&2; exit 1; }
    set_flag pool "$2" active 1
    ;;
  pool-destroy)
    [[ "${FAKE_SSH_PROFILE:-good}" != rollback-pool-destroy-fails ]] || { echo 'injected pool-destroy failure' >&2; exit 1; }
    set_flag pool "$2" active 0
    ;;
  pool-undefine)
    [[ "${FAKE_SSH_PROFILE:-good}" != rollback-pool-undefine-fails ]] || { echo 'injected pool-undefine failure' >&2; exit 1; }
    rm -f "${state}/pool.$2."*
    ;;
  net-info) net_info "$2" ;;
  net-dumpxml) net_xml "$2" ;;
  net-list)
    echo default
    for f in "${state}"/net.*.exists; do
      [[ -e "${f}" ]] || continue
      name="${f##*/net.}"; echo "${name%.exists}"
    done
    ;;
  net-define)
    name="$(sed -n "s:.*<name>\([^<]*\)</name>.*:\1:p" "$2")"
    if [[ "${FAKE_SSH_PROFILE:-good}" == partial-failure && "${name}" == ken-deploy-net ]] ||
       [[ "${FAKE_SSH_PROFILE:-good}" == partial-preexisting && "${name}" == ken-deploy-net ]] ||
       [[ "${FAKE_SSH_PROFILE:-good}" == rollback-net-destroy-fails && "${name}" == ken-deploy-net ]] ||
       [[ "${FAKE_SSH_PROFILE:-good}" == rollback-net-undefine-fails && "${name}" == ken-deploy-net ]] ||
       [[ "${FAKE_SSH_PROFILE:-good}" == rollback-pool-destroy-fails && "${name}" == ken-deploy-net ]] ||
       [[ "${FAKE_SSH_PROFILE:-good}" == rollback-pool-undefine-fails && "${name}" == ken-deploy-net ]]; then
      echo 'injected deploy network failure' >&2
      exit 1
    fi
    touch "${state}/net.${name}.exists"
    set_flag net "${name}" active 0
    set_flag net "${name}" auto 0
    ;;
  net-autostart)
    value=1; [[ "${3:-}" == --disable ]] && value=0
    set_flag net "$2" auto "${value}"
    ;;
  net-start)
    if ! command -v dnsmasq >/dev/null 2>&1; then
      echo "Unable to find 'dnsmasq' binary in \$PATH" >&2
      exit 1
    fi
    [[ "$(flag net "$2" active)" == 0 ]] || { echo 'already active' >&2; exit 1; }
    set_flag net "$2" active 1
    ;;
  net-destroy)
    [[ "${FAKE_SSH_PROFILE:-good}" != rollback-net-destroy-fails || "$2" != ken-ci-net ]] || { echo 'injected net-destroy failure' >&2; exit 1; }
    set_flag net "$2" active 0
    ;;
  net-undefine)
    [[ "${FAKE_SSH_PROFILE:-good}" != rollback-net-undefine-fails || "$2" != ken-ci-net ]] || { echo 'injected net-undefine failure' >&2; exit 1; }
    rm -f "${state}/net.$2."*
    ;;
  nodeinfo) echo 'CPU model: fake' ;;
  *) echo "unsupported virsh invocation: $*" >&2; exit 64 ;;
esac
SH

  cat >"${fake_bin}/pgrep" <<'SH'
#!/usr/bin/env bash
echo '4242 /usr/share/elasticsearch/bin/elasticsearch'
SH
  cat >"${fake_bin}/ss" <<'SH'
#!/usr/bin/env bash
echo 'tcp LISTEN 0 128 127.0.0.1:9200 0.0.0.0:* users:(("java",pid=4242,fd=1))'
SH
  cat >"${fake_bin}/du" <<'SH'
#!/usr/bin/env bash
echo '1G /var'
SH
  cat >"${fake_bin}/journalctl" <<'SH'
#!/usr/bin/env bash
echo 'Archived and active journals take up 1.0G.'
SH
  chmod +x "${fake_bin}"/*

  reset_fixture() {
    rm -rf "${state_root}" "${data_root}" "${escape_root}"
    rm -f "${fake_bin}/dnsmasq"
    mkdir -p "${state_root}" "${data_root}" "${escape_root}"
    : >"${ssh_log}"
    : >"${command_log}"
  }

  seed_existing_resources() {
    local active="$1" auto="$2" name
    touch "${state_root}/pool.ken-actions.exists"
    printf '%s\n' "${active}" >"${state_root}/pool.ken-actions.active"
    printf '%s\n' "${auto}" >"${state_root}/pool.ken-actions.auto"
    for name in ken-ci-net ken-deploy-net; do
      touch "${state_root}/net.${name}.exists"
      printf '%s\n' "${active}" >"${state_root}/net.${name}.active"
      printf '%s\n' "${auto}" >"${state_root}/net.${name}.auto"
    done
  }

  exercise_inner() {
    local profile="$1"
    shift
    set +e
    output="$(
      FAKE_SSH_LOG="${ssh_log}" \
      FAKE_COMMAND_LOG="${command_log}" \
      FAKE_SSH_PROFILE="${profile}" \
      FAKE_BIN="${fake_bin}" \
      FAKE_STATE_ROOT="${state_root}" \
      FAKE_DATA_ROOT="${data_root}" \
      PROVISION_HOST_SSH_BIN="${fake_ssh}" \
      PROVISION_HOST_EXPECTED_DATA_MOUNT="${data_root}" \
      bash "${HOST_PROVISION}" "$@" 2>&1
    )"
    status=$?
    set -e
  }

  exercise() {
    local profile="$1"
    shift
    reset_fixture
    case "${profile}" in
      existing-running|wrong-prefix|extra-network-ip|extra-network-route) seed_existing_resources 1 1 ;;
      preexisting-inactive) seed_existing_resources 0 0 ;;
      partial-preexisting)
        seed_existing_resources 0 0
        rm -f "${state_root}/net.ken-deploy-net."*
        ;;
    esac
    exercise_inner "${profile}" "$@"
  }

  expect_failure() {
    local profile="$1" expected="$2"
    exercise "${profile}" --dry-run root@167.235.8.250
    if (( status != 0 )) && grep -Fq "${expected}" <<<"${output}" && ! grep -Fxq apply "${ssh_log}"; then
      pass "host gate rejects ${profile} before apply"
    else
      fail "host gate did not reject ${profile} safely"
      printf '%s\n' "${output}"
    fi
  }

  echo "== host preflight boundaries =="
  expect_failure root-low "root filesystem free space"
  expect_failure data-low "/mnt/data free space"
  expect_failure memory-low "host MemAvailable"
  expect_failure wrong-mount "dedicated /mnt/data mount"
  expect_failure read-only-data "/mnt/data is not read-write"
  expect_failure no-kvm "/dev/kvm is not ready"
  expect_failure grok-unhealthy "all 6 Grok runners"

  echo "== host storage and network safety =="
  reset_fixture
  ln -s "${escape_root}" "${data_root}/libvirt"
  exercise_inner symlink-escape root@167.235.8.250
  if (( status != 0 )) && grep -Fq "resolves outside the approved data path" <<<"${output}" && ! grep -Fq 'apt-get update' "${command_log}"; then
    pass "storage symlink escape fails before package mutation"
  else
    fail "storage symlink escape was not rejected before mutation"
  fi

  for profile in route-conflict bridge-conflict docker-conflict wrong-prefix extra-network-ip extra-network-route; do
    exercise "${profile}" root@167.235.8.250
    if (( status != 0 )) && grep -Fq "network" <<<"${output}" && ! grep -Fq 'apt-get update' "${command_log}"; then
      pass "${profile} fails before package mutation"
    else
      fail "${profile} did not fail before mutation"
      printf '%s\n' "${output}"
    fi
  done

  exercise mount-drift root@167.235.8.250
  if (( status != 0 )) && grep -Fq "/mnt/data" <<<"${output}" && ! grep -Fq 'apt-get update' "${command_log}"; then
    pass "apply recheck catches read-only or mount drift before mutation"
  else
    fail "apply accepted mount drift"
  fi

  echo "== host dry run =="
  exercise good --dry-run root@167.235.8.250
  if (( status == 0 )) &&
    grep -Fq "/mnt/data/libvirt/images" <<<"${output}" &&
    grep -Fq "ken-ci-net" <<<"${output}" &&
    grep -Fq "ken-deploy-net" <<<"${output}" &&
    grep -Fq "qemu-kvm" <<<"${output}" &&
    grep -Fq "dnsmasq-base" <<<"${output}" &&
    [[ "$(grep -Fxc preflight "${ssh_log}")" == 1 ]] &&
    ! grep -Fxq apply "${ssh_log}"; then
    pass "dry run reports the approved plan without apply"
  else
    fail "dry run did not preserve the no-mutation boundary"
    printf '%s\n' "${output}"
  fi
  if (( status == 0 )) &&
    grep -Fxq 'df --output=iavail /' "${command_log}" &&
    grep -Fxq "df --output=iavail ${data_root}" "${command_log}"; then
    pass "embedded inode metric uses GNU-compatible df options"
  else
    fail "embedded inode metric used incompatible df options"
  fi

  echo "== host apply readback =="
  exercise good root@167.235.8.250
  if (( status == 0 )) &&
    [[ "$(grep -Fxc preflight "${ssh_log}")" == 1 ]] &&
    [[ "$(grep -Fxc apply "${ssh_log}")" == 1 ]] &&
    grep -Fq "Host provisioning verified" <<<"${output}" &&
    grep -Fq 'apt-get install -y --no-install-recommends qemu-kvm libvirt-daemon-system libvirt-clients virtinst cloud-image-utils jq nftables dnsmasq-base libguestfs-tools' "${command_log}" &&
    grep -Fq "Rollback state:" <<<"${output}"; then
    pass "real embedded apply converges with exact packages and rollback evidence"
  else
    fail "embedded apply sequencing or readback validation failed"
    printf '%s\n' "${output}"
  fi
  first_rollback_path="$(awk -F': ' '/^Rollback state:/ { print $2; exit }' <<<"${output}")"

  pool_starts_before="$(grep -Fc 'virsh pool-start ken-actions' "${command_log}" || true)"
  exercise_inner existing-running root@167.235.8.250
  pool_starts_after="$(grep -Fc 'virsh pool-start ken-actions' "${command_log}" || true)"
  if (( status == 0 )) && [[ "${pool_starts_before}" == "${pool_starts_after}" ]]; then
    pass "second apply leaves an already-running pool running"
  else
    fail "second apply tried to restart the running pool"
    printf '%s\n' "${output}"
  fi

  exercise_inner existing-running --rollback "${first_rollback_path}" root@167.235.8.250
  if (( status == 0 )) &&
    [[ ! -e "${state_root}/pool.ken-actions.exists" ]] &&
    [[ ! -e "${state_root}/net.ken-ci-net.exists" ]] &&
    [[ ! -e "${state_root}/net.ken-deploy-net.exists" ]]; then
    pass "recorded rollback state restores the pre-first-apply resource set"
  else
    fail "manual rollback did not restore the captured resource set"
    printf '%s\n' "${output}"
  fi

  exercise storage-mount-drift root@167.235.8.250
  if (( status != 0 )) && grep -Fq "same dedicated filesystem" <<<"${output}"; then
    pass "post-create storage mount drift fails closed"
  else
    fail "post-create storage mount drift was accepted"
  fi

  exercise docker-restarted root@167.235.8.250
  if (( status != 0 )) && grep -Fq "Protected docker entries disappeared or changed" <<<"${output}"; then
    pass "restarted running Docker container is detected"
  else
    fail "Docker restart identity drift was accepted"
  fi

  exercise docker-no-health root@167.235.8.250
  if (( status == 0 )) &&
    grep -Fq 'Host provisioning verified' <<<"${output}" &&
    ! grep -Fq 'SNAPSHOT_SECRET_CANARY' <<<"${output}" &&
    ! grep -R -Fq 'SNAPSHOT_SECRET_CANARY' "${state_root}"; then
    pass "container without a healthcheck is snapshotted without leaking environment values"
  else
    fail "container without a healthcheck broke or leaked from the protected-state snapshot"
    printf '%s\n' "${output}"
  fi

  exercise memory-after-low root@167.235.8.250
  if (( status != 0 )) && grep -Fq "MemAvailable fell below 128 GiB" <<<"${output}"; then
    pass "low post-apply memory fails closed"
  else
    fail "low post-apply memory was accepted"
  fi

  echo "== host dnsmasq dependency =="
  exercise missing-dnsmasq root@167.235.8.250
  if (( status != 0 )) &&
    grep -Fq 'apt-get install' "${command_log}" &&
    grep -Eq 'virsh net-(define|start)' "${command_log}" &&
    grep -Fq "Unable to find 'dnsmasq' binary in \$PATH" <<<"${output}" &&
    grep -Fq 'AUTO_ROLLBACK_STATUS=ok' <<<"${output}" &&
    [[ ! -e "${state_root}/pool.ken-actions.exists" ]] &&
    [[ ! -e "${state_root}/net.ken-ci-net.exists" ]] &&
    [[ ! -e "${state_root}/net.ken-deploy-net.exists" ]]; then
    pass "missing dnsmasq fails at network start and auto-rolls back"
  else
    fail "missing dnsmasq did not fail at network start with automatic rollback"
    printf '%s\n' "${output}"
  fi

  exercise partial-failure root@167.235.8.250
  if (( status != 0 )) &&
    [[ ! -e "${state_root}/pool.ken-actions.exists" ]] &&
    [[ ! -e "${state_root}/net.ken-ci-net.exists" ]] &&
    grep -Fq 'AUTO_ROLLBACK_STATUS=ok' <<<"${output}"; then
    pass "partial failure removes only resources created by this run"
  else
    fail "partial failure did not roll back newly created resources"
    printf '%s\n' "${output}"
  fi

  exercise partial-preexisting root@167.235.8.250
  if (( status != 0 )) &&
    [[ -e "${state_root}/pool.ken-actions.exists" ]] &&
    [[ "$(cat "${state_root}/pool.ken-actions.active")" == 0 ]] &&
    [[ "$(cat "${state_root}/pool.ken-actions.auto")" == 0 ]] &&
    [[ -e "${state_root}/net.ken-ci-net.exists" ]] &&
    [[ "$(cat "${state_root}/net.ken-ci-net.active")" == 0 ]] &&
    [[ "$(cat "${state_root}/net.ken-ci-net.auto")" == 0 ]] &&
    grep -Fq 'AUTO_ROLLBACK_STATUS=ok' <<<"${output}"; then
    pass "partial failure restores preexisting inactive and no-autostart state"
  else
    fail "partial failure did not restore preexisting resource state"
    printf '%s\n' "${output}"
  fi

  for profile in rollback-net-destroy-fails rollback-net-undefine-fails rollback-pool-destroy-fails rollback-pool-undefine-fails; do
    exercise "${profile}" root@167.235.8.250
    retained_state="$(find "${state_root}" -maxdepth 1 -type d -name 'ken-actions-host.*' -print -quit)"
    if (( status != 0 )) &&
      grep -Fq 'AUTO_ROLLBACK_STATUS=failed' <<<"${output}" &&
      ! grep -Fq 'AUTO_ROLLBACK_STATUS=ok' <<<"${output}" &&
      [[ -n "${retained_state}" && -d "${retained_state}" ]]; then
      pass "${profile} is reported and retains rollback state"
    else
      fail "${profile} was hidden or lost rollback evidence"
      printf '%s\n' "${output}"
    fi
  done

  echo "== host shell syntax =="
  embedded="${test_dir}/embedded.sh"
  awk '/^IFS= read -r -d .*REMOTE_SCRIPT/{capture=1; next} /^REMOTE$/{capture=0} capture' "${HOST_PROVISION}" >"${embedded}"
  if bash -n "${HOST_PROVISION}" && bash -n "${embedded}"; then
    pass "provision-host and embedded remote script bash -n"
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
