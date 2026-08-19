#!/usr/bin/env bash
# Thin inventory entry point. Parser/classifier behavior lives in
# test_audit_workflows.py.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
GA_ROOT="${ROOT}/infra/github-actions"
INV="${GA_ROOT}/inventory"
AUDIT="${GA_ROOT}/scripts/audit-workflows.sh"
HOST_PROVISION="${GA_ROOT}/scripts/provision-host.sh"
VM_PROVISION="${GA_ROOT}/scripts/provision-vms.sh"
VM_FIREWALL="${GA_ROOT}/scripts/lib/vm-firewall.sh"
LIBVIRT_ROOT="${GA_ROOT}/libvirt"
CLOUD_INIT_ROOT="${GA_ROOT}/cloud-init"
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

run_vm_definitions() {
  local path output status vm_test_dir fake_ssh fake_bin vm_state vm_data command_log summary_label
  summary_label=vm-definitions
  [[ "${VM_TEST_STATIC_ONLY:-0}" == 1 ]] && summary_label=vm-static

  echo "== VM definition files =="
  for path in \
    "${LIBVIRT_ROOT}/ken-ci.xml" \
    "${LIBVIRT_ROOT}/ken-deploy.xml" \
    "${CLOUD_INIT_ROOT}/ken-ci-user-data.yaml" \
    "${CLOUD_INIT_ROOT}/ken-deploy-user-data.yaml" \
    "${VM_FIREWALL}" \
    "${VM_PROVISION}"; do
    require_file "${path}"
  done

  echo "== VM and cloud-init semantics =="
  if python3 - "${GA_ROOT}" <<'PY'
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import yaml

root = Path(sys.argv[1])
failures = []


def check(condition, message):
    if not condition:
        failures.append(message)


contracts = {
    "ken-ci": (112 * 1024 * 1024, 32, 750, "ken-ci-net", "192.168.210.1", "ken-ci-runner"),
    "ken-deploy": (12 * 1024 * 1024, 4, 80, "ken-deploy-net", "192.168.211.1", "ken-deploy-runner"),
}

for name, (memory_kib, vcpus, disk_gib, network, gateway, runner_name) in contracts.items():
    xml_path = root / "libvirt" / f"{name}.xml"
    user_data_path = root / "cloud-init" / f"{name}-user-data.yaml"
    if not xml_path.is_file() or not user_data_path.is_file():
        continue

    domain = ET.parse(xml_path).getroot()
    memory = domain.find("memory")
    vcpu = domain.find("vcpu")
    cpu = domain.find("cpu")
    clock = domain.find("clock")
    check(domain.tag == "domain" and domain.attrib.get("type") == "kvm", f"{name}: KVM domain")
    check(domain.findtext("name") == name, f"{name}: domain name")
    check(memory is not None and memory.attrib.get("unit") == "KiB" and int(memory.text or 0) == memory_kib, f"{name}: memory")
    check(vcpu is not None and int(vcpu.text or 0) == vcpus, f"{name}: vCPU")
    check(cpu is not None and cpu.attrib.get("mode") == "host-passthrough", f"{name}: host-passthrough CPU")
    check(clock is not None and clock.attrib.get("offset") == "utc", f"{name}: UTC clock")
    vm_contract = domain.find("./metadata/{urn:ken-actions:v1}vm-contract")
    check(
        vm_contract is not None
        and vm_contract.attrib.get("disk-capacity-gib") == str(disk_gib)
        and vm_contract.attrib.get("image-customization-network") == "disabled",
        f"{name}: machine-readable disk and offline-image contract",
    )

    os_disks = []
    seeds = []
    for disk in domain.findall("./devices/disk"):
        source = disk.find("source")
        target = disk.find("target")
        driver = disk.find("driver")
        source_file = source.attrib.get("file", "") if source is not None else ""
        if target is not None and target.attrib.get("dev") == "vda":
            os_disks.append((source_file, target.attrib.get("bus"), driver.attrib.get("type") if driver is not None else None))
        if disk.attrib.get("device") == "cdrom":
            seeds.append(source_file)
    check(os_disks == [(f"/mnt/data/libvirt/images/{name}.qcow2", "virtio", "qcow2")], f"{name}: approved qcow2 OS disk")
    check(seeds == [f"/mnt/data/libvirt/seed/{name}-seed.img"], f"{name}: cloud-init seed")

    interfaces = domain.findall("./devices/interface")
    attached = [i.find("source").attrib.get("network") for i in interfaces if i.find("source") is not None]
    check(attached == [network] and "default" not in attached, f"{name}: isolated network")
    check(len(interfaces) == 1 and interfaces[0].find("model") is not None and interfaces[0].find("model").attrib.get("type") == "virtio", f"{name}: virtio NIC")
    check(any(c.find("target") is not None and c.find("target").attrib.get("name") == "org.qemu.guest_agent.0" for c in domain.findall("./devices/channel")), f"{name}: guest agent channel")

    data = yaml.safe_load(user_data_path.read_text())
    check(data.get("hostname") == name and data.get("timezone") == "UTC", f"{name}: identity and UTC")
    check(data.get("package_update") is False and data.get("package_upgrade") is False, f"{name}: no guest package-mirror refresh")
    check("packages" not in data and "apt" not in data, f"{name}: no cloud-init package installation")
    check(data.get("ssh_pwauth") is False and data.get("disable_root") is True, f"{name}: password and root SSH disabled")
    users = {u.get("name"): u for u in data.get("users") or [] if isinstance(u, dict)}
    check(set(users) == {"ken-admin", runner_name}, f"{name}: exact users")
    runner = users.get(runner_name, {})
    check(runner.get("lock_passwd") is True and runner.get("sudo") in (None, [], False), f"{name}: locked no-sudo runner")
    check(not set(runner.get("groups") or []) & {"sudo", "adm", "wheel"}, f"{name}: runner outside admin groups")
    admin = users.get("ken-admin", {})
    check(admin.get("lock_passwd") is True and admin.get("ssh_authorized_keys") == ["__HOST_ADMIN_SSH_KEY__"], f"{name}: host-managed admin key")
    files = {entry.get("path"): entry for entry in data.get("write_files") or [] if isinstance(entry, dict)}
    package_verifier = files.get("/usr/local/sbin/verify-offline-image", {}).get("content", "")
    check(
        "dpkg-query" in package_verifier
        and "qemu-guest-agent" in package_verifier
        and "docker.io" in package_verifier
        and "apt-get" not in package_verifier
        and "curl --" not in package_verifier,
        f"{name}: offline package presence verifier",
    )
    firewall = files.get("/etc/nftables.conf", {}).get("content", "")
    check("policy drop" in firewall and gateway in firewall and "tcp dport 22 accept" in firewall, f"{name}: host-only inbound SSH")
    check("0.0.0.0/0" not in firewall, f"{name}: no public SSH source")
    commands = [str(c).strip() for c in data.get("runcmd") or []]
    check(commands[0] == "/usr/local/sbin/verify-offline-image", f"{name}: offline image verified before services")
    check("systemctl enable --now qemu-guest-agent nftables" in commands, f"{name}: services enabled")
    if name == "ken-deploy":
        op_verifier = files.get("/usr/local/sbin/verify-1password-cli", {}).get("content", "")
        check("command -v op" in op_verifier and "apt-get" not in op_verifier and "curl" not in op_verifier, "ken-deploy: offline-seeded 1Password CLI required")

secret_patterns = [
    re.compile(r"-----BEGIN [A-Z0-9 ]+PRIVATE KEY-----"),
    re.compile(r"\bgh[op]_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bops_[A-Za-z0-9]{20,}\b"),
]
for path in [*root.glob("libvirt/*.xml"), *root.glob("cloud-init/*.yaml")]:
    text = path.read_text()
    for pattern in secret_patterns:
        check(not pattern.search(text), f"{path.name}: secret-shaped material")

if failures:
    print("\n".join(f"VM_SEMANTIC_FAIL {item}" for item in failures))
    raise SystemExit(1)
print("VM_SEMANTIC_OK")
PY
  then
    pass "VM XML and cloud-init contracts"
  else
    fail "VM XML and cloud-init contracts"
  fi

  echo "== VM provisioning boundary =="
  set +e
  output="$(PROVISION_VMS_SSH_BIN=false bash "${VM_PROVISION}" --dry-run root@167.235.8.250 2>&1)"
  status=$?
  set -e
  if (( status == 0 )) &&
    grep -Fq 'ken-ci: 32 vCPU, 112 GiB RAM, 750 GiB qcow2' <<<"${output}" &&
    grep -Fq 'ken-deploy: 4 vCPU, 12 GiB RAM, 80 GiB qcow2' <<<"${output}" &&
    grep -Fq 'No host or guest changes were requested' <<<"${output}"; then
    pass "VM dry run reports the immutable plan without SSH"
  else
    fail "VM dry run boundary"
    printf '%s\n' "${output}"
  fi

  contract_dir="$(mktemp -d)"
  mkdir -p "${contract_dir}/libvirt" "${contract_dir}/cloud-init" "${contract_dir}/scripts/lib"
  cp "${LIBVIRT_ROOT}/ken-ci.xml" "${LIBVIRT_ROOT}/ken-deploy.xml" "${contract_dir}/libvirt/"
  cp "${CLOUD_INIT_ROOT}/ken-ci-user-data.yaml" "${CLOUD_INIT_ROOT}/ken-deploy-user-data.yaml" "${contract_dir}/cloud-init/"
  cp "${VM_FIREWALL}" "${contract_dir}/scripts/lib/vm-firewall.sh"
  sed -i.bak "s/disk-capacity-gib='750'/disk-capacity-gib='751'/" "${contract_dir}/libvirt/ken-ci.xml"
  rm -f "${contract_dir}/libvirt/ken-ci.xml.bak"
  set +e
  output="$(PROVISION_VMS_GA_ROOT="${contract_dir}" bash "${VM_PROVISION}" --dry-run root@167.235.8.250 2>&1)"
  status=$?
  set -e
  if (( status == 0 )) && grep -Fq 'ken-ci: 32 vCPU, 112 GiB RAM, 751 GiB qcow2' <<<"${output}"; then
    pass "VM dry run consumes machine-readable disk capacity"
  else
    fail "VM dry run ignored machine-readable disk capacity"
  fi
  rm -rf "${contract_dir}"

  set +e
  output="$(bash "${VM_PROVISION}" --dry-run root@185.183.35.189 2>&1)"
  status=$?
  set -e
  if (( status != 0 )) && grep -Fq 'target must be root@167.235.8.250' <<<"${output}"; then
    pass "VM provisioner rejects every non-devws target"
  else
    fail "VM provisioner target guard"
  fi

  guard_dir="$(mktemp -d)"
  cat >"${guard_dir}/ssh" <<'SH'
#!/usr/bin/env bash
touch "${PROVISION_VMS_GUARD_MARKER:?}"
exit 70
SH
  chmod +x "${guard_dir}/ssh"
  set +e
  output="$(
    PROVISION_VMS_SSH_BIN="${guard_dir}/ssh" \
    PROVISION_VMS_GUARD_MARKER="${guard_dir}/ssh-called" \
    bash "${VM_PROVISION}" root@167.235.8.250 2>&1
  )"
  status=$?
  set -e
  if (( status != 0 )) &&
    grep -Fq 'live VM apply is blocked pending approval for dedicated reboot-persistent isolation services' <<<"${output}" &&
    [[ ! -e "${guard_dir}/ssh-called" ]]; then
    pass "unapproved live VM apply fails before SSH or guest start"
  else
    fail "live VM approval boundary"
  fi
  rm -rf "${guard_dir}"

  echo "== host-enforced VM firewall =="
  if [[ -f "${VM_FIREWALL}" ]]; then
    firewall_test_dir="$(mktemp -d)"
    firewall_path="${firewall_test_dir}/ken-actions-vms.nft"
    # shellcheck source=/dev/null
    source "${VM_FIREWALL}"
    render_ken_actions_firewall "${firewall_path}" 140.82.112.3 140.82.114.21 13.107.42.16
    if python3 - "${firewall_path}" "${VM_FIREWALL}" "${VM_PROVISION}" <<'PY'
import ipaddress
import re
import sys
from pathlib import Path

text = Path(sys.argv[1]).read_text()
helper = Path(sys.argv[2]).read_text()
provisioner = Path(sys.argv[3]).read_text()


def block(kind, name):
    match = re.search(rf"  {kind} {re.escape(name)} \{{\n(.*?)\n  \}}", text, re.S)
    if not match:
        raise AssertionError(f"missing {kind} {name}")
    return match.group(1)


def addresses_from_set(name):
    body = block("set", name)
    match = re.search(r"elements = \{(.*?)\}", body, re.S)
    if not match:
        return []
    return [part.strip() for part in match.group(1).split(",") if part.strip()]


named_sets = {
    "ci_denied_v4": addresses_from_set("ci_denied_v4"),
    "deploy_https_v4": addresses_from_set("deploy_https_v4"),
}


def port_matches(line, packet):
    if "tcp dport" in line and packet["proto"] != "tcp":
        return False
    if "udp dport" in line and packet["proto"] != "udp":
        return False
    l4 = re.search(r"meta l4proto \{ ([^}]*) \}", line)
    if l4 and packet["proto"] not in {item.strip() for item in l4.group(1).split(",")}:
        return False
    dport_set = re.search(r"(?:tcp|udp) dport \{ ([^}]*) \}", line)
    if dport_set and packet["dport"] not in {int(item.strip()) for item in dport_set.group(1).split(",")}:
        return False
    dport = re.search(r"(?:tcp|udp|th) dport ([0-9]+)", line)
    if dport and packet["dport"] != int(dport.group(1)):
        return False
    sport = re.search(r"udp sport ([0-9]+)", line)
    return not sport or packet["sport"] == int(sport.group(1))


def address_matches(line, packet):
    if "ip daddr" not in line:
        return True
    address = ipaddress.ip_address(packet["dest"])
    if address.version != 4:
        return False
    named = re.search(r"ip daddr @([a-z0-9_]+)", line)
    if named:
        return any(address in ipaddress.ip_network(value) for value in named_sets[named.group(1)])
    inline = re.search(r"ip daddr \{ ([^}]*) \}", line)
    if inline:
        return any(address in ipaddress.ip_network(value.strip()) for value in inline.group(1).split(","))
    exact = re.search(r"ip daddr ([0-9./]+)", line)
    return not exact or address in ipaddress.ip_network(exact.group(1))


def matches(line, packet):
    interface = re.search(r'iifname "([^"]+)"', line)
    if interface and packet["iif"] != interface.group(1):
        return False
    interface = re.search(r'oifname "([^"]+)"', line)
    if interface and packet["oif"] != interface.group(1):
        return False
    state = re.search(r"ct state ([a-z,]+)", line)
    if state and packet["state"] not in state.group(1).split(","):
        return False
    family = re.search(r"meta nfproto (ipv[46])", line)
    if family and packet["family"] != family.group(1):
        return False
    return address_matches(line, packet) and port_matches(line, packet)


def decide(chain_name, **overrides):
    packet = {
        "iif": "eth0",
        "oif": "eth1",
        "state": "new",
        "family": "ipv4",
        "dest": "8.8.8.8",
        "proto": "tcp",
        "sport": 50000,
        "dport": 443,
    }
    packet.update(overrides)
    body = block("chain", chain_name)
    policy = re.search(r"policy (accept|drop);", body).group(1)
    for raw in body.splitlines():
        line = raw.strip()
        if not line.endswith((" accept", " drop")):
            continue
        if matches(line, packet):
            return line.rsplit(maxsplit=1)[1]
    return policy


fixtures = {
    "host SSH return from CI": ("input", "accept", {"iif": "virbr-ci", "oif": "", "state": "established", "dest": "192.168.210.1"}),
    "host related return from deploy": ("input", "accept", {"iif": "virbr-deploy", "oif": "", "state": "related", "dest": "192.168.211.1"}),
    "new CI DNS to host": ("input", "accept", {"iif": "virbr-ci", "oif": "", "dest": "192.168.210.1", "proto": "udp", "dport": 53}),
    "new deploy DHCP to host": ("input", "accept", {"iif": "virbr-deploy", "oif": "", "dest": "192.168.211.1", "proto": "udp", "sport": 68, "dport": 67}),
    "new guest Elasticsearch to host": ("input", "drop", {"iif": "virbr-ci", "oif": "", "dest": "192.168.210.1", "dport": 9200}),
    "CI public HTTPS": ("forward", "accept", {"iif": "virbr-ci", "dest": "8.8.8.8"}),
    "CI host public IP": ("forward", "drop", {"iif": "virbr-ci", "dest": "167.235.8.250"}),
    "CI production IP": ("forward", "drop", {"iif": "virbr-ci", "dest": "185.183.35.189"}),
    "CI host bridge": ("forward", "drop", {"iif": "virbr-ci", "dest": "192.168.210.1"}),
    "CI deploy bridge": ("forward", "drop", {"iif": "virbr-ci", "dest": "192.168.211.1"}),
    "CI Tailscale": ("forward", "drop", {"iif": "virbr-ci", "dest": "100.100.100.100"}),
    "CI loopback": ("forward", "drop", {"iif": "virbr-ci", "dest": "127.0.0.1"}),
    "CI documentation range": ("forward", "drop", {"iif": "virbr-ci", "dest": "192.0.2.10"}),
    "CI IPv6 global": ("forward", "drop", {"iif": "virbr-ci", "family": "ipv6", "dest": "2606:4700:4700::1111"}),
    "CI IPv6 ULA": ("forward", "drop", {"iif": "virbr-ci", "family": "ipv6", "dest": "fd00::1"}),
    "CI IPv6 link local": ("forward", "drop", {"iif": "virbr-ci", "family": "ipv6", "dest": "fe80::1"}),
    "CI IPv6 loopback": ("forward", "drop", {"iif": "virbr-ci", "family": "ipv6", "dest": "::1"}),
    "invalid CI egress": ("forward", "drop", {"iif": "virbr-ci", "state": "invalid"}),
    "established inbound to CI": ("forward", "accept", {"oif": "virbr-ci", "state": "established", "dest": "192.168.210.10"}),
    "new inbound to CI": ("forward", "drop", {"oif": "virbr-ci", "state": "new", "dest": "192.168.210.10"}),
    "invalid inbound to deploy": ("forward", "drop", {"oif": "virbr-deploy", "state": "invalid", "dest": "192.168.211.10"}),
    "related inbound to deploy": ("forward", "accept", {"oif": "virbr-deploy", "state": "related", "dest": "192.168.211.10"}),
    "deploy approved HTTPS": ("forward", "accept", {"iif": "virbr-deploy", "dest": "140.82.112.3"}),
    "deploy unapproved HTTPS": ("forward", "drop", {"iif": "virbr-deploy", "dest": "8.8.8.8"}),
    "deploy production SSH": ("forward", "accept", {"iif": "virbr-deploy", "dest": "185.183.35.189", "dport": 22}),
}

failed = []
for name, (chain, expected, packet) in fixtures.items():
    actual = decide(chain, **packet)
    if actual != expected:
        failed.append(f"{name}: expected {expected}, got {actual}")

required_non_global = {
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
    "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
    "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24",
    "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
    "167.235.8.250", "185.183.35.189",
}
if not required_non_global <= set(named_sets["ci_denied_v4"]):
    failed.append("CI non-global/reserved IPv4 set is incomplete")
for network_text in required_non_global:
    network = ipaddress.ip_network(network_text)
    representative = str(network.network_address if network.prefixlen == 32 else network.network_address + 1)
    actual = decide("forward", iif="virbr-ci", dest=representative)
    if actual != "drop":
        failed.append(f"CI non-global/reserved fixture {representative} was {actual}")
if "api.cloudflare.com" in helper:
    failed.append("Cloudflare was added without an inventory target")
if "flush ruleset" in helper + provisioner or "/etc/nftables.conf" in helper + provisioner:
    failed.append("host firewall code contains a global ruleset mutation")
if failed:
    print("FIREWALL_FAIL " + "; ".join(failed))
    raise SystemExit(1)
print("FIREWALL_OK")
PY
    then
      pass "host nftables policy enforces CI and deployment egress boundaries"
    else
      fail "host nftables policy"
    fi
    rm -rf "${firewall_test_dir}"
    set +e
    resolver_output="$(
      # shellcheck disable=SC2329
      getent() {
        [[ "${2:-}" == api.github.com ]] && return 2
        printf '140.82.112.3 STREAM %s\n' "${2:-endpoint}"
      }
      resolve_ken_actions_endpoint_ipv4
    ) 2>&1)"
    resolver_status=$?
    set -e
    if (( resolver_status != 0 )); then
      pass "required deployment endpoint DNS failure leaves the firewall fail-closed"
    else
      fail "deployment endpoint resolver accepted a partial DNS result"
      printf '%s\n' "${resolver_output}"
    fi
  else
    fail "host nftables policy"
  fi

  if [[ "${VM_TEST_STATIC_ONLY:-0}" == 1 ]]; then
    echo "== VM apply behavior =="
    echo "  PENDING APPROVAL  persistent firewall, refresh timer, and ordered VM startup"
  else
  echo "== VM apply behavior =="
  vm_test_dir="$(mktemp -d)"
  fake_ssh="${vm_test_dir}/ssh"
  fake_bin="${vm_test_dir}/bin"
  vm_state="${vm_test_dir}/state"
  vm_data="${vm_test_dir}/data"
  command_log="${vm_test_dir}/commands.log"
  mkdir -p "${fake_bin}" "${vm_state}" "${vm_data}/libvirt/images" "${vm_data}/libvirt/seed"
  printf '%s\n' 'test-only Ubuntu cloud image bytes' >"${vm_state}/cloud-image"
  printf '%s\n' 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestOnlyKeyMaterial ken-vm-test' >"${vm_state}/authorized_keys"

  cat >"${fake_ssh}" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
args=("$@")
if [[ " $* " == *" tar -C "* ]]; then
  stage="$(cat "${FAKE_VM_STATE:?}/stage-path")"
  /usr/bin/tar -C "${stage}" -xf -
  exit 0
fi
phase=''
argument=''
for ((i=0; i<${#args[@]}; i++)); do
  if [[ "${args[i]}" == -- ]]; then
    phase="${args[i+1]:-}"
    argument="${args[i+2]:-}"
    break
  fi
done
[[ -n "${phase}" ]] || { echo 'fake ssh missing phase' >&2; exit 64; }
remote="${FAKE_VM_STATE:?}/remote-${phase}.sh"
cat >"${remote}"
bash -n "${remote}"
export PATH="${FAKE_VM_BIN:?}:/usr/bin:/bin"
export PROVISION_VMS_ALLOW_NON_ROOT=1
export PROVISION_VMS_DATA_ROOT="${FAKE_VM_DATA:?}"
export PROVISION_VMS_STAGE_PARENT="${FAKE_VM_STATE:?}"
export PROVISION_VMS_AUTHORIZED_KEYS="${FAKE_VM_STATE:?}/authorized_keys"
export PROVISION_VMS_TEST_IMAGE="${FAKE_VM_STATE:?}/cloud-image"
export PROVISION_VMS_COMMAND_LOG="${FAKE_VM_COMMAND_LOG:?}"
export PROVISION_VMS_NFT_DIR="${FAKE_VM_STATE:?}/nftables.d"
export PROVISION_VMS_NFT_MAIN="${FAKE_VM_STATE:?}/nftables.conf"
if [[ "${phase}" == create-stage ]]; then
  result="$(bash "${remote}" "${phase}" "${argument}")"
  printf '%s\n' "${result}" >"${FAKE_VM_STATE:?}/stage-path"
  printf '%s\n' "${result}"
else
  bash "${remote}" "${phase}" "${argument}"
fi
SH
  chmod +x "${fake_ssh}"

  cat >"${fake_bin}/curl" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
printf 'curl %s\n' "$*" >>"${PROVISION_VMS_COMMAND_LOG:?}"
destination=''
url="${*: -1}"
args=("$@")
for ((i=0; i<${#args[@]}; i++)); do
  [[ "${args[i]}" == -o ]] && destination="${args[i+1]}"
done
[[ -n "${destination}" ]] || exit 64
if [[ "${url}" == */SHA256SUMS ]]; then
  hash="$(sha256sum "${PROVISION_VMS_TEST_IMAGE:?}" | awk '{print $1}')"
  printf '%s *noble-server-cloudimg-amd64.img\n' "${hash}" >"${destination}"
else
  cp "${PROVISION_VMS_TEST_IMAGE:?}" "${destination}"
fi
SH

  cat >"${fake_bin}/sha256sum" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == -c ]]; then
  exec /usr/bin/shasum -a 256 -c "$2"
fi
/usr/bin/shasum -a 256 "$@"
SH

  cat >"${fake_bin}/qemu-img" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
printf 'qemu-img %s\n' "$*" >>"${PROVISION_VMS_COMMAND_LOG:?}"
case "${1:-}" in
  info)
    printf '{"format":"qcow2","virtual-size":10737418240}\n'
    ;;
  create)
    output="${*: -2:1}"
    size="${*: -1}"
    : >"${output}"
    printf '%s\n' "${size}" >"${output}.size"
    ;;
  convert)
    source="${*: -2:1}"
    output="${*: -1}"
    cp "${source}" "${output}"
    ;;
  *) exit 64 ;;
esac
SH

  cat >"${fake_bin}/virt-customize" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
printf 'virt-customize %s\n' "$*" >>"${PROVISION_VMS_COMMAND_LOG:?}"
args=("$@")
image=''
generation=''
for ((i=0; i<${#args[@]}; i++)); do
  [[ "${args[i]}" == -a ]] && image="${args[i+1]}"
  if [[ "${args[i]}" == --write ]]; then
    generation="${args[i+1]##*:}"
  fi
done
[[ -n "${image}" && -n "${generation}" ]] || exit 64
printf '\ncustomized\n' >>"${image}"
printf '%s\n' "${generation}" >"${image}.generation"
SH

  cat >"${fake_bin}/virt-cat" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
[[ "${1:-}" == -a ]] || exit 64
cat "$2.generation"
SH

  cat >"${fake_bin}/cloud-localds" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
printf 'cloud-localds %s\n' "$*" >>"${PROVISION_VMS_COMMAND_LOG:?}"
output="${3:?}"
printf 'seed\n' >"${output}"
SH

  cat >"${fake_bin}/virt-xml-validate" <<'SH'
#!/usr/bin/env bash
exit 0
SH

  cat >"${fake_bin}/virsh" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
printf 'virsh %s\n' "$*" >>"${PROVISION_VMS_COMMAND_LOG:?}"
state="${FAKE_VM_STATE:?}"
case "${1:-}" in
  pool-info|net-info) printf 'Name: %s\nActive: yes\nPersistent: yes\n' "${2:-resource}" ;;
  dominfo) [[ -e "${state}/domain.$2" ]] || exit 1; printf 'Name: %s\nState: running\n' "$2" ;;
  define)
    name="$(sed -n 's:.*<name>\([^<]*\)</name>.*:\1:p' "$2")"
    touch "${state}/domain.${name}"
    ;;
  start) touch "${state}/running.$2" ;;
  domstate) [[ -e "${state}/running.$2" ]] && echo running || echo shut-off ;;
  domblklist)
    printf 'Target Source\n------------------------------------------------\n'
    printf 'vda %s/libvirt/images/%s.qcow2\n' "${FAKE_VM_DATA:?}" "$2"
    printf 'sda %s/libvirt/seed/%s-seed.img\n' "${FAKE_VM_DATA:?}" "$2"
    ;;
  domiflist)
    network=ken-ci-net; [[ "$2" == ken-deploy ]] && network=ken-deploy-net
    printf 'Interface Type Source Model MAC\n- - - - -\nvnet0 network %s virtio 52:54:00:00:00:01\n' "${network}"
    ;;
  qemu-agent-command)
    if [[ "$*" == *guest-exec-status* ]]; then
      printf '{"return":{"exited":true,"exitcode":0}}\n'
    elif [[ "$*" == *guest-exec* ]]; then
      printf '{"return":{"pid":7}}\n'
    else
      printf '{"return":{}}\n'
    fi
    ;;
  *) exit 64 ;;
esac
SH

  cat >"${fake_bin}/nft" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
printf 'nft %s\n' "$*" >>"${PROVISION_VMS_COMMAND_LOG:?}"
state="${FAKE_VM_STATE:?}"
if [[ "${1:-}" == list ]]; then
  [[ -e "${state}/nft-loaded" ]]
elif [[ "${1:-}" == delete ]]; then
  rm -f "${state}/nft-loaded"
elif [[ "${1:-}" == -c && "${2:-}" == -f ]]; then
  exit 0
elif [[ "${1:-}" == -f ]]; then
  cp "$2" "${state}/nft-loaded"
else
  exit 64
fi
SH

  cat >"${fake_bin}/systemctl" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
printf 'systemctl %s\n' "$*" >>"${PROVISION_VMS_COMMAND_LOG:?}"
case "${1:-}" in
  is-active) exit 0 ;;
  enable) exit 0 ;;
  *) exit 0 ;;
esac
SH

  cat >"${fake_bin}/free" <<'SH'
#!/usr/bin/env bash
printf 'Mem: 269509197824 0 0 0 0 68719476736\n'
SH

  cat >"${fake_bin}/getent" <<'SH'
#!/usr/bin/env bash
printf '%s STREAM %s\n' "${FAKE_VM_ENDPOINT_IP:-140.82.112.3}" "${2:-endpoint}"
SH
  cat >"${fake_bin}/readlink" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
[[ "${1:-}" == -m ]] || exit 64
shift
[[ "${1:-}" == -- ]] && shift
python3 -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "$1"
SH
  ln -s "$(command -v jq)" "${fake_bin}/jq"
  chmod +x "${fake_bin}"/*

  set +e
  output="$(
    FAKE_VM_STATE="${vm_state}" \
    FAKE_VM_DATA="${vm_data}" \
    FAKE_VM_BIN="${fake_bin}" \
    FAKE_VM_COMMAND_LOG="${command_log}" \
    PROVISION_VMS_SSH_BIN="${fake_ssh}" \
    PROVISION_VMS_EXPECTED_STAGE_PARENT="${vm_state}" \
    bash "${VM_PROVISION}" root@167.235.8.250 2>&1
  )"
  status=$?
  set -e
  if (( status == 0 )) &&
    grep -Fq 'VM provisioning verified' <<<"${output}" &&
    [[ -e "${vm_state}/running.ken-ci" && -e "${vm_state}/running.ken-deploy" ]] &&
    [[ "$(cat "${vm_data}/libvirt/images/ken-ci.qcow2.size")" == 750G ]] &&
    [[ "$(cat "${vm_data}/libvirt/images/ken-deploy.qcow2.size")" == 80G ]] &&
    grep -Fq 'qemu-img convert -O qcow2' "${command_log}" &&
    grep -Fq 'virt-customize -a' "${command_log}" &&
    grep -Fq -- '--no-network' "${command_log}" &&
    grep -Fq '185.183.35.189 tcp dport 22 accept' "${vm_state}/nft-loaded" &&
    ! grep -R -Eq '(__HOST_ADMIN_SSH_KEY__|BEGIN .*PRIVATE KEY|gh[op]_)' "${vm_data}/libvirt/seed"; then
    pass "VM apply verifies image, thin disks, seeds, guests, guest agent, and host firewall"
  else
    fail "PENDING APPROVAL: VM apply behavior"
    printf '%s\n' "${output}"
  fi
  rm -rf "${vm_test_dir}"
  fi

  echo "== VM shell syntax =="
  if [[ -f "${VM_PROVISION}" && -f "${VM_FIREWALL}" ]] && bash -n "${VM_PROVISION}" && bash -n "${VM_FIREWALL}" && bash -n "${GA_ROOT}/tests/test-config.sh"; then
    pass "VM provisioner and test entry point bash -n"
  else
    fail "VM shell syntax"
  fi

  echo
  if (( FAILED == 0 )); then
    echo "${summary_label}: ${RAN} assertions passed"
    return 0
  fi
  echo "${summary_label}: ${FAILED} failed / ${RAN} assertions"
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
  vm-definitions)
    run_vm_definitions
    ;;
  vm-static)
    VM_TEST_STATIC_ONLY=1 run_vm_definitions
    ;;
  all)
    run_inventory
    run_host
    run_vm_definitions
    ;;
  runners)
    echo "runners: Task 5 owns runner-service tests"
    exit 2
    ;;
  -h|--help)
    echo "Usage: bash infra/github-actions/tests/test-config.sh [inventory|host|vm-static|vm-definitions|all]"
    ;;
  *)
    echo "Usage: bash infra/github-actions/tests/test-config.sh [inventory|host|vm-static|vm-definitions|all]"
    exit 2
    ;;
esac
