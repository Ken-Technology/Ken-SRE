#!/usr/bin/env bash
set -euo pipefail

readonly APPROVED_TARGET="root@167.235.8.250"
readonly GIB=$((1024 * 1024 * 1024))
readonly MIN_ROOT_BEFORE_BYTES=$((25 * GIB))
readonly MIN_ROOT_AFTER_BYTES=$((20 * GIB))
readonly MIN_DATA_BYTES=$((850 * GIB))
readonly MIN_MEMORY_BEFORE_BYTES=$((128 * GIB))
readonly MIN_INODES=100000
readonly EXPECTED_GROK_RUNNERS=6
readonly SSH_BIN="${PROVISION_HOST_SSH_BIN:-ssh}"

usage() {
  cat <<'EOF'
Usage: bash infra/github-actions/scripts/provision-host.sh [--dry-run] root@167.235.8.250

Runs a read-only capacity and protected-service preflight first. Without
--dry-run, installs the approved libvirt stack and configures storage and
networks only after every gate passes.
EOF
}

die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

metric() {
  local report="$1" key="$2" value
  value="$(awk -F= -v key="${key}" '$1 == key { value=substr($0, length(key) + 2) } END { print value }' <<<"${report}")"
  [[ -n "${value}" ]] || die "preflight did not report ${key}"
  printf '%s\n' "${value}"
}

require_uint() {
  local label="$1" value="$2"
  [[ "${value}" =~ ^[0-9]+$ ]] || die "${label} is not an unsigned integer: ${value}"
}

gib() {
  local bytes="$1"
  awk -v bytes="${bytes}" 'BEGIN { printf "%.1f", bytes / 1073741824 }'
}

REMOTE_SCRIPT=''
IFS= read -r -d '' REMOTE_SCRIPT <<'REMOTE' || true
#!/usr/bin/env bash
set -euo pipefail

readonly GIB=$((1024 * 1024 * 1024))
readonly MIN_ROOT_BEFORE_BYTES=$((25 * GIB))
readonly MIN_ROOT_AFTER_BYTES=$((20 * GIB))
readonly MIN_DATA_BYTES=$((850 * GIB))
readonly MIN_MEMORY_BEFORE_BYTES=$((128 * GIB))
readonly MIN_INODES=100000
readonly EXPECTED_GROK_RUNNERS=6
readonly STORAGE_ROOT=/mnt/data/libvirt
readonly IMAGE_ROOT=/mnt/data/libvirt/images
readonly SEED_ROOT=/mnt/data/libvirt/seed
readonly POOL_NAME=ken-actions
readonly PACKAGES=(qemu-kvm libvirt-daemon-system libvirt-clients virtinst cloud-image-utils jq nftables)
readonly GROK_UNITS=(
  actions.runner.Ken-Technology-ken-agents.hetzner-grok-review-ken-agents.service
  actions.runner.Ken-Technology-ken-ai-mcp.hetzner-grok-review-ken-ai-mcp.service
  actions.runner.Ken-Technology-ken-backend.hetzner-grok-review-ken-backend.service
  actions.runner.Ken-Technology-ken-frontend.hetzner-grok-review-ken-frontend.service
  actions.runner.Ken-Technology-ken-scraping.hetzner-grok-review-ken-scraping.service
  actions.runner.Ken-Technology-ken-search.hetzner-grok-review-ken-search.service
)

die() {
  printf 'REMOTE_ERROR: %s\n' "$*" >&2
  exit 1
}

root_free_bytes() {
  df --output=avail -B1 / | awk 'NR == 2 { gsub(/[[:space:]]/, ""); print }'
}

free_inodes() {
  df --output=iavail -P "$1" | awk 'NR == 2 { gsub(/[[:space:]]/, ""); print }'
}

data_mount() {
  findmnt -n -o TARGET --target /mnt/data
}

data_options() {
  findmnt -n -o OPTIONS --target /mnt/data
}

data_free_bytes() {
  df --output=avail -B1 /mnt/data | awk 'NR == 2 { gsub(/[[:space:]]/, ""); print }'
}

memory_available_bytes() {
  awk '/^MemAvailable:/ { printf "%.0f\n", $2 * 1024 }' /proc/meminfo
}

kvm_ready() {
  if [[ -c /dev/kvm && -r /dev/kvm && -w /dev/kvm ]]; then
    echo 1
  else
    echo 0
  fi
}

grok_total() {
  local unit count=0
  for unit in "${GROK_UNITS[@]}"; do
    if systemctl cat "${unit}" >/dev/null 2>&1; then
      count=$((count + 1))
    fi
  done
  echo "${count}"
}

grok_active() {
  local unit count=0
  for unit in "${GROK_UNITS[@]}"; do
    if systemctl is-active --quiet "${unit}"; then
      count=$((count + 1))
    fi
  done
  echo "${count}"
}

emit_metrics() {
  printf 'ROOT_FREE_BYTES=%s\n' "$(root_free_bytes)"
  printf 'ROOT_FREE_INODES=%s\n' "$(free_inodes /)"
  printf 'DATA_MOUNT=%s\n' "$(data_mount)"
  printf 'DATA_OPTIONS=%s\n' "$(data_options)"
  printf 'DATA_FREE_BYTES=%s\n' "$(data_free_bytes)"
  printf 'DATA_FREE_INODES=%s\n' "$(free_inodes /mnt/data)"
  printf 'MEM_AVAILABLE_BYTES=%s\n' "$(memory_available_bytes)"
  printf 'KVM_DEVICE_READY=%s\n' "$(kvm_ready)"
  printf 'GROK_RUNNERS_TOTAL=%s\n' "$(grok_total)"
  printf 'GROK_RUNNERS_ACTIVE=%s\n' "$(grok_active)"
}

preflight_gate() {
  local root_free root_inodes mount options data_free data_inodes memory kvm total active
  root_free="$(root_free_bytes)"
  root_inodes="$(free_inodes /)"
  mount="$(data_mount)"
  options="$(data_options)"
  data_free="$(data_free_bytes)"
  data_inodes="$(free_inodes /mnt/data)"
  memory="$(memory_available_bytes)"
  kvm="$(kvm_ready)"
  total="$(grok_total)"
  active="$(grok_active)"

  (( root_free >= MIN_ROOT_BEFORE_BYTES )) || die "root filesystem free space is below 25 GiB"
  (( root_inodes >= MIN_INODES )) || die "root filesystem has fewer than ${MIN_INODES} free inodes"
  [[ "${mount}" == "/mnt/data" ]] || die "/mnt/data is not a dedicated mount"
  [[ ",${options}," == *,rw,* ]] || die "/mnt/data is not read-write"
  (( data_free >= MIN_DATA_BYTES )) || die "/mnt/data free space is below 850 GiB"
  (( data_inodes >= MIN_INODES )) || die "/mnt/data has fewer than ${MIN_INODES} free inodes"
  (( memory >= MIN_MEMORY_BEFORE_BYTES )) || die "host MemAvailable is below 128 GiB"
  [[ "${kvm}" == 1 ]] || die "/dev/kvm is not ready"
  [[ "${total}" == "${EXPECTED_GROK_RUNNERS}" && "${active}" == "${EXPECTED_GROK_RUNNERS}" ]] || die "all 6 Grok runners must exist and be active"
}

write_diagnostics() {
  echo 'DIAGNOSTICS_ROOT_CONSUMERS_BEGIN'
  du -xhd1 /var /opt /root /home 2>/dev/null | sort -h || true
  du -xhd1 /home/cristian/.grok 2>/dev/null | sort -h || true
  echo 'DIAGNOSTICS_ROOT_CONSUMERS_END'
  journalctl --disk-usage 2>/dev/null || true
  echo 'DIAGNOSTICS_APT_AUTOREMOVE_SIMULATION_BEGIN'
  apt-get -s autoremove 2>/dev/null || true
  echo 'DIAGNOSTICS_APT_AUTOREMOVE_SIMULATION_END'
}

snapshot_protected_state() {
  local destination="$1" unit
  : >"${destination}/services"
  for unit in "${GROK_UNITS[@]}" elasticsearch.service docker.service; do
    systemctl show "${unit}" --property=Id --property=LoadState --property=ActiveState --property=SubState --property=MainPID >>"${destination}/services" 2>/dev/null || true
  done
  sort -o "${destination}/services" "${destination}/services"
  docker ps --format '{{.ID}}|{{.Names}}|{{.Image}}|{{.State}}' 2>/dev/null | sort >"${destination}/docker"
  pgrep -af 'Runner\.(Listener|Worker)|/usr/share/elasticsearch|dockerd' | sort >"${destination}/processes" || true
  ss -H -lntup 2>/dev/null | sort >"${destination}/ports"
}

assert_preserved() {
  local before="$1" after="$2" file
  for file in services docker processes ports; do
    if ! comm -23 "${before}/${file}" "${after}/${file}" | grep -q .; then
      continue
    fi
    echo "Protected ${file} entries disappeared or changed:" >&2
    comm -23 "${before}/${file}" "${after}/${file}" >&2
    return 1
  done
}

ensure_pool() {
  local current_target
  if virsh pool-info "${POOL_NAME}" >/dev/null 2>&1; then
    current_target="$(virsh pool-dumpxml "${POOL_NAME}" | sed -n 's:.*<path>\(.*\)</path>.*:\1:p')"
    [[ "${current_target}" == "${IMAGE_ROOT}" ]] || die "existing ${POOL_NAME} pool target is ${current_target}, expected ${IMAGE_ROOT}"
  else
    virsh pool-define-as --name "${POOL_NAME}" --type dir --target "${IMAGE_ROOT}" >/dev/null
  fi
  virsh pool-autostart "${POOL_NAME}" >/dev/null
  if [[ "$(virsh pool-info "${POOL_NAME}" | awk -F: '/^State:/ { gsub(/[[:space:]]/, "", $2); print $2 }')" != active ]]; then
    virsh pool-start "${POOL_NAME}" >/dev/null
  fi
}

ensure_network() {
  local name="$1" bridge="$2" address="$3" start="$4" end="$5" xml current_xml current_address current_bridge
  xml="${SEED_ROOT}/${name}.xml"
  if virsh net-info "${name}" >/dev/null 2>&1; then
    current_xml="$(virsh net-dumpxml "${name}")"
    current_address="$(sed -n "s/.*<ip address='\([^']*\)'.*/\1/p" <<<"${current_xml}")"
    current_bridge="$(sed -n "s/.*<bridge name='\([^']*\)'.*/\1/p" <<<"${current_xml}")"
    [[ "${current_address}" == "${address}" && "${current_bridge}" == "${bridge}" ]] || die "existing ${name} network does not match the approved address and bridge"
    grep -Fq "<forward mode='nat'" <<<"${current_xml}" || die "existing ${name} network is not NAT"
    grep -Fq "<range start='${start}' end='${end}'" <<<"${current_xml}" || die "existing ${name} network has an unexpected DHCP range"
  else
    cat >"${xml}" <<EOF
<network>
  <name>${name}</name>
  <forward mode='nat'/>
  <bridge name='${bridge}' stp='on' delay='0'/>
  <ip address='${address}' netmask='255.255.255.0'>
    <dhcp>
      <range start='${start}' end='${end}'/>
    </dhcp>
  </ip>
</network>
EOF
    virsh net-define "${xml}" >/dev/null
  fi
  virsh net-autostart "${name}" >/dev/null
  if [[ "$(virsh net-info "${name}" | awk -F: '/^Active:/ { gsub(/[[:space:]]/, "", $2); print $2 }')" != yes ]]; then
    virsh net-start "${name}" >/dev/null
  fi
}

phase="${1:-}"
case "${phase}" in
  preflight)
    emit_metrics
    write_diagnostics
    ;;
  apply)
    preflight_gate
    state_root="$(mktemp -d /tmp/ken-actions-host.XXXXXX)"
    trap 'rm -rf "${state_root}"' EXIT
    mkdir "${state_root}/before" "${state_root}/after"
    snapshot_protected_state "${state_root}/before"

    export DEBIAN_FRONTEND=noninteractive
    export NEEDRESTART_MODE=l
    apt-get update
    apt-get install -y --no-install-recommends "${PACKAGES[@]}"
    (( $(root_free_bytes) >= MIN_ROOT_AFTER_BYTES )) || die "root filesystem fell below 20 GiB after package installation"
    systemctl enable --now libvirtd
    install -d -m 0755 "${STORAGE_ROOT}" "${IMAGE_ROOT}" "${SEED_ROOT}"
    ensure_pool
    ensure_network ken-ci-net virbr-ci 192.168.210.1 192.168.210.10 192.168.210.254
    ensure_network ken-deploy-net virbr-deploy 192.168.211.1 192.168.211.10 192.168.211.254

    (( $(data_free_bytes) >= MIN_DATA_BYTES )) || die "/mnt/data fell below 850 GiB during host provisioning"
    systemctl is-active --quiet libvirtd || die "libvirtd is not active"
    virsh nodeinfo >/dev/null || die "virsh nodeinfo failed"
    virsh net-info default >/dev/null || die "libvirt default network is not readable"
    snapshot_protected_state "${state_root}/after"
    assert_preserved "${state_root}/before" "${state_root}/after" || die "protected host state changed"
    [[ "$(grok_total)" == "${EXPECTED_GROK_RUNNERS}" && "$(grok_active)" == "${EXPECTED_GROK_RUNNERS}" ]] || die "Grok runners changed during provisioning"

    printf 'ROOT_FREE_AFTER_BYTES=%s\n' "$(root_free_bytes)"
    printf 'DATA_FREE_AFTER_BYTES=%s\n' "$(data_free_bytes)"
    printf 'MEM_AVAILABLE_AFTER_BYTES=%s\n' "$(memory_available_bytes)"
    printf 'GROK_RUNNERS_TOTAL_AFTER=%s\n' "$(grok_total)"
    printf 'GROK_RUNNERS_ACTIVE_AFTER=%s\n' "$(grok_active)"
    echo 'PROTECTED_STATE_OK=1'
    echo 'LIBVIRTD_ACTIVE=1'
    echo 'POOL_READY=1'
    echo 'KEN_CI_NET_READY=1'
    echo 'KEN_DEPLOY_NET_READY=1'
    echo 'APPLY_STATUS=ok'
    ;;
  *)
    die "unknown phase: ${phase}"
    ;;
esac
REMOTE

run_remote() {
  local target="$1" phase="$2"
  printf '%s\n' "${REMOTE_SCRIPT}" | "${SSH_BIN}" \
    -o BatchMode=yes \
    -o StrictHostKeyChecking=yes \
    -o ConnectTimeout=15 \
    "${target}" bash -s -- "${phase}"
}

dry_run=0
if [[ "${1:-}" == "--dry-run" ]]; then
  dry_run=1
  shift
fi
[[ $# == 1 ]] || {
  usage >&2
  exit 2
}
target="$1"
[[ "${target}" == "${APPROVED_TARGET}" ]] || die "target must be ${APPROVED_TARGET}"

printf 'Read-only preflight on %s\n' "${target}"
preflight="$(run_remote "${target}" preflight)"
root_free="$(metric "${preflight}" ROOT_FREE_BYTES)"
root_inodes="$(metric "${preflight}" ROOT_FREE_INODES)"
data_mount="$(metric "${preflight}" DATA_MOUNT)"
data_options="$(metric "${preflight}" DATA_OPTIONS)"
data_free="$(metric "${preflight}" DATA_FREE_BYTES)"
data_inodes="$(metric "${preflight}" DATA_FREE_INODES)"
memory_available="$(metric "${preflight}" MEM_AVAILABLE_BYTES)"
kvm="$(metric "${preflight}" KVM_DEVICE_READY)"
grok_total="$(metric "${preflight}" GROK_RUNNERS_TOTAL)"
grok_active="$(metric "${preflight}" GROK_RUNNERS_ACTIVE)"

if grep -Fq DIAGNOSTICS_ROOT_CONSUMERS_BEGIN <<<"${preflight}"; then
  echo 'Host diagnostics:'
  sed -n '/^DIAGNOSTICS_ROOT_CONSUMERS_BEGIN$/,$p' <<<"${preflight}"
fi

for pair in \
  "ROOT_FREE_BYTES:${root_free}" \
  "ROOT_FREE_INODES:${root_inodes}" \
  "DATA_FREE_BYTES:${data_free}" \
  "DATA_FREE_INODES:${data_inodes}" \
  "MEM_AVAILABLE_BYTES:${memory_available}" \
  "KVM_DEVICE_READY:${kvm}" \
  "GROK_RUNNERS_TOTAL:${grok_total}" \
  "GROK_RUNNERS_ACTIVE:${grok_active}"; do
  require_uint "${pair%%:*}" "${pair#*:}"
done

(( root_free >= MIN_ROOT_BEFORE_BYTES )) || die "root filesystem free space is $(gib "${root_free}") GiB; at least 25 GiB is required before package installation"
(( root_inodes >= MIN_INODES )) || die "root filesystem has ${root_inodes} free inodes; at least ${MIN_INODES} are required"
[[ "${data_mount}" == "/mnt/data" ]] || die "expected a dedicated /mnt/data mount, found ${data_mount}"
[[ ",${data_options}," == *,rw,* ]] || die "/mnt/data is not read-write"
(( data_free >= MIN_DATA_BYTES )) || die "/mnt/data free space is $(gib "${data_free}") GiB; at least 850 GiB is required"
(( data_inodes >= MIN_INODES )) || die "/mnt/data has ${data_inodes} free inodes; at least ${MIN_INODES} are required"
(( memory_available >= MIN_MEMORY_BEFORE_BYTES )) || die "host MemAvailable is $(gib "${memory_available}") GiB; at least 128 GiB is required before VM creation"
[[ "${kvm}" == 1 ]] || die "/dev/kvm is not ready"
[[ "${grok_total}" == "${EXPECTED_GROK_RUNNERS}" && "${grok_active}" == "${EXPECTED_GROK_RUNNERS}" ]] || die "all 6 Grok runners must exist and be active; found ${grok_active}/${grok_total} active"

printf 'Preflight passed: root %s GiB free, /mnt/data %s GiB free, memory %s GiB available, Grok runners %s/%s active.\n' \
  "$(gib "${root_free}")" "$(gib "${data_free}")" "$(gib "${memory_available}")" "${grok_active}" "${grok_total}"

cat <<'EOF'
Approved host changes:
  packages: qemu-kvm libvirt-daemon-system libvirt-clients virtinst cloud-image-utils jq nftables
  storage: /mnt/data/libvirt/images and /mnt/data/libvirt/seed
  pool: ken-actions -> /mnt/data/libvirt/images
  networks: ken-ci-net (virbr-ci) and ken-deploy-net (virbr-deploy)
  default network: read-only verification; no guest attachment or modification
EOF

if (( dry_run == 1 )); then
  echo 'Dry run complete. No host changes were requested.'
  exit 0
fi

printf 'Applying approved host changes on %s\n' "${target}"
apply_report="$(run_remote "${target}" apply)"
for expected in \
  APPLY_STATUS=ok \
  PROTECTED_STATE_OK=1 \
  LIBVIRTD_ACTIVE=1 \
  POOL_READY=1 \
  KEN_CI_NET_READY=1 \
  KEN_DEPLOY_NET_READY=1 \
  GROK_RUNNERS_TOTAL_AFTER=6 \
  GROK_RUNNERS_ACTIVE_AFTER=6; do
  grep -Fxq "${expected}" <<<"${apply_report}" || die "apply readback is incomplete; missing ${expected}"
done

root_after="$(metric "${apply_report}" ROOT_FREE_AFTER_BYTES)"
data_after="$(metric "${apply_report}" DATA_FREE_AFTER_BYTES)"
memory_after="$(metric "${apply_report}" MEM_AVAILABLE_AFTER_BYTES)"
require_uint ROOT_FREE_AFTER_BYTES "${root_after}"
require_uint DATA_FREE_AFTER_BYTES "${data_after}"
require_uint MEM_AVAILABLE_AFTER_BYTES "${memory_after}"
(( root_after >= MIN_ROOT_AFTER_BYTES )) || die "root filesystem has less than 20 GiB free after apply"
(( data_after >= MIN_DATA_BYTES )) || die "/mnt/data has less than 850 GiB free after apply"

printf 'Host provisioning verified: root %s GiB free, /mnt/data %s GiB free, memory %s GiB available, all protected services preserved.\n' \
  "$(gib "${root_after}")" "$(gib "${data_after}")" "$(gib "${memory_after}")"
