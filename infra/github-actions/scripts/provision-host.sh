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
readonly EXPECTED_DATA_MOUNT="${PROVISION_HOST_EXPECTED_DATA_MOUNT:-/mnt/data}"

usage() {
  cat <<'EOF'
Usage:
  bash infra/github-actions/scripts/provision-host.sh [--dry-run] root@167.235.8.250
  bash infra/github-actions/scripts/provision-host.sh --rollback STATE_DIR root@167.235.8.250

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
readonly DATA_ROOT="${PROVISION_HOST_DATA_ROOT:-/mnt/data}"
readonly STORAGE_ROOT="${DATA_ROOT}/libvirt"
readonly IMAGE_ROOT="${STORAGE_ROOT}/images"
readonly SEED_ROOT="${STORAGE_ROOT}/seed"
readonly KVM_DEVICE="${PROVISION_HOST_KVM_DEVICE:-/dev/kvm}"
readonly STATE_PARENT="${PROVISION_HOST_STATE_PARENT:-/var/tmp}"
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
  df --output=iavail "$1" | awk 'NR == 2 { gsub(/[[:space:]]/, ""); print }'
}

data_mount() {
  findmnt -n -o TARGET --target "${DATA_ROOT}"
}

data_options() {
  findmnt -n -o OPTIONS --target "${DATA_ROOT}"
}

data_free_bytes() {
  df --output=avail -B1 "${DATA_ROOT}" | awk 'NR == 2 { gsub(/[[:space:]]/, ""); print }'
}

memory_available_bytes() {
  free --bytes | awk '/^Mem:/ { print $NF }'
}

kvm_ready() {
  if [[ -c "${KVM_DEVICE}" && -r "${KVM_DEVICE}" && -w "${KVM_DEVICE}" ]]; then
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
  printf 'DATA_FREE_INODES=%s\n' "$(free_inodes "${DATA_ROOT}")"
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
  data_inodes="$(free_inodes "${DATA_ROOT}")"
  memory="$(memory_available_bytes)"
  kvm="$(kvm_ready)"
  total="$(grok_total)"
  active="$(grok_active)"

  (( root_free >= MIN_ROOT_BEFORE_BYTES )) || die "root filesystem free space is below 25 GiB"
  (( root_inodes >= MIN_INODES )) || die "root filesystem has fewer than ${MIN_INODES} free inodes"
  [[ "${mount}" == "${DATA_ROOT}" ]] || die "${DATA_ROOT} is not a dedicated mount"
  [[ ",${options}," == *,rw,* ]] || die "${DATA_ROOT} is not read-write"
  (( data_free >= MIN_DATA_BYTES )) || die "${DATA_ROOT} free space is below 850 GiB"
  (( data_inodes >= MIN_INODES )) || die "${DATA_ROOT} has fewer than ${MIN_INODES} free inodes"
  (( memory >= MIN_MEMORY_BEFORE_BYTES )) || die "host MemAvailable is below 128 GiB"
  [[ "${kvm}" == 1 ]] || die "${KVM_DEVICE} is not ready"
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

validate_storage_path_plan() {
  local path resolved
  for path in "${DATA_ROOT}" "${STORAGE_ROOT}" "${IMAGE_ROOT}" "${SEED_ROOT}"; do
    resolved="$(readlink -m -- "${path}")" || die "cannot resolve approved storage path ${path}"
    [[ "${resolved}" == "${path}" ]] || die "storage path ${path} resolves outside the approved data path: ${resolved}"
  done
}

verify_storage_directories() {
  local data_source path resolved source target options
  data_source="$(findmnt -n -o SOURCE --target "${DATA_ROOT}")"
  [[ -n "${data_source}" ]] || die "cannot identify the ${DATA_ROOT} filesystem"
  for path in "${STORAGE_ROOT}" "${IMAGE_ROOT}" "${SEED_ROOT}"; do
    resolved="$(readlink -e -- "${path}")" || die "approved storage directory does not exist: ${path}"
    [[ "${resolved}" == "${path}" ]] || die "storage path ${path} resolves outside the approved data path: ${resolved}"
    source="$(findmnt -n -o SOURCE --target "${path}")"
    target="$(findmnt -n -o TARGET --target "${path}")"
    options="$(findmnt -n -o OPTIONS --target "${path}")"
    [[ "${source}" == "${data_source}" && "${target}" == "${DATA_ROOT}" ]] || die "${path} is not on the same dedicated filesystem as ${DATA_ROOT}"
    [[ ",${options}," == *,rw,* ]] || die "${path} is not on a read-write filesystem"
  done
}

xml_attribute() {
  local xml="$1" element="$2" attribute="$3" tag
  tag="$(grep -Eo "<${element}([[:space:]][^>]*)?>" <<<"${xml}" | head -n 1)"
  sed -n -E "s/.*${attribute}=['\"]([^'\"]*)['\"].*/\1/p" <<<"${tag}"
}

ipv4_to_int() {
  local ip="$1" a b c d
  IFS=. read -r a b c d <<<"${ip}"
  for octet in "${a:-}" "${b:-}" "${c:-}" "${d:-}"; do
    [[ "${octet}" =~ ^[0-9]+$ ]] && (( octet >= 0 && octet <= 255 )) || return 1
  done
  printf '%u\n' "$(( (a << 24) | (b << 16) | (c << 8) | d ))"
}

netmask_prefix() {
  case "$1" in
    255.255.255.255) echo 32 ;;
    255.255.255.254) echo 31 ;;
    255.255.255.252) echo 30 ;;
    255.255.255.248) echo 29 ;;
    255.255.255.240) echo 28 ;;
    255.255.255.224) echo 27 ;;
    255.255.255.192) echo 26 ;;
    255.255.255.128) echo 25 ;;
    255.255.255.0) echo 24 ;;
    255.255.254.0) echo 23 ;;
    255.255.252.0) echo 22 ;;
    255.255.248.0) echo 21 ;;
    255.255.240.0) echo 20 ;;
    255.255.224.0) echo 19 ;;
    255.255.192.0) echo 18 ;;
    255.255.128.0) echo 17 ;;
    255.255.0.0) echo 16 ;;
    255.254.0.0) echo 15 ;;
    255.252.0.0) echo 14 ;;
    255.248.0.0) echo 13 ;;
    255.240.0.0) echo 12 ;;
    255.224.0.0) echo 11 ;;
    255.192.0.0) echo 10 ;;
    255.128.0.0) echo 9 ;;
    255.0.0.0) echo 8 ;;
    254.0.0.0) echo 7 ;;
    252.0.0.0) echo 6 ;;
    248.0.0.0) echo 5 ;;
    240.0.0.0) echo 4 ;;
    224.0.0.0) echo 3 ;;
    192.0.0.0) echo 2 ;;
    128.0.0.0) echo 1 ;;
    0.0.0.0) echo 0 ;;
    *) return 1 ;;
  esac
}

cidr_overlaps() {
  local left="$1" right="$2" left_ip left_prefix right_ip right_prefix left_int right_int left_size right_size left_start right_start
  left_ip="${left%/*}"
  [[ "${left}" == */* ]] && left_prefix="${left#*/}" || left_prefix=32
  right_ip="${right%/*}"
  [[ "${right}" == */* ]] && right_prefix="${right#*/}" || right_prefix=32
  [[ "${left_prefix}" =~ ^[0-9]+$ && "${right_prefix}" =~ ^[0-9]+$ ]] || return 1
  (( left_prefix >= 0 && left_prefix <= 32 && right_prefix >= 0 && right_prefix <= 32 )) || return 1
  left_int="$(ipv4_to_int "${left_ip}")" || return 1
  right_int="$(ipv4_to_int "${right_ip}")" || return 1
  left_size=$((1 << (32 - left_prefix)))
  right_size=$((1 << (32 - right_prefix)))
  left_start=$((left_int / left_size * left_size))
  right_start=$((right_int / right_size * right_size))
  (( left_start <= right_start + right_size - 1 && right_start <= left_start + left_size - 1 ))
}

network_exists() {
  virsh net-info "$1" >/dev/null 2>&1
}

network_contract() {
  local name="$1" bridge="$2" address="$3" netmask="$4" start="$5" end="$6" xml contract_error
  network_exists "${name}" || return 0
  xml="$(virsh net-dumpxml "${name}")"
  command -v python3 >/dev/null 2>&1 || die "python3 is required to validate the full ${name} network contract"
  if ! contract_error="$(python3 - "${name}" "${bridge}" "${address}" "${netmask}" "${start}" "${end}" "${xml}" <<'PY'
import re
import sys
import xml.etree.ElementTree as ET

name, bridge, address, netmask, start, end, xml = sys.argv[1:]


def reject(message):
    print(message)
    raise SystemExit(1)


def exact_attributes(element, expected):
    if element.attrib != expected:
        reject(f"{element.tag} attributes are {element.attrib!r}, expected {expected!r}")


def no_content(element):
    if list(element) or (element.text or "").strip():
        reject(f"{element.tag} contains unexpected nested or text content")


try:
    root = ET.fromstring(xml)
except ET.ParseError as exc:
    reject(f"XML is not parseable: {exc}")

if root.tag != "network":
    reject(f"root element is {root.tag!r}, expected 'network'")
unexpected_root_attributes = set(root.attrib) - {"connections"}
if unexpected_root_attributes:
    reject(f"network has functional attributes {sorted(unexpected_root_attributes)!r}")
if "connections" in root.attrib and not root.attrib["connections"].isdigit():
    reject("network connections metadata is not an unsigned integer")

children = list(root)
allowed = {"name", "uuid", "forward", "bridge", "mac", "ip"}
unexpected = [child.tag for child in children if child.tag not in allowed]
if unexpected:
    reject(f"network contains unexpected elements {unexpected!r}")


def elements(tag, required=1, maximum=1):
    matches = [child for child in children if child.tag == tag]
    if not (required <= len(matches) <= maximum):
        reject(f"network has {len(matches)} {tag} elements, expected {required}..{maximum}")
    return matches


name_element = elements("name")[0]
exact_attributes(name_element, {})
if list(name_element) or (name_element.text or "").strip() != name:
    reject("name element does not exactly match the approved network name")

uuid_elements = elements("uuid", required=0)
if uuid_elements:
    uuid_element = uuid_elements[0]
    exact_attributes(uuid_element, {})
    if list(uuid_element) or not re.fullmatch(
        r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
        (uuid_element.text or "").strip(),
    ):
        reject("uuid metadata is not a single canonical UUID")

forward = elements("forward")[0]
exact_attributes(forward, {"mode": "nat"})
no_content(forward)

bridge_element = elements("bridge")[0]
exact_attributes(bridge_element, {"name": bridge, "stp": "on", "delay": "0"})
no_content(bridge_element)

mac_elements = elements("mac", required=0)
if mac_elements:
    mac = mac_elements[0]
    if set(mac.attrib) != {"address"} or not re.fullmatch(
        r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", mac.attrib["address"]
    ):
        reject("mac metadata is not a single canonical address")
    no_content(mac)

ip = elements("ip")[0]
exact_attributes(ip, {"address": address, "netmask": netmask})
if (ip.text or "").strip():
    reject("ip contains unexpected text content")
if [child.tag for child in ip] != ["dhcp"]:
    reject("ip must contain exactly one dhcp element and no other functional elements")

dhcp = ip[0]
exact_attributes(dhcp, {})
if (dhcp.text or "").strip():
    reject("dhcp contains unexpected text content")
if [child.tag for child in dhcp] != ["range"]:
    reject("dhcp must contain exactly one range element and no other functional elements")

dhcp_range = dhcp[0]
exact_attributes(dhcp_range, {"start": start, "end": end})
no_content(dhcp_range)
PY
)"; then
    die "existing ${name} network does not match the full approved contract: ${contract_error}"
  fi
  [[ "$(virsh net-info "${name}" | awk -F: '/^Persistent:/ { gsub(/[[:space:]]/, "", $2); print tolower($2) }')" == yes ]] || die "existing ${name} network is transient and cannot be converged safely"
}

network_cidr_from_xml() {
  local xml="$1" address netmask prefix
  address="$(xml_attribute "${xml}" ip address)"
  netmask="$(xml_attribute "${xml}" ip netmask)"
  [[ -n "${address}" && -n "${netmask}" ]] || return 1
  prefix="$(netmask_prefix "${netmask}")" || return 1
  printf '%s/%s\n' "${address}" "${prefix}"
}

validate_network_conflicts() {
  local name="$1" bridge="$2" subnet="$3" exists=0 line destination dev id other xml other_cidr
  network_exists "${name}" && exists=1

  if ip -o link show "${bridge}" >/dev/null 2>&1 && (( exists == 0 )); then
    die "network bridge ${bridge} already exists without the approved ${name} definition"
  fi

  while IFS= read -r line; do
    [[ -n "${line}" ]] || continue
    destination="${line%% *}"
    case "${destination}" in
      local|broadcast|unreachable|blackhole|prohibit|throw)
        line="${line#* }"
        destination="${line%% *}"
        ;;
    esac
    [[ "${destination}" == default ]] && continue
    dev="$(awk '{ for (i=1; i<=NF; i++) if ($i == "dev") { print $(i+1); exit } }' <<<"${line}")"
    if cidr_overlaps "${subnet}" "${destination}"; then
      if (( exists == 1 )) && [[ "${destination}" == "${subnet}" && "${dev}" == "${bridge}" ]]; then
        continue
      fi
      die "network ${subnet} conflicts with host route ${line}"
    fi
  done < <(ip -o -4 route show table all)

  if command -v docker >/dev/null 2>&1; then
    while IFS= read -r id; do
      [[ -n "${id}" ]] || continue
      while IFS= read -r other_cidr; do
        [[ -n "${other_cidr}" ]] || continue
        if cidr_overlaps "${subnet}" "${other_cidr}"; then
          die "network ${subnet} conflicts with Docker network ${id} (${other_cidr})"
        fi
      done < <(docker network inspect --format '{{range .IPAM.Config}}{{.Subnet}}{{"\n"}}{{end}}' "${id}" 2>/dev/null || true)
    done < <(docker network ls -q 2>/dev/null || true)
  fi

  if command -v virsh >/dev/null 2>&1; then
    while IFS= read -r other; do
      [[ -n "${other}" && "${other}" != "${name}" ]] || continue
      xml="$(virsh net-dumpxml "${other}" 2>/dev/null)" || continue
      other_cidr="$(network_cidr_from_xml "${xml}")" || continue
      if cidr_overlaps "${subnet}" "${other_cidr}"; then
        die "network ${subnet} conflicts with libvirt network ${other} (${other_cidr})"
      fi
    done < <(virsh net-list --all --name 2>/dev/null || true)
  fi
}

validate_network_plan() {
  network_contract ken-ci-net virbr-ci 192.168.210.1 255.255.255.0 192.168.210.10 192.168.210.254
  network_contract ken-deploy-net virbr-deploy 192.168.211.1 255.255.255.0 192.168.211.10 192.168.211.254
  validate_network_conflicts ken-ci-net virbr-ci 192.168.210.0/24
  validate_network_conflicts ken-deploy-net virbr-deploy 192.168.211.0/24
}

read_only_safety_gate() {
  validate_storage_path_plan
  validate_network_plan
}

snapshot_protected_state() {
  local destination="$1" unit container_id
  : >"${destination}/services"
  for unit in "${GROK_UNITS[@]}" elasticsearch.service docker.service; do
    systemctl show "${unit}" --property=Id --property=LoadState --property=ActiveState --property=SubState --property=MainPID >>"${destination}/services" 2>/dev/null || true
  done
  sort -o "${destination}/services" "${destination}/services"
  : >"${destination}/docker"
  while IFS= read -r container_id; do
    [[ -n "${container_id}" ]] || continue
    docker inspect --format '{{.Id}}|{{.Name}}|{{.Config.Image}}|{{.State.Status}}|{{.State.StartedAt}}|{{.RestartCount}}|{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "${container_id}" >>"${destination}/docker"
  done < <(docker ps -q 2>/dev/null | sort)
  sort -o "${destination}/docker" "${destination}/docker"
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
  local current_target info state autostart persistent
  if virsh pool-info "${POOL_NAME}" >/dev/null 2>&1; then
    info="$(virsh pool-info "${POOL_NAME}")"
    persistent="$(awk -F: '/^Persistent:/ { gsub(/[[:space:]]/, "", $2); print tolower($2) }' <<<"${info}")"
    [[ "${persistent}" == yes ]] || die "existing ${POOL_NAME} pool is transient and cannot be converged safely"
    current_target="$(virsh pool-dumpxml "${POOL_NAME}" | sed -n 's:.*<path>\(.*\)</path>.*:\1:p')"
    [[ "${current_target}" == "${IMAGE_ROOT}" ]] || die "existing ${POOL_NAME} pool target is ${current_target}, expected ${IMAGE_ROOT}"
  else
    virsh pool-define-as --name "${POOL_NAME}" --type dir --target "${IMAGE_ROOT}" >/dev/null
    info="$(virsh pool-info "${POOL_NAME}")"
  fi
  autostart="$(awk -F: '/^Autostart:/ { gsub(/[[:space:]]/, "", $2); print tolower($2) }' <<<"${info}")"
  [[ "${autostart}" == yes ]] || virsh pool-autostart "${POOL_NAME}" >/dev/null
  state="$(awk -F: '/^State:/ { gsub(/[[:space:]]/, "", $2); print tolower($2) }' <<<"${info}")"
  if [[ "${state}" != running ]]; then
    virsh pool-start "${POOL_NAME}" >/dev/null
  fi
}

ensure_network() {
  local name="$1" bridge="$2" address="$3" start="$4" end="$5" xml info autostart active
  xml="${SEED_ROOT}/${name}.xml"
  if virsh net-info "${name}" >/dev/null 2>&1; then
    network_contract "${name}" "${bridge}" "${address}" 255.255.255.0 "${start}" "${end}"
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
  info="$(virsh net-info "${name}")"
  autostart="$(awk -F: '/^Autostart:/ { gsub(/[[:space:]]/, "", $2); print tolower($2) }' <<<"${info}")"
  [[ "${autostart}" == yes ]] || virsh net-autostart "${name}" >/dev/null
  active="$(awk -F: '/^Active:/ { gsub(/[[:space:]]/, "", $2); print tolower($2) }' <<<"${info}")"
  if [[ "${active}" != yes ]]; then
    virsh net-start "${name}" >/dev/null
  fi
}

state_value() {
  local file="$1" key="$2"
  awk -F= -v key="${key}" '$1 == key { print substr($0, length(key) + 2); exit }' "${file}"
}

capture_pool_state() {
  local destination="$1" info state autostart persistent target
  if virsh pool-info "${POOL_NAME}" >/dev/null 2>&1; then
    info="$(virsh pool-info "${POOL_NAME}")"
    state="$(awk -F: '/^State:/ { gsub(/[[:space:]]/, "", $2); print tolower($2) }' <<<"${info}")"
    autostart="$(awk -F: '/^Autostart:/ { gsub(/[[:space:]]/, "", $2); print tolower($2) }' <<<"${info}")"
    persistent="$(awk -F: '/^Persistent:/ { gsub(/[[:space:]]/, "", $2); print tolower($2) }' <<<"${info}")"
    target="$(virsh pool-dumpxml "${POOL_NAME}" | sed -n 's:.*<path>\(.*\)</path>.*:\1:p')"
    virsh pool-dumpxml "${POOL_NAME}" >"${destination}.xml"
    cat >"${destination}" <<EOF
EXISTED=1
ACTIVE=$([[ "${state}" == running ]] && echo 1 || echo 0)
AUTOSTART=$([[ "${autostart}" == yes ]] && echo 1 || echo 0)
PERSISTENT=$([[ "${persistent}" == yes ]] && echo 1 || echo 0)
TARGET=${target}
EOF
  else
    cat >"${destination}" <<EOF
EXISTED=0
ACTIVE=0
AUTOSTART=0
PERSISTENT=0
TARGET=${IMAGE_ROOT}
EOF
  fi
}

capture_network_state() {
  local name="$1" destination="$2" info active autostart persistent
  if virsh net-info "${name}" >/dev/null 2>&1; then
    info="$(virsh net-info "${name}")"
    active="$(awk -F: '/^Active:/ { gsub(/[[:space:]]/, "", $2); print tolower($2) }' <<<"${info}")"
    autostart="$(awk -F: '/^Autostart:/ { gsub(/[[:space:]]/, "", $2); print tolower($2) }' <<<"${info}")"
    persistent="$(awk -F: '/^Persistent:/ { gsub(/[[:space:]]/, "", $2); print tolower($2) }' <<<"${info}")"
    virsh net-dumpxml "${name}" >"${destination}.xml"
    cat >"${destination}" <<EOF
EXISTED=1
ACTIVE=$([[ "${active}" == yes ]] && echo 1 || echo 0)
AUTOSTART=$([[ "${autostart}" == yes ]] && echo 1 || echo 0)
PERSISTENT=$([[ "${persistent}" == yes ]] && echo 1 || echo 0)
EOF
  else
    cat >"${destination}" <<'EOF'
EXISTED=0
ACTIVE=0
AUTOSTART=0
PERSISTENT=0
EOF
  fi
}

capture_resource_state() {
  local destination="$1"
  capture_pool_state "${destination}/pool-ken-actions.state"
  capture_network_state ken-ci-net "${destination}/net-ken-ci-net.state"
  capture_network_state ken-deploy-net "${destination}/net-ken-deploy-net.state"
}

restore_pool_state() {
  local file="$1" existed active autostart current_info current_state current_autostart failed=0
  existed="$(state_value "${file}" EXISTED)"
  active="$(state_value "${file}" ACTIVE)"
  autostart="$(state_value "${file}" AUTOSTART)"
  if [[ ! "${existed}" =~ ^[01]$ || ! "${active}" =~ ^[01]$ || ! "${autostart}" =~ ^[01]$ ]]; then
    echo "ROLLBACK_ERROR=pool:${POOL_NAME}:recorded state is invalid" >&2
    return 1
  fi
  if [[ "${existed}" == 0 ]]; then
    if current_info="$(virsh pool-info "${POOL_NAME}" 2>/dev/null)"; then
      current_state="$(awk -F: '/^State:/ { gsub(/[[:space:]]/, "", $2); print tolower($2) }' <<<"${current_info}")"
      if [[ "${current_state}" == running ]] && ! virsh pool-destroy "${POOL_NAME}" >/dev/null; then
        echo "ROLLBACK_ERROR=pool:${POOL_NAME}:pool-destroy failed" >&2
        failed=1
      fi
      if ! virsh pool-undefine "${POOL_NAME}" >/dev/null; then
        echo "ROLLBACK_ERROR=pool:${POOL_NAME}:pool-undefine failed" >&2
        failed=1
      fi
    fi
    if virsh pool-info "${POOL_NAME}" >/dev/null 2>&1; then
      echo "ROLLBACK_ERROR=pool:${POOL_NAME}:expected resource to be absent" >&2
      failed=1
    fi
    return "${failed}"
  fi
  if ! current_info="$(virsh pool-info "${POOL_NAME}" 2>/dev/null)"; then
    echo "ROLLBACK_ERROR=pool:${POOL_NAME}:preexisting resource is missing" >&2
    return 1
  fi
  current_state="$(awk -F: '/^State:/ { gsub(/[[:space:]]/, "", $2); print tolower($2) }' <<<"${current_info}")"
  if [[ "${active}" == 1 && "${current_state}" != running ]]; then
    if ! virsh pool-start "${POOL_NAME}" >/dev/null; then
      echo "ROLLBACK_ERROR=pool:${POOL_NAME}:pool-start failed" >&2
      failed=1
    fi
  elif [[ "${active}" == 0 && "${current_state}" == running ]]; then
    if ! virsh pool-destroy "${POOL_NAME}" >/dev/null; then
      echo "ROLLBACK_ERROR=pool:${POOL_NAME}:pool-destroy failed" >&2
      failed=1
    fi
  fi
  if [[ "${autostart}" == 1 ]]; then
    if ! virsh pool-autostart "${POOL_NAME}" >/dev/null; then
      echo "ROLLBACK_ERROR=pool:${POOL_NAME}:pool-autostart failed" >&2
      failed=1
    fi
  else
    if ! virsh pool-autostart "${POOL_NAME}" --disable >/dev/null; then
      echo "ROLLBACK_ERROR=pool:${POOL_NAME}:pool-autostart disable failed" >&2
      failed=1
    fi
  fi
  if ! current_info="$(virsh pool-info "${POOL_NAME}" 2>/dev/null)"; then
    echo "ROLLBACK_ERROR=pool:${POOL_NAME}:resource disappeared during restore" >&2
    return 1
  fi
  current_state="$(awk -F: '/^State:/ { gsub(/[[:space:]]/, "", $2); print tolower($2) }' <<<"${current_info}")"
  current_autostart="$(awk -F: '/^Autostart:/ { gsub(/[[:space:]]/, "", $2); print tolower($2) }' <<<"${current_info}")"
  if [[ ( "${active}" == 1 && "${current_state}" != running ) || ( "${active}" == 0 && "${current_state}" == running ) ]]; then
    echo "ROLLBACK_ERROR=pool:${POOL_NAME}:active-state verification failed" >&2
    failed=1
  fi
  if [[ ( "${autostart}" == 1 && "${current_autostart}" != yes ) || ( "${autostart}" == 0 && "${current_autostart}" != no ) ]]; then
    echo "ROLLBACK_ERROR=pool:${POOL_NAME}:autostart verification failed" >&2
    failed=1
  fi
  return "${failed}"
}

restore_network_state() {
  local name="$1" file="$2" existed active autostart current_info current_active current_autostart failed=0
  existed="$(state_value "${file}" EXISTED)"
  active="$(state_value "${file}" ACTIVE)"
  autostart="$(state_value "${file}" AUTOSTART)"
  if [[ ! "${existed}" =~ ^[01]$ || ! "${active}" =~ ^[01]$ || ! "${autostart}" =~ ^[01]$ ]]; then
    echo "ROLLBACK_ERROR=network:${name}:recorded state is invalid" >&2
    return 1
  fi
  if [[ "${existed}" == 0 ]]; then
    if current_info="$(virsh net-info "${name}" 2>/dev/null)"; then
      current_active="$(awk -F: '/^Active:/ { gsub(/[[:space:]]/, "", $2); print tolower($2) }' <<<"${current_info}")"
      if [[ "${current_active}" == yes ]] && ! virsh net-destroy "${name}" >/dev/null; then
        echo "ROLLBACK_ERROR=network:${name}:net-destroy failed" >&2
        failed=1
      fi
      if ! virsh net-undefine "${name}" >/dev/null; then
        echo "ROLLBACK_ERROR=network:${name}:net-undefine failed" >&2
        failed=1
      fi
    fi
    if virsh net-info "${name}" >/dev/null 2>&1; then
      echo "ROLLBACK_ERROR=network:${name}:expected resource to be absent" >&2
      failed=1
    fi
    return "${failed}"
  fi
  if ! current_info="$(virsh net-info "${name}" 2>/dev/null)"; then
    echo "ROLLBACK_ERROR=network:${name}:preexisting resource is missing" >&2
    return 1
  fi
  current_active="$(awk -F: '/^Active:/ { gsub(/[[:space:]]/, "", $2); print tolower($2) }' <<<"${current_info}")"
  if [[ "${active}" == 1 && "${current_active}" != yes ]]; then
    if ! virsh net-start "${name}" >/dev/null; then
      echo "ROLLBACK_ERROR=network:${name}:net-start failed" >&2
      failed=1
    fi
  elif [[ "${active}" == 0 && "${current_active}" == yes ]]; then
    if ! virsh net-destroy "${name}" >/dev/null; then
      echo "ROLLBACK_ERROR=network:${name}:net-destroy failed" >&2
      failed=1
    fi
  fi
  if [[ "${autostart}" == 1 ]]; then
    if ! virsh net-autostart "${name}" >/dev/null; then
      echo "ROLLBACK_ERROR=network:${name}:net-autostart failed" >&2
      failed=1
    fi
  else
    if ! virsh net-autostart "${name}" --disable >/dev/null; then
      echo "ROLLBACK_ERROR=network:${name}:net-autostart disable failed" >&2
      failed=1
    fi
  fi
  if ! current_info="$(virsh net-info "${name}" 2>/dev/null)"; then
    echo "ROLLBACK_ERROR=network:${name}:resource disappeared during restore" >&2
    return 1
  fi
  current_active="$(awk -F: '/^Active:/ { gsub(/[[:space:]]/, "", $2); print tolower($2) }' <<<"${current_info}")"
  current_autostart="$(awk -F: '/^Autostart:/ { gsub(/[[:space:]]/, "", $2); print tolower($2) }' <<<"${current_info}")"
  if [[ ( "${active}" == 1 && "${current_active}" != yes ) || ( "${active}" == 0 && "${current_active}" != no ) ]]; then
    echo "ROLLBACK_ERROR=network:${name}:active-state verification failed" >&2
    failed=1
  fi
  if [[ ( "${autostart}" == 1 && "${current_autostart}" != yes ) || ( "${autostart}" == 0 && "${current_autostart}" != no ) ]]; then
    echo "ROLLBACK_ERROR=network:${name}:autostart verification failed" >&2
    failed=1
  fi
  return "${failed}"
}

restore_resource_state() {
  local destination="$1" failed=0
  if ! restore_network_state ken-deploy-net "${destination}/net-ken-deploy-net.state"; then
    failed=1
  fi
  if ! restore_network_state ken-ci-net "${destination}/net-ken-ci-net.state"; then
    failed=1
  fi
  if ! restore_pool_state "${destination}/pool-ken-actions.state"; then
    failed=1
  fi
  return "${failed}"
}

validate_state_directory() {
  local destination="$1" canonical parent
  [[ -d "${destination}" && ! -L "${destination}" ]] || die "rollback state directory is missing or is a symlink: ${destination}"
  canonical="$(readlink -e -- "${destination}")"
  parent="$(readlink -e -- "${STATE_PARENT}")"
  [[ "${canonical}" == "${parent}"/ken-actions-host.* ]] || die "rollback state directory is outside ${STATE_PARENT}"
  for file in pool-ken-actions.state net-ken-ci-net.state net-ken-deploy-net.state; do
    [[ -f "${canonical}/${file}" && ! -L "${canonical}/${file}" ]] || die "rollback state is incomplete: ${file}"
  done
}

report_resource_change() {
  local kind="$1" name="$2" file="$3" info active_after autostart_after existed active_before autostart_before
  existed="$(state_value "${file}" EXISTED)"
  active_before="$(state_value "${file}" ACTIVE)"
  autostart_before="$(state_value "${file}" AUTOSTART)"
  if [[ "${kind}" == pool ]]; then
    info="$(virsh pool-info "${name}")"
    [[ "$(awk -F: '/^State:/ { gsub(/[[:space:]]/, "", $2); print tolower($2) }' <<<"${info}")" == running ]] && active_after=1 || active_after=0
  else
    info="$(virsh net-info "${name}")"
    [[ "$(awk -F: '/^Active:/ { gsub(/[[:space:]]/, "", $2); print tolower($2) }' <<<"${info}")" == yes ]] && active_after=1 || active_after=0
  fi
  [[ "$(awk -F: '/^Autostart:/ { gsub(/[[:space:]]/, "", $2); print tolower($2) }' <<<"${info}")" == yes ]] && autostart_after=1 || autostart_after=0
  printf 'RESOURCE_CHANGE=%s:%s:created=%s:active_changed=%s:autostart_changed=%s\n' \
    "${kind}" "${name}" "$((1 - existed))" "$((active_before != active_after))" "$((autostart_before != autostart_after))"
}

phase="${1:-}"
case "${phase}" in
  preflight)
    emit_metrics
    read_only_safety_gate
    write_diagnostics
    ;;
  apply)
    preflight_gate
    read_only_safety_gate
    state_root="$(mktemp -d "${STATE_PARENT}/ken-actions-host.XXXXXX")"
    chmod 0700 "${state_root}"
    mkdir "${state_root}/before" "${state_root}/after"
    snapshot_protected_state "${state_root}/before"

    export DEBIAN_FRONTEND=noninteractive
    export NEEDRESTART_MODE=l
    apt-get update
    apt-get install -y --no-install-recommends "${PACKAGES[@]}"
    (( $(root_free_bytes) >= MIN_ROOT_AFTER_BYTES )) || die "root filesystem fell below 20 GiB after package installation"
    validate_network_plan
    capture_resource_state "${state_root}"
    rollback_on_failure() {
      local status=$?
      trap - EXIT
      if (( status != 0 )); then
        if restore_resource_state "${state_root}"; then
          echo 'AUTO_ROLLBACK_STATUS=ok' >&2
        else
          echo "AUTO_ROLLBACK_STATUS=failed; state retained at ${state_root}" >&2
        fi
      fi
      exit "${status}"
    }
    trap rollback_on_failure EXIT
    systemctl enable --now libvirtd
    validate_network_plan
    install -d -m 0755 "${STORAGE_ROOT}" "${IMAGE_ROOT}" "${SEED_ROOT}"
    verify_storage_directories
    ensure_pool
    ensure_network ken-ci-net virbr-ci 192.168.210.1 192.168.210.10 192.168.210.254
    ensure_network ken-deploy-net virbr-deploy 192.168.211.1 192.168.211.10 192.168.211.254

    (( $(data_free_bytes) >= MIN_DATA_BYTES )) || die "${DATA_ROOT} fell below 850 GiB during host provisioning"
    (( $(memory_available_bytes) >= MIN_MEMORY_BEFORE_BYTES )) || die "host MemAvailable fell below 128 GiB during host provisioning"
    systemctl is-active --quiet libvirtd || die "libvirtd is not active"
    virsh nodeinfo >/dev/null || die "virsh nodeinfo failed"
    virsh net-info default >/dev/null || die "libvirt default network is not readable"
    snapshot_protected_state "${state_root}/after"
    assert_preserved "${state_root}/before" "${state_root}/after" || die "protected host state changed"
    [[ "$(grok_total)" == "${EXPECTED_GROK_RUNNERS}" && "$(grok_active)" == "${EXPECTED_GROK_RUNNERS}" ]] || die "Grok runners changed during provisioning"

    trap - EXIT
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
    printf 'ROLLBACK_STATE_DIR=%s\n' "${state_root}"
    report_resource_change pool "${POOL_NAME}" "${state_root}/pool-ken-actions.state"
    report_resource_change network ken-ci-net "${state_root}/net-ken-ci-net.state"
    report_resource_change network ken-deploy-net "${state_root}/net-ken-deploy-net.state"
    echo 'APPLY_STATUS=ok'
    ;;
  rollback)
    state_root="${2:-}"
    validate_state_directory "${state_root}"
    if ! restore_resource_state "${state_root}"; then
      die "rollback failed; state retained at ${state_root}"
    fi
    echo 'ROLLBACK_STATUS=ok'
    ;;
  *)
    die "unknown phase: ${phase}"
    ;;
esac
REMOTE

run_remote() {
  local target="$1" phase="$2" argument="${3:-}"
  printf '%s\n' "${REMOTE_SCRIPT}" | "${SSH_BIN}" \
    -o BatchMode=yes \
    -o StrictHostKeyChecking=yes \
    -o ConnectTimeout=15 \
    "${target}" bash -s -- "${phase}" "${argument}"
}

dry_run=0
rollback_state=''
if [[ "${1:-}" == "--dry-run" ]]; then
  dry_run=1
  shift
elif [[ "${1:-}" == "--rollback" ]]; then
  [[ $# -ge 2 ]] || die "--rollback requires a state directory"
  rollback_state="$2"
  shift 2
fi
[[ $# == 1 ]] || {
  usage >&2
  exit 2
}
target="$1"
[[ "${target}" == "${APPROVED_TARGET}" ]] || die "target must be ${APPROVED_TARGET}"

if [[ -n "${rollback_state}" ]]; then
  rollback_report="$(run_remote "${target}" rollback "${rollback_state}")"
  grep -Fxq ROLLBACK_STATUS=ok <<<"${rollback_report}" || die "rollback readback is incomplete"
  printf 'Rollback restored the recorded libvirt resource state from %s.\n' "${rollback_state}"
  exit 0
fi

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
[[ "${data_mount}" == "${EXPECTED_DATA_MOUNT}" ]] || die "expected a dedicated /mnt/data mount, found ${data_mount}"
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
(( memory_after >= MIN_MEMORY_BEFORE_BYTES )) || die "host MemAvailable is less than 128 GiB after apply"

rollback_state_dir="$(metric "${apply_report}" ROLLBACK_STATE_DIR)"
printf 'Rollback state: %s\n' "${rollback_state_dir}"

printf 'Host provisioning verified: root %s GiB free, /mnt/data %s GiB free, memory %s GiB available, all protected services preserved.\n' \
  "$(gib "${root_after}")" "$(gib "${data_after}")" "$(gib "${memory_after}")"
