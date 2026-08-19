#!/usr/bin/env bash
set -euo pipefail

readonly APPROVED_TARGET="root@167.235.8.250"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SCRIPT_DIR
if [[ -n "${PROVISION_VMS_GA_ROOT:-}" ]]; then
  GA_ROOT="$(cd "${PROVISION_VMS_GA_ROOT}" && pwd -P)"
else
  GA_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd -P)"
fi
readonly GA_ROOT

die() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

usage() {
  cat <<'EOF'
Usage: bash infra/github-actions/scripts/provision-vms.sh [--dry-run] root@167.235.8.250
EOF
}

validate_local_contract() {
  local path
  for path in \
    "${GA_ROOT}/libvirt/ken-ci.xml" \
    "${GA_ROOT}/libvirt/ken-deploy.xml" \
    "${GA_ROOT}/cloud-init/ken-ci-user-data.yaml" \
    "${GA_ROOT}/cloud-init/ken-deploy-user-data.yaml" \
    "${GA_ROOT}/scripts/lib/vm-firewall.sh"; do
    [[ -f "${path}" && ! -L "${path}" ]] || die "required VM definition is missing or symlinked: ${path}"
  done
}

read_vm_contract() {
  local name="$1"
  python3 - "${GA_ROOT}/libvirt/${name}.xml" <<'PY'
import sys
import xml.etree.ElementTree as ET

domain = ET.parse(sys.argv[1]).getroot()
memory = domain.find("memory")
vcpu = domain.find("vcpu")
contract = domain.find("./metadata/{urn:ken-actions:v1}vm-contract")
if (
    memory is None
    or memory.attrib.get("unit") != "KiB"
    or vcpu is None
    or contract is None
    or contract.attrib.get("image-customization-network") != "disabled"
):
    raise SystemExit("invalid machine-readable VM contract")
memory_kib = int(memory.text or "0")
if memory_kib <= 0 or memory_kib % (1024 * 1024):
    raise SystemExit("VM memory must be a positive whole GiB")
disk_gib = int(contract.attrib.get("disk-capacity-gib", "0"))
if disk_gib <= 0:
    raise SystemExit("VM disk capacity must be positive")
print(f"{int(vcpu.text or '0')}|{memory_kib // (1024 * 1024)}|{disk_gib}")
PY
}

dry_run=0
if [[ "${1:-}" == --dry-run ]]; then
  dry_run=1
  shift
fi
if [[ "${1:-}" == -h || "${1:-}" == --help ]]; then
  usage
  exit 0
fi
[[ $# == 1 ]] || {
  usage >&2
  exit 2
}

target="$1"
[[ "${target}" == "${APPROVED_TARGET}" ]] || die "target must be ${APPROVED_TARGET}"

validate_local_contract

IFS='|' read -r ci_vcpu ci_memory_gib ci_disk_gib < <(read_vm_contract ken-ci)
IFS='|' read -r deploy_vcpu deploy_memory_gib deploy_disk_gib < <(read_vm_contract ken-deploy)

cat <<'EOF'
Approved VM plan:
EOF
printf '  ken-ci: %s vCPU, %s GiB RAM, %s GiB qcow2, ken-ci-net only\n' "${ci_vcpu}" "${ci_memory_gib}" "${ci_disk_gib}"
printf '  ken-deploy: %s vCPU, %s GiB RAM, %s GiB qcow2, ken-deploy-net only\n' "${deploy_vcpu}" "${deploy_memory_gib}" "${deploy_disk_gib}"
cat <<'EOF'
  image: Ubuntu 24.04 cloud image, checksum-verified and customized offline
  storage: /mnt/data/libvirt/images and /mnt/data/libvirt/seed only
  access: host-managed SSH keys; no credentials in definitions or seed templates
  isolation: guest default-deny input plus host-enforced nftables forwarding policy
EOF

if (( dry_run == 1 )); then
  echo 'No host or guest changes were requested.'
  exit 0
fi

# Live creation remains deliberately unavailable until the dedicated firewall
# service, DNS-refresh timer, and VM-start ordering unit are approved. Refuse
# locally so a caller cannot contact the host or start a guest first.
die 'live VM apply is blocked pending approval for dedicated reboot-persistent isolation services'
