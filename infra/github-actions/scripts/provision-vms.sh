#!/usr/bin/env bash
set -euo pipefail

readonly APPROVED_TARGET="root@167.235.8.250"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SCRIPT_DIR
GA_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd -P)"
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

cat <<'EOF'
Approved VM plan:
  ken-ci: 32 vCPU, 112 GiB RAM, 750 GiB qcow2, ken-ci-net only
  ken-deploy: 4 vCPU, 12 GiB RAM, 80 GiB qcow2, ken-deploy-net only
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
