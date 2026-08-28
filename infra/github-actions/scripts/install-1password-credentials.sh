#!/usr/bin/env bash
set -euo pipefail

readonly APPROVED_HOST='root@167.235.8.250'
readonly OP_BIN='/usr/local/bin/op'
readonly CLASSES=('ci' 'nonproduction' 'production')
readonly VAULTS=('Ken CI Runtime' 'Ken Deploy Nonproduction' 'Ken Deploy Production')
readonly OUTPUTS=('ken-op-ci.token' 'ken-op-nonproduction.token' 'ken-op-production.token')

die() {
  printf 'credential installation refused: %s\n' "$*" >&2
  exit 1
}

usage() {
  printf 'Usage: bash infra/github-actions/scripts/install-1password-credentials.sh --host %s --interactive-all\n' "${APPROVED_HOST}"
}

[[ $# == 3 && "$1" == --host && "$2" == "${APPROVED_HOST}" && "$3" == --interactive-all ]] || {
  usage >&2
  exit 2
}
[[ -r /dev/tty && -w /dev/tty ]] || die '/dev/tty is unavailable'

old_tty=''
current=''
cleanup() {
  if [[ -n "${old_tty}" ]]; then
    stty "${old_tty}" </dev/tty 2>/dev/null || true
  fi
  current=''
  unset current OP_SERVICE_ACCOUNT_TOKEN
}
trap cleanup EXIT HUP INT TERM

validate_scope() {
  local token="$1" expected_vault="$2" identity vaults
  [[ -x "${OP_BIN}" ]] || die 'pinned /usr/local/bin/op is unavailable'
  identity="$(env -i PATH=/usr/bin:/bin HOME=/nonexistent LANG=C.UTF-8 OP_SERVICE_ACCOUNT_TOKEN="${token}" "${OP_BIN}" whoami --format=json 2>/dev/null)" || die 'service-account identity validation failed'
  vaults="$(env -i PATH=/usr/bin:/bin HOME=/nonexistent LANG=C.UTF-8 OP_SERVICE_ACCOUNT_TOKEN="${token}" "${OP_BIN}" vault list --format=json 2>/dev/null)" || die 'service-account vault validation failed'
  python3 - "${expected_vault}" "${identity}" "${vaults}" <<'PY' >/dev/null
import json
import sys
expected, identity_raw, vaults_raw = sys.argv[1:]
identity = json.loads(identity_raw)
vaults = json.loads(vaults_raw)
if identity.get("type") not in {"SERVICE_ACCOUNT", "service_account"}:
    raise SystemExit(1)
if not isinstance(vaults, list) or len(vaults) != 1 or vaults[0].get("name") != expected:
    raise SystemExit(1)
PY
  identity=''; vaults=''
}

install_encrypted() {
  local token="$1" output="$2"
  printf '%s' "${token}" | ssh \
    -o BatchMode=yes -o ClearAllForwardings=yes -o PermitLocalCommand=no \
    -- "${APPROVED_HOST}" \
    "set -eu; umask 077; install -d -m 0700 -o root -g root /etc/credstore.encrypted; temporary=/etc/credstore.encrypted/.${output}.new; trap 'rm -f \"\$temporary\"' EXIT; systemd-creds encrypt --name=op-service-account-token - \"\$temporary\" >/dev/null; chown root:root \"\$temporary\"; chmod 0600 \"\$temporary\"; mv -f \"\$temporary\" /etc/credstore.encrypted/${output}; trap - EXIT"
}

for index in 0 1 2; do
  old_tty="$(stty -g </dev/tty)"
  stty -echo </dev/tty
  printf 'Enter the %s service-account token: ' "${CLASSES[index]}" >/dev/tty
  IFS= read -r current </dev/tty || die 'token input failed'
  printf '\n' >/dev/tty
  stty "${old_tty}" </dev/tty
  old_tty=''
  [[ -n "${current}" && ${#current} -le 4096 && "${current}" != *$'\n'* ]] || die 'token input is empty or oversized'
  validate_scope "${current}" "${VAULTS[index]}"
  install_encrypted "${current}" "${OUTPUTS[index]}"
  current=''
  unset current OP_SERVICE_ACCOUNT_TOKEN
done

printf 'Installed three encrypted class credentials; no service was enabled or restarted.\n'
