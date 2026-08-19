#!/usr/bin/env bash

readonly KEN_ACTIONS_DEPLOY_ENDPOINTS=(
  api.github.com
  codeload.github.com
  github.com
  ghcr.io
  objects.githubusercontent.com
  pkg.actions.githubusercontent.com
  pkg-containers.githubusercontent.com
  pipelines.actions.githubusercontent.com
  raw.githubusercontent.com
  releases.githubusercontent.com
  results-receiver.actions.githubusercontent.com
  downloads.1password.com
  events.1password.com
  my.1password.com
)

validate_public_ipv4() {
  python3 - "$@" <<'PY'
import ipaddress
import sys

if len(sys.argv) == 1:
    raise SystemExit("no deployment endpoint addresses resolved")
for raw in sys.argv[1:]:
    address = ipaddress.ip_address(raw)
    if address.version != 4 or not address.is_global:
        raise SystemExit(f"deployment endpoint is not a public IPv4 address: {raw}")
PY
}

resolve_ken_actions_endpoint_ipv4() {
  local domain address sorted answer
  local -a addresses=() unique=()
  for domain in "${KEN_ACTIONS_DEPLOY_ENDPOINTS[@]}"; do
    answer="$(getent ahostsv4 "${domain}")" || {
      printf 'required endpoint did not resolve: %s\n' "${domain}" >&2
      return 1
    }
    [[ -n "${answer}" ]] || {
      printf 'required endpoint resolved no IPv4 addresses: %s\n' "${domain}" >&2
      return 1
    }
    while IFS= read -r address; do
      [[ -n "${address}" ]] && addresses+=("${address}")
    done < <(awk '{print $1}' <<<"${answer}" | sort -u)
  done
  sorted="$(printf '%s\n' "${addresses[@]}" | sed '/^$/d' | sort -u)"
  while IFS= read -r address; do
    [[ -n "${address}" ]] && unique+=("${address}")
  done <<<"${sorted}"
  validate_public_ipv4 "${unique[@]}"
  printf '%s\n' "${unique[@]}"
}

render_ken_actions_firewall() {
  local destination="$1"
  shift
  local -a addresses=("$@")
  local elements generation

  validate_public_ipv4 "${addresses[@]}"
  elements="$(IFS=', '; printf '%s' "${addresses[*]}")"
  generation="$(printf '%s\n' "${addresses[@]}" | python3 -c 'import hashlib,sys; print(hashlib.sha256(sys.stdin.buffer.read()).hexdigest())')"

  umask 077
  cat >"${destination}" <<EOF
table inet ken_actions_vms {
  comment "managed-by=ken-actions generation=${generation}"
  set ci_denied_v4 {
    type ipv4_addr
    flags interval
    elements = { 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.0.0.0/24, 192.0.2.0/24, 192.88.99.0/24, 192.168.0.0/16, 198.18.0.0/15, 198.51.100.0/24, 203.0.113.0/24, 224.0.0.0/4, 240.0.0.0/4, 167.235.8.250, 185.183.35.189 }
  }
  set deploy_https_v4 {
    type ipv4_addr
    flags interval
    elements = { ${elements} }
  }

  chain input {
    type filter hook input priority -20; policy accept;
    iifname "virbr-ci" ct state invalid drop
    iifname "virbr-deploy" ct state invalid drop
    iifname "virbr-ci" ct state established,related accept
    iifname "virbr-deploy" ct state established,related accept
    iifname "virbr-ci" udp sport 68 udp dport 67 accept
    iifname "virbr-deploy" udp sport 68 udp dport 67 accept
    iifname "virbr-ci" meta l4proto { tcp, udp } th dport 53 accept
    iifname "virbr-deploy" meta l4proto { tcp, udp } th dport 53 accept
    iifname "virbr-ci" drop
    iifname "virbr-deploy" drop
  }

  chain forward {
    type filter hook forward priority -20; policy accept;
    oifname "virbr-ci" ct state established,related accept
    oifname "virbr-ci" ct state invalid drop
    oifname "virbr-ci" ct state new drop
    oifname "virbr-ci" drop
    oifname "virbr-deploy" ct state established,related accept
    oifname "virbr-deploy" ct state invalid drop
    oifname "virbr-deploy" ct state new drop
    oifname "virbr-deploy" drop

    iifname "virbr-ci" ct state invalid drop
    iifname "virbr-ci" meta nfproto ipv6 drop
    iifname "virbr-ci" ip daddr @ci_denied_v4 drop
    iifname "virbr-ci" meta nfproto ipv4 tcp dport { 80, 443 } accept
    iifname "virbr-ci" meta nfproto ipv4 udp dport 443 accept
    iifname "virbr-ci" drop

    iifname "virbr-deploy" ct state invalid drop
    iifname "virbr-deploy" ip daddr @deploy_https_v4 tcp dport 443 accept
    iifname "virbr-deploy" ip daddr 185.183.35.189 tcp dport 22 accept
    iifname "virbr-deploy" drop
  }
}
EOF
  chmod 0600 "${destination}"
}
