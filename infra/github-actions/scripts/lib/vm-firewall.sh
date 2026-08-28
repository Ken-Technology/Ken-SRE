#!/usr/bin/env bash

readonly KEN_ACTIONS_CONTROL_PLANE_ENDPOINTS=(
  api.github.com
  github.com
  pipelines.actions.githubusercontent.com
  results-receiver.actions.githubusercontent.com
)

validate_public_ipv4() {
  python3 - "$@" <<'PY'
import ipaddress
import sys

if len(sys.argv) == 1:
    raise SystemExit("no endpoint addresses supplied")
for raw in sys.argv[1:]:
    address = ipaddress.ip_address(raw)
    if address.version != 4 or not address.is_global:
        raise SystemExit(f"endpoint is not a public IPv4 address: {raw}")
PY
}

resolve_ken_actions_endpoint_ipv4() {
  local domain address sorted answer
  local -a addresses=() unique=()
  for domain in "${KEN_ACTIONS_CONTROL_PLANE_ENDPOINTS[@]}"; do
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

render_ken_actions_numeric_generation() {
  local mode="$1" guest_class="$2" profile="$3" phase="$4" generation_file="$5" destination="$6"
  local proxy_uid="${7:-0}" now_epoch="${KEN_ACTIONS_FIREWALL_NOW_EPOCH:-$(date +%s)}"
  [[ "${destination}" == /* && -f "${generation_file}" && ! -L "${generation_file}" ]] || {
    printf 'numeric firewall generation input or destination is unsafe\n' >&2
    return 1
  }
  python3 - "${mode}" "${guest_class}" "${profile}" "${phase}" "${generation_file}" "${destination}" "${proxy_uid}" "${now_epoch}" <<'PY'
import ipaddress
import json
import re
import sys
from pathlib import Path

mode, guest_class, requested_profile, requested_phase, generation_name, destination_name, proxy_uid_raw, now_raw = sys.argv[1:]


def no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def exact(value, keys, message):
    if type(value) is not dict or set(value) != set(keys):
        raise SystemExit(message)


def exact_int(value, message):
    if type(value) is not int:
        raise SystemExit(message)
    return value


def valid_ipv4(values, message):
    if type(values) is not list or not values or len(values) != len(set(values)):
        raise SystemExit(message)
    result = []
    for raw in values:
        if type(raw) is not str:
            raise SystemExit(message)
        try:
            address = ipaddress.ip_address(raw)
        except ValueError as error:
            raise SystemExit(message) from error
        if address.version != 4 or not address.is_global:
            raise SystemExit(message)
        result.append(str(address))
    if result != sorted(result, key=ipaddress.ip_address):
        raise SystemExit(message)
    return result


path = Path(generation_name)
try:
    generation = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=no_duplicates,
                            parse_constant=lambda raw: (_ for _ in ()).throw(ValueError(raw)))
except (OSError, UnicodeError, ValueError) as error:
    raise SystemExit(f"numeric firewall generation is malformed: {error}") from error
exact(generation, {
    "schema_version", "authority", "generated_at_epoch", "expires_at_epoch",
    "refresh_interval_seconds", "profiles", "bridges", "ci_runner_egress",
    "proxy", "onepassword_endpoint_authority",
}, "numeric firewall generation schema drift")
if exact_int(generation["schema_version"], "numeric firewall generation version invalid") != 1:
    raise SystemExit("numeric firewall generation version invalid")
authority = generation["authority"]
exact(authority, {
    "plan_sha256", "runner_platform_path", "runner_platform_sha256",
    "broker_runtime_lock_path", "broker_runtime_lock_sha256",
    "op_broker_policy_path", "op_broker_policy_sha256",
    "action_transport_lock_path", "action_transport_lock_sha256",
    "firewall_endpoint_policy_sha256",
}, "numeric firewall generation authority schema drift")
for key, value in authority.items():
    if key.endswith("sha256") and (type(value) is not str or re.fullmatch(r"[0-9a-f]{64}", value) is None):
        raise SystemExit("numeric firewall generation digest invalid")
if authority["plan_sha256"] != "75715a5a3973f3ed9813e66c809d76ec1281d537afae0c08d66b02684583a658":
    raise SystemExit("numeric firewall generation plan drift")
expected_authority_paths = {
    "runner_platform_path": "inventory/runner-platform.yaml",
    "broker_runtime_lock_path": "inventory/broker-runtime.lock.yaml",
    "op_broker_policy_path": "inventory/op-broker-policy.yaml",
    "action_transport_lock_path": "inventory/action-transport.lock.yaml",
}
if any(authority[key] != value for key, value in expected_authority_paths.items()):
    raise SystemExit("numeric firewall generation authority path drift")
generated_at = exact_int(generation["generated_at_epoch"], "numeric firewall generation epoch invalid")
expires_at = exact_int(generation["expires_at_epoch"], "numeric firewall generation expiry invalid")
now = int(now_raw)
if generation["refresh_interval_seconds"] != 900 or type(generation["refresh_interval_seconds"]) is not int:
    raise SystemExit("numeric firewall generation refresh drift")
if generated_at <= 0 or expires_at - generated_at != 3600 or now < generated_at or now >= expires_at:
    raise SystemExit("numeric firewall generation is future or expired")

profiles = generation["profiles"]
if type(profiles) is not dict or not profiles:
    raise SystemExit("numeric firewall profile authority invalid")
normalized_profiles = {}
for profile, record in profiles.items():
    if type(profile) is not str or re.fullmatch(r"[a-z0-9-]+", profile) is None:
        raise SystemExit("numeric firewall profile name invalid")
    exact(record, {"guest", "bridge", "phases"}, "numeric firewall profile schema drift")
    if record["guest"] not in {"ken-ci", "ken-deploy"} or record["bridge"] not in {"virbr-ci", "virbr-deploy"}:
        raise SystemExit("numeric firewall profile placement invalid")
    if (record["guest"], record["bridge"]) not in {("ken-ci", "virbr-ci"), ("ken-deploy", "virbr-deploy")}:
        raise SystemExit("numeric firewall profile placement mismatch")
    phases = record["phases"]
    if type(phases) is not dict:
        raise SystemExit("numeric firewall phase authority invalid")
    normalized_profiles[profile] = {"guest": record["guest"], "phases": {}}
    for phase, phase_record in phases.items():
        exact(phase_record, {"uids", "activation", "routes"}, "numeric firewall phase schema drift")
        uids = phase_record["uids"]
        routes = phase_record["routes"]
        if (type(phase) is not str or re.fullmatch(r"[a-z0-9-]+", phase) is None
                or type(uids) is not list or not uids or len(uids) != len(set(uids))
                or any(type(uid) is not int or uid <= 0 for uid in uids)
                or phase_record["activation"] not in {"standing", "request-bound"}
                or type(routes) is not list):
            raise SystemExit("numeric firewall phase authority invalid")
        normalized_routes = []
        for route in routes:
            exact(route, {"endpoint_id", "fqdn", "protocol", "port", "ipv4"}, "numeric firewall route schema drift")
            if (type(route["endpoint_id"]) is not str or type(route["fqdn"]) is not str
                    or route["protocol"] != "tcp" or type(route["port"]) is not int
                    or route["port"] not in {22, 443}):
                raise SystemExit("numeric firewall route authority invalid")
            normalized_routes.append({**route, "ipv4": valid_ipv4(route["ipv4"], "numeric firewall route address invalid")})
        normalized_profiles[profile]["phases"][phase] = {
            "uids": uids,
            "activation": phase_record["activation"],
            "routes": normalized_routes,
        }

bridges = generation["bridges"]
exact(bridges, {"virbr-ci", "virbr-deploy"}, "numeric firewall bridge schema drift")
normalized_bridges = {}
for bridge, routes in bridges.items():
    if type(routes) is not list or not routes:
        raise SystemExit("numeric firewall bridge union empty")
    normalized_bridges[bridge] = []
    for route in routes:
        exact(route, {"protocol", "port", "ipv4"}, "numeric firewall bridge route schema drift")
        if route["protocol"] != "tcp" or type(route["port"]) is not int or route["port"] not in {22, 443}:
            raise SystemExit("numeric firewall bridge route invalid")
        normalized_bridges[bridge].append({**route, "ipv4": valid_ipv4(route["ipv4"], "numeric firewall bridge address invalid")})
    route_keys = [(route["protocol"], route["port"]) for route in normalized_bridges[bridge]]
    if len(route_keys) != len(set(route_keys)):
        raise SystemExit("numeric deploy bridge port authority duplicated" if bridge == "virbr-deploy" else "numeric CI bridge port authority duplicated")
if [route["port"] for route in normalized_bridges["virbr-ci"]] != [443]:
    raise SystemExit("numeric CI bridge route union drift")
if [route["port"] for route in normalized_bridges["virbr-deploy"]] != [22, 443]:
    raise SystemExit("numeric deploy bridge route union drift")

ci = generation["ci_runner_egress"]
exact(ci, {
    "guest", "bridge", "uids", "address_family", "protocol", "ports",
    "denied_endpoint_ids", "denied_networks", "proxy_access", "ipv6", "denied_ipv4",
}, "numeric CI runner egress schema drift")
if (ci["guest"] != "ken-ci" or ci["bridge"] != "virbr-ci"
        or ci["uids"] != [21001,21002,21003,21004,21005,21006,21007,21008,21011,21012]
        or any(type(uid) is not int for uid in ci["uids"])
        or ci["address_family"] != "ipv4-public-only" or ci["protocol"] != "tcp"
        or ci["ports"] != [80, 443] or any(type(port) is not int for port in ci["ports"])
        or ci["proxy_access"] != "denied" or ci["ipv6"] != "denied"):
    raise SystemExit("numeric CI runner egress boundary drift")
expected_denied_endpoint_ids = [
    "onepassword-service-account", "vexa-ssh", "vexa-public-health",
    "website-ssh", "ken-so-public-health", "getken-ai-separation",
    "frontend-deploy", "frontend-public-health",
]
if ci["denied_endpoint_ids"] != expected_denied_endpoint_ids:
    raise SystemExit("numeric CI denied endpoint authority drift")
expected_denied_networks = [
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
    "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
    "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15",
    "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
]
if ci["denied_networks"] != expected_denied_networks:
    raise SystemExit("numeric CI denied network authority drift")
ci_denied_ipv4 = valid_ipv4(ci["denied_ipv4"], "numeric CI denied endpoint address invalid")
if type(ci["denied_networks"]) is not list or not ci["denied_networks"]:
    raise SystemExit("numeric CI denied networks invalid")
for raw in ci["denied_networks"]:
    try:
        network = ipaddress.ip_network(raw, strict=True)
    except ValueError as error:
        raise SystemExit("numeric CI denied network invalid") from error
    if network.version != 4:
        raise SystemExit("numeric CI denied network invalid")

proxy = generation["proxy"]
expected_proxy = {
    "included_in_targets": False,
    "included_in_bridge_direct_unions": False,
    "listen_interface": "virbr-deploy",
    "listen_address": "192.168.211.1",
    "listen_port": 3128,
    "protocol": "tcp",
    "connect_port": 443,
    "fqdn_regex": "^[a-z0-9]{3,24}[.]blob[.]core[.]windows[.]net$",
    "ipv4_only": True,
    "public_only": True,
    "resolver_addresses": ["127.0.0.53"],
    "resolver_protocols": ["udp", "tcp"],
    "resolver_port": 53,
}
if proxy != expected_proxy:
    raise SystemExit("numeric firewall proxy boundary drift")

onepassword = generation["onepassword_endpoint_authority"]
exact(onepassword, {
    "status", "endpoint_id", "fqdn", "protocol", "port", "source_report_path",
    "source_report_sha256", "linux_canary",
}, "numeric 1Password endpoint authority schema drift")
canary = onepassword["linux_canary"]
exact(canary, {
    "status", "commands", "cache", "fresh_config", "direct_egress",
    "exact_relay_authority", "receipt_path", "receipt_sha256",
}, "numeric 1Password endpoint canary schema drift")
expected_onepassword = {
    "status": "ready",
    "endpoint_id": "onepassword-service-account",
    "fqdn": "ken-ai.1password.com",
    "protocol": "tcp",
    "port": 443,
    "source_report_path": ".superpowers/sdd/2026-08-19-org-ci-cutover/task-4-1password-endpoint-authority.md",
    "source_report_sha256": "61f5584151143932e7a4e6311852eaf3932b0225537d05c357a66ed25b58a345",
}
if any(onepassword[key] != value or type(onepassword[key]) is not type(value) for key, value in expected_onepassword.items()):
    raise SystemExit("numeric 1Password endpoint authority drift")
expected_canary = {
    "status": "ready",
    "commands": ["op-read", "op-inject", "op-run"],
    "cache": False,
    "fresh_config": True,
    "direct_egress": "denied",
    "exact_relay_authority": "ken-ai.1password.com:443",
    "receipt_path": "/var/lib/ken-actions/receipts/onepassword-linux-canary.json",
}
if any(canary[key] != value or type(canary[key]) is not type(value) for key, value in expected_canary.items()):
    raise SystemExit("numeric 1Password endpoint canary drift")
if type(canary["receipt_sha256"]) is not str or re.fullmatch(r"[0-9a-f]{64}", canary["receipt_sha256"]) is None:
    raise SystemExit("numeric 1Password endpoint canary digest invalid")

admin_address = "192.168.210.1" if guest_class == "ken-ci" else "192.168.211.1"


def ip_set(name, values, interval=False):
    flags = "\n    flags interval" if interval else ""
    return f"  set {name} {{\n    type ipv4_addr{flags}\n    elements = {{ {', '.join(values)} }}\n  }}"


def common_guest_header(comment, sets):
    return f'''destroy table inet ken_actions_guest
table inet ken_actions_guest {{
  comment "managed-by=ken-actions {comment}"
{sets}
  # KEN_ACTIONS_DYNAMIC_SETS
  chain input {{
    type filter hook input priority -20; policy drop;
    iifname "lo" accept
    ct state invalid drop
    ct state established,related accept
    udp sport 67 udp dport 68 accept
    ip saddr {admin_address} tcp dport 22 accept
  }}
  chain forward {{ type filter hook forward priority -20; policy drop; }}
  chain output {{
    type filter hook output priority -20; policy drop;
    oifname "lo" accept
    ct state invalid drop
    ct state established,related accept
    udp sport 68 udp dport 67 accept
    meta skuid 0 ip daddr {admin_address} meta l4proto {{ tcp, udp }} th dport 53 accept
'''


if mode == "guest-phase":
    if guest_class not in {"ken-ci", "ken-deploy"} or requested_profile not in normalized_profiles:
        raise SystemExit("numeric guest phase profile invalid")
    record = normalized_profiles[requested_profile]
    expected_guest = "ken-ci" if guest_class == "ken-ci" else "ken-deploy"
    if record["guest"] != expected_guest or requested_phase not in record["phases"]:
        raise SystemExit("numeric guest phase placement invalid")
    phase = record["phases"][requested_phase]
    if phase["activation"] != "request-bound":
        raise SystemExit("standing firewall phase cannot be request-bound")
    grouped = {}
    for route in phase["routes"]:
        grouped.setdefault(route["port"], set()).update(route["ipv4"])
    sets = []
    rules = []
    for port, addresses in sorted(grouped.items()):
        name = f"phase_target_{port}_v4"
        sets.append(f"  set {name} {{ type ipv4_addr; elements = {{ {', '.join(sorted(addresses, key=ipaddress.ip_address))} }} }}")
        rules.extend(f"    meta skuid {uid} ip daddr @{name} tcp dport {port} accept" for uid in phase["uids"])
    text = common_guest_header(
        f"guest={guest_class} profile={requested_profile} phase={requested_phase}", "\n".join(sets)
    ) + "\n".join(rules) + '''
    # KEN_ACTIONS_DYNAMIC_RULES
  }
}
'''
elif mode == "guest-base":
    if guest_class not in {"ken-ci", "ken-deploy"}:
        raise SystemExit("numeric guest class invalid")
    sets = []
    rules = []
    if guest_class == "ken-ci":
        sets.extend([
            ip_set("ci_denied_endpoint_v4", ci_denied_ipv4),
            ip_set("ci_denied_network_v4", ci["denied_networks"], interval=True),
        ])
        for uid in ci["uids"]:
            rules.extend([
                f"    meta skuid {uid} ip daddr {admin_address} meta l4proto {{ tcp, udp }} th dport 53 accept",
                f"    meta skuid {uid} meta nfproto ipv6 drop",
                f"    meta skuid {uid} ip daddr @ci_denied_network_v4 drop",
                f"    meta skuid {uid} ip daddr @ci_denied_endpoint_v4 drop",
                f"    meta skuid {uid} tcp dport {{ 80, 443 }} accept",
                f"    meta skuid {uid} drop",
            ])
    else:
        rules.extend([
            "    meta skuid 21013 ip daddr 192.168.211.1 tcp dport 3128 accept",
            "    meta skuid 21014 ip daddr 192.168.211.1 tcp dport 3128 accept",
        ])
    set_index = 0
    for profile, record in normalized_profiles.items():
        if record["guest"] != guest_class:
            continue
        for phase_name, phase in record["phases"].items():
            if phase["activation"] != "standing":
                continue
            for route in phase["routes"]:
                name = f"standing_{set_index}_v4"
                set_index += 1
                sets.append(ip_set(name, route["ipv4"]))
                rules.extend(f"    meta skuid {uid} ip daddr @{name} tcp dport {route['port']} accept" for uid in phase["uids"])
    text = common_guest_header(f"guest={guest_class} generation={generated_at}", "\n".join(sets)) + "\n".join(rules) + '''
    # KEN_ACTIONS_DYNAMIC_RULES
  }
}
'''
elif mode == "host":
    try:
        proxy_uid = int(proxy_uid_raw)
    except ValueError as error:
        raise SystemExit("numeric host proxy UID invalid") from error
    if proxy_uid <= 0 or str(proxy_uid) != proxy_uid_raw:
        raise SystemExit("numeric host proxy UID invalid")
    deploy_by_port = {route["port"]: route["ipv4"] for route in normalized_bridges["virbr-deploy"]}
    if set(deploy_by_port) != {22, 443}:
        raise SystemExit("numeric deploy bridge route union drift")
    sets = "\n".join([
        ip_set("ci_denied_endpoint_v4", ci_denied_ipv4),
        ip_set("denied_private_v4", ci["denied_networks"], interval=True),
        ip_set("proxy_resolver_v4", proxy["resolver_addresses"]),
        ip_set("deploy_tcp_22_v4", deploy_by_port[22]),
        ip_set("deploy_tcp_443_v4", deploy_by_port[443]),
    ])
    text = f'''destroy table inet ken_actions_vms
table inet ken_actions_vms {{
  comment "managed-by=ken-actions generation={generated_at} expires={expires_at} proxy_uid={proxy_uid}"
{sets}
  chain input {{
    type filter hook input priority -20; policy accept;
    iifname "virbr-deploy" ip daddr 192.168.211.1 tcp dport 3128 accept
    iifname "virbr-ci" ip daddr 192.168.211.1 tcp dport 3128 drop
    iifname != "virbr-deploy" ip daddr 192.168.211.1 tcp dport 3128 drop
    meta nfproto ipv6 tcp dport 3128 drop
    iifname {{ "virbr-ci", "virbr-deploy" }} ct state established,related accept
    iifname {{ "virbr-ci", "virbr-deploy" }} udp sport 68 udp dport 67 accept
    iifname {{ "virbr-ci", "virbr-deploy" }} meta l4proto {{ tcp, udp }} th dport 53 accept
    iifname {{ "virbr-ci", "virbr-deploy" }} drop
  }}
  chain forward {{
    type filter hook forward priority -20; policy accept;
    oifname {{ "virbr-ci", "virbr-deploy" }} ct state established,related accept
    oifname {{ "virbr-ci", "virbr-deploy" }} drop
    iifname "virbr-ci" meta nfproto ipv6 drop
    iifname "virbr-ci" ip daddr @denied_private_v4 drop
    iifname "virbr-ci" ip daddr @ci_denied_endpoint_v4 drop
    iifname "virbr-ci" tcp dport {{ 80, 443 }} accept
    iifname "virbr-ci" drop
    iifname "virbr-deploy" meta nfproto ipv6 drop
    iifname "virbr-deploy" ip daddr @denied_private_v4 drop
    iifname "virbr-deploy" ip daddr @deploy_tcp_22_v4 tcp dport 22 accept
    iifname "virbr-deploy" ip daddr @deploy_tcp_443_v4 tcp dport 443 accept
    iifname "virbr-deploy" drop
  }}
  chain output {{
    type filter hook output priority -20; policy accept;
    meta skuid {proxy_uid} ip daddr @proxy_resolver_v4 meta l4proto {{ tcp, udp }} th dport 53 accept
    meta skuid {proxy_uid} ip daddr @denied_private_v4 drop
    meta skuid {proxy_uid} meta nfproto ipv6 drop
    meta skuid {proxy_uid} tcp dport 443 accept
    meta skuid {proxy_uid} drop
  }}
}}
'''
else:
    raise SystemExit("numeric firewall renderer mode invalid")

destination = Path(destination_name)
destination.write_text(text, encoding="utf-8")
destination.chmod(0o600)
print(f"NUMERIC_FIREWALL_OK mode={mode} generation={generated_at}")
PY
}

render_ken_actions_host_base() {
  local destination="$1"
  shift
  local -a resolver_addresses=("$@")
  local resolver_elements generation proxy_uid
  [[ "${destination}" == /* ]] || {
    printf 'firewall destination must be absolute\n' >&2
    return 1
  }
  validate_public_ipv4 "${resolver_addresses[@]}"
  proxy_uid="${KEN_ACTIONS_PROXY_UID:-}"
  [[ "${proxy_uid}" =~ ^[0-9]+$ ]] || {
    printf 'KEN_ACTIONS_PROXY_UID must be an exact numeric UID\n' >&2
    return 1
  }
  resolver_elements="$(IFS=', '; printf '%s' "${resolver_addresses[*]}")"
  generation="$(printf '%s\n' "${resolver_addresses[@]}" | python3 -c 'import hashlib,sys; print(hashlib.sha256(sys.stdin.buffer.read()).hexdigest())')"
  umask 077
  cat >"${destination}" <<EOF
destroy table inet ken_actions_vms
table inet ken_actions_vms {
  comment "managed-by=ken-actions base-generation=${generation} readiness=blocked proxy_uid=${proxy_uid}"
  set trusted_resolver_v4 {
    type ipv4_addr
    elements = { ${resolver_elements} }
  }
  set denied_private_v4 {
    type ipv4_addr
    flags interval
    elements = { 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.0.0.0/24, 192.0.2.0/24, 192.88.99.0/24, 192.168.0.0/16, 198.18.0.0/15, 198.51.100.0/24, 203.0.113.0/24, 224.0.0.0/4, 240.0.0.0/4 }
  }
  set proxy_resolver_v4 {
    type ipv4_addr
    elements = { 127.0.0.53 }
  }

  chain input {
    type filter hook input priority -20; policy accept;
    iifname "virbr-deploy" ip daddr 192.168.211.1 tcp dport 3128 accept
    iifname "virbr-ci" ip daddr 192.168.211.1 tcp dport 3128 drop
    iifname != "virbr-deploy" ip daddr 192.168.211.1 tcp dport 3128 drop
    meta nfproto ipv6 tcp dport 3128 drop
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
    oifname { "virbr-ci", "virbr-deploy" } ct state established,related accept
    oifname { "virbr-ci", "virbr-deploy" } drop
    iifname "virbr-ci" ip daddr @denied_private_v4 drop
    iifname "virbr-ci" drop
    iifname "virbr-deploy" ip daddr @denied_private_v4 drop
    iifname "virbr-deploy" drop
  }

  chain output {
    type filter hook output priority -20; policy accept;
    meta skuid ${proxy_uid} ip daddr @proxy_resolver_v4 meta l4proto { tcp, udp } th dport 53 accept
    meta skuid ${proxy_uid} ip daddr @denied_private_v4 drop
    meta skuid ${proxy_uid} meta nfproto ipv6 drop
    meta skuid ${proxy_uid} tcp dport 443 accept
    meta skuid ${proxy_uid} drop
  }
}

EOF
  chmod 0600 "${destination}"
}

render_ken_actions_host_blocked() {
  local destination="$1" proxy_uid="$2" reason="$3"
  [[ "${destination}" == /* && "${proxy_uid}" =~ ^[0-9]+$ && "${reason}" =~ ^[a-z0-9-]+$ ]] || {
    printf 'blocked host firewall arguments are invalid\n' >&2
    return 1
  }
  umask 077
  cat >"${destination}" <<EOF
destroy table inet ken_actions_vms
table inet ken_actions_vms {
  comment "managed-by=ken-actions readiness=blocked reason=${reason} proxy_uid=${proxy_uid}"
  chain input {
    type filter hook input priority -20; policy accept;
    iifname { "virbr-ci", "virbr-deploy" } drop
  }
  chain forward {
    type filter hook forward priority -20; policy accept;
    iifname { "virbr-ci", "virbr-deploy" } drop
    oifname { "virbr-ci", "virbr-deploy" } drop
  }
  chain output {
    type filter hook output priority -20; policy accept;
    meta skuid ${proxy_uid} drop
  }
}
EOF
  chmod 0600 "${destination}"
}

render_ken_actions_guest_base() {
  local guest_class="$1" destination="$2" reason="${3:-missing-final-task6-policy-and-identities}" admin_address
  case "${guest_class}" in
    ci) admin_address=192.168.210.1 ;;
    deploy) admin_address=192.168.211.1 ;;
    *)
      printf 'unknown guest class: %s\n' "${guest_class}" >&2
      return 1
      ;;
  esac
  [[ "${destination}" == /* ]] || {
    printf 'firewall destination must be absolute\n' >&2
    return 1
  }
  umask 077
  cat >"${destination}" <<EOF
destroy table inet ken_actions_guest
table inet ken_actions_guest {
  comment "managed-by=ken-actions guest=${guest_class} blocker=${reason}"
  # KEN_ACTIONS_DYNAMIC_SETS
  chain input {
    type filter hook input priority -20; policy drop;
    iifname "lo" accept
    ct state invalid drop
    ct state established,related accept
    udp sport 67 udp dport 68 accept
    ip saddr ${admin_address} tcp dport 22 accept
  }
  chain forward {
    type filter hook forward priority -20; policy drop;
  }
  chain output {
    type filter hook output priority -20; policy drop;
    oifname "lo" accept
    ct state invalid drop
    ct state established,related accept
    udp sport 68 udp dport 67 accept
    meta skuid 0 ip daddr ${admin_address} meta l4proto { tcp, udp } th dport 53 accept
    # KEN_ACTIONS_DYNAMIC_RULES
  }
}
EOF
  chmod 0600 "${destination}"
}

render_ken_actions_guest_phase() {
  local guest_class="$1" trust_class="$2" phase="$3" destination="$4"
  local policy_file="${KEN_ACTIONS_FIREWALL_POLICY_FILE:-}"
  local runner_file="${KEN_ACTIONS_FIREWALL_RUNNER_FILE:-}"
  [[ "${destination}" == /* ]] || {
    printf 'firewall destination must be absolute\n' >&2
    return 1
  }
  case "${guest_class}:${trust_class}" in
    ci:ci|deploy:nonproduction|deploy:production) ;;
    *)
      printf 'guest class and trust class mismatch\n' >&2
      return 1
      ;;
  esac
  [[ -f "${policy_file}" && ! -L "${policy_file}" && -f "${runner_file}" && ! -L "${runner_file}" ]] || {
    printf 'missing-final-task6-policy-and-identities\n' >&2
    return 78
  }
  python3 - "${guest_class}" "${trust_class}" "${phase}" "${destination}" "${policy_file}" "${runner_file}" <<'PY'
import ipaddress
import os
import re
import socket
import sys
from pathlib import Path
from urllib.parse import urlparse

import yaml

guest_class, trust_class, phase, destination, policy_name, runner_name = sys.argv[1:]


class StrictLoader(yaml.SafeLoader):
    pass


def mapping(loader, node, deep=False):
    seen = set()
    for key_node, _ in node.value:
        key = loader.construct_object(key_node, deep=False)
        if key in seen:
            raise SystemExit(f"duplicate YAML key: {key}")
        seen.add(key)
    return yaml.SafeLoader.construct_mapping(loader, node, deep=deep)


StrictLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, mapping)


def load(name):
    path = Path(name)
    if not path.is_file() or path.is_symlink():
        raise SystemExit("unsafe firewall authority")
    return yaml.load(path.read_text(encoding="utf-8"), Loader=StrictLoader)


policy = load(policy_name)
platform = load(runner_name)
if type(policy) is not dict or type(policy.get("schema_version")) is not int or policy["schema_version"] != 1:
    raise SystemExit("unsupported firewall policy schema")
if type(platform) is not dict or type(platform.get("schema_version")) is not int or platform["schema_version"] != 2:
    raise SystemExit("unsupported runner platform schema")

enabled = [entry for entry in platform.get("runners", []) if entry.get("enabled") is True]
runner_uids = {
    "ci": [entry["uid"] for entry in enabled if entry.get("vm") == "ken-ci"],
    "nonproduction": [entry["uid"] for entry in enabled if entry.get("class") == "nonproduction"],
    "production": [entry["uid"] for entry in enabled if entry.get("class") == "production"],
}

if any(type(uid) is not int or uid <= 0 for values in runner_uids.values() for uid in values):
    raise SystemExit("runner UID authority invalid")
classes = policy.get("classes")
if type(classes) is not dict or set(classes) != {"ci", "nonproduction", "production"}:
    raise SystemExit("firewall class authority invalid")
broker_uid = (classes.get(trust_class) or {}).get("broker_network_uid")
if type(broker_uid) is not int or broker_uid <= 0:
    raise SystemExit("broker UID authority invalid")

actions = policy.get("actions")
if type(actions) is not list:
    raise SystemExit("firewall action authority invalid")
frontend = next((item for item in actions if item.get("action_id") == "ken-frontend-production-release"), None)
build = (frontend or {}).get("production_build") or {}
phase_contract = {
    "control": (runner_uids[trust_class], "github-control", ["github.com", "api.github.com", "pipelines.actions.githubusercontent.com", "results-receiver.actions.githubusercontent.com"]),
    "broker": ([broker_uid], "broker-control", [urlparse(policy.get("issuer", "")).hostname, urlparse(policy.get("jwks_uri", "")).hostname, "api.github.com", "1password.com"]),
}
if trust_class == "production":
    if phase in {"build-offline", "dependency-read", "posthog-upload", "ghcr-write", "deploy-target"}:
        if type(frontend) is not dict or frontend.get("enabled") is not True or frontend.get("blocked_reason_code") is not None or frontend.get("deferred_bindings") != []:
            raise SystemExit("firewall action disabled")
        if not re.fullmatch(r"[0-9a-f]{64}", str(build.get("phase_transport_sha256") or "")):
            raise SystemExit("firewall phase transport authority missing")
        for name, key, profile, hosts in (
            ("build-offline", "builder_uid", "offline-no-network", []),
            ("dependency-read", "builder_uid", "dependency-read", ["nodejs.org", "registry.npmjs.org"]),
            ("posthog-upload", "uploader_uid", "posthog-upload", [urlparse(str(build.get("source_map_endpoint", ""))).hostname]),
        ):
            uid = build.get(key)
            if type(uid) is int and uid > 0 and type(hosts) is list and all(type(host) is str and host for host in hosts):
                phase_contract[name] = ([uid], profile, hosts)
        ghcr_hosts = build.get("ghcr_hosts", [])
        if type(ghcr_hosts) is list and all(type(host) is str and host for host in ghcr_hosts):
            phase_contract["ghcr-write"] = ([broker_uid], "ghcr-write", ghcr_hosts)
        if phase == "deploy-target":
            raise SystemExit("firewall deploy target authority unavailable")
if phase not in phase_contract:
    raise SystemExit("unsupported firewall phase")
uids, profile, hosts = phase_contract[phase]
if not uids:
    raise SystemExit("firewall phase has no authorized UID")
if len(uids) != len(set(uids)):
    raise SystemExit("duplicate firewall UID authority")
if phase == "build-offline" and hosts:
    raise SystemExit("offline build phase gained network")

test_addresses = {}
if os.environ.get("KEN_ACTIONS_FIREWALL_COMMAND_TEST") == "1":
    for item in os.environ.get("KEN_ACTIONS_FIREWALL_TEST_IPS", "").split(","):
        if not item:
            continue
        host, separator, address = item.partition("=")
        if not separator or host in test_addresses:
            raise SystemExit("firewall test address authority invalid")
        test_addresses[host] = [address]

addresses = []
for host in sorted(set(hosts)):
    if not host:
        raise SystemExit("firewall target host invalid")
    if test_addresses:
        values = test_addresses.get(host, [])
    else:
        values = sorted({item[4][0] for item in socket.getaddrinfo(host, 443, socket.AF_INET, socket.SOCK_STREAM)})
    if not values:
        raise SystemExit(f"firewall target did not resolve: {host}")
    for raw in values:
        address = ipaddress.ip_address(raw)
        if address.version != 4 or not address.is_global:
            raise SystemExit(f"firewall target is not public IPv4: {host}")
        addresses.append(str(address))
addresses = sorted(set(addresses), key=ipaddress.ip_address)

uid_values = sorted(uids)
uid_set = ", ".join(str(uid) for uid in uid_values)
address_set = ", ".join(addresses)
network_rules = ""
if addresses:
    network_rules = f'''  set phase_target_v4 {{ type ipv4_addr; elements = {{ {address_set} }} }}
'''
uid_rules = "\n".join(f"    meta skuid {uid} ip daddr @phase_target_v4 tcp dport 443 accept" for uid in uid_values) if addresses else ""
host_comment = ",".join(hosts) if hosts else "none"
admin_address = "192.168.210.1" if guest_class == "ci" else "192.168.211.1"
text = f'''destroy table inet ken_actions_guest
table inet ken_actions_guest {{
  comment "managed-by=ken-actions guest={guest_class} trust={trust_class} phase={phase} uid={uid_set} hosts={host_comment}"
  set authorized_uids {{ type uid; elements = {{ {uid_set} }} }}
{network_rules}  chain input {{
    type filter hook input priority -20; policy drop;
    iifname "lo" accept
    ct state invalid drop
    ct state established,related accept
    udp sport 67 udp dport 68 accept
    ip saddr {admin_address} tcp dport 22 accept
  }}
  chain forward {{ type filter hook forward priority -20; policy drop; }}
  chain output {{
    type filter hook output priority -20; policy drop;
    oifname "lo" accept
    ct state invalid drop
    ct state established,related accept
    udp sport 68 udp dport 67 accept
{uid_rules}
  }}
}}
'''
Path(destination).write_text(text, encoding="utf-8")
Path(destination).chmod(0o600)
print(f"phase={phase} uid={uid_set} profile={profile}")
PY
}

render_ken_actions_guest_request_union() {
  local guest_class="$1" active_request_dir="$2" base_file="$3" destination="$4"
  local file request_id profile phase trust_class fragment fragment_root request_record status
  local -a files=() fragment_args=()
  [[ -d "${active_request_dir}" && ! -L "${active_request_dir}" && -f "${base_file}" && ! -L "${base_file}" ]] || {
    printf 'guest firewall union authority is missing or unsafe\n' >&2
    return 1
  }
  if ! compgen -G "${active_request_dir}/*.json" >/dev/null; then
    install -m 0600 "${base_file}" "${destination}"
    return 0
  fi
  shopt -s nullglob
  files=("${active_request_dir}"/*.json)
  shopt -u nullglob
  python3 - "${files[@]}" <<'PY'
import json
import sys
from pathlib import Path

profiles = []
for raw in sys.argv[1:]:
    try:
        value = json.loads(Path(raw).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as error:
        raise SystemExit(f"active phase request is malformed: {error}") from error
    profiles.append(value.get("profile") if type(value) is dict else None)
if "frontend-production-digest-deploy" in profiles and len(profiles) != 1:
    raise SystemExit("frontend firewall phases are exclusive")
PY
  ((${#files[@]} <= 2)) || {
    printf 'guest firewall active request cardinality exceeded\n' >&2
    return 1
  }
  fragment_root="$(mktemp -d "${KEN_ACTIONS_FIREWALL_RUNTIME_ROOT:-/run/ken-actions-firewall}/guest-union.XXXXXX")"
  for file in "${files[@]}"; do
    if ! request_record="$(python3 - "${file}" <<'PY'
import json
import re
import sys
from pathlib import Path

path = Path(sys.argv[1])
try:
    value = json.loads(path.read_text(encoding="utf-8"))
except (OSError, UnicodeError, ValueError) as error:
    raise SystemExit(f"active phase request is malformed: {error}") from error
if type(value) is not dict or set(value) != {"schema_version", "request_id", "profile", "phase"}:
    raise SystemExit("active phase request schema drift")
request_id = value["request_id"]
if (type(value["schema_version"]) is not int or value["schema_version"] != 1
        or type(request_id) is not str or re.fullmatch(r"[0-9a-f]{64}", request_id) is None
        or path.name != f"{request_id}.json"
        or type(value["profile"]) is not str or re.fullmatch(r"[a-z0-9-]+", value["profile"]) is None
        or type(value["phase"]) is not str or re.fullmatch(r"[a-z0-9-]+", value["phase"]) is None):
    raise SystemExit("active phase request authority mismatch")
print(request_id, value["profile"], value["phase"], sep="\t")
PY
    )"; then
      rm -rf -- "${fragment_root}"
      return 1
    fi
    IFS=$'\t' read -r request_id profile phase <<<"${request_record}"
    validate_ken_actions_phase_request "${file}" "${request_id}" "${profile}" "${phase}" || {
      rm -rf -- "${fragment_root}"
      return 1
    }
    validate_ken_actions_phase_interface "${KEN_ACTIONS_FIREWALL_POLICY_FILE:-/etc/ken-op-broker/op-broker-policy.yaml}" "${profile}" "${phase}" || {
      rm -rf -- "${fragment_root}"
      return 1
    }
    case "${profile}" in
      github-control-ci) trust_class=ci ;;
      github-control-nonproduction) trust_class=nonproduction ;;
      github-control-production|vexa-production-fixed-target|website-production-fixed-target|beehiiv-api-fixed-target|github-ssh-ken-website-fixed-target|frontend-production-digest-deploy) trust_class=production ;;
      *) printf 'guest firewall profile authority invalid\n' >&2; rm -rf -- "${fragment_root}"; return 1 ;;
    esac
    fragment="${fragment_root}/${request_id}.nft"
    if [[ -n "${KEN_ACTIONS_FIREWALL_ENDPOINT_GENERATION_FILE:-}" ]]; then
      render_ken_actions_numeric_generation guest-phase "ken-${guest_class}" "${profile}" "${phase}" \
        "${KEN_ACTIONS_FIREWALL_ENDPOINT_GENERATION_FILE}" "${fragment}" >/dev/null
    else
      render_ken_actions_guest_phase "${guest_class}" "${trust_class}" "${phase}" "${fragment}" >/dev/null
    fi || {
      rm -rf -- "${fragment_root}"
      return 1
    }
    fragment_args+=("${request_id}" "${fragment}")
  done
  python3 - "${base_file}" "${destination}" "${fragment_args[@]}" <<'PY'
import re
import sys
from pathlib import Path

base_path, destination = map(Path, sys.argv[1:3])
arguments = sys.argv[3:]
if len(arguments) % 2:
    raise SystemExit("guest firewall fragment authority invalid")
base = base_path.read_text(encoding="utf-8")
if base.count("# KEN_ACTIONS_DYNAMIC_SETS") != 1 or base.count("# KEN_ACTIONS_DYNAMIC_RULES") != 1:
    raise SystemExit("guest firewall base injection markers invalid")
sets = []
rules = []
request_ids = []
for request_id, raw_fragment in zip(arguments[0::2], arguments[1::2]):
    if re.fullmatch(r"[0-9a-f]{64}", request_id) is None:
        raise SystemExit("guest firewall request id invalid")
    fragment = Path(raw_fragment).read_text(encoding="utf-8")
    set_matches = dict(re.findall(r"^  set (phase_target(?:_(?:22|443))?_v4) \{ type ipv4_addr; elements = \{ ([0-9., ]+) \} \}$", fragment, re.MULTILINE))
    rule_matches = re.findall(r"^    meta skuid ([0-9]+) ip daddr @(phase_target(?:_(?:22|443))?_v4) tcp dport (22|443) accept$", fragment, re.MULTILINE)
    if len(set_matches) > 2 or bool(set_matches) != bool(rule_matches) or any(name not in set_matches for _, name, _ in rule_matches):
        raise SystemExit("guest firewall phase fragment schema drift")
    request_ids.append(request_id)
    for source_name, elements in sorted(set_matches.items()):
        set_name = f"request_{request_id}_{source_name}"
        sets.append(f"  set {set_name} {{ type ipv4_addr; elements = {{ {elements} }} }}")
    for uid, source_name, port in rule_matches:
        set_name = f"request_{request_id}_{source_name}"
        rules.append(f"    meta skuid {uid} ip daddr @{set_name} tcp dport {port} accept")
marker = ",".join(request_ids)
if marker:
    base = base.replace('comment "managed-by=ken-actions ', f'comment "managed-by=ken-actions requests={marker} ', 1)
base = base.replace("  # KEN_ACTIONS_DYNAMIC_SETS", "\n".join(sets) or "  # KEN_ACTIONS_DYNAMIC_SETS")
base = base.replace("    # KEN_ACTIONS_DYNAMIC_RULES", "\n".join(rules) or "    # KEN_ACTIONS_DYNAMIC_RULES")
destination.write_text(base, encoding="utf-8")
destination.chmod(0o600)
PY
  status=$?
  rm -rf -- "${fragment_root}"
  return "${status}"
}

activate_ken_actions_firewall_generation() {
  local candidate="$1" active="$2" backup="$3" table_name="${4:-ken_actions_vms}" marker="${5:-managed-by=ken-actions}"
  local active_parent staging
  [[ -f "${candidate}" && ! -L "${candidate}" ]] || {
    printf 'candidate firewall generation is not a regular file\n' >&2
    return 1
  }
  active_parent="$(dirname "${active}")"
  [[ -d "${active_parent}" && ! -L "${active_parent}" ]] || {
    printf 'active firewall parent is unsafe\n' >&2
    return 1
  }
  python3 - "${active_parent}" "${active}" "${backup}" "${KEN_ACTIONS_FIREWALL_COMMAND_TEST:-0}" <<'PY'
import stat
import sys
from pathlib import Path

parent, active, backup = map(Path, sys.argv[1:4])
command_test = sys.argv[4]
metadata = parent.stat()
if (not parent.is_absolute() or not parent.is_dir() or parent.is_symlink()
        or stat.S_IMODE(metadata.st_mode) != 0o700
        or (metadata.st_uid != 0 and command_test != "1")):
    raise SystemExit("firewall state parent is unsafe")
for path in (active, backup):
    if path.parent != parent or (path.exists() or path.is_symlink()) and (not path.is_file() or path.is_symlink()):
        raise SystemExit("firewall state file is unsafe")
PY
  nft -c -f "${candidate}"
  staging="$(mktemp "${active_parent}/.ken-actions-firewall.XXXXXX")"
  trap 'rm -f -- "${staging}"' RETURN
  if [[ "${KEN_ACTIONS_FIREWALL_COMMAND_TEST:-0}" == 1 ]]; then
    install -m 0600 "${candidate}" "${staging}"
  else
    install -m 0600 -o root -g root "${candidate}" "${staging}"
  fi
  if [[ -f "${active}" && ! -L "${active}" ]]; then
    if [[ "${KEN_ACTIONS_FIREWALL_COMMAND_TEST:-0}" == 1 ]]; then
      install -m 0600 "${active}" "${backup}"
    else
      install -m 0600 -o root -g root "${active}" "${backup}"
    fi
  fi
  if ! nft -f "${staging}"; then
    printf 'firewall generation apply failed\n' >&2
    if [[ -f "${backup}" && ! -L "${backup}" ]]; then
      if ! nft -c -f "${backup}" || ! nft -f "${backup}" || ! nft list table inet "${table_name}" | grep -Fq 'managed-by=ken-actions'; then
        printf 'firewall last-known-good restoration failed\n' >&2
      fi
    fi
    return 1
  fi
  if ! nft list table inet "${table_name}" | grep -Fq -- "${marker}"; then
    printf 'firewall generation readback failed\n' >&2
    if [[ -f "${backup}" && ! -L "${backup}" ]]; then
      if ! nft -c -f "${backup}" || ! nft -f "${backup}" || ! nft list table inet "${table_name}" | grep -Fq 'managed-by=ken-actions'; then
        printf 'firewall last-known-good restoration failed\n' >&2
      fi
    fi
    return 1
  fi
  mv -f -- "${staging}" "${active}"
}

validate_ken_actions_phase_request() {
  local request_file="$1" request_id="$2" profile="$3" phase="$4"
  python3 - "${request_file}" "${request_id}" "${profile}" "${phase}" "${KEN_ACTIONS_FIREWALL_COMMAND_TEST:-0}" <<'PY'
import json
import os
import stat
import sys
from pathlib import Path

path, request_id, profile, phase, command_test = Path(sys.argv[1]), *sys.argv[2:]
if not path.is_file() or path.is_symlink() or not stat.S_ISREG(path.stat().st_mode):
    raise SystemExit("phase request is missing or unsafe")
metadata = path.stat()
if stat.S_IMODE(metadata.st_mode) != 0o600 or (metadata.st_uid != 0 and command_test != "1"):
    raise SystemExit("phase request ownership or mode is unsafe")
parent = path.parent
parent_metadata = parent.stat()
if (not parent.is_dir() or parent.is_symlink() or stat.S_IMODE(parent_metadata.st_mode) != 0o700
        or (parent_metadata.st_uid != 0 and command_test != "1")):
    raise SystemExit("phase request parent is unsafe")


def no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


try:
    value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=no_duplicates,
                       parse_constant=lambda raw: (_ for _ in ()).throw(ValueError(raw)))
except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as error:
    raise SystemExit(f"phase request is malformed: {error}") from error
expected = {"schema_version": 1, "request_id": request_id, "profile": profile, "phase": phase}
if value != expected or type(value.get("schema_version")) is not int:
    raise SystemExit("phase request authority mismatch")
PY
}

validate_ken_actions_phase_interface() {
  local policy_file="$1" profile="$2" phase="$3"
  python3 - "${policy_file}" "${profile}" "${phase}" <<'PY'
import sys
from pathlib import Path
import yaml


class StrictLoader(yaml.SafeLoader):
    pass


def mapping(loader, node, deep=False):
    seen = set()
    for key_node, _ in node.value:
        key = loader.construct_object(key_node, deep=False)
        if key in seen:
            raise SystemExit(f"duplicate YAML key: {key}")
        seen.add(key)
    return yaml.SafeLoader.construct_mapping(loader, node, deep=deep)


StrictLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, mapping)
path, profile, phase = Path(sys.argv[1]), sys.argv[2], sys.argv[3]
if not path.is_file() or path.is_symlink():
    raise SystemExit("unsafe firewall policy authority")
policy = yaml.load(path.read_text(encoding="utf-8"), Loader=StrictLoader)
interface = (policy or {}).get("firewall_phase_interface") or {}
if interface.get("command") != ["/usr/local/libexec/ken-actions-guest-firewall", "phase"]:
    raise SystemExit("firewall phase command authority mismatch")
if interface.get("arguments") != ["--request-id", "{request_id}", "--profile", "{network_profile}", "--phase", "{phase}", "--state", "{activate|deactivate}"]:
    raise SystemExit("firewall phase argument authority mismatch")
if interface.get("target_authority") != "policy-only" or interface.get("activation") != "root-created-request-id" or interface.get("teardown") != "mandatory-on-exit":
    raise SystemExit("firewall phase lifecycle authority mismatch")
profiles = interface.get("profiles")
if type(profiles) is not dict or profile not in profiles or type(profiles[profile]) is not list or phase not in profiles[profile]:
    raise SystemExit("firewall profile or phase is not authorized")
PY
}

recover_ken_actions_guest_firewall_transaction() {
  local state_root="$1" active_request_dir="$2" active="$3" backup="$4" journal="$5"
  local lkg_requests="${state_root}/active-requests.lkg" previous="${state_root}/.active-requests.recovery-old"
  [[ -f "${journal}" && ! -L "${journal}" && -f "${backup}" && ! -L "${backup}" && -d "${lkg_requests}" && ! -L "${lkg_requests}" ]] || {
    printf 'guest firewall interrupted transaction authority is unsafe\n' >&2
    return 1
  }
  nft -c -f "${backup}"
  nft -f "${backup}"
  nft list table inet ken_actions_guest | grep -Fq 'managed-by=ken-actions' || {
    printf 'guest firewall interrupted transaction recovery readback failed\n' >&2
    return 1
  }
  install -m 0600 "${backup}" "${active}"
  rm -rf -- "${previous}"
  if [[ -d "${active_request_dir}" && ! -L "${active_request_dir}" ]]; then
    mv -- "${active_request_dir}" "${previous}"
  fi
  cp -R -- "${lkg_requests}" "${active_request_dir}"
  chmod 0700 "${active_request_dir}"
  rm -rf -- "${previous}"
  rm -f -- "${journal}"
  find "${state_root}" -maxdepth 1 -type d -name '.active-requests.candidate.*' -exec rm -rf -- {} +
}

ken_actions_guest_firewall_transaction() (
  set -euo pipefail
  local guest_class="$1" request_file="$2" request_id="$3" profile="$4" phase="$5" state="$6"
  local runtime_root="$7" state_root="$8" base_file="$9"
  local active_request_dir="${state_root}/active-requests" lkg_requests="${state_root}/active-requests.lkg"
  local active="${state_root}/guest-active.nft" backup="${state_root}/guest-active.lkg.nft"
  local journal="${state_root}/phase-transaction.json" lock_dir="${runtime_root}/phase-transition.lock"
  local staged_requests candidate previous

  mkdir "${lock_dir}" 2>/dev/null || {
    printf 'another guest firewall transition is in progress\n' >&2
    return 1
  }
  trap 'rmdir -- "${lock_dir}" 2>/dev/null || true' EXIT
  if [[ -e "${journal}" || -L "${journal}" ]]; then
    recover_ken_actions_guest_firewall_transaction "${state_root}" "${active_request_dir}" "${active}" "${backup}" "${journal}"
  fi
  if [[ ! -e "${active}" ]]; then
    [[ -f "${base_file}" && ! -L "${base_file}" ]] || {
      printf 'guest firewall base authority is missing or unsafe\n' >&2
      return 1
    }
    install -m 0600 "${base_file}" "${active}"
  fi
  [[ -f "${active}" && ! -L "${active}" ]] || {
    printf 'guest firewall active generation is unsafe\n' >&2
    return 1
  }
  if [[ ! -e "${active_request_dir}" ]]; then
    mkdir -m 0700 "${active_request_dir}"
  fi
  [[ -d "${active_request_dir}" && ! -L "${active_request_dir}" ]] || {
    printf 'guest firewall active request state is unsafe\n' >&2
    return 1
  }
  chmod 0700 "${active_request_dir}"
  staged_requests="$(mktemp -d "${state_root}/.active-requests.candidate.XXXXXX")"
  chmod 0700 "${staged_requests}"
  shopt -s nullglob
  local current_file
  for current_file in "${active_request_dir}"/*.json; do
    [[ -f "${current_file}" && ! -L "${current_file}" ]] || {
      printf 'guest firewall active request is unsafe\n' >&2
      return 1
    }
    install -m 0600 "${current_file}" "${staged_requests}/$(basename "${current_file}")"
  done
  shopt -u nullglob
  if [[ "${state}" == activate ]]; then
    if [[ -e "${staged_requests}/${request_id}.json" ]]; then
      cmp -s -- "${request_file}" "${staged_requests}/${request_id}.json" || {
        printf 'guest firewall active request id collision\n' >&2
        return 1
      }
    else
      install -m 0600 "${request_file}" "${staged_requests}/${request_id}.json"
    fi
  else
    if [[ ! -f "${staged_requests}/${request_id}.json" || -L "${staged_requests}/${request_id}.json" ]] || \
       ! cmp -s -- "${request_file}" "${staged_requests}/${request_id}.json"; then
      printf 'guest firewall phase teardown request mismatch\n' >&2
      return 1
    fi
    rm -f -- "${staged_requests}/${request_id}.json"
  fi

  candidate="$(mktemp "${runtime_root}/guest-phase.XXXXXX")"
  render_ken_actions_guest_request_union "${guest_class}" "${staged_requests}" "${base_file}" "${candidate}" || return 1
  rm -rf -- "${lkg_requests}"
  cp -R -- "${active_request_dir}" "${lkg_requests}"
  chmod 0700 "${lkg_requests}"
  install -m 0600 "${active}" "${backup}"
  python3 - "${journal}" "${request_id}" "${profile}" "${phase}" "${state}" <<'PY'
import json
import sys
from pathlib import Path

path, request_id, profile, phase, state = Path(sys.argv[1]), *sys.argv[2:]
path.write_text(json.dumps({
    "schema_version": 1,
    "request_id": request_id,
    "profile": profile,
    "phase": phase,
    "state": state,
}, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
path.chmod(0o600)
PY
  if [[ "${KEN_ACTIONS_FIREWALL_INJECT_FAILURE:-}" == after-journal ]]; then
    printf 'injected guest firewall failure after journal\n' >&2
    return 99
  fi
  local expected_marker='managed-by=ken-actions'
  if [[ "${state}" == activate ]]; then
    expected_marker="requests="
  fi
  activate_ken_actions_firewall_generation "${candidate}" "${active}" "${backup}" ken_actions_guest "${expected_marker}" || return 1
  if [[ "${KEN_ACTIONS_FIREWALL_INJECT_FAILURE:-}" == after-apply ]]; then
    printf 'injected guest firewall failure after apply\n' >&2
    return 99
  fi
  previous="${state_root}/.active-requests.previous"
  rm -rf -- "${previous}"
  mv -- "${active_request_dir}" "${previous}"
  mv -- "${staged_requests}" "${active_request_dir}"
  rm -rf -- "${previous}"
  rm -f -- "${journal}" "${candidate}"
  if [[ "${state}" == deactivate ]]; then
    rm -f -- "${request_file}"
  fi
)

ken_actions_guest_firewall_refresh() (
  set -euo pipefail
  local runtime_root state_root base_file generation_file guest_class_file policy_file runner_file
  local resolver generation_candidate='' base_candidate='' union_candidate='' blocked_candidate='' active backup
  local generation_lkg active_request_dir journal lock_dir source=fresh resolver_ok=0 guest_class_raw guest_class expected_marker
  runtime_root="${KEN_ACTIONS_FIREWALL_RUNTIME_ROOT:-/run/ken-actions-firewall}"
  state_root="${KEN_ACTIONS_FIREWALL_STATE_ROOT:-/var/lib/ken-actions-firewall}"
  base_file="${KEN_ACTIONS_FIREWALL_BASE_FILE:-/etc/ken-actions/guest-base.nft}"
  generation_file="${KEN_ACTIONS_FIREWALL_ENDPOINT_GENERATION_FILE:-/etc/ken-actions/firewall-endpoint-generation.json}"
  guest_class_file="${KEN_ACTIONS_FIREWALL_GUEST_CLASS_FILE:-/etc/ken-actions/guest-class}"
  policy_file="${KEN_ACTIONS_FIREWALL_POLICY_FILE:-/etc/ken-op-broker/op-broker-policy.yaml}"
  runner_file="${KEN_ACTIONS_FIREWALL_RUNNER_FILE:-/etc/ken-actions/runner-platform.yaml}"
  [[ "${EUID}" == 0 || "${KEN_ACTIONS_FIREWALL_COMMAND_TEST:-0}" == 1 ]] || {
    printf 'guest firewall refresh requires root\n' >&2
    return 1
  }
  python3 - "${guest_class_file}" "${policy_file}" "${runner_file}" "${base_file}" "${generation_file}" "${KEN_ACTIONS_FIREWALL_COMMAND_TEST:-0}" <<'PY'
import stat
import sys
from pathlib import Path

guest, policy, runner, base, generation = map(Path, sys.argv[1:6])
command_test = sys.argv[6]
for path, must_exist in ((guest, True), (policy, True), (runner, True), (base, False), (generation, False)):
    if not path.is_absolute() or path.is_symlink() or (must_exist and not path.is_file()):
        raise SystemExit(f"guest firewall refresh authority path is unsafe: {path}")
    if path.exists():
        metadata = path.stat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & 0o022 or (metadata.st_uid != 0 and command_test != "1"):
            raise SystemExit("guest firewall refresh authority file is unsafe")
PY
  guest_class_raw="$(<"${guest_class_file}")"
  case "${guest_class_raw}" in
    ken-ci) guest_class=ci ;;
    ken-deploy) guest_class=deploy ;;
    *) printf 'guest firewall class authority invalid\n' >&2; return 1 ;;
  esac
  install -d -m 0700 "${runtime_root}" "${state_root}"
  active_request_dir="${state_root}/active-requests"
  install -d -m 0700 "${active_request_dir}"
  lock_dir="${runtime_root}/phase-transition.lock"
  mkdir "${lock_dir}" 2>/dev/null || {
    printf 'guest firewall transition already in progress\n' >&2
    return 1
  }
  trap 'rmdir -- "${lock_dir}" 2>/dev/null || true; rm -f -- "${generation_candidate}" "${base_candidate}" "${union_candidate}" "${blocked_candidate}"' EXIT
  active="${state_root}/guest-active.nft"
  backup="${state_root}/guest-active.lkg.nft"
  journal="${state_root}/phase-transaction.json"
  if [[ -f "${journal}" && ! -L "${journal}" ]]; then
    recover_ken_actions_guest_firewall_transaction "${state_root}" "${active_request_dir}" "${active}" "${backup}" "${journal}"
  fi
  generation_candidate="$(mktemp "${runtime_root}/endpoint-generation.XXXXXX")"
  base_candidate="$(mktemp "${runtime_root}/guest-base.XXXXXX")"
  union_candidate="$(mktemp "${runtime_root}/guest-union.XXXXXX")"
  blocked_candidate="$(mktemp "${runtime_root}/guest-blocked.XXXXXX")"
  generation_lkg="${state_root}/firewall-endpoint-generation.lkg.json"
  if [[ -n "${KEN_ACTIONS_FIREWALL_GENERATION_SOURCE:-}" ]]; then
    if [[ -f "${KEN_ACTIONS_FIREWALL_GENERATION_SOURCE}" && ! -L "${KEN_ACTIONS_FIREWALL_GENERATION_SOURCE}" ]]; then
      install -m 0600 "${KEN_ACTIONS_FIREWALL_GENERATION_SOURCE}" "${generation_candidate}"
      resolver_ok=1
    fi
  else
    resolver="${KEN_ACTIONS_FIREWALL_RESOLVER:-/usr/local/libexec/ken-actions-firewall-endpoint-resolve}"
    if "${resolver}" --resolve-firewall-endpoints \
      /etc/ken-actions/firewall-endpoint-policy.yaml \
      "${runner_file}" \
      /etc/ken-op-broker/broker-runtime.lock.yaml \
      "${policy_file}" \
      /etc/ken-actions/action-transport.lock.yaml \
      "${generation_candidate}" >/dev/null; then
      resolver_ok=1
    fi
  fi
  if ((resolver_ok != 1)) || ! render_ken_actions_numeric_generation guest-base "ken-${guest_class}" none none "${generation_candidate}" "${base_candidate}" >/dev/null; then
    source=lkg
    if [[ ! -f "${generation_lkg}" || -L "${generation_lkg}" ]] || \
       ! install -m 0600 "${generation_lkg}" "${generation_candidate}" || \
       ! render_ken_actions_numeric_generation guest-base "ken-${guest_class}" none none "${generation_candidate}" "${base_candidate}" >/dev/null; then
        render_ken_actions_guest_base "${guest_class}" "${blocked_candidate}" expired-or-missing-generation
        activate_ken_actions_firewall_generation "${blocked_candidate}" "${active}" "${backup}" ken_actions_guest managed-by=ken-actions
        if [[ "${KEN_ACTIONS_FIREWALL_COMMAND_TEST:-0}" == 1 ]]; then
          install -m 0600 "${blocked_candidate}" "${base_file}"
        else
          install -m 0600 -o root -g root "${blocked_candidate}" "${base_file}"
        fi
        printf 'guest firewall endpoint generation unavailable and LKG expired or missing\n' >&2
        return 1
    fi
  fi
  export KEN_ACTIONS_FIREWALL_ENDPOINT_GENERATION_FILE="${generation_candidate}"
  export KEN_ACTIONS_FIREWALL_POLICY_FILE="${policy_file}"
  export KEN_ACTIONS_FIREWALL_RUNNER_FILE="${runner_file}"
  render_ken_actions_guest_request_union "${guest_class}" "${active_request_dir}" "${base_candidate}" "${union_candidate}"
  if compgen -G "${active_request_dir}/*.json" >/dev/null; then expected_marker=requests=; else expected_marker=managed-by=ken-actions; fi
  activate_ken_actions_firewall_generation "${union_candidate}" "${active}" "${backup}" ken_actions_guest "${expected_marker}"
  if [[ "${KEN_ACTIONS_FIREWALL_COMMAND_TEST:-0}" == 1 ]]; then
    install -m 0600 "${generation_candidate}" "${generation_file}"
    install -m 0600 "${generation_candidate}" "${generation_lkg}"
    install -m 0600 "${base_candidate}" "${base_file}"
  else
    install -m 0600 -o root -g root "${generation_candidate}" "${generation_file}"
    install -m 0600 -o root -g root "${generation_candidate}" "${generation_lkg}"
    install -m 0600 -o root -g root "${base_candidate}" "${base_file}"
  fi
  if [[ "${source}" == fresh ]]; then
    printf 'GUEST_FIREWALL_OK source=fresh guest=ken-%s\n' "${guest_class}"
  else
    printf 'GUEST_FIREWALL_LKG_OK guest=ken-%s\n' "${guest_class}"
  fi
)

ken_actions_guest_firewall_cli() {
  local operation="${1:-}" request_id='' profile='' phase='' state=''
  local guest_class_raw guest_class trust_class request_file runtime_root request_root state_root base_file
  local active_request_dir
  shift || true
  if [[ "${operation}" == refresh ]]; then
    (($# == 0)) || {
      printf 'unsupported guest firewall argument\n' >&2
      return 64
    }
    ken_actions_guest_firewall_refresh
    return
  fi
  [[ "${operation}" == phase ]] || {
    printf 'unsupported guest firewall operation\n' >&2
    return 64
  }
  while (($#)); do
    case "$1" in
      --request-id) [[ $# -ge 2 && -z "${request_id}" ]] || return 64; request_id="$2"; shift 2 ;;
      --profile) [[ $# -ge 2 && -z "${profile}" ]] || return 64; profile="$2"; shift 2 ;;
      --phase) [[ $# -ge 2 && -z "${phase}" ]] || return 64; phase="$2"; shift 2 ;;
      --state) [[ $# -ge 2 && -z "${state}" ]] || return 64; state="$2"; shift 2 ;;
      *) printf 'unsupported guest firewall argument\n' >&2; return 64 ;;
    esac
  done
  [[ "${request_id}" =~ ^[0-9a-f]{64}$ && -n "${profile}" && -n "${phase}" && "${state}" =~ ^(activate|deactivate)$ ]] || {
    printf 'guest firewall phase arguments are invalid\n' >&2
    return 64
  }
  if [[ "${KEN_ACTIONS_FIREWALL_COMMAND_TEST:-0}" != 1 && "${EUID}" != 0 ]]; then
    printf 'guest firewall phase transition requires root\n' >&2
    return 1
  fi
  if [[ "${KEN_ACTIONS_FIREWALL_COMMAND_TEST:-0}" == 1 ]]; then
    runtime_root="${KEN_ACTIONS_FIREWALL_RUNTIME_ROOT:-/run/ken-actions-firewall}"
    request_root="${KEN_ACTIONS_FIREWALL_REQUEST_ROOT:-${runtime_root}/requests}"
    state_root="${KEN_ACTIONS_FIREWALL_STATE_ROOT:-/var/lib/ken-actions-firewall}"
    base_file="${KEN_ACTIONS_FIREWALL_BASE_FILE:-/etc/ken-actions/guest-base.nft}"
  else
    runtime_root=/run/ken-actions-firewall
    request_root=/run/ken-actions-firewall/requests
    state_root=/var/lib/ken-actions-firewall
    base_file=/etc/ken-actions/guest-base.nft
    KEN_ACTIONS_FIREWALL_POLICY_FILE=/etc/ken-op-broker/op-broker-policy.yaml
    KEN_ACTIONS_FIREWALL_RUNNER_FILE=/etc/ken-actions/runner-platform.yaml
    KEN_ACTIONS_FIREWALL_GUEST_CLASS_FILE=/etc/ken-actions/guest-class
    KEN_ACTIONS_FIREWALL_ENDPOINT_GENERATION_FILE=/etc/ken-actions/firewall-endpoint-generation.json
    export KEN_ACTIONS_FIREWALL_POLICY_FILE KEN_ACTIONS_FIREWALL_RUNNER_FILE KEN_ACTIONS_FIREWALL_GUEST_CLASS_FILE KEN_ACTIONS_FIREWALL_ENDPOINT_GENERATION_FILE
  fi
  request_file="${request_root}/${request_id}.json"
  active_request_dir="${state_root}/active-requests"
  validate_ken_actions_phase_request "${request_file}" "${request_id}" "${profile}" "${phase}" || return 1
  validate_ken_actions_phase_interface "${KEN_ACTIONS_FIREWALL_POLICY_FILE:-/etc/ken-op-broker/op-broker-policy.yaml}" "${profile}" "${phase}" || return 1
  python3 - "${KEN_ACTIONS_FIREWALL_POLICY_FILE:-/etc/ken-op-broker/op-broker-policy.yaml}" "${KEN_ACTIONS_FIREWALL_RUNNER_FILE:-/etc/ken-actions/runner-platform.yaml}" "${KEN_ACTIONS_FIREWALL_GUEST_CLASS_FILE:-/etc/ken-actions/guest-class}" "${KEN_ACTIONS_FIREWALL_ENDPOINT_GENERATION_FILE:-}" "${KEN_ACTIONS_FIREWALL_COMMAND_TEST:-0}" <<'PY'
import stat
import sys
from pathlib import Path

command_test = sys.argv[5]
for raw in sys.argv[1:5]:
    if not raw:
        continue
    path = Path(raw)
    if not path.is_absolute() or not path.is_file() or path.is_symlink():
        raise SystemExit("guest firewall authority file is unsafe")
    metadata = path.stat()
    if metadata.st_mode & 0o022 or (metadata.st_uid != 0 and command_test != "1"):
        raise SystemExit("guest firewall authority ownership or mode is unsafe")
PY
  guest_class_raw="$(<"${KEN_ACTIONS_FIREWALL_GUEST_CLASS_FILE:-/etc/ken-actions/guest-class}")"
  case "${guest_class_raw}" in
    ken-ci) guest_class=ci ;;
    ken-deploy) guest_class=deploy ;;
    *) printf 'guest firewall class authority invalid\n' >&2; return 1 ;;
  esac
  case "${profile}" in
    github-control-ci) trust_class=ci ;;
    github-control-nonproduction) trust_class=nonproduction ;;
    github-control-production|vexa-production-fixed-target|website-production-fixed-target|beehiiv-api-fixed-target|github-ssh-ken-website-fixed-target|frontend-production-digest-deploy) trust_class=production ;;
    *) printf 'guest firewall profile authority invalid\n' >&2; return 1 ;;
  esac
  case "${guest_class}:${trust_class}" in
    ci:ci|deploy:nonproduction|deploy:production) ;;
    *) printf 'guest class and trust class mismatch\n' >&2; return 1 ;;
  esac
  for root in "${runtime_root}" "${request_root}" "${state_root}"; do
    if [[ -e "${root}" || -L "${root}" ]]; then
      [[ -d "${root}" && ! -L "${root}" ]] || {
        printf 'guest firewall state directory is unsafe\n' >&2
        return 1
      }
    else
      mkdir -m 0700 "${root}"
    fi
    chmod 0700 "${root}"
  done
  ken_actions_guest_firewall_transaction "${guest_class}" "${request_file}" "${request_id}" "${profile}" "${phase}" "${state}" \
    "${runtime_root}" "${state_root}" "${base_file}" || return 1
  printf 'GUEST_FIREWALL_PHASE_OK state=%s request_id=%s profile=%s phase=%s\n' "${state}" "${request_id}" "${profile}" "${phase}"
}

# Compatibility entry point used by the earlier host test harness. It now emits
# the same fail-closed base generation rather than the retired broad web policy.
render_ken_actions_firewall() {
  render_ken_actions_host_base "$@"
}

ken_actions_host_firewall_cli() {
  local operation="${1:-}" runtime_root state_root authority_root resolver proxy_uid
  local generation_candidate rules_candidate active backup generation_lkg blocked_candidate
  local resolver_ok=0
  [[ "${operation}" == refresh ]] || {
    printf 'unsupported host firewall operation\n' >&2
    return 64
  }
  [[ "${EUID}" == 0 || "${KEN_ACTIONS_FIREWALL_COMMAND_TEST:-0}" == 1 ]] || {
    printf 'host firewall refresh requires root\n' >&2
    return 1
  }
  if [[ "${KEN_ACTIONS_FIREWALL_COMMAND_TEST:-0}" == 1 ]]; then
    runtime_root="${KEN_ACTIONS_FIREWALL_RUNTIME_ROOT:-/run/ken-actions-firewall}"
    state_root="${KEN_ACTIONS_FIREWALL_STATE_ROOT:-/var/lib/ken-actions-firewall}"
    authority_root="${KEN_ACTIONS_FIREWALL_AUTHORITY_ROOT:-/var/lib/ken-actions/authority}"
    proxy_uid="${KEN_ACTIONS_PROXY_UID:-29999}"
  else
    runtime_root=/run/ken-actions-firewall
    state_root=/var/lib/ken-actions-firewall
    authority_root=/var/lib/ken-actions/authority
    proxy_uid="$(id -u ken-actions-proxy)" || return 1
  fi
  [[ "${proxy_uid}" =~ ^[0-9]+$ ]] || {
    printf 'host firewall proxy UID authority invalid\n' >&2
    return 1
  }
  install -d -m 0700 "${runtime_root}" "${state_root}"
  generation_candidate="$(mktemp "${runtime_root}/endpoint-generation.XXXXXX")"
  rules_candidate="$(mktemp "${runtime_root}/host-base.XXXXXX")"
  blocked_candidate="$(mktemp "${runtime_root}/host-blocked.XXXXXX")"
  active="${state_root}/host-base.nft"
  backup="${state_root}/host-base.lkg.nft"
  generation_lkg="${state_root}/firewall-endpoint-generation.lkg.json"
  trap 'rm -f -- "${generation_candidate}" "${rules_candidate}" "${blocked_candidate}"' EXIT
  if [[ -n "${KEN_ACTIONS_FIREWALL_GENERATION_SOURCE:-}" ]]; then
    if [[ -f "${KEN_ACTIONS_FIREWALL_GENERATION_SOURCE}" && ! -L "${KEN_ACTIONS_FIREWALL_GENERATION_SOURCE}" ]]; then
      install -m 0600 "${KEN_ACTIONS_FIREWALL_GENERATION_SOURCE}" "${generation_candidate}"
      resolver_ok=1
    fi
  else
    resolver="${KEN_ACTIONS_FIREWALL_RESOLVER:-/usr/local/sbin/ken-actions-vm-authority-verify}"
    if "${resolver}" --resolve-firewall-endpoints \
      "${authority_root}/firewall-endpoint-policy.yaml" \
      "${authority_root}/runner-platform.yaml" \
      "${authority_root}/broker-runtime.lock.yaml" \
      "${authority_root}/op-broker-policy.yaml" \
      "${authority_root}/action-transport.lock.yaml" \
      "${generation_candidate}" >/dev/null; then
      resolver_ok=1
    fi
  fi
  if ((resolver_ok == 1)) && render_ken_actions_numeric_generation host none none none "${generation_candidate}" "${rules_candidate}" "${proxy_uid}" >/dev/null; then
    activate_ken_actions_firewall_generation "${rules_candidate}" "${active}" "${backup}"
    install -m 0600 "${generation_candidate}" "${generation_lkg}"
    printf 'HOST_FIREWALL_OK source=fresh proxy_uid=%s\n' "${proxy_uid}"
    return 0
  fi
  if [[ -f "${generation_lkg}" && ! -L "${generation_lkg}" ]] && \
     render_ken_actions_numeric_generation host none none none "${generation_lkg}" "${rules_candidate}" "${proxy_uid}" >/dev/null; then
    activate_ken_actions_firewall_generation "${rules_candidate}" "${active}" "${backup}"
    printf 'HOST_FIREWALL_LKG_OK proxy_uid=%s\n' "${proxy_uid}"
    return 0
  fi
  render_ken_actions_host_blocked "${blocked_candidate}" "${proxy_uid}" expired-or-missing-generation
  activate_ken_actions_firewall_generation "${blocked_candidate}" "${active}" "${backup}"
  printf 'host firewall endpoint generation unavailable and LKG expired or missing\n' >&2
  return 1
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  if [[ "$(basename "$0")" == ken-actions-guest-firewall ]]; then
    ken_actions_guest_firewall_cli "$@"
  else
    ken_actions_host_firewall_cli "$@"
  fi
fi
