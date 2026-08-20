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
Usage:
  bash infra/github-actions/scripts/provision-vms.sh --verify-static
  bash infra/github-actions/scripts/provision-vms.sh --check-readiness
  bash infra/github-actions/scripts/provision-vms.sh --validate-runtime-authority MANIFEST LOCK POLICY
  bash infra/github-actions/scripts/provision-vms.sh --resolve-firewall-endpoints ENDPOINT_POLICY RUNNER LOCK POLICY TASK7_LOCK OUTPUT [RECEIPT]
  bash infra/github-actions/scripts/provision-vms.sh --build-offline MANIFEST LOCK POLICY ENDPOINT_POLICY GENERATION GENERATION_RECEIPT TASK7_LOCK ONEPASSWORD_RECEIPT PAYLOAD_ROOT OUTPUT_ROOT
  bash infra/github-actions/scripts/provision-vms.sh --apply-ready MANIFEST LOCK POLICY BUILD_ROOT APPROVAL root@167.235.8.250
  bash infra/github-actions/scripts/provision-vms.sh --solve-closure BASE STAGED ROOTS ARCH
  bash infra/github-actions/scripts/provision-vms.sh --fake-image-transaction SOURCE DESTINATION
  bash infra/github-actions/scripts/provision-vms.sh --dry-run root@167.235.8.250
  bash infra/github-actions/scripts/provision-vms.sh root@167.235.8.250
EOF
}

validate_local_contract() {
  local path
  for path in \
    "${GA_ROOT}/libvirt/ken-ci.xml" \
    "${GA_ROOT}/libvirt/ken-deploy.xml" \
    "${GA_ROOT}/cloud-init/ken-ci-user-data.yaml" \
    "${GA_ROOT}/cloud-init/ken-deploy-user-data.yaml" \
    "${GA_ROOT}/inventory/guest-image-manifest.yaml" \
    "${GA_ROOT}/inventory/firewall-endpoint-policy.yaml" \
    "${GA_ROOT}/inventory/runner-platform.yaml" \
    "${GA_ROOT}/proxy/ken-actions-artifact-proxy-deploy.conf" \
    "${GA_ROOT}/proxy/ken-actions-artifact-proxy-runtime.yaml" \
    "${GA_ROOT}/systemd/ken-actions-artifact-proxy-deploy.service" \
    "${GA_ROOT}/systemd/ken-actions-vm-firewall.service" \
    "${GA_ROOT}/systemd/ken-actions-vm-firewall.timer" \
    "${GA_ROOT}/systemd/ken-actions-vms.service" \
    "${GA_ROOT}/scripts/lib/vm-firewall.sh"; do
    [[ -f "${path}" && ! -L "${path}" ]] || die "required VM definition is missing or symlinked: ${path}"
  done
}

resolve_firewall_endpoints() {
  local endpoint_policy="$1" runner="$2" lock="$3" broker_policy="$4" task7_lock="$5" output="$6" receipt="${7:-}"
  python3 - "${endpoint_policy}" "${runner}" "${lock}" "${broker_policy}" "${task7_lock}" "${output}" "${receipt}" <<'PY'
import hashlib
import ipaddress
import json
import os
import re
import socket
import stat
import sys
import time
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


def exact(value, keys, message):
    if type(value) is not dict or set(value) != set(keys):
        raise SystemExit(message)


def exact_int(value, expected, message):
    if type(value) is not int or value != expected:
        raise SystemExit(message)


def digest(value, message, length=64):
    if type(value) is not str or re.fullmatch(rf"[0-9a-f]{{{length}}}", value) is None:
        raise SystemExit(message)


def no_duplicates(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def read(path, label, *, root_owned=False):
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise SystemExit(f"{label} is missing or unsafe") from error
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & 0o022:
            raise SystemExit(f"{label} is unsafe")
        test_owner = os.environ.get("PROVISION_VMS_COMMAND_TEST") == "1" and metadata.st_uid == os.getuid()
        if root_owned and metadata.st_uid != 0 and not test_owner:
            raise SystemExit(f"{label} owner is unsafe")
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = -1
            return stream.read()
    finally:
        if descriptor >= 0:
            os.close(descriptor)


endpoint_path, runner_path, lock_path, broker_path, task7_path, output_path = map(Path, sys.argv[1:7])
receipt_path = Path(sys.argv[7]) if sys.argv[7] else None
endpoint_bytes = read(endpoint_path, "firewall endpoint policy")
try:
    endpoint = yaml.load(endpoint_bytes.decode("utf-8"), Loader=StrictLoader)
except (UnicodeError, yaml.YAMLError) as error:
    raise SystemExit(f"firewall endpoint policy is malformed: {error}") from error
exact(endpoint, {"schema_version", "authority", "refresh", "endpoint_catalog", "profiles", "bridge_profiles", "ci_runner_egress", "proxy", "onepassword_endpoint_authority", "unresolved_targets", "generation", "readiness"}, "firewall endpoint policy schema drift")
exact_int(endpoint["schema_version"], 1, "firewall endpoint policy schema version invalid")
readiness = endpoint["readiness"]
exact(readiness, {"state", "blockers"}, "firewall endpoint readiness schema drift")
if readiness["state"] == "blocked":
    blockers = readiness["blockers"]
    if type(blockers) is not list or "missing-final-firewall-endpoint-generation" not in blockers:
        raise SystemExit("firewall endpoint blocker schema drift")
    raise SystemExit("missing-final-firewall-endpoint-generation")
if readiness != {"state": "resolution-ready", "blockers": []}:
    raise SystemExit("firewall endpoint policy is not resolution-ready")

authority = endpoint["authority"]
exact(authority, {
    "plan_sha256", "runner_platform_path", "runner_platform_sha256",
    "broker_runtime_lock_path", "broker_runtime_lock_sha256",
    "op_broker_policy_path", "op_broker_policy_sha256",
    "action_transport_lock_path", "action_transport_lock_sha256",
}, "firewall endpoint authority schema drift")
if authority["plan_sha256"] != "75715a5a3973f3ed9813e66c809d76ec1281d537afae0c08d66b02684583a658":
    raise SystemExit("firewall endpoint plan authority mismatch")
for key in ("runner_platform_sha256", "broker_runtime_lock_sha256", "op_broker_policy_sha256", "action_transport_lock_sha256"):
    digest(authority[key], f"firewall endpoint authority digest malformed: {key}")
expected_paths = {
    "runner_platform_path": "inventory/runner-platform.yaml",
    "broker_runtime_lock_path": "inventory/broker-runtime.lock.yaml",
    "op_broker_policy_path": "inventory/op-broker-policy.yaml",
    "action_transport_lock_path": "inventory/action-transport.lock.yaml",
}
for key, expected in expected_paths.items():
    if authority[key] != expected:
        raise SystemExit(f"firewall endpoint authority path mismatch: {key}")

inputs = {}
for name, path, expected_sha in (
    ("runner", runner_path, authority["runner_platform_sha256"]),
    ("runtime lock", lock_path, authority["broker_runtime_lock_sha256"]),
    ("broker policy", broker_path, authority["op_broker_policy_sha256"]),
    ("Task 7 transport", task7_path, authority["action_transport_lock_sha256"]),
):
    raw = read(path, name)
    if hashlib.sha256(raw).hexdigest() != expected_sha:
        raise SystemExit(f"{name} digest mismatch")
    try:
        inputs[name] = yaml.load(raw.decode("utf-8"), Loader=StrictLoader)
    except (UnicodeError, yaml.YAMLError) as error:
        raise SystemExit(f"{name} is malformed: {error}") from error
runner = inputs["runner"]
lock = inputs["runtime lock"]
broker = inputs["broker policy"]
task7 = inputs["Task 7 transport"]
if type(runner) is not dict or type(runner.get("schema_version")) is not int or runner["schema_version"] != 2:
    raise SystemExit("runner authority schema invalid")
if type(lock) is not dict or type(lock.get("schema_version")) is not int or lock["schema_version"] != 1 or lock.get("plan_sha256") != authority["plan_sha256"]:
    raise SystemExit("runtime lock authority invalid")
if type(broker) is not dict or type(broker.get("schema_version")) is not int or broker["schema_version"] != 1:
    raise SystemExit("broker policy authority invalid")
if type(task7) is not dict or type(task7.get("schema_version")) is not int or task7["schema_version"] != 1 or (task7.get("task6_final") or {}).get("status") != "ready":
    raise SystemExit("Task 7 transport authority is not final")

refresh = endpoint["refresh"]
expected_refresh = {
    "interval_seconds": 900,
    "generation_ttl_seconds": 3600,
    "resolver_family": "ipv4-only",
    "empty_or_partial_generation_allowed": False,
    "unexpired_lkg_required_on_failure": True,
    "expired_lkg_action": "install-blocked-generation",
}
if refresh != expected_refresh:
    raise SystemExit("firewall endpoint refresh contract drift")
if endpoint["generation"] != {"status": "resolution-required", "receipt_path": None, "receipt_sha256": None}:
    raise SystemExit("firewall endpoint generation state drift")
if endpoint["unresolved_targets"] != []:
    raise SystemExit("firewall endpoint target readback is incomplete")

catalog = endpoint["endpoint_catalog"]
if type(catalog) is not list or not catalog:
    raise SystemExit("firewall endpoint catalog is empty")
catalog_by_id = {}
fqdn_pattern = re.compile(r"(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
for record in catalog:
    exact(record, {"id", "fqdn", "protocol", "port", "source"}, "firewall endpoint catalog schema drift")
    endpoint_id = record["id"]
    if type(endpoint_id) is not str or re.fullmatch(r"[a-z0-9][a-z0-9-]{1,62}", endpoint_id) is None or endpoint_id in catalog_by_id:
        raise SystemExit("firewall endpoint id invalid or duplicated")
    if type(record["fqdn"]) is not str or fqdn_pattern.fullmatch(record["fqdn"]) is None or record["fqdn"] != record["fqdn"].lower():
        raise SystemExit("firewall endpoint FQDN invalid")
    if record["protocol"] != "tcp" or type(record["port"]) is not int or record["port"] not in {22, 443}:
        raise SystemExit("firewall endpoint protocol or port invalid")
    if record["source"] not in {"plan-static", "task6-policy", "task7-transport", "single-stop-target-readback", "reviewed-endpoint-report"}:
        raise SystemExit("firewall endpoint source invalid")
    catalog_by_id[endpoint_id] = record

profiles = endpoint["profiles"]
task6_profiles = (broker.get("firewall_phase_interface") or {}).get("profiles")
if type(profiles) is not dict or type(task6_profiles) is not dict or set(profiles) != {"github-runner-control", *task6_profiles}:
    raise SystemExit("firewall endpoint profile set drift")
principal_profiles = {}
for principal in (lock.get("runtime_contract") or {}).get("principals", []):
    profile = principal.get("network_profile")
    uid = principal.get("uid")
    if type(profile) is not str or type(uid) is not int or isinstance(uid, bool):
        raise SystemExit("runtime firewall principal authority invalid")
    principal_profiles.setdefault(profile, set()).add(uid)
runner_uids = [item.get("uid") for item in runner.get("runners", []) if item.get("enabled") is True]
if runner_uids != [21001, 21002, 21003, 21004, 21005, 21006, 21007, 21008, 21011, 21012, 21013, 21014]:
    raise SystemExit("runner firewall UID authority drift")
ci_runner_uids = runner_uids[:10]
deploy_runner_uids = runner_uids[10:]
if any(item.get("uid") in {21009, 21010} and item.get("enabled") is not False for item in runner.get("runners", [])):
    raise SystemExit("disabled runner reservation became enabled")
for profile, profile_record in profiles.items():
    exact(profile_record, {"guest", "bridge", "phases"}, "firewall endpoint profile schema drift")
    phases = profile_record["phases"]
    if type(phases) is not dict or profile_record["guest"] not in {"both", "ken-ci", "ken-deploy"} or profile_record["bridge"] not in {"both", "virbr-ci", "virbr-deploy"}:
        raise SystemExit("firewall endpoint phase map invalid")
    if profile != "github-runner-control":
        policy_phases = task6_profiles[profile]
        if type(policy_phases) is not list or len(policy_phases) != len(set(policy_phases)):
            raise SystemExit("Task 6 firewall phase authority invalid")
        extra = set(phases) - set(policy_phases)
        if extra not in (set(), {"onepassword-service"}) or (extra and not profile.startswith("github-control-")):
            raise SystemExit("firewall endpoint phase set broadens Task 6")
    for phase, phase_record in phases.items():
        exact(phase_record, {"uids", "targets", "activation"}, "firewall endpoint phase schema drift")
        endpoint_ids = phase_record["targets"]
        uids = phase_record["uids"]
        if (type(phase) is not str or type(endpoint_ids) is not list or len(endpoint_ids) != len(set(endpoint_ids))
                or type(uids) is not list or not uids or len(uids) != len(set(uids))
                or any(type(uid) is not int or isinstance(uid, bool) or uid <= 0 for uid in uids)
                or phase_record["activation"] not in {"standing", "request-bound"}):
            raise SystemExit("firewall endpoint phase route invalid")
        if (not endpoint_ids) != (profile == "frontend-production-digest-deploy" and phase == "build-offline"):
            raise SystemExit("firewall endpoint empty-target phase drift")
        if not set(endpoint_ids) <= set(catalog_by_id):
            raise SystemExit("firewall endpoint phase references unknown target")
        if profile == "github-runner-control":
            if uids != deploy_runner_uids or phase_record["activation"] != "standing":
                raise SystemExit("runner firewall profile UID drift")
        elif profile.startswith("github-control-"):
            if set(uids) != principal_profiles.get(profile, set()) or phase_record["activation"] != "standing":
                raise SystemExit("broker control firewall profile UID drift")
        elif not set(uids) <= principal_profiles.get(profile, set()) and profile != "frontend-production-digest-deploy":
            raise SystemExit("executor firewall profile UID drift")

frontend = profiles["frontend-production-digest-deploy"]["phases"]
expected_frontend_uids = {
    "node-base-read": [22201],
    "package-read": [22201],
    "build-offline": [22201],
    "posthog-upload": [22202],
    "ghcr-write": [22003],
    "frontend-deploy": [22203],
    "frontend-public-health": [22203],
}
if set(frontend) != set(expected_frontend_uids) or any(frontend[phase]["uids"] != uids for phase, uids in expected_frontend_uids.items()):
    raise SystemExit("frontend firewall phase UID ownership drift")

proxy = endpoint["proxy"]
if proxy != {
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
}:
    raise SystemExit("firewall proxy boundary drift")

ci_runner_egress = endpoint["ci_runner_egress"]
exact(ci_runner_egress, {
    "guest", "bridge", "uids", "address_family", "protocol", "ports",
    "denied_endpoint_ids", "denied_networks", "proxy_access", "ipv6",
}, "CI runner egress schema drift")
if (ci_runner_egress["guest"] != "ken-ci" or ci_runner_egress["bridge"] != "virbr-ci"
        or ci_runner_egress["uids"] != ci_runner_uids
        or ci_runner_egress["address_family"] != "ipv4-public-only"
        or ci_runner_egress["protocol"] != "tcp"
        or ci_runner_egress["ports"] != [80, 443]
        or any(type(port) is not int for port in ci_runner_egress["ports"])
        or ci_runner_egress["proxy_access"] != "denied"
        or ci_runner_egress["ipv6"] != "denied"):
    raise SystemExit("CI runner egress boundary drift")
denied_endpoint_ids = ci_runner_egress["denied_endpoint_ids"]
expected_denied_endpoint_ids = [
    "onepassword-service-account",
    *[record["id"] for record in catalog if record["source"] == "single-stop-target-readback"],
]
if (type(denied_endpoint_ids) is not list or denied_endpoint_ids != expected_denied_endpoint_ids
        or len(denied_endpoint_ids) != len(set(denied_endpoint_ids))
        or not set(denied_endpoint_ids) <= set(catalog_by_id)):
    raise SystemExit("CI runner denied endpoint authority drift")
expected_denied_networks = [
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
    "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
    "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15",
    "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
]
if ci_runner_egress["denied_networks"] != expected_denied_networks:
    raise SystemExit("CI runner denied network authority drift")
for raw_network in ci_runner_egress["denied_networks"]:
    try:
        network = ipaddress.ip_network(raw_network, strict=True)
    except ValueError as error:
        raise SystemExit("CI runner denied network is malformed") from error
    if network.version != 4:
        raise SystemExit("CI runner denied network is not IPv4")

onepassword = endpoint["onepassword_endpoint_authority"]
exact(onepassword, {
    "status", "endpoint_id", "fqdn", "protocol", "port", "source_report_path",
    "source_report_sha256", "linux_canary",
}, "1Password endpoint authority schema drift")
canary = onepassword["linux_canary"]
exact(canary, {
    "status", "commands", "cache", "fresh_config", "direct_egress",
    "exact_relay_authority", "receipt_path", "receipt_sha256",
}, "1Password endpoint canary schema drift")
if (onepassword["endpoint_id"] != "onepassword-service-account"
        or onepassword["fqdn"] != "ken-ai.1password.com"
        or onepassword["protocol"] != "tcp"
        or type(onepassword["port"]) is not int or onepassword["port"] != 443
        or onepassword["source_report_path"] != ".superpowers/sdd/2026-08-19-org-ci-cutover/task-4-1password-endpoint-authority.md"):
    raise SystemExit("1Password endpoint boundary drift")
digest(onepassword["source_report_sha256"], "1Password endpoint report digest malformed")
expected_canary = {
    "status": "ready",
    "commands": ["op-read", "op-inject", "op-run"],
    "cache": False,
    "fresh_config": True,
    "direct_egress": "denied",
    "exact_relay_authority": "ken-ai.1password.com:443",
}
if any(canary.get(key) != value for key, value in expected_canary.items()):
    raise SystemExit("1Password endpoint Linux canary is not ready")
digest(canary.get("receipt_sha256"), "1Password endpoint canary receipt digest malformed")
if type(canary.get("receipt_path")) is not str or not canary["receipt_path"].startswith("/var/lib/ken-actions/receipts/"):
    raise SystemExit("1Password endpoint canary receipt path invalid")
canary_path = Path(canary["receipt_path"])
if os.environ.get("PROVISION_VMS_COMMAND_TEST") == "1" and os.environ.get("KEN_ACTIONS_ONEPASSWORD_CANARY_RECEIPT"):
    canary_path = Path(os.environ["KEN_ACTIONS_ONEPASSWORD_CANARY_RECEIPT"])
try:
    canary_bytes = read(canary_path, "1Password endpoint canary receipt", root_owned=True)
except SystemExit as error:
    raise SystemExit("1Password endpoint canary receipt is missing or unsafe") from error
if hashlib.sha256(canary_bytes).hexdigest() != canary["receipt_sha256"]:
    raise SystemExit("1Password endpoint canary receipt digest mismatch")
try:
    canary_receipt = json.loads(canary_bytes, object_pairs_hook=no_duplicates,
                                parse_constant=lambda raw: (_ for _ in ()).throw(ValueError(raw)))
except (UnicodeError, json.JSONDecodeError, ValueError) as error:
    raise SystemExit(f"1Password endpoint canary receipt is malformed: {error}") from error
expected_canary_receipt = {
    "schema_version": 1,
    "status": "ready",
    "commands": ["op-read", "op-inject", "op-run"],
    "cache": False,
    "fresh_config": True,
    "direct_egress": "denied",
    "observed_relay_authorities": ["ken-ai.1password.com:443"],
}
if canary_receipt != expected_canary_receipt or type(canary_receipt.get("schema_version")) is not int:
    raise SystemExit("1Password endpoint canary receipt authority mismatch")

bridges = endpoint["bridge_profiles"]
exact(bridges, {"virbr-ci", "virbr-deploy"}, "firewall bridge authority drift")
if bridges["virbr-ci"] != ["github-control-ci"]:
    raise SystemExit("CI bridge endpoint profile drift")
expected_deploy = ["github-runner-control", *[name for name in task6_profiles if name != "github-control-ci"]]
if bridges["virbr-deploy"] != expected_deploy or set(bridges["virbr-ci"]) & set(bridges["virbr-deploy"]):
    raise SystemExit("deploy bridge endpoint profile drift")

test_map = {}
if os.environ.get("PROVISION_VMS_COMMAND_TEST") == "1":
    for item in os.environ.get("KEN_ACTIONS_FIREWALL_TEST_IPS", "").split(","):
        if not item:
            continue
        fqdn, separator, raw_addresses = item.partition("=")
        if not separator or fqdn in test_map:
            raise SystemExit("firewall endpoint test resolution map invalid")
        test_map[fqdn] = raw_addresses.split("+")


def resolve(fqdn):
    if test_map:
        raw_values = test_map.get(fqdn, [])
    else:
        raw_values = [item[4][0] for item in socket.getaddrinfo(fqdn, None, socket.AF_INET, socket.SOCK_STREAM)]
    values = []
    for raw in raw_values:
        try:
            address = ipaddress.ip_address(raw)
        except ValueError as error:
            raise SystemExit(f"firewall endpoint answer invalid: {fqdn}") from error
        if address.version != 4 or not address.is_global:
            raise SystemExit(f"firewall endpoint answer is not public IPv4: {fqdn}")
        values.append(str(address))
    values = sorted(set(values), key=ipaddress.ip_address)
    if not values:
        raise SystemExit(f"firewall endpoint resolution is empty: {fqdn}")
    return values


resolved_fqdns = {record["fqdn"]: resolve(record["fqdn"]) for record in catalog}
resolved_profiles = {}
for profile, profile_record in profiles.items():
    resolved_profiles[profile] = {
        "guest": profile_record["guest"],
        "bridge": profile_record["bridge"],
        "phases": {},
    }
    for phase, phase_record in profile_record["phases"].items():
        resolved_profiles[profile]["phases"][phase] = {
            "uids": phase_record["uids"],
            "activation": phase_record["activation"],
            "routes": [
                {
                    "endpoint_id": endpoint_id,
                    "fqdn": catalog_by_id[endpoint_id]["fqdn"],
                    "protocol": catalog_by_id[endpoint_id]["protocol"],
                    "port": catalog_by_id[endpoint_id]["port"],
                    "ipv4": resolved_fqdns[catalog_by_id[endpoint_id]["fqdn"]],
                }
                for endpoint_id in phase_record["targets"]
            ],
        }

bridge_routes = {}
for bridge, profile_names in bridges.items():
    grouped = {}
    for profile in profile_names:
        for phase_record in resolved_profiles[profile]["phases"].values():
            for route in phase_record["routes"]:
                grouped.setdefault((route["protocol"], route["port"]), set()).update(route["ipv4"])
    bridge_routes[bridge] = [
        {"protocol": protocol, "port": port, "ipv4": sorted(addresses, key=ipaddress.ip_address)}
        for (protocol, port), addresses in sorted(grouped.items(), key=lambda item: (item[0][1], item[0][0]))
    ]
    if not bridge_routes[bridge]:
        raise SystemExit("firewall bridge route union is empty")

if not output_path.is_absolute() or output_path == Path("/") or output_path.is_symlink():
    raise SystemExit("firewall endpoint generation output is unsafe")
output_path.parent.mkdir(parents=True, exist_ok=True)
if output_path.parent.is_symlink():
    raise SystemExit("firewall endpoint generation parent is unsafe")
generated_at = int(os.environ.get("KEN_ACTIONS_FIREWALL_GENERATED_AT_EPOCH", str(int(time.time()))))
if generated_at <= 0:
    raise SystemExit("firewall endpoint generation epoch invalid")
generation = {
    "schema_version": 1,
    "authority": {**authority, "firewall_endpoint_policy_sha256": hashlib.sha256(endpoint_bytes).hexdigest()},
    "generated_at_epoch": generated_at,
    "expires_at_epoch": generated_at + refresh["generation_ttl_seconds"],
    "refresh_interval_seconds": refresh["interval_seconds"],
    "profiles": resolved_profiles,
    "bridges": bridge_routes,
    "ci_runner_egress": {
        **ci_runner_egress,
        "denied_ipv4": sorted({
            address
            for endpoint_id in denied_endpoint_ids
            for address in resolved_fqdns[catalog_by_id[endpoint_id]["fqdn"]]
        }, key=ipaddress.ip_address),
    },
    "proxy": proxy,
    "onepassword_endpoint_authority": onepassword,
}
temporary = output_path.with_name(f".{output_path.name}.{os.getpid()}.tmp")
temporary.write_text(json.dumps(generation, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
temporary.chmod(0o600)
os.replace(temporary, output_path)
if receipt_path is not None:
    if not receipt_path.is_absolute() or receipt_path == Path("/") or receipt_path.is_symlink():
        raise SystemExit("firewall endpoint generation receipt output is unsafe")
    receipt_path.parent.mkdir(parents=True, exist_ok=True)
    if receipt_path.parent.is_symlink():
        raise SystemExit("firewall endpoint generation receipt parent is unsafe")
    generation_bytes = output_path.read_bytes()
    receipt = {
        "schema_version": 1,
        "authority": generation["authority"],
        "generation": {
            "path": "/var/lib/ken-actions/authority/firewall-endpoint-generation.json",
            "sha256": hashlib.sha256(generation_bytes).hexdigest(),
            "generated_at_epoch": generation["generated_at_epoch"],
            "expires_at_epoch": generation["expires_at_epoch"],
        },
        "verification": {
            "public_ipv4_only": True,
            "exact_profiles": True,
            "exact_bridge_unions": True,
            "onepassword_canary_bound": True,
        },
    }
    receipt_temporary = receipt_path.with_name(f".{receipt_path.name}.{os.getpid()}.tmp")
    receipt_temporary.write_text(json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
    receipt_temporary.chmod(0o600)
    os.replace(receipt_temporary, receipt_path)
print(f"FIREWALL_ENDPOINTS_OK endpoints={len(catalog)} profiles={len(profiles)} expires={generation['expires_at_epoch']}")
PY
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
    domain.attrib.get("type") != "kvm"
    or memory is None
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

verify_static() {
  validate_local_contract
  python3 - "${GA_ROOT}" <<'PY'
import hashlib
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import yaml

ga = Path(sys.argv[1])


class StrictLoader(yaml.SafeLoader):
    pass


def construct_mapping(loader, node, deep=False):
    seen = set()
    for key_node, _ in node.value:
        key = loader.construct_object(key_node, deep=False)
        if key in seen:
            raise SystemExit(f"duplicate YAML key: {key}")
        seen.add(key)
    return yaml.SafeLoader.construct_mapping(loader, node, deep=deep)


StrictLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, construct_mapping
)


def load(path):
    with path.open(encoding="utf-8") as stream:
        return yaml.load(stream, Loader=StrictLoader)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require(condition, message):
    if not condition:
        raise SystemExit(message)


def require_exact(value, keys, message):
    require(type(value) is dict and set(value) == set(keys), message)


def is_sha256(value):
    return type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def is_commit(value):
    return type(value) is str and re.fullmatch(r"[0-9a-f]{40}", value) is not None


manifest_path = ga / "inventory/guest-image-manifest.yaml"
runner_path = ga / "inventory/runner-platform.yaml"
manifest = load(manifest_path)
runner = load(runner_path)
authority = manifest.get("authority") or {}
readiness = manifest.get("readiness") or {}
require(
    type(manifest.get("schema_version")) is int
    and manifest.get("schema_version") == 1,
    "unsupported guest manifest schema",
)
require(set(manifest) == {
    "schema_version", "authority", "base_image", "common_runtime", "ci_image",
    "deploy_image", "remote_pinned_build_inputs", "provenance_only",
    "generated_files", "verification", "derived_images", "firewall", "readiness",
}, "guest manifest section drift")
require_exact(authority, {
    "plan_sha256", "task5_integrated_commit", "runner_platform_path",
    "runner_platform_sha256", "task6_commit", "broker_runtime_lock_path",
    "broker_runtime_lock_sha256", "op_broker_policy_path",
    "op_broker_policy_sha256", "task7_commit", "action_transport_lock_path",
    "action_transport_lock_sha256", "firewall_endpoint_policy_path",
    "firewall_endpoint_policy_sha256", "firewall_endpoint_generation_sha256",
    "firewall_endpoint_generation_receipt_sha256", "onepassword_canary_receipt_sha256",
    "guest_install_contract_sha256", "immutable_payload_manifest_sha256", "platform_payload_manifest_sha256",
    "generated_at_input_epoch",
}, "guest manifest authority schema drift")
require(authority.get("plan_sha256") == "75715a5a3973f3ed9813e66c809d76ec1281d537afae0c08d66b02684583a658", "plan digest drift")
require(authority.get("task5_integrated_commit") == "e2b3b2b50890be01601288f5294ac847fb575e71", "Task 5 commit drift")
require(authority.get("runner_platform_path") == "inventory/runner-platform.yaml", "runner platform path drift")
require(authority.get("runner_platform_sha256") == digest(runner_path), "runner platform digest drift")
require(authority.get("broker_runtime_lock_path") == "inventory/broker-runtime.lock.yaml", "runtime lock path drift")
require(authority.get("op_broker_policy_path") == "inventory/op-broker-policy.yaml", "broker policy path drift")
require(authority.get("action_transport_lock_path") == "inventory/action-transport.lock.yaml", "action transport path drift")
require(authority.get("firewall_endpoint_policy_path") == "inventory/firewall-endpoint-policy.yaml", "firewall endpoint policy path drift")
require(authority.get("task6_commit") is None, "unreviewed Task 6 commit present")
require(authority.get("broker_runtime_lock_sha256") is None, "unreviewed Task 6 lock digest present")
require(authority.get("op_broker_policy_sha256") is None, "unreviewed Task 6 policy digest present")
require(authority.get("task7_commit") is None, "unreviewed Task 7 commit present")
for key in (
    "action_transport_lock_sha256", "firewall_endpoint_policy_sha256",
    "firewall_endpoint_generation_sha256", "firewall_endpoint_generation_receipt_sha256",
    "onepassword_canary_receipt_sha256",
):
    require(authority.get(key) is None, f"unreviewed firewall authority present: {key}")
require(authority.get("guest_install_contract_sha256") is None, "unobserved guest install contract present")
require(authority.get("platform_payload_manifest_sha256") == "dd26525559aa26532fc58658ea4c668f72df73b6cd77a60eef7ec5cb73c2a8c0", "platform payload manifest digest drift")
require(is_sha256(authority.get("immutable_payload_manifest_sha256")), "immutable payload manifest digest drift")
require(type(authority.get("generated_at_input_epoch")) is int and authority.get("generated_at_input_epoch") >= 0, "guest manifest generated epoch type drift")
require_exact(readiness, {"state", "live_apply_allowed", "ready_marker", "blockers"}, "guest manifest readiness schema drift")
require(readiness.get("state") == "blocked", "unobserved manifest readiness")
require(readiness.get("live_apply_allowed") is False, "unapproved live apply")
require(readiness.get("ready_marker") is None, "unobserved ready marker")
require(readiness.get("blockers") == [
    "missing-final-task6-lock",
    "missing-final-task6-policy-and-identities",
    "missing-final-task7-transport-manifest",
    "missing-single-stop-production-target-readback",
    "missing-approved-onepassword-endpoint-canary",
    "missing-final-firewall-endpoint-generation",
    "missing-both-guest-runtime-receipts",
], "guest manifest blocker set drift")
require(manifest.get("firewall") == {
    "status": "blocked",
    "blocker": "missing-final-firewall-endpoint-generation",
    "refresh_interval_seconds": 900,
    "generation_ttl_seconds": 3600,
    "host_generation_path": "/var/lib/ken-actions/authority/firewall-endpoint-generation.json",
    "guest_generation_path": "/etc/ken-actions/firewall-endpoint-generation.json",
    "guest_base_path": "/etc/ken-actions/guest-base.nft",
    "guest_resolver_path": "/usr/local/libexec/ken-actions-firewall-endpoint-resolve",
}, "guest manifest firewall contract drift")
derived = manifest.get("derived_images") or {}
require_exact(derived, {"status", "ci", "deploy"}, "guest manifest derived-image schema drift")
require(derived.get("status") == "blocked", "unobserved derived-image status")
ci_size = (derived.get("ci") or {}).get("virtual_size_gib")
deploy_size = (derived.get("deploy") or {}).get("virtual_size_gib")
require(type(ci_size) is int and ci_size == 750, "CI derived-image size drift")
require(type(deploy_size) is int and deploy_size == 80, "deploy derived-image size drift")
require(all((derived.get(name) or {}).get(field) is None for name in ("ci", "deploy") for field in ("path", "sha256", "receipt_sha256")), "unobserved derived-image evidence present")
for name, size in (("ci", 750), ("deploy", 80)):
    require_exact(derived.get(name), {"path", "sha256", "virtual_size_gib", "receipt_sha256"}, f"{name} derived-image schema drift")
    require(type(derived[name].get("virtual_size_gib")) is int and derived[name]["virtual_size_gib"] == size, f"{name} derived-image type drift")

require_exact(manifest.get("base_image"), {
    "status", "blocker", "release_identifier", "architecture", "url", "sha256",
    "signed_checksum_file_sha256", "signature_sha256", "signer_fingerprint",
    "dpkg_inventory_sha256",
}, "guest manifest base-image schema drift")
require(manifest["base_image"] == {
    "status": "ready",
    "blocker": None,
    "release_identifier": "ubuntu-24.04",
    "architecture": "amd64",
    "url": "file:///private/tmp/ken-offline-payloads.WtdFkz/platform-extension/payloads/noble-server-cloudimg-amd64-20260814.img",
    "sha256": "6e40c07ae715f744f84af0bec76415cc1987dd115b4b8de437818561f01a3733",
    "signed_checksum_file_sha256": "3048af3f296287780875ec1ca467f2ff9c080991a50a426062d2d7d4ec3adbb6",
    "signature_sha256": "9ed5c3c40f723e87c00016edb357f0638a714c2004789e1f7a58fdd4515c8b40",
    "signer_fingerprint": "D2EB44626FDDC30B513D5BB71A5D6C4C7DB87C81",
    "dpkg_inventory_sha256": "eeabaab04e894d41d33b207718b189b7bc27716af8f25aa2857a68e434203316",
}, "approved Ubuntu base-image authority drift")
require_exact(manifest.get("common_runtime"), {
    "status", "blocker", "exact_op_path", "payloads", "installed_files", "required_checks",
}, "guest manifest common-runtime schema drift")
for section, extra in (
    ("ci_image", {"status", "virtual_size_gib", "platform_payloads", "installed_files", "common_runtime_included", "task6_ci_files"}),
    ("deploy_image", {"status", "virtual_size_gib", "platform_payloads", "installed_files", "common_runtime_included", "deploy_toolchain_payloads", "task6_deploy_files", "task6_principals", "builder_subuid_range", "builder_subgid_range"}),
    ("remote_pinned_build_inputs", {"status", "blocker", "inputs"}),
    ("provenance_only", {"installable", "inputs"}),
    ("generated_files", {"status", "files"}),
    ("verification", {"network_allowed", "required_commands", "result_receipts"}),
):
    require_exact(manifest.get(section), extra, f"guest manifest {section.replace('_', '-')} schema drift")
require_exact(manifest["verification"].get("result_receipts"), {"ci", "deploy"}, "guest manifest receipt map schema drift")
for name in ("ci", "deploy"):
    require_exact(manifest["verification"]["result_receipts"].get(name), {"path", "sha256"}, f"guest manifest {name} receipt schema drift")

authority_inputs = [
    manifest_path,
    runner_path,
    ga / "libvirt/ken-ci.xml",
    ga / "libvirt/ken-deploy.xml",
    ga / "cloud-init/ken-ci-user-data.yaml",
    ga / "cloud-init/ken-deploy-user-data.yaml",
    ga / "proxy/ken-actions-artifact-proxy-deploy.conf",
]
for path in authority_inputs:
    require(path.is_file() and not path.is_symlink(), f"unsafe authority input: {path}")
    require(path.stat().st_mode & 0o022 == 0, f"group- or world-writable authority input: {path}")

enabled = [item for item in runner.get("runners") or [] if item.get("enabled")]
disabled = [item for item in runner.get("runners") or [] if not item.get("enabled")]
require([item.get("uid") for item in enabled] == [21001,21002,21003,21004,21005,21006,21007,21008,21011,21012,21013,21014], "Task 5 enabled identity drift")
require([item.get("uid") for item in disabled] == [21009,21010], "Task 5 disabled identity drift")
require(all(item.get("slice") is None for item in disabled), "disabled identity acquired a slice")

for name, vcpu, memory_gib, disk_gib, network in (
    ("ken-ci", 32, 112, 750, "ken-ci-net"),
    ("ken-deploy", 4, 12, 80, "ken-deploy-net"),
):
    domain = ET.parse(ga / f"libvirt/{name}.xml").getroot()
    contract = domain.find("./metadata/{urn:ken-actions:v1}vm-contract")
    require(domain.attrib.get("type") == "kvm", f"{name} is not KVM")
    require(domain.find("./cpu").attrib.get("mode") == "host-passthrough", f"{name} CPU mode drift")
    require(int(domain.findtext("vcpu", "0")) == vcpu, f"{name} vCPU drift")
    require(int(domain.findtext("memory", "0")) == memory_gib * 1024 * 1024, f"{name} memory drift")
    require(contract is not None and int(contract.attrib.get("disk-capacity-gib", "0")) == disk_gib, f"{name} disk drift")
    require([node.attrib.get("network") for node in domain.findall("./devices/interface/source")] == [network], f"{name} network drift")
    require(all((node.attrib.get("file") or "").startswith("/mnt/data/libvirt/") for node in domain.findall("./devices/disk/source")), f"{name} storage drift")

for guest in ("ken-ci", "ken-deploy"):
    path = ga / f"cloud-init/{guest}-user-data.yaml"
    data = load(path)
    text = path.read_text(encoding="utf-8")
    require(data.get("package_update") is False and data.get("package_upgrade") is False, f"{guest} package network enabled")
    require(not data.get("packages"), f"{guest} cloud package install present")
    require("flush ruleset" not in text, f"{guest} flushes unrelated firewall state")
    require(not re.search(r"\b(apt(?:-get)?|curl|wget|pip|npm|docker pull|corepack prepare)\b", text), f"{guest} network installer present")
    require("ken-actions-guest-firewall.service" in text, f"{guest} firewall gate absent")
    require("ken-actions-guest-runtime-verify.service" in text, f"{guest} runtime gate absent")
    require("/usr/local/bin/op" in text, f"{guest} op path drift")

proxy = (ga / "proxy/ken-actions-artifact-proxy-deploy.conf").read_text(encoding="utf-8")
require("http_port 192.168.211.1:3128" in proxy, "proxy bind drift")
require("^[a-z0-9]{3,24}[.]blob[.]core[.]windows[.]net$" in proxy, "proxy host grammar drift")
require("^[a-z0-9]{3,24}[.]blob[.]core[.]windows[.]net:443$" in proxy, "proxy CONNECT authority grammar drift")
require("dns_nameservers 127.0.0.53" in proxy, "proxy resolver drift")
require("http_access deny all" in proxy, "proxy default deny absent")
require(not any(item in proxy for item in ("ssl_bump", "http_access allow all", "http_port 0.0.0.0")), "proxy broadened")

for path in ga.rglob("*"):
    if not path.is_file() or path.is_symlink():
        continue
    if path.suffix not in {".yaml", ".yml", ".sh", ".service", ".timer", ".conf", ".xml"}:
        continue
    text = path.read_text(encoding="utf-8", errors="replace")
    require(not re.search(r"-----BEGIN [A-Z0-9 ]+PRIVATE KEY-----\s+[A-Za-z0-9+/=\n]{64,}", text), f"secret-shaped material in {path}")
    require(not re.search(r"\b(ghp_|github_pat_|ops_)[A-Za-z0-9_=-]{16,}", text), f"token-shaped material in {path}")

print("STATIC_OK readiness=blocked blocker=missing-final-task6-lock")
PY
}

check_readiness() {
  validate_local_contract
  python3 - "${GA_ROOT}/inventory/guest-image-manifest.yaml" <<'PY'
import re
import sys
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
with open(sys.argv[1], encoding="utf-8") as stream:
    manifest = yaml.load(stream, Loader=StrictLoader)
if type(manifest) is not dict:
    raise SystemExit("guest manifest schema drift")
authority = manifest.get("authority")
if type(authority) is not dict or set(authority) != {
    "plan_sha256", "task5_integrated_commit", "runner_platform_path",
    "runner_platform_sha256", "task6_commit", "broker_runtime_lock_path",
    "broker_runtime_lock_sha256", "op_broker_policy_path",
    "op_broker_policy_sha256", "task7_commit", "action_transport_lock_path",
    "action_transport_lock_sha256", "firewall_endpoint_policy_path",
    "firewall_endpoint_policy_sha256", "firewall_endpoint_generation_sha256",
    "firewall_endpoint_generation_receipt_sha256", "onepassword_canary_receipt_sha256",
    "guest_install_contract_sha256", "immutable_payload_manifest_sha256", "platform_payload_manifest_sha256",
    "generated_at_input_epoch",
}:
    raise SystemExit("guest manifest authority schema drift")
if authority.get("task6_commit") is not None and (
    type(authority.get("task6_commit")) is not str
    or re.fullmatch(r"[0-9a-f]{40}", authority["task6_commit"]) is None
):
    raise SystemExit("guest manifest Task 6 commit type drift")
if authority.get("task7_commit") is not None and (
    type(authority.get("task7_commit")) is not str
    or re.fullmatch(r"[0-9a-f]{40}", authority["task7_commit"]) is None
):
    raise SystemExit("guest manifest Task 7 commit type drift")
for key in (
    "broker_runtime_lock_sha256", "op_broker_policy_sha256", "action_transport_lock_sha256",
    "firewall_endpoint_policy_sha256", "firewall_endpoint_generation_sha256",
    "firewall_endpoint_generation_receipt_sha256", "onepassword_canary_receipt_sha256",
):
    value = authority.get(key)
    if value is not None and (type(value) is not str or re.fullmatch(r"[0-9a-f]{64}", value) is None):
        raise SystemExit(f"guest manifest {key} type drift")
if type(authority.get("generated_at_input_epoch")) is not int or authority["generated_at_input_epoch"] < 0:
    raise SystemExit("guest manifest generated epoch type drift")
readiness = manifest.get("readiness")
if type(readiness) is not dict or set(readiness) != {"state", "live_apply_allowed", "ready_marker", "blockers"}:
    raise SystemExit("guest manifest readiness schema drift")
blockers = readiness.get("blockers")
if type(blockers) is not list or any(type(value) is not str for value in blockers) or len(blockers) != len(set(blockers)):
    raise SystemExit("guest manifest blocker set drift")
if readiness.get("state") != "ready" or readiness.get("live_apply_allowed") is not True:
    reason = blockers[0] if blockers else "guest-image-not-ready"
    print(reason, file=sys.stderr)
    raise SystemExit(78)
if any(not authority.get(key) for key in ("task6_commit", "broker_runtime_lock_sha256", "op_broker_policy_sha256")):
    print("missing-final-task6-lock", file=sys.stderr)
    raise SystemExit(78)
if any(not authority.get(key) for key in (
    "task7_commit", "action_transport_lock_sha256", "firewall_endpoint_policy_sha256",
    "firewall_endpoint_generation_sha256", "firewall_endpoint_generation_receipt_sha256",
    "onepassword_canary_receipt_sha256",
)):
    print("missing-final-firewall-endpoint-generation", file=sys.stderr)
    raise SystemExit(78)
if blockers:
    print("guest-image-ready-with-blockers", file=sys.stderr)
    raise SystemExit(78)
print("READY")
PY
}

validate_runtime_authority() {
  local manifest="$1" lock="$2" policy="$3"
  local runner_platform="${PROVISION_VMS_RUNNER_PLATFORM:-${GA_ROOT}/inventory/runner-platform.yaml}"
  python3 - "${manifest}" "${lock}" "${policy}" "${runner_platform}" <<'PY'
import hashlib
import os
import re
import stat
import sys
from pathlib import Path, PurePosixPath

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


def read_authority(raw, label):
    path = Path(raw)
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise SystemExit(f"{label} is missing or unsafe: {error}") from error
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) & 0o022:
            raise SystemExit(f"{label} has unsafe type or mode")
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = -1
            content = stream.read()
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    try:
        value = yaml.load(content.decode("utf-8"), Loader=StrictLoader)
    except (UnicodeError, yaml.YAMLError) as error:
        raise SystemExit(f"{label} is malformed: {error}") from error
    if type(value) is not dict:
        raise SystemExit(f"{label} must be a mapping")
    return content, value


def exact(value, keys, message):
    if type(value) is not dict or set(value) != set(keys):
        raise SystemExit(message)


def sha(value, message):
    if type(value) is not str or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise SystemExit(message)


def positive_int(value, message):
    if type(value) is not int or value <= 0:
        raise SystemExit(message)


manifest_bytes, manifest = read_authority(sys.argv[1], "guest manifest")
lock_bytes, lock = read_authority(sys.argv[2], "runtime lock")
policy_bytes, policy = read_authority(sys.argv[3], "broker policy")
runner_bytes, runner_platform = read_authority(sys.argv[4], "runner platform")
del manifest_bytes

if type(manifest.get("schema_version")) is not int or manifest["schema_version"] != 1:
    raise SystemExit("guest manifest schema version invalid")
authority = manifest.get("authority")
if type(authority) is not dict:
    raise SystemExit("guest manifest authority invalid")
commit = authority.get("task6_commit")
if type(commit) is not str or re.fullmatch(r"[0-9a-f]{40}", commit) is None:
    raise SystemExit("guest manifest Task 6 commit type drift")
if hashlib.sha256(lock_bytes).hexdigest() != authority.get("broker_runtime_lock_sha256"):
    raise SystemExit("runtime lock digest mismatch")
if hashlib.sha256(policy_bytes).hexdigest() != authority.get("op_broker_policy_sha256"):
    raise SystemExit("broker policy digest mismatch")
if hashlib.sha256(runner_bytes).hexdigest() != authority.get("runner_platform_sha256"):
    raise SystemExit("runner platform digest mismatch")

exact(lock, {
    "schema_version", "lock_version", "plan_sha256", "target", "compatibility",
    "runtime_contract", "components", "provenance_payloads", "installed_files",
    "verification",
}, "runtime lock top-level schema drift")
if type(lock.get("schema_version")) is not int or lock["schema_version"] != 1:
    raise SystemExit("runtime lock schema version invalid")
if type(lock.get("lock_version")) is not str or not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}[.][0-9]+", lock["lock_version"]):
    raise SystemExit("runtime lock version invalid")
if lock.get("plan_sha256") != authority.get("plan_sha256"):
    raise SystemExit("runtime lock plan digest mismatch")
exact(lock.get("target"), {"os", "architecture"}, "runtime target schema drift")
if lock["target"] != {"os": "ubuntu-24.04", "architecture": "amd64"}:
    raise SystemExit("runtime target drift")

compatibility = lock.get("compatibility")
exact(compatibility, {
    "artifact_class", "payload_manifest_sha256", "payload_count",
    "corrupt_payloads_allowed", "installation_readiness", "blocking_conditions",
    "live_verification", "task4_consumer_contract",
}, "runtime compatibility schema drift")
payload_count = compatibility.get("payload_count")
positive_int(payload_count, "runtime payload count type invalid")
sha(compatibility.get("payload_manifest_sha256"), "runtime payload manifest digest invalid")
if compatibility.get("corrupt_payloads_allowed") is not False:
    raise SystemExit("runtime corrupt-payload policy invalid")
if type(compatibility.get("blocking_conditions")) is not list or any(type(item) is not str for item in compatibility["blocking_conditions"]):
    raise SystemExit("runtime blocking-condition schema invalid")
consumer = compatibility.get("task4_consumer_contract")
exact(consumer, {
    "required_guests", "bind_exact_lock_sha256", "install_network_disabled",
    "dependency_closure_from_signed_indexes", "guest_image_manifest_required",
    "offline_hash_import_abi_checks_required",
}, "runtime Task 4 consumer schema drift")
if consumer != {
    "required_guests": ["ken-ci", "ken-deploy"],
    "bind_exact_lock_sha256": True,
    "install_network_disabled": True,
    "dependency_closure_from_signed_indexes": True,
    "guest_image_manifest_required": True,
    "offline_hash_import_abi_checks_required": True,
}:
    raise SystemExit("runtime Task 4 consumer contract drift")

component_key_sets = {
    "1password-cli": {"id", "version", "source_url", "payload_filename", "payload_sha256", "hosts", "verification"},
    "python": {"id", "version", "source_url", "payload_filename", "payload_sha256", "hosts", "payloads", "installed_tree", "compatibility"},
    "pyyaml": {"id", "version", "source_url", "payload_filename", "payload_sha256", "hosts", "installed_tree", "compatibility"},
    "pyjwt": {"id", "version", "source_url", "payload_filename", "payload_sha256", "hosts", "installed_tree", "compatibility"},
    "cryptography": {"id", "version", "source_url", "payload_filename", "payload_sha256", "hosts", "payloads", "installed_tree", "compatibility"},
    "ca-certificates": {"id", "version", "source_url", "payload_filename", "payload_sha256", "hosts", "installed_tree", "deterministic_post_install_verification"},
    "git": {"id", "version", "source_url", "payload_filename", "payload_sha256", "hosts", "payloads", "compatibility"},
    "systemd": {"id", "version", "source_url", "payload_filename", "payload_sha256", "hosts", "payloads", "compatibility"},
    "zip-safety": {"id", "version", "source_url", "payload_filename", "payload_sha256", "hosts", "payloads", "compatibility"},
    "buildkit": {"id", "version", "source_url", "payload_filename", "payload_sha256", "hosts", "installed_tree", "verification"},
    "rootlesskit": {"id", "version", "source_url", "payload_filename", "payload_sha256", "hosts", "verification", "compatibility"},
    "buildkit-rootless-prerequisites": {"id", "version", "source_url", "payload_filename", "payload_sha256", "hosts", "payloads"},
    "node": {"id", "version", "source_url", "payload_filename", "payload_sha256", "hosts", "verification", "compatibility"},
    "corepack": {"id", "version", "source_url", "payload_filename", "payload_sha256", "hosts", "installed_tree", "compatibility"},
    "pnpm": {"id", "version", "source_url", "payload_filename", "payload_sha256", "hosts", "installed_tree", "compatibility", "verification"},
    "oci-image-tools": {"id", "version", "source_url", "payload_filename", "payload_sha256", "hosts", "payloads", "compatibility", "verification"},
    "node-build-base": {"id", "version", "source_url", "payload_filename", "payload_sha256", "hosts", "delivery_class", "compatibility"},
}
components = lock.get("components")
if type(components) is not list or len(components) != len(component_key_sets):
    raise SystemExit("runtime component cardinality invalid")
component_ids = [item.get("id") for item in components if type(item) is dict]
if len(component_ids) != len(components) or len(component_ids) != len(set(component_ids)) or set(component_ids) != set(component_key_sets):
    raise SystemExit("runtime component set invalid")
payloads = {}
for component in components:
    component_id = component["id"]
    exact(component, component_key_sets[component_id], f"runtime component schema drift: {component_id}")
    if type(component.get("version")) is not str or not component["version"]:
        raise SystemExit("runtime component version invalid")
    if type(component.get("source_url")) is not str or not component["source_url"].startswith("https://"):
        raise SystemExit("runtime component source URL invalid")
    sha(component.get("payload_sha256"), "runtime component payload digest invalid")
    hosts = component.get("hosts")
    if type(hosts) is not list or not hosts or len(hosts) != len(set(hosts)) or not set(hosts) <= {"ken-ci", "ken-deploy"}:
        raise SystemExit("runtime component host scope invalid")
    if PurePosixPath(component.get("payload_filename", "")).name != component.get("payload_filename"):
        raise SystemExit("runtime component payload filename invalid")
    nested = component.get("payloads", [])
    if type(nested) is not list:
        raise SystemExit("runtime nested payload schema invalid")
    for entry in [
        {"filename": component["payload_filename"], "source_url": component["source_url"], "sha256": component["payload_sha256"]},
        *nested,
    ]:
        exact(entry, {"filename", "source_url", "sha256"}, "runtime nested payload schema invalid")
        if PurePosixPath(entry["filename"]).name != entry["filename"] or not entry["source_url"].startswith("https://"):
            raise SystemExit("runtime nested payload source invalid")
        sha(entry["sha256"], "runtime nested payload digest invalid")
        prior = payloads.setdefault(entry["filename"], entry)
        if prior != entry:
            raise SystemExit("runtime payload filename has conflicting authority")
if len(payloads) != payload_count:
    raise SystemExit("runtime payload count mismatch")

installed = lock.get("installed_files")
if type(installed) is not list:
    raise SystemExit("runtime installed-file cardinality invalid")
paths = []
for entry in installed:
    exact(entry, {"path", "sha256", "hosts", "source"}, "runtime installed-file schema drift")
    path = entry.get("path")
    if type(path) is not str or not path.startswith("/") or ".." in PurePosixPath(path).parts:
        raise SystemExit("runtime installed-file path invalid")
    paths.append(path)
    sha(entry.get("sha256"), "runtime installed-file digest invalid")
    hosts = entry.get("hosts")
    if type(hosts) is not list or not hosts or len(hosts) != len(set(hosts)) or not set(hosts) <= {"ken-ci", "ken-deploy"}:
        raise SystemExit("runtime installed-file host scope invalid")
    source = entry.get("source")
    if type(source) is not str or not (
        source.startswith("component:") and source.removeprefix("component:") in component_key_sets
        or re.fullmatch(r"repo:(?:bin|inventory|systemd)/[A-Za-z0-9_.@/-]+", source)
    ):
        raise SystemExit("runtime installed-file source invalid")
if len(paths) != len(set(paths)):
    raise SystemExit("runtime installed-file path duplicate")
if len(installed) != 46:
    raise SystemExit("runtime installed-file cardinality invalid")
required_paths = {
    "/usr/local/bin/op",
    "/usr/bin/python3.12",
    "/usr/lib/python3/dist-packages/yaml/__init__.py",
    "/usr/lib/python3/dist-packages/yaml/_yaml.cpython-312-x86_64-linux-gnu.so",
    "/usr/lib/python3/dist-packages/jwt/__init__.py",
    "/usr/lib/python3/dist-packages/cryptography/__init__.py",
    "/usr/lib/python3/dist-packages/cryptography/hazmat/bindings/_rust.abi3.so",
    "/usr/sbin/update-ca-certificates",
    "/usr/local/libexec/ken-actions/runtime-known-answer.py",
}
if not required_paths <= set(paths):
    raise SystemExit("runtime import, ABI, CA, or known-answer evidence missing")

runtime = lock.get("runtime_contract")
exact(runtime, {
    "op_path", "guest_payload_count", "remote_build_inputs", "principals",
    "subordinate_ids", "firewall_phase_interface", "startup_gates",
    "deferred_execution_transport",
}, "runtime contract schema drift")
if runtime.get("op_path") != "/usr/local/bin/op" or type(runtime.get("guest_payload_count")) is not int:
    raise SystemExit("runtime path or payload count invalid")
principals = runtime.get("principals")
expected_principals = {
    ("ken-ci", "ken-op-net-ci", 22001, 22001, "system.slice", "github-control-ci"),
    ("ken-deploy", "ken-op-net-nonprod", 22002, 22002, "ken-actions-deploy-brokers.slice", "github-control-nonproduction"),
    ("ken-deploy", "ken-op-net-prod", 22003, 22003, "ken-actions-deploy-brokers.slice", "github-control-production"),
    ("ken-deploy", "ken-vexa-deploy", 22101, 22101, None, "vexa-production-fixed-target"),
    ("ken-deploy", "ken-beehiiv-generate", 22102, 22102, None, "beehiiv-api-fixed-target"),
    ("ken-deploy", "ken-website-deploy", 22103, 22103, None, "website-production-fixed-target"),
    ("ken-deploy", "ken-beehiiv-push", 22104, 22104, None, "github-ssh-ken-website-fixed-target"),
    ("ken-deploy", "ken-fe-builder", 22201, 22201, None, "frontend-production-digest-deploy"),
    ("ken-deploy", "ken-fe-uploader", 22202, 22202, None, "frontend-production-digest-deploy"),
    ("ken-deploy", "ken-fe-deploy", 22203, 22203, None, "frontend-production-digest-deploy"),
}
if type(principals) is not list or len(principals) != len(expected_principals):
    raise SystemExit("runtime principal cardinality invalid")
principal_uids = []
principal_contract = set()
for principal in principals:
    exact(principal, {"guest", "name", "uid", "gid", "slice", "network_profile"}, "runtime principal schema drift")
    if principal.get("guest") not in {"ken-ci", "ken-deploy"} or type(principal.get("uid")) is not int or type(principal.get("gid")) is not int:
        raise SystemExit("runtime principal identity invalid")
    principal_uids.append(principal["uid"])
    principal_contract.add((principal["guest"], principal["name"], principal["uid"], principal["gid"], principal["slice"], principal["network_profile"]))
if len(principal_uids) != len(set(principal_uids)):
    raise SystemExit("runtime principal UID duplicate")
if principal_contract != expected_principals:
    raise SystemExit("runtime principal contract drift")

subordinate_ids = runtime.get("subordinate_ids")
if type(subordinate_ids) is not list or len(subordinate_ids) != 1:
    raise SystemExit("runtime subordinate-ID cardinality invalid")
subordinate = subordinate_ids[0]
exact(subordinate, {"guest", "name", "uid", "subuid_start", "subuid_count", "subgid_start", "subgid_count"}, "runtime subordinate-ID schema drift")
for key in ("uid", "subuid_start", "subuid_count", "subgid_start", "subgid_count"):
    positive_int(subordinate.get(key), "runtime subordinate-ID type invalid")
if subordinate != {
    "guest": "ken-deploy",
    "name": "ken-fe-builder",
    "uid": 22201,
    "subuid_start": 300000,
    "subuid_count": 65536,
    "subgid_start": 300000,
    "subgid_count": 65536,
}:
    raise SystemExit("runtime subordinate-ID contract drift")

exact(runner_platform, {
    "schema_version", "organization", "source_inventory", "runner_distribution",
    "groups", "classes", "deploy_resources", "runners",
}, "runner platform top-level schema drift")
if type(runner_platform.get("schema_version")) is not int or runner_platform["schema_version"] != 2:
    raise SystemExit("runner platform schema version invalid")
runners = runner_platform.get("runners")
if type(runners) is not list or len(runners) != 14:
    raise SystemExit("runner cardinality invalid")
runner_keys = {
    "name", "enabled", "vm", "class", "runner_group", "labels", "user", "uid", "gid",
    "home", "runner_root", "work_root", "docker", "subuid_start", "subgid_start",
    "subid_count", "systemd_instance", "slice",
}
runner_names = []
runner_uids = []
runner_gids = []
runner_subuid_ranges = []
runner_subgid_ranges = []
for runner in runners:
    exact(runner, runner_keys, "runner identity schema drift")
    if type(runner.get("enabled")) is not bool:
        raise SystemExit("runner enabled type invalid")
    for key in ("uid", "gid", "subuid_start", "subgid_start", "subid_count"):
        positive_int(runner.get(key), "runner identity or subordinate-ID type invalid")
    if type(runner.get("name")) is not str or type(runner.get("user")) is not str:
        raise SystemExit("runner identity or subordinate-ID type invalid")
    runner_names.append(runner["name"])
    runner_uids.append(runner["uid"])
    runner_gids.append(runner["gid"])
    runner_subuid_ranges.append((runner["subuid_start"], runner["subuid_start"] + runner["subid_count"]))
    runner_subgid_ranges.append((runner["subgid_start"], runner["subgid_start"] + runner["subid_count"]))
if len(runner_names) != len(set(runner_names)) or len(runner_uids) != len(set(runner_uids)) or len(runner_gids) != len(set(runner_gids)):
    raise SystemExit("runner identity duplicate")
runtime_ids = {item[2] for item in expected_principals} | {item[3] for item in expected_principals}
if (set(runner_uids) | set(runner_gids)) & runtime_ids:
    raise SystemExit("runner and runtime principal identity collision")

def overlaps(left, right):
    return left[0] < right[1] and right[0] < left[1]

runtime_subuid = (subordinate["subuid_start"], subordinate["subuid_start"] + subordinate["subuid_count"])
runtime_subgid = (subordinate["subgid_start"], subordinate["subgid_start"] + subordinate["subgid_count"])
if any(overlaps(item, runtime_subuid) for item in runner_subuid_ranges) or any(overlaps(item, runtime_subgid) for item in runner_subgid_ranges):
    raise SystemExit("runner and runtime subordinate-ID collision")
for ranges in (runner_subuid_ranges, runner_subgid_ranges):
    if any(overlaps(left, right) for index, left in enumerate(ranges) for right in ranges[index + 1:]):
        raise SystemExit("runner subordinate-ID ranges overlap")
expected_runner_names = [
    *[f"ken-ci-standard-{index:02d}" for index in range(1, 11)],
    "ken-ci-heavy-01", "ken-ci-heavy-02",
    "ken-deploy-nonproduction-01", "ken-deploy-production-01",
]
if runner_names != expected_runner_names or runner_uids != list(range(21001, 21015)) or runner_gids != list(range(21001, 21015)):
    raise SystemExit("runner identity contract drift")
if [runner["name"] for runner in runners if runner["enabled"]] != [name for name in expected_runner_names if name not in {"ken-ci-standard-09", "ken-ci-standard-10"}]:
    raise SystemExit("runner enabled cardinality drift")
if [runner["name"] for runner in runners if not runner["enabled"]] != ["ken-ci-standard-09", "ken-ci-standard-10"]:
    raise SystemExit("runner disabled reservations drift")
for index, runner in enumerate(runners):
    expected_start = 1000000 + index * 65536
    if runner["subuid_start"] != expected_start or runner["subgid_start"] != expected_start or runner["subid_count"] != 65536:
        raise SystemExit("runner subordinate-ID contract drift")

exact(policy, {
    "schema_version", "policy_version", "issuer", "discovery_url", "jwks_uri",
    "organization", "protocol", "jwks", "github_api", "artifact", "source_commit",
    "credentials", "deploy_leases", "firewall_phase_interface", "classes", "actions",
}, "broker policy top-level schema drift")
if type(policy.get("schema_version")) is not int or policy["schema_version"] != 1:
    raise SystemExit("broker policy schema version invalid")
classes = policy.get("classes")
if type(classes) is not dict or set(classes) != {"ci", "nonproduction", "production"}:
    raise SystemExit("broker policy class set invalid")
class_uids = []
for name, expected_uid in (("ci", 22001), ("nonproduction", 22002), ("production", 22003)):
    value = classes[name]
    exact(value, {"audience", "broker_network_uid", "broker_network_gid", "vault", "active_connections_max"}, "broker policy class schema drift")
    if type(value.get("broker_network_uid")) is not int or value["broker_network_uid"] != expected_uid:
        raise SystemExit("broker policy class UID drift")
    class_uids.append(value["broker_network_uid"])
leases = policy.get("deploy_leases")
if type(leases) is not dict or type(leases.get("ordinary_slots")) is not int or leases["ordinary_slots"] != 2:
    raise SystemExit("broker policy lease count invalid")
actions = policy.get("actions")
if type(actions) is not list or len(actions) != 4 or len({item.get("action_id") for item in actions if type(item) is dict}) != 4:
    raise SystemExit("broker policy action cardinality invalid")
if set(class_uids) != {item["uid"] for item in principals if item["name"].startswith("ken-op-net-")}:
    raise SystemExit("runtime and broker class UID mismatch")

print(f"RUNTIME_AUTHORITY_OK components={len(components)} installed_files={len(installed)} principals={len(principals)}")
PY
}

validate_platform_extension() {
  local manifest="$1" extension_root="$2"
  local runner_platform="${PROVISION_VMS_RUNNER_PLATFORM:-${GA_ROOT}/inventory/runner-platform.yaml}"
  local platform_manifest="${extension_root}/platform-payload-manifest.json"
  if [[ -n "${PROVISION_VMS_PLATFORM_MANIFEST:-}" ]]; then
    [[ "${PROVISION_VMS_COMMAND_TEST:-0}" == 1 ]] || die 'platform manifest override is test-only'
    platform_manifest="${PROVISION_VMS_PLATFORM_MANIFEST}"
  fi
  python3 - "${manifest}" "${extension_root}" "${runner_platform}" "${platform_manifest}" <<'PY'
import hashlib
import ipaddress
import json
import math
import os
import re
import stat
import sys
from pathlib import Path, PurePosixPath

import yaml


def duplicate_json(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise SystemExit(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def invalid_constant(value):
    raise SystemExit(f"invalid JSON numeric constant: {value}")


def read(path, label):
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise SystemExit(f"{label} is missing or unsafe") from error
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) & 0o022:
            raise SystemExit(f"{label} type or mode is unsafe")
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = -1
            return stream.read()
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def file_evidence(path, label):
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise SystemExit(f"{label} is missing or unsafe") from error
    digest = hashlib.sha256()
    size = 0
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) & 0o022:
            raise SystemExit(f"{label} type or mode is unsafe")
        while True:
            block = os.read(descriptor, 1024 * 1024)
            if not block:
                break
            size += len(block)
            digest.update(block)
    finally:
        os.close(descriptor)
    return size, digest.hexdigest()


def exact(value, keys, message):
    if type(value) is not dict or set(value) != set(keys):
        raise SystemExit(message)


manifest_path, extension_root, runner_path, platform_path = map(Path, sys.argv[1:])
if not extension_root.is_dir() or extension_root.is_symlink():
    raise SystemExit("platform extension root is missing or unsafe")
manifest = yaml.safe_load(read(manifest_path, "guest manifest"))
platform_bytes = read(platform_path, "platform payload manifest")
try:
    platform = json.loads(platform_bytes, object_pairs_hook=duplicate_json, parse_constant=invalid_constant)
except (UnicodeError, json.JSONDecodeError) as error:
    raise SystemExit(f"platform payload manifest is malformed: {error}") from error
authority = manifest.get("authority") or {}
if hashlib.sha256(platform_bytes).hexdigest() != authority.get("platform_payload_manifest_sha256"):
    raise SystemExit("platform payload manifest digest mismatch")
exact(platform, {"authority", "collection_date", "dependency_closure", "image_evidence", "installation_safety", "isolation", "packages", "payload_checksum_list", "payload_count", "payloads", "rootless_identities", "rootless_known_answer_requirements", "runner_extract_evidence", "schema_version", "selection", "target"}, "platform payload top-level schema drift")
if type(platform["schema_version"]) is not int or platform["schema_version"] != 1 or platform["target"] != {"architecture":"amd64", "distribution":"Ubuntu", "release":"24.04 LTS Noble"}:
    raise SystemExit("platform payload schema or target drift")
pa = platform["authority"]
if (pa.get("approved_plan_sha256") != "00e93ef99f75e4101028a4838156c730f4d6bb306f20e5340bf4812128171d0f"
        or pa.get("task5_runner_inventory_sha256") != "1197d4ec41f714d1f25e8ed2ec79ca977a46a6e7a5058b9ce16b3b722d8424ce"
        or pa.get("task5_runtime_commit") != "816efcd148e6ad4586f93f13676d0540e39dc8b3"):
    raise SystemExit("platform payload plan or Task 5 authority drift")
runner_bytes = read(runner_path, "runner platform")
if hashlib.sha256(runner_bytes).hexdigest() != authority.get("runner_platform_sha256"):
    raise SystemExit("platform payload runner inventory binding mismatch")
runner = yaml.safe_load(runner_bytes)
if platform.get("payload_count") != 16 or type(platform.get("payload_count")) is not int:
    raise SystemExit("platform payload cardinality invalid")
payloads = platform.get("payloads")
if type(payloads) is not list or len(payloads) != 16:
    raise SystemExit("platform payload cardinality invalid")
records = {}
total = 0
for item in payloads:
    exact(item, {"path", "role", "sha256", "size_bytes", "source_url"}, "platform payload entry schema drift")
    path = item.get("path")
    if type(path) is not str or not path.startswith("payloads/") or ".." in PurePosixPath(path).parts or PurePosixPath(path).is_absolute() or path in records:
        raise SystemExit("platform payload path invalid")
    if type(item.get("sha256")) is not str or re.fullmatch(r"[0-9a-f]{64}", item["sha256"]) is None or type(item.get("size_bytes")) is not int or item["size_bytes"] <= 0 or type(item.get("source_url")) is not str or not item["source_url"].startswith("https://"):
        raise SystemExit("platform payload metadata invalid")
    size, observed_sha = file_evidence(extension_root / path, f"platform payload {path}")
    if size != item["size_bytes"] or observed_sha != item["sha256"]:
        raise SystemExit(f"platform payload content mismatch: {path}")
    records[path] = item
    total += size
if sorted(item["role"] for item in payloads).count("github_actions_runner") != 1 or sorted(item["role"] for item in payloads).count("ubuntu_noble_qcow2_base") != 1 or sorted(item["role"] for item in payloads).count("offline_deb") != 14:
    raise SystemExit("platform payload role cardinality invalid")
checksum = platform.get("payload_checksum_list")
exact(checksum, {"path", "sha256"}, "platform checksum-list schema drift")
if checksum["path"] != "PLATFORM-PAYLOADS.sha256" or hashlib.sha256(read(extension_root / checksum["path"], "platform checksum list")).hexdigest() != checksum["sha256"]:
    raise SystemExit("platform checksum-list authority mismatch")
expected_lines = [f'{records[path]["sha256"]}  {path}' for path in sorted(records)]
if (extension_root / checksum["path"]).read_text().splitlines() != expected_lines:
    raise SystemExit("platform checksum-list content mismatch")
selection = platform.get("selection") or {}
if selection.get("actions_runner_version") != runner.get("runner_distribution", {}).get("version") or selection.get("docker_engine_version") != "5:29.7.2-1~ubuntu.24.04~noble" or selection.get("compose_required") is not True:
    raise SystemExit("platform version selection drift")
runner_payload = next(item for item in payloads if item["role"] == "github_actions_runner")
if runner_payload["sha256"] != runner["runner_distribution"]["sha256"]:
    raise SystemExit("platform runner archive digest mismatch")
base_payload = next(item for item in payloads if item["role"] == "ubuntu_noble_qcow2_base")
base = manifest.get("base_image") or {}
if base.get("sha256") != base_payload["sha256"] or Path(str(base.get("url", "")).removeprefix("file://")) != extension_root / base_payload["path"]:
    raise SystemExit("platform Ubuntu base-image binding mismatch")
packages = platform.get("packages")
expected_packages = {"containerd.io", "docker-buildx-plugin", "docker-ce", "docker-ce-cli", "docker-ce-rootless-extras", "docker-compose-plugin", "fuse-overlayfs", "liblttng-ust-common1t64", "liblttng-ust-ctl5t64", "liblttng-ust1t64", "libslirp0", "libsubid4", "slirp4netns", "uidmap"}
if type(packages) is not list or {item.get("package") for item in packages if type(item) is dict} != expected_packages:
    raise SystemExit("platform package set drift")
closure = platform.get("dependency_closure") or {}
if closure.get("closed") is not True or closure.get("unresolved_count") != 0 or closure.get("conflicts_or_breaks_count") != 0 or closure.get("selected_package_count") != 14:
    raise SystemExit("platform dependency closure is not complete")
safety = platform.get("installation_safety") or {}
if safety.get("offline_only") is not True or safety.get("network_fallback_forbidden") is not True:
    raise SystemExit("platform installation safety drift")
isolation = platform.get("isolation") or {}
if isolation.get("original_files_modified") is not False or isolation.get("original_payload_count") != 31 or isolation.get("original_payload_manifest_copy", {}).get("sha256") != authority.get("immutable_payload_manifest_sha256"):
    raise SystemExit("platform original-payload isolation drift")
rootless = platform.get("rootless_identities")
expected_rootless = [item for item in runner["runners"] if item.get("enabled") is True and item.get("docker", {}).get("enabled") is True]
if type(rootless) is not list or len(rootless) != 10 or [item.get("name") for item in rootless] != [item["name"] for item in expected_rootless]:
    raise SystemExit("platform rootless identity cardinality drift")
for observed, expected in zip(rootless, expected_rootless):
    if observed.get("uid") != expected["uid"] or observed.get("gid") != expected["gid"] or observed.get("subuid_start") != expected["subuid_start"] or observed.get("subgid_start") != expected["subgid_start"] or observed.get("subid_count") != expected["subid_count"]:
        raise SystemExit("platform rootless identity contract drift")
print(f"PLATFORM_PAYLOADS_OK payloads=16 bytes={total} rootless=10")
PY
}

build_offline() {
  local manifest="$1" lock="$2" policy="$3" endpoint_policy="$4" generation="$5" generation_receipt="$6"
  local task7_lock="$7" onepassword_receipt="$8" payload_root="$9" output_root="${10}"
  local base_image base_sha payload_manifest_sha build_metadata contract contract_sha install_script ci_plan deploy_plan
  local candidate guest size image_path image_sha receipt_path info virtual_size guest_base guest_plan ci_base deploy_base
  local repo_upload_guest repo_upload_source repo_upload_target repo_upload_digest
  local -a candidates=() ci_repo_upload_args=() deploy_repo_upload_args=() guest_repo_upload_args=()

  [[ -f "${manifest}" && ! -L "${manifest}" ]] || die 'guest manifest is missing or unsafe'
  for candidate in "${endpoint_policy}" "${generation}" "${generation_receipt}" "${task7_lock}" "${onepassword_receipt}"; do
    [[ -f "${candidate}" && ! -L "${candidate}" ]] || die 'firewall build authority is missing or unsafe'
  done
  [[ -d "${payload_root}" && ! -L "${payload_root}" ]] || die 'offline payload root is missing or unsafe'
  [[ -f "${payload_root}/PAYLOADS.sha256" && ! -L "${payload_root}/PAYLOADS.sha256" ]] || die 'offline payload manifest is missing or unsafe'
  [[ -d "${payload_root}/payloads" && ! -L "${payload_root}/payloads" ]] || die 'offline payload directory is missing or unsafe'
  [[ "${output_root}" == /* && "${output_root}" != / && "${output_root}" != "${HOME:-/__unset_home__}" ]] || die 'offline output root is unsafe'

  build_metadata="$(python3 - "${manifest}" "${endpoint_policy}" "${generation}" "${generation_receipt}" "${task7_lock}" "${onepassword_receipt}" <<'PY'
import hashlib
import json
import os
import re
import sys
from pathlib import Path
from urllib.parse import unquote, urlparse

import yaml


def _strict_json(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


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
with open(sys.argv[1], encoding="utf-8") as stream:
    manifest = yaml.load(stream, Loader=StrictLoader)
endpoint_policy, generation_path, generation_receipt_path, task7_path, onepassword_path = map(Path, sys.argv[2:])
for path in (endpoint_policy, generation_path, generation_receipt_path, task7_path, onepassword_path):
    if not path.is_file() or path.is_symlink() or path.stat().st_mode & 0o022:
        raise SystemExit("firewall build authority is unsafe")
authority = manifest.get("authority") or {}
readiness = manifest.get("readiness") or {}
if not authority.get("task6_commit"):
    raise SystemExit("missing-final-task6-lock")
for name in (
    "broker_runtime_lock_sha256", "op_broker_policy_sha256", "action_transport_lock_sha256",
    "firewall_endpoint_policy_sha256", "firewall_endpoint_generation_sha256",
    "firewall_endpoint_generation_receipt_sha256", "onepassword_canary_receipt_sha256",
    "immutable_payload_manifest_sha256", "platform_payload_manifest_sha256",
):
    if type(authority.get(name)) is not str or re.fullmatch(r"[0-9a-f]{64}", authority[name]) is None:
        raise SystemExit(f"missing or malformed build authority: {name}")
if authority.get("guest_install_contract_sha256") is not None:
    raise SystemExit("input manifest already has a guest install contract result")
if readiness != {
    "state": "build-ready",
    "live_apply_allowed": False,
    "ready_marker": None,
    "blockers": ["missing-both-guest-runtime-receipts"],
}:
    raise SystemExit("guest manifest is not in the frozen build-ready state")
if type(authority.get("task7_commit")) is not str or re.fullmatch(r"[0-9a-f]{40}", authority["task7_commit"]) is None:
    raise SystemExit("missing or malformed build authority: task7_commit")
for path, key in (
    (endpoint_policy, "firewall_endpoint_policy_sha256"),
    (generation_path, "firewall_endpoint_generation_sha256"),
    (generation_receipt_path, "firewall_endpoint_generation_receipt_sha256"),
    (task7_path, "action_transport_lock_sha256"),
    (onepassword_path, "onepassword_canary_receipt_sha256"),
):
    if hashlib.sha256(path.read_bytes()).hexdigest() != authority[key]:
        raise SystemExit(f"firewall build authority digest mismatch: {key}")
firewall = manifest.get("firewall") or {}
if firewall != {
    "status": "ready", "blocker": None, "refresh_interval_seconds": 900,
    "generation_ttl_seconds": 3600,
    "host_generation_path": "/var/lib/ken-actions/authority/firewall-endpoint-generation.json",
    "guest_generation_path": "/etc/ken-actions/firewall-endpoint-generation.json",
    "guest_base_path": "/etc/ken-actions/guest-base.nft",
    "guest_resolver_path": "/usr/local/libexec/ken-actions-firewall-endpoint-resolve",
}:
    raise SystemExit("firewall build contract is not ready")
try:
    generation = json.loads(generation_path.read_text(), object_pairs_hook=lambda pairs: _strict_json(pairs))
    generation_receipt = json.loads(generation_receipt_path.read_text(), object_pairs_hook=lambda pairs: _strict_json(pairs))
    onepassword_receipt = json.loads(onepassword_path.read_text(), object_pairs_hook=lambda pairs: _strict_json(pairs))
except (UnicodeError, json.JSONDecodeError, ValueError) as error:
    raise SystemExit(f"firewall build receipt is malformed: {error}") from error
if type(generation) is not dict or type(generation.get("schema_version")) is not int or generation["schema_version"] != 1:
    raise SystemExit("firewall generation schema invalid")
expected_generation_authority = {
    "plan_sha256": authority["plan_sha256"],
    "runner_platform_path": authority["runner_platform_path"],
    "runner_platform_sha256": authority["runner_platform_sha256"],
    "broker_runtime_lock_path": authority["broker_runtime_lock_path"],
    "broker_runtime_lock_sha256": authority["broker_runtime_lock_sha256"],
    "op_broker_policy_path": authority["op_broker_policy_path"],
    "op_broker_policy_sha256": authority["op_broker_policy_sha256"],
    "action_transport_lock_path": authority["action_transport_lock_path"],
    "action_transport_lock_sha256": authority["action_transport_lock_sha256"],
    "firewall_endpoint_policy_sha256": authority["firewall_endpoint_policy_sha256"],
}
if generation.get("authority") != expected_generation_authority:
    raise SystemExit("firewall generation manifest authority mismatch")
generation_digest = hashlib.sha256(generation_path.read_bytes()).hexdigest()
expected_generation_receipt = {
    "path": "/var/lib/ken-actions/authority/firewall-endpoint-generation.json",
    "sha256": generation_digest,
    "generated_at_epoch": generation.get("generated_at_epoch"),
    "expires_at_epoch": generation.get("expires_at_epoch"),
}
expected_generation_verification = {
    "public_ipv4_only": True,
    "exact_profiles": True,
    "exact_bridge_unions": True,
    "onepassword_canary_bound": True,
}
if (type(generation_receipt) is not dict or set(generation_receipt) != {"schema_version", "authority", "generation", "verification"}
        or type(generation_receipt.get("schema_version")) is not int or generation_receipt["schema_version"] != 1
        or generation_receipt.get("authority") != expected_generation_authority
        or generation_receipt.get("generation") != expected_generation_receipt
        or generation_receipt.get("verification") != expected_generation_verification):
    raise SystemExit("firewall generation receipt authority mismatch")
now = int(os.environ.get("KEN_ACTIONS_FIREWALL_NOW_EPOCH", "0"))
if (type(generation.get("generated_at_epoch")) is not int or type(generation.get("expires_at_epoch")) is not int
        or generation["expires_at_epoch"] - generation["generated_at_epoch"] != 3600
        or now < generation["generated_at_epoch"] or now >= generation["expires_at_epoch"]):
    raise SystemExit("firewall generation is not live for image build")
if type(onepassword_receipt) is not dict or onepassword_receipt != {
    "schema_version": 1, "status": "ready", "commands": ["op-read", "op-inject", "op-run"],
    "cache": False, "fresh_config": True, "direct_egress": "denied",
    "observed_relay_authorities": ["ken-ai.1password.com:443"],
} or type(onepassword_receipt["schema_version"]) is not int:
    raise SystemExit("1Password Linux canary receipt authority mismatch")
base = manifest.get("base_image") or {}
if base.get("status") != "ready" or base.get("blocker") is not None or base.get("release_identifier") != "ubuntu-24.04" or base.get("architecture") != "amd64":
    raise SystemExit("Ubuntu base-image authority is not ready")
for name in ("sha256", "signed_checksum_file_sha256", "signature_sha256", "dpkg_inventory_sha256"):
    if type(base.get(name)) is not str or re.fullmatch(r"[0-9a-f]{64}", base[name]) is None:
        raise SystemExit(f"Ubuntu base-image authority is malformed: {name}")
if type(base.get("signer_fingerprint")) is not str or re.fullmatch(r"[0-9A-F]{40}", base["signer_fingerprint"]) is None:
    raise SystemExit("Ubuntu base-image signer authority is malformed")
url = urlparse(str(base.get("url", "")))
if url.scheme != "file" or url.netloc not in {"", "localhost"}:
    raise SystemExit("offline build requires a file URL for the verified Ubuntu image")
base_path = Path(unquote(url.path))
for section in ("common_runtime", "ci_image", "deploy_image", "remote_pinned_build_inputs", "generated_files"):
    if (manifest.get(section) or {}).get("status") != "ready":
        raise SystemExit(f"build section is not ready: {section}")
if (manifest.get("verification") or {}).get("network_allowed") is not False:
    raise SystemExit("offline build gained network permission")
ci = manifest.get("ci_image") or {}
deploy = manifest.get("deploy_image") or {}
if ci.get("virtual_size_gib") != 750 or deploy.get("virtual_size_gib") != 80:
    raise SystemExit("derived-image virtual size drift")
if deploy.get("task6_principals") != [22001, 22002, 22003, 22101, 22102, 22103, 22104, 22201, 22202, 22203]:
    raise SystemExit("Task 6 principal image prerequisite drift")
if deploy.get("builder_subuid_range") != "300000:65536" or deploy.get("builder_subgid_range") != "300000:65536":
    raise SystemExit("Task 6 builder subordinate-ID drift")
if not ci.get("platform_payloads") and not (
    __import__("os").environ.get("PROVISION_VMS_COMMAND_TEST") == "1"
    and __import__("os").environ.get("PROVISION_VMS_ALLOW_INCOMPLETE_PLATFORM_TEST") == "1"
):
    raise SystemExit("missing-offline-platform-payload-closure")
print(f'{base_path}|{base["sha256"]}|{authority["immutable_payload_manifest_sha256"]}')
PY
  )"
  IFS='|' read -r base_image base_sha payload_manifest_sha <<<"${build_metadata}"

  [[ -f "${base_image}" && ! -L "${base_image}" ]] || die 'verified Ubuntu base image is missing or unsafe'
  [[ "$(sha256sum "${base_image}" | awk '{print $1}')" == "${base_sha}" ]] || die 'verified Ubuntu base-image digest mismatch'
  [[ "$(sha256sum "${payload_root}/PAYLOADS.sha256" | awk '{print $1}')" == "${payload_manifest_sha}" ]] || die 'offline payload-manifest digest mismatch'
  (
    cd "${payload_root}/payloads"
    sha256sum -c "${payload_root}/PAYLOADS.sha256" >/dev/null
  ) || die 'offline payload hash verification failed'
  if [[ "${PROVISION_VMS_COMMAND_TEST:-0}" != 1 || "${PROVISION_VMS_ALLOW_INCOMPLETE_PLATFORM_TEST:-0}" != 1 ]]; then
    validate_platform_extension "${manifest}" "${payload_root}/platform-extension" >/dev/null
  fi

  validate_runtime_authority "${manifest}" "${lock}" "${policy}"
  while IFS='|' read -r repo_upload_guest repo_upload_source repo_upload_target repo_upload_digest; do
    if [[ ! -f "${repo_upload_source}" || -L "${repo_upload_source}" ]]; then
      if [[ "${PROVISION_VMS_COMMAND_TEST:-0}" == 1 && "${PROVISION_VMS_ALLOW_INCOMPLETE_PLATFORM_TEST:-0}" == 1 ]]; then
        continue
      fi
      die "reviewed repo runtime input is missing: ${repo_upload_source}"
    fi
    [[ "$(sha256sum "${repo_upload_source}" | awk '{print $1}')" == "${repo_upload_digest}" ]] || die "reviewed repo runtime input digest mismatch: ${repo_upload_source}"
    case "${repo_upload_guest}" in
      ken-ci) ci_repo_upload_args+=(--mkdir "$(dirname "${repo_upload_target}")" --upload "${repo_upload_source}:${repo_upload_target}") ;;
      ken-deploy) deploy_repo_upload_args+=(--mkdir "$(dirname "${repo_upload_target}")" --upload "${repo_upload_source}:${repo_upload_target}") ;;
      *) die "reviewed repo runtime host scope is invalid: ${repo_upload_guest}" ;;
    esac
  done < <(python3 - "${lock}" "${GA_ROOT}" <<'PY'
from pathlib import Path
import sys
import yaml

lock = yaml.safe_load(Path(sys.argv[1]).read_text())
root = Path(sys.argv[2])
for entry in lock["installed_files"]:
    source = entry["source"]
    if source.startswith("repo:"):
        for host in entry["hosts"]:
            print(f"{host}|{root / source.removeprefix('repo:')}|{entry['path']}|{entry['sha256']}")
PY
  )
  mkdir -p "${output_root}" "${output_root}/receipts"
  [[ -d "${output_root}" && ! -L "${output_root}" && -d "${output_root}/receipts" && ! -L "${output_root}/receipts" ]] || die 'offline output directories are unsafe'
  contract="$(mktemp "${output_root}/.guest-install-contract.XXXXXX")"
  install_script="$(mktemp "${output_root}/.offline-install.XXXXXX")"
  ci_base="$(mktemp "${output_root}/.ken-ci-base.XXXXXX")"
  deploy_base="$(mktemp "${output_root}/.ken-deploy-base.XXXXXX")"
  ci_plan="$(mktemp "${output_root}/.ken-ci-install-plan.XXXXXX")"
  deploy_plan="$(mktemp "${output_root}/.ken-deploy-install-plan.XXXXXX")"
  candidates+=("${contract}" "${install_script}" "${ci_base}" "${deploy_base}" "${ci_plan}" "${deploy_plan}")
  # shellcheck disable=SC2329
  cleanup_offline_build() {
    local item
    for item in "${candidates[@]}"; do
      [[ -n "${item}" ]] && rm -f -- "${item}"
    done
  }
  trap cleanup_offline_build EXIT

  local host_transport_root="${output_root}/host-transport" relative source_path destination
  mkdir -p "${host_transport_root}"
  [[ -d "${host_transport_root}" && ! -L "${host_transport_root}" ]] || die 'offline host transport root is unsafe'
  while IFS= read -r relative; do
    source_path="${GA_ROOT}/${relative}"
    destination="${host_transport_root}/${relative}"
    [[ -f "${source_path}" && ! -L "${source_path}" ]] || die "reviewed host transport input is missing: ${relative}"
    [[ ! -L "${destination}" ]] || die "offline host transport destination is unsafe: ${relative}"
    mkdir -p "$(dirname "${destination}")"
    install -m 0600 "${source_path}" "${destination}"
  done <<'EOF'
libvirt/ken-ci.xml
libvirt/ken-deploy.xml
cloud-init/ken-ci-user-data.yaml
cloud-init/ken-deploy-user-data.yaml
proxy/ken-actions-artifact-proxy-deploy.conf
proxy/ken-actions-artifact-proxy-runtime.yaml
systemd/ken-actions-artifact-proxy-deploy.service
systemd/ken-actions-vm-firewall.service
systemd/ken-actions-vm-firewall.timer
systemd/ken-actions-vms.service
scripts/lib/vm-firewall.sh
scripts/provision-vms.sh
inventory/runner-platform.yaml
EOF

  # Both image-bound standing policies are rendered from the exact, still-live
  # numeric authority before any image transport is invoked.
  bash -c 'set -euo pipefail; source "$1"; render_ken_actions_numeric_generation guest-base ken-ci none none "$2" "$3"' \
    _ "${GA_ROOT}/scripts/lib/vm-firewall.sh" "${generation}" "${ci_base}" >/dev/null
  bash -c 'set -euo pipefail; source "$1"; render_ken_actions_numeric_generation guest-base ken-deploy none none "$2" "$3"' \
    _ "${GA_ROOT}/scripts/lib/vm-firewall.sh" "${generation}" "${deploy_base}" >/dev/null

  python3 - "${lock}" "${manifest}" "${payload_root}" "${ci_plan}" "${deploy_plan}" <<'PY'
import hashlib
import json
from pathlib import Path
import sys
import yaml

lock_path, manifest_path, payload_root, ci_output, deploy_output = map(Path, sys.argv[1:])
lock = yaml.safe_load(lock_path.read_text())
manifest = yaml.safe_load(manifest_path.read_text())

def checksums(path):
    result = {}
    for line in path.read_text().splitlines():
        digest, name = line.split("  ", 1)
        if name in result or len(digest) != 64:
            raise SystemExit("offline payload checksum manifest invalid")
        result[name] = digest
    return result

payload_hashes = checksums(payload_root / "PAYLOADS.sha256")
platform_hashes = checksums(payload_root / "platform-extension/PLATFORM-PAYLOADS.sha256")
platform_names = {Path(name).name for name in platform_hashes}
provenance = {}
for item in lock.get("provenance_payloads", []):
    if set(item) != {"id","version","filename","source_url","sha256","install_on_guest","purpose"} or item["install_on_guest"] is not False:
        raise SystemExit("offline provenance-only authority invalid")
    provenance[item["filename"]] = item["sha256"]

component_payloads = {}
component_hosts = {}
component_ids_by_filename = {}
for component in lock["components"]:
    if component.get("delivery_class") == "remote-pinned-build-input":
        continue
    entries = component.get("payloads") or [{"filename":component["payload_filename"], "sha256":component["payload_sha256"]}]
    for item in entries:
        name, digest = item["filename"], item["sha256"]
        if name in component_payloads and component_payloads[name] != digest:
            raise SystemExit("offline component payload digest conflict")
        component_payloads[name] = digest
        component_hosts.setdefault(name, set()).update(component["hosts"])
        component_ids_by_filename.setdefault(name, set()).add(component["id"])
if set(payload_hashes) != set(component_payloads) | set(provenance):
    raise SystemExit("offline payload inventory is not the reviewed component plus provenance closure")
for name, digest in {**component_payloads, **provenance}.items():
    if payload_hashes.get(name) != digest:
        raise SystemExit(f"offline reviewed payload digest mismatch: {name}")

platform_selected = json.loads((payload_root / "platform-extension/metadata/selected-packages.json").read_text())
selected_names = {Path(item["Filename"]).name for item in platform_selected}
for guest, output, image_key in (("ken-ci", ci_output, "ci_image"), ("ken-deploy", deploy_output, "deploy_image")):
    declared_platform = set(manifest[image_key]["platform_payloads"])
    if (not declared_platform <= platform_names
            or platform_names - declared_platform != {"noble-server-cloudimg-amd64-20260814.img"}
            or selected_names != {name for name in declared_platform if name.endswith(".deb")}):
        raise SystemExit(f"offline platform dependency closure drift: {guest}")
    original = sorted(name for name, hosts in component_hosts.items() if guest in hosts and name not in declared_platform)
    if set(original) & set(provenance):
        raise SystemExit("provenance-only payload entered guest scope")
    debs = [f"/var/cache/ken-actions/payloads/{name}" for name in original if name.endswith(".deb")]
    debs += [f"/var/cache/ken-actions/platform-extension/payloads/{name}" for name in sorted(selected_names)]
    archives = {}
    for name in original:
        if not name.endswith(".deb"):
            for component_id in sorted(component_ids_by_filename[name]):
                archives[component_id] = f"/var/cache/ken-actions/payloads/{name}"
    runner_name = "actions-runner-linux-x64-2.336.0.tar.gz"
    archives["actions-runner"] = f"/var/cache/ken-actions/platform-extension/payloads/{runner_name}"
    deploy_only = {"buildkit","rootlesskit","node","corepack","pnpm","oci-image-tools"}
    if guest == "ken-ci" and set(archives) & deploy_only:
        raise SystemExit("deploy-only toolchain entered CI guest plan")
    plan = {
        "schema_version": 1,
        "guest": guest,
        "authority": {
            "runtime_lock_sha256": hashlib.sha256(lock_path.read_bytes()).hexdigest(),
            "payload_manifest_sha256": hashlib.sha256((payload_root / "PAYLOADS.sha256").read_bytes()).hexdigest(),
            "platform_payload_manifest_sha256": hashlib.sha256((payload_root / "platform-extension/PLATFORM-PAYLOADS.sha256").read_bytes()).hexdigest(),
        },
        "debs": debs,
        "archives": archives,
        "repo_installed_files": [
            entry for entry in lock["installed_files"]
            if entry["source"].startswith("repo:") and guest in entry["hosts"]
        ],
        "provenance_only": sorted(provenance),
    }
    output.write_text(json.dumps(plan, sort_keys=True, separators=(",", ":")) + "\n")
    output.chmod(0o600)
PY
  mkdir -p "${output_root}/guest-install-plans"
  [[ -d "${output_root}/guest-install-plans" && ! -L "${output_root}/guest-install-plans" ]] || die 'offline guest install-plan output is unsafe'
  install -m 0600 "${ci_plan}" "${output_root}/guest-install-plans/ken-ci.json"
  install -m 0600 "${deploy_plan}" "${output_root}/guest-install-plans/ken-deploy.json"

  python3 - "${manifest}" "${contract}" "${GA_ROOT}/scripts/lib/vm-firewall.sh" "${GA_ROOT}/inventory/runner-platform.yaml" \
    "${GA_ROOT}/scripts/provision-vms.sh" "${endpoint_policy}" "${generation}" "${generation_receipt}" \
    "${task7_lock}" "${onepassword_receipt}" "${ci_base}" "${deploy_base}" "${host_transport_root}" "${ci_plan}" "${deploy_plan}" <<'PY'
import hashlib
import json
from pathlib import Path
import sys
import yaml

manifest = yaml.safe_load(Path(sys.argv[1]).read_text())
authority = manifest["authority"]
contract = {
    "schema_version": 1,
    "authority": {
        key: authority[key]
        for key in (
            "plan_sha256", "task5_integrated_commit", "runner_platform_sha256",
            "task6_commit", "broker_runtime_lock_sha256", "op_broker_policy_sha256",
            "task7_commit", "action_transport_lock_sha256", "firewall_endpoint_policy_sha256",
            "firewall_endpoint_generation_sha256", "firewall_endpoint_generation_receipt_sha256",
            "onepassword_canary_receipt_sha256",
            "immutable_payload_manifest_sha256", "platform_payload_manifest_sha256", "generated_at_input_epoch",
        )
    },
    "base_image": manifest["base_image"],
    "common_runtime": manifest["common_runtime"],
    "guest_images": {"ken-ci": manifest["ci_image"], "ken-deploy": manifest["deploy_image"]},
    "remote_pinned_build_inputs": manifest["remote_pinned_build_inputs"],
    "generated_files": manifest["generated_files"],
    "task4_runtime": {
        "guest_firewall": {
            "path": "/usr/local/libexec/ken-actions-guest-firewall",
            "sha256": hashlib.sha256(Path(sys.argv[3]).read_bytes()).hexdigest(),
        },
        "runner_platform": {
            "path": "/etc/ken-actions/runner-platform.yaml",
            "sha256": hashlib.sha256(Path(sys.argv[4]).read_bytes()).hexdigest(),
        },
        "firewall_endpoint_resolver": {
            "path": "/usr/local/libexec/ken-actions-firewall-endpoint-resolve",
            "sha256": hashlib.sha256(Path(sys.argv[5]).read_bytes()).hexdigest(),
        },
        "firewall_endpoint_policy": {
            "path": "/etc/ken-actions/firewall-endpoint-policy.yaml",
            "sha256": hashlib.sha256(Path(sys.argv[6]).read_bytes()).hexdigest(),
        },
        "firewall_endpoint_generation": {
            "path": "/etc/ken-actions/firewall-endpoint-generation.json",
            "sha256": hashlib.sha256(Path(sys.argv[7]).read_bytes()).hexdigest(),
        },
        "firewall_endpoint_generation_receipt": {
            "path": "/var/lib/ken-actions/receipts/firewall-endpoint-generation.json",
            "sha256": hashlib.sha256(Path(sys.argv[8]).read_bytes()).hexdigest(),
        },
        "action_transport_lock": {
            "path": "/etc/ken-actions/action-transport.lock.yaml",
            "sha256": hashlib.sha256(Path(sys.argv[9]).read_bytes()).hexdigest(),
        },
        "onepassword_canary_receipt": {
            "path": "/var/lib/ken-actions/receipts/onepassword-linux-canary.json",
            "sha256": hashlib.sha256(Path(sys.argv[10]).read_bytes()).hexdigest(),
        },
        "guest_firewall_base": {
            "path": "/etc/ken-actions/guest-base.nft",
            "sha256_by_guest": {
                "ken-ci": hashlib.sha256(Path(sys.argv[11]).read_bytes()).hexdigest(),
                "ken-deploy": hashlib.sha256(Path(sys.argv[12]).read_bytes()).hexdigest(),
            },
        },
        "host_transport": {
            str(path.relative_to(Path(sys.argv[13]))): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(Path(sys.argv[13]).rglob("*"))
            if path.is_file() and not path.is_symlink()
        },
        "guest_install_plans": {
            "ken-ci": hashlib.sha256(Path(sys.argv[14]).read_bytes()).hexdigest(),
            "ken-deploy": hashlib.sha256(Path(sys.argv[15]).read_bytes()).hexdigest(),
        },
        "guest_repo_installed_files": {
            "ken-ci": json.loads(Path(sys.argv[14]).read_text())["repo_installed_files"],
            "ken-deploy": json.loads(Path(sys.argv[15]).read_text())["repo_installed_files"],
        },
    },
    "verification": {
        "network_allowed": manifest["verification"]["network_allowed"],
        "required_commands": manifest["verification"]["required_commands"],
    },
}
Path(sys.argv[2]).write_text(json.dumps(contract, sort_keys=True, separators=(",", ":")) + "\n")
Path(sys.argv[2]).chmod(0o600)
PY
  contract_sha="$(sha256sum "${contract}" | awk '{print $1}')"

  # This script runs only inside virt-customize's network-disabled appliance.
  # It installs the frozen local Debian closure first; archive components and
  # repo-owned files are placed by the explicit copy/upload operations below.
  python3 - "${install_script}" <<'INSTALLER_PY'
from pathlib import Path
import sys

Path(sys.argv[1]).write_text('''#!/usr/bin/env bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
cd /var/cache/ken-actions/payloads
sha256sum -c ../PAYLOADS.sha256
cd /var/cache/ken-actions/platform-extension
sha256sum -c PLATFORM-PAYLOADS.sha256
debs=()
while IFS= read -r deb; do debs+=("${deb}"); done < <(/usr/bin/python3 - <<'PY'
import hashlib,json
from pathlib import Path
plan_path=Path('/etc/ken-actions/guest-install-plan.json')
plan=json.loads(plan_path.read_text())
guest=Path('/etc/ken-actions/guest-class').read_text().strip()
if set(plan) != {'schema_version','guest','authority','debs','archives','repo_installed_files','provenance_only'} or type(plan['schema_version']) is not int or plan['schema_version'] != 1 or plan['guest'] != guest:
    raise SystemExit('guest-install-plan-schema-invalid')
if set(plan['authority']) != {'runtime_lock_sha256','payload_manifest_sha256','platform_payload_manifest_sha256'}:
    raise SystemExit('guest-install-plan-authority-invalid')
for path,key in ((Path('/etc/ken-op-broker/broker-runtime.lock.yaml'),'runtime_lock_sha256'),(Path('/var/cache/ken-actions/PAYLOADS.sha256'),'payload_manifest_sha256'),(Path('/var/cache/ken-actions/platform-extension/PLATFORM-PAYLOADS.sha256'),'platform_payload_manifest_sha256')):
    if hashlib.sha256(path.read_bytes()).hexdigest() != plan['authority'][key]:
        raise SystemExit('guest-install-plan-authority-mismatch')
if 'ubuntu-keyring_2023.11.28.1_all.deb' not in plan['provenance_only']:
    raise SystemExit('guest-install-plan-provenance-missing')
if any(Path(item).name in plan['provenance_only'] for item in plan['debs']):
    raise SystemExit('guest-install-plan-provenance-installed')
deploy_only={'buildkit','rootlesskit','node','corepack','pnpm','oci-image-tools'}
if guest == 'ken-ci' and set(plan['archives']) & deploy_only:
    raise SystemExit('guest-install-plan-scope-invalid')
if type(plan['repo_installed_files']) is not list:
    raise SystemExit('guest-install-plan-repo-scope-invalid')
for deb in plan['debs']:
    path=Path(deb)
    if not path.is_file() or path.is_symlink() or path.suffix != '.deb':
        raise SystemExit('guest-install-plan-deb-invalid')
    print(deb)
PY
)
(( ${#debs[@]} > 0 ))
policy_created=0
if [[ -e /usr/sbin/policy-rc.d ]]; then
  cp -a /usr/sbin/policy-rc.d /var/cache/ken-actions/policy-rc.d.saved
else
  policy_created=1
fi
printf '#!/bin/sh\\nexit 101\\n' >/usr/sbin/policy-rc.d
chmod 0755 /usr/sbin/policy-rc.d
systemctl mask docker.service docker.socket containerd.service
dpkg --unpack "${debs[@]}"
dpkg --configure -a
if (( policy_created == 1 )); then rm -f /usr/sbin/policy-rc.d; else mv /var/cache/ken-actions/policy-rc.d.saved /usr/sbin/policy-rc.d; fi
install -d -m 0755 /usr/local/bin /usr/local/libexec/ken-actions /opt/ken-toolchain
chmod 0755 /usr/local/libexec/ken-actions-guest-firewall
chmod 0755 /usr/local/libexec/ken-actions-firewall-endpoint-resolve
chmod 0644 /etc/ken-actions/runner-platform.yaml
chmod 0600 /etc/ken-actions/firewall-endpoint-policy.yaml /etc/ken-actions/firewall-endpoint-generation.json /etc/ken-actions/action-transport.lock.yaml /etc/ken-actions/guest-base.nft
chmod 0600 /var/lib/ken-actions/receipts/firewall-endpoint-generation.json /var/lib/ken-actions/receipts/onepassword-linux-canary.json
install -d -m 0755 /opt/ken-actions/payloads
install -m 0444 /var/cache/ken-actions/platform-extension/payloads/actions-runner-linux-x64-2.336.0.tar.gz /opt/ken-actions/payloads/actions-runner-linux-x64-2.336.0.tar.gz
test "$(sha256sum /opt/ken-actions/payloads/actions-runner-linux-x64-2.336.0.tar.gz | awk '{print $1}')" = 04cf0be1aff4c3ec3554466c39124ca250e3effd8873bb7e8d68535aa9505d5d
test -x /usr/bin/dockerd-rootless-setuptool.sh
test -x /usr/bin/newuidmap
test -x /usr/bin/newgidmap
test "$(stat -c '%u:%g:%a' /usr/bin/newuidmap)" = 0:0:4755
test "$(stat -c '%u:%g:%a' /usr/bin/newgidmap)" = 0:0:4755
systemctl is-enabled docker.service | grep -qx masked
systemctl is-enabled docker.socket | grep -qx masked
unzip -p /var/cache/ken-actions/payloads/op_linux_amd64_v2.39.0.zip op > /usr/local/bin/op
chmod 0755 /usr/local/bin/op
guest="$(cat /etc/ken-actions/guest-class)"
if [[ "${guest}" == ken-deploy ]]; then
  tar -xzf /var/cache/ken-actions/payloads/buildkit-v0.24.0.linux-amd64.tar.gz -C /usr/local --strip-components=0
  tar -xzf /var/cache/ken-actions/payloads/rootlesskit-x86_64-v2.3.6.tar.gz -C /usr/local/bin
  tar -xJf /var/cache/ken-actions/payloads/node-v22.20.0-linux-x64.tar.xz -C /opt/ken-toolchain
  install -d -m 0755 /opt/ken-toolchain/lib/node_modules/pnpm
  tar -xzf /var/cache/ken-actions/payloads/pnpm-10.28.2.tgz -C /opt/ken-toolchain/lib/node_modules/pnpm --strip-components=1
  tar -xzf /var/cache/ken-actions/payloads/go-containerregistry_Linux_x86_64-v0.21.7.tar.gz -C /usr/local/bin crane gcrane krane
fi
update-ca-certificates --fresh
test "$(/usr/local/bin/op --version)" = 2.39.0
/usr/bin/python3.12 -I /usr/local/libexec/ken-actions/runtime-known-answer.py yaml-duplicate-key
/usr/bin/python3.12 -I /usr/local/libexec/ken-actions/runtime-known-answer.py jwt-rs256
test -s /etc/ssl/certs/ca-certificates.crt
/usr/bin/python3.12 -I - <<'PY'
import hashlib
import json
from pathlib import Path
import re
import stat
import subprocess
import yaml

class StrictLoader(yaml.SafeLoader):
    pass

def mapping(loader, node, deep=False):
    seen = set()
    for key_node, _ in node.value:
        key = loader.construct_object(key_node, deep=False)
        if key in seen:
            raise SystemExit(f"duplicate-yaml-key:{key}")
        seen.add(key)
    return yaml.SafeLoader.construct_mapping(loader, node, deep=deep)

StrictLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, mapping)
lock = yaml.load(Path("/etc/ken-op-broker/broker-runtime.lock.yaml").read_text(), Loader=StrictLoader)
if type(lock) is not dict or type(lock.get("schema_version")) is not int or lock["schema_version"] != 1:
    raise SystemExit("runtime-lock-schema-invalid")
guest = Path("/etc/ken-actions/guest-class").read_text().strip()
if guest not in {"ken-ci", "ken-deploy"}:
    raise SystemExit("guest-class-invalid")
selected = [entry for entry in lock.get("installed_files", []) if guest in entry.get("hosts", [])]
foreign = [entry for entry in lock.get("installed_files", []) if guest not in entry.get("hosts", [])]
if not selected or len({entry.get("path") for entry in selected}) != len(selected):
    raise SystemExit("installed-file-cardinality-invalid")
plan = json.loads(Path("/etc/ken-actions/guest-install-plan.json").read_text())
expected_repo = [entry for entry in selected if entry["source"].startswith("repo:")]
if plan.get("repo_installed_files") != expected_repo:
    raise SystemExit("guest-install-plan-repo-scope-invalid")
for entry in foreign:
    if set(entry) != {"path", "sha256", "hosts", "source"}:
        raise SystemExit("installed-file-schema-invalid")
    path = Path(entry["path"])
    if path.exists() or path.is_symlink():
        raise SystemExit(f"wrong-host-runtime-file-present:{path}")
locked = {}
for entry in selected:
    if set(entry) != {"path", "sha256", "hosts", "source"}:
        raise SystemExit("installed-file-schema-invalid")
    path = Path(entry["path"])
    if not path.is_absolute() or not path.is_file() or path.is_symlink() or not stat.S_ISREG(path.stat().st_mode):
        raise SystemExit("installed-file-invalid")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if digest != entry["sha256"]:
        raise SystemExit("installed-file-digest-mismatch")
    locked[str(path)] = digest

import cryptography
import jwt
import yaml as imported_yaml

modules = {
    "yaml": (imported_yaml, "6.0.1"),
    "jwt": (jwt, "2.7.0"),
    "cryptography": (cryptography, "41.0.7"),
}
imports = {}
for name, (module, version) in modules.items():
    path = str(Path(module.__file__).resolve())
    if path not in locked or str(getattr(module, "__version__", "")) != version:
        raise SystemExit(f"runtime-import-origin-or-version-mismatch:{name}")
    imports[name] = {"path": path, "sha256": locked[path], "version": version}

native_paths = [
    "/usr/lib/python3/dist-packages/yaml/_yaml.cpython-312-x86_64-linux-gnu.so",
    "/usr/lib/python3/dist-packages/cryptography/hazmat/bindings/_rust.abi3.so",
]
native = {}
for raw in native_paths:
    path = Path(raw)
    header = path.read_bytes()[:20]
    if header[:4] != b"\x7fELF" or header[4] != 2 or int.from_bytes(header[18:20], "little") != 62:
        raise SystemExit("native-elf-abi-mismatch")
    result = subprocess.run(["/usr/bin/ldd", raw], text=True, capture_output=True, check=False)
    if result.returncode != 0 or "not found" in result.stdout + result.stderr:
        raise SystemExit("native-soname-resolution-failed")
    sonames = sorted(set(re.findall(r"(?:^|\\s)([A-Za-z0-9_.+-]+[.]so(?:[.][0-9]+)*)", result.stdout, re.M)))
    if not sonames or raw not in locked:
        raise SystemExit("native-soname-evidence-missing")
    native[raw] = {"sha256": locked[raw], "elf_machine": "Advanced Micro Devices X86-64", "sonames": sonames}

ca = Path("/etc/ssl/certs/ca-certificates.crt")
runner_archive = Path("/opt/ken-actions/payloads/actions-runner-linux-x64-2.336.0.tar.gz")
package_versions = {}
for package in (
    "containerd.io", "docker-buildx-plugin", "docker-ce", "docker-ce-cli",
    "docker-ce-rootless-extras", "docker-compose-plugin", "fuse-overlayfs",
    "liblttng-ust-common1t64", "liblttng-ust-ctl5t64", "liblttng-ust1t64",
    "libslirp0", "libsubid4", "slirp4netns", "uidmap",
):
    result = subprocess.run(["/usr/bin/dpkg-query", "-W", "-f=${Version}", package], text=True, capture_output=True, check=True)
    package_versions[package] = result.stdout
platform = {
    "runner_archive": {
        "path": str(runner_archive),
        "sha256": hashlib.sha256(runner_archive.read_bytes()).hexdigest(),
        "mode": format(stat.S_IMODE(runner_archive.stat().st_mode), "04o"),
    },
    "package_versions": package_versions,
    "newuidmap": {"path": "/usr/bin/newuidmap", "mode": format(stat.S_IMODE(Path("/usr/bin/newuidmap").stat().st_mode), "04o")},
    "newgidmap": {"path": "/usr/bin/newgidmap", "mode": format(stat.S_IMODE(Path("/usr/bin/newgidmap").stat().st_mode), "04o")},
    "rootful_services_masked": all(
        subprocess.run(["/usr/bin/systemctl", "is-enabled", unit], text=True, capture_output=True).stdout.strip() == "masked"
        for unit in ("docker.service", "docker.socket", "containerd.service")
    ),
}
receipt = {
    "schema_version": 1,
    "ca_bundle_sha256": hashlib.sha256(ca.read_bytes()).hexdigest(),
    "op_version": subprocess.run(["/usr/local/bin/op", "--version"], text=True, capture_output=True, check=True).stdout.strip(),
    "imports": imports,
    "native_objects": native,
    "runtime_scope": {
        "present": locked,
        "absent": sorted(entry["path"] for entry in foreign),
    },
    "platform": platform,
}
output = Path("/var/lib/ken-actions/offline-runtime-receipt.json")
output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
output.write_text(json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n")
output.chmod(0o600)
PY
''')
Path(sys.argv[1]).chmod(0o700)
INSTALLER_PY

  for guest in ken-ci ken-deploy; do
    if [[ "${guest}" == ken-ci ]]; then
      size=750; guest_base="${ci_base}"; guest_plan="${ci_plan}"
      guest_repo_upload_args=()
      if [[ -n "${ci_repo_upload_args[0]+present}" ]]; then guest_repo_upload_args=("${ci_repo_upload_args[@]}"); fi
    else
      size=80; guest_base="${deploy_base}"; guest_plan="${deploy_plan}"
      guest_repo_upload_args=()
      if [[ -n "${deploy_repo_upload_args[0]+present}" ]]; then guest_repo_upload_args=("${deploy_repo_upload_args[@]}"); fi
    fi
    image_path="${output_root}/${guest}.qcow2"
    candidate="$(mktemp "${output_root}/.${guest}.candidate.XXXXXX")"
    candidates+=("${candidate}")
    qemu-img convert -O qcow2 -o compat=1.1,lazy_refcounts=on "${base_image}" "${candidate}"
    qemu-img resize "${candidate}" "${size}G"
    virt-customize --no-network -a "${candidate}" \
      --mkdir /var/cache/ken-actions \
      --copy-in "${payload_root}/payloads:/var/cache/ken-actions" \
      --upload "${payload_root}/PAYLOADS.sha256:/var/cache/ken-actions/PAYLOADS.sha256" \
      --mkdir /var/cache/ken-actions/platform-extension \
      --copy-in "${payload_root}/platform-extension/payloads:/var/cache/ken-actions/platform-extension" \
      --upload "${payload_root}/platform-extension/PLATFORM-PAYLOADS.sha256:/var/cache/ken-actions/platform-extension/PLATFORM-PAYLOADS.sha256" \
      --mkdir /etc/ken-actions \
      --mkdir /etc/ken-op-broker \
      --mkdir /var/lib/ken-actions/receipts \
      --mkdir /usr/local/sbin \
      --write "/etc/ken-actions/guest-class:${guest}" \
      --upload "${guest_plan}:/etc/ken-actions/guest-install-plan.json" \
      --upload "${contract}:/etc/ken-actions/guest-install-contract.yaml" \
      --upload "${lock}:/etc/ken-op-broker/broker-runtime.lock.yaml" \
      --upload "${policy}:/etc/ken-op-broker/op-broker-policy.yaml" \
      --upload "${GA_ROOT}/inventory/runner-platform.yaml:/etc/ken-actions/runner-platform.yaml" \
      --upload "${endpoint_policy}:/etc/ken-actions/firewall-endpoint-policy.yaml" \
      --upload "${generation}:/etc/ken-actions/firewall-endpoint-generation.json" \
      --upload "${generation_receipt}:/var/lib/ken-actions/receipts/firewall-endpoint-generation.json" \
      --upload "${task7_lock}:/etc/ken-actions/action-transport.lock.yaml" \
      --upload "${onepassword_receipt}:/var/lib/ken-actions/receipts/onepassword-linux-canary.json" \
      --upload "${guest_base}:/etc/ken-actions/guest-base.nft" \
      --mkdir /usr/local/libexec \
      --upload "${GA_ROOT}/scripts/lib/vm-firewall.sh:/usr/local/libexec/ken-actions-guest-firewall" \
      --upload "${GA_ROOT}/scripts/provision-vms.sh:/usr/local/libexec/ken-actions-firewall-endpoint-resolve" \
      --upload "${install_script}:/usr/local/sbin/ken-actions-offline-install" \
      ${guest_repo_upload_args[@]+"${guest_repo_upload_args[@]}"} \
      --run-command /usr/local/sbin/ken-actions-offline-install
    [[ "${KEN_ACTIONS_INJECT_FAILURE:-}" != "after-${guest}-customize" ]] || die "injected failure: after-${guest}-customize"
    qemu-img check "${candidate}" >/dev/null
    info="$(qemu-img info --output=json "${candidate}")"
    virtual_size="$(python3 -c 'import json,sys; value=json.load(sys.stdin); print(value.get("virtual-size", -1))' <<<"${info}")"
    [[ "${virtual_size}" == "$((size * 1024 * 1024 * 1024))" ]] || die "${guest} qcow2 virtual-size mismatch"
    observed="$(mktemp "${output_root}/.${guest}.observed-runtime.XXXXXX")"
    candidates+=("${observed}")
    virt-cat -a "${candidate}" /var/lib/ken-actions/offline-runtime-receipt.json >"${observed}"
    python3 - "${lock}" "${observed}" "${guest}" <<'PY'
import json
from pathlib import Path
import re
import sys
import yaml

lock = yaml.safe_load(Path(sys.argv[1]).read_text())
observed = json.loads(Path(sys.argv[2]).read_text())
guest = sys.argv[3]
if guest not in {"ken-ci", "ken-deploy"}:
    raise SystemExit("observed guest scope invalid")
if set(observed) != {"schema_version", "ca_bundle_sha256", "op_version", "imports", "native_objects", "runtime_scope", "platform"}:
    raise SystemExit("observed runtime receipt schema drift")
if type(observed["schema_version"]) is not int or observed["schema_version"] != 1:
    raise SystemExit("observed runtime receipt version invalid")
if not re.fullmatch(r"[0-9a-f]{64}", str(observed["ca_bundle_sha256"])):
    raise SystemExit("observed CA bundle digest invalid")
components = {item["id"]: item for item in lock["components"]}
if observed["op_version"] != components["1password-cli"]["version"]:
    raise SystemExit("observed op version mismatch")
installed = {item["path"]: item["sha256"] for item in lock["installed_files"]}
expected_present = {
    item["path"]: item["sha256"] for item in lock["installed_files"]
    if guest in item["hosts"]
}
expected_absent = sorted(
    item["path"] for item in lock["installed_files"] if guest not in item["hosts"]
)
if observed["runtime_scope"] != {"present": expected_present, "absent": expected_absent}:
    raise SystemExit("observed runtime host scope mismatch")
expected_imports = {
    "yaml": ("/usr/lib/python3/dist-packages/yaml/__init__.py", "6.0.1"),
    "jwt": ("/usr/lib/python3/dist-packages/jwt/__init__.py", "2.7.0"),
    "cryptography": ("/usr/lib/python3/dist-packages/cryptography/__init__.py", "41.0.7"),
}
if set(observed["imports"]) != set(expected_imports):
    raise SystemExit("observed import set mismatch")
for name, (path, version) in expected_imports.items():
    if observed["imports"][name] != {"path": path, "sha256": installed[path], "version": version}:
        raise SystemExit(f"observed import authority mismatch: {name}")
native_paths = {
    "/usr/lib/python3/dist-packages/yaml/_yaml.cpython-312-x86_64-linux-gnu.so",
    "/usr/lib/python3/dist-packages/cryptography/hazmat/bindings/_rust.abi3.so",
}
if set(observed["native_objects"]) != native_paths:
    raise SystemExit("observed native object set mismatch")
for path, evidence in observed["native_objects"].items():
    if set(evidence) != {"sha256", "elf_machine", "sonames"} or evidence["sha256"] != installed[path] or evidence["elf_machine"] != "Advanced Micro Devices X86-64" or not isinstance(evidence["sonames"], list) or not evidence["sonames"]:
        raise SystemExit(f"observed native ABI or SONAME mismatch: {path}")
platform = observed["platform"]
if set(platform) != {"runner_archive", "package_versions", "newuidmap", "newgidmap", "rootful_services_masked"}:
    raise SystemExit("observed platform receipt schema drift")
if platform["runner_archive"] != {"path":"/opt/ken-actions/payloads/actions-runner-linux-x64-2.336.0.tar.gz", "sha256":"04cf0be1aff4c3ec3554466c39124ca250e3effd8873bb7e8d68535aa9505d5d", "mode":"0444"}:
    raise SystemExit("observed runner archive authority mismatch")
expected_packages = {
    "containerd.io": "2.3.3-1~ubuntu.24.04~noble",
    "docker-buildx-plugin": "0.36.1-1~ubuntu.24.04~noble",
    "docker-ce": "5:29.7.2-1~ubuntu.24.04~noble",
    "docker-ce-cli": "5:29.7.2-1~ubuntu.24.04~noble",
    "docker-ce-rootless-extras": "5:29.7.2-1~ubuntu.24.04~noble",
    "docker-compose-plugin": "5.5.0-1~ubuntu.24.04~noble",
    "fuse-overlayfs": "1.13-1",
    "liblttng-ust-common1t64": "2.13.7-1.1ubuntu2",
    "liblttng-ust-ctl5t64": "2.13.7-1.1ubuntu2",
    "liblttng-ust1t64": "2.13.7-1.1ubuntu2",
    "libslirp0": "4.7.0-1ubuntu3.1",
    "libsubid4": "1:4.13+dfsg1-4ubuntu3.2",
    "slirp4netns": "1.2.1-1build2",
    "uidmap": "1:4.13+dfsg1-4ubuntu3.2",
}
if platform["package_versions"] != expected_packages:
    raise SystemExit("observed platform package version mismatch")
if platform["newuidmap"] != {"path":"/usr/bin/newuidmap", "mode":"4755"} or platform["newgidmap"] != {"path":"/usr/bin/newgidmap", "mode":"4755"} or platform["rootful_services_masked"] is not True:
    raise SystemExit("observed rootless prerequisite mismatch")
PY
    image_sha="$(sha256sum "${candidate}" | awk '{print $1}')"
    if [[ -e "${image_path}" ]]; then
      [[ -f "${image_path}" && ! -L "${image_path}" ]] || die "existing ${guest} image is unsafe"
      [[ "$(sha256sum "${image_path}" | awk '{print $1}')" == "${image_sha}" ]] || die "existing ${guest} image differs from frozen build"
      rm -f -- "${candidate}"
    else
      mv -- "${candidate}" "${image_path}"
    fi
    candidate=''
    receipt_path="${output_root}/receipts/${guest}.json"
    python3 - "${manifest}" "${guest}" "${size}" "${image_sha}" "${contract_sha}" "${observed}" "${receipt_path}" <<'PY'
import json
from pathlib import Path
import sys
import yaml

manifest = yaml.safe_load(Path(sys.argv[1]).read_text())
guest, size, image_sha, contract_sha, observed_path, output = sys.argv[2:]
authority = manifest["authority"]
receipt = {
    "schema_version": 1,
    "guest": guest,
    "authority": {
        "plan_sha256": authority["plan_sha256"],
        "task5_integrated_commit": authority["task5_integrated_commit"],
        "task6_commit": authority["task6_commit"],
        "runner_platform_sha256": authority["runner_platform_sha256"],
        "broker_runtime_lock_sha256": authority["broker_runtime_lock_sha256"],
        "op_broker_policy_sha256": authority["op_broker_policy_sha256"],
        "task7_commit": authority["task7_commit"],
        "action_transport_lock_sha256": authority["action_transport_lock_sha256"],
        "firewall_endpoint_policy_sha256": authority["firewall_endpoint_policy_sha256"],
        "firewall_endpoint_generation_sha256": authority["firewall_endpoint_generation_sha256"],
        "firewall_endpoint_generation_receipt_sha256": authority["firewall_endpoint_generation_receipt_sha256"],
        "onepassword_canary_receipt_sha256": authority["onepassword_canary_receipt_sha256"],
        "immutable_payload_manifest_sha256": authority["immutable_payload_manifest_sha256"],
        "platform_payload_manifest_sha256": authority["platform_payload_manifest_sha256"],
        "guest_install_contract_sha256": contract_sha,
    },
    "image": {
        "path": f"/mnt/data/libvirt/images/{guest}.qcow2",
        "sha256": image_sha,
        "virtual_size_gib": int(size),
    },
    "verification": {
        "network_disabled": True,
        "qemu_img_check": True,
        "runtime_hashes": True,
        "import_versions": True,
        "native_abi_soname": True,
        "op_exact_version": True,
        "ca_bundle": True,
        "platform_known_answers": True,
        "numeric_firewall_authority": True,
        "guest_firewall_base": True,
    },
    "observed_runtime": json.loads(Path(observed_path).read_text()),
}
path = Path(output)
path.write_text(json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n")
path.chmod(0o600)
PY
  done

  install -m 0600 "${endpoint_policy}" "${output_root}/firewall-endpoint-policy.yaml"
  install -m 0600 "${generation}" "${output_root}/firewall-endpoint-generation.json"
  install -m 0600 "${generation_receipt}" "${output_root}/firewall-endpoint-generation.receipt.json"
  install -m 0600 "${task7_lock}" "${output_root}/action-transport.lock.yaml"
  install -m 0600 "${onepassword_receipt}" "${output_root}/onepassword-linux-canary.json"

  python3 - "${manifest}" "${output_root}" "${contract_sha}" <<'PY'
import hashlib
from pathlib import Path
import sys
import yaml

manifest_path, output_root, contract_sha = sys.argv[1:]
output = Path(output_root)
manifest = yaml.safe_load(Path(manifest_path).read_text())
manifest["authority"]["guest_install_contract_sha256"] = contract_sha
manifest["derived_images"]["status"] = "ready"
for guest, key, size in (("ken-ci", "ci", 750), ("ken-deploy", "deploy", 80)):
    image = output / f"{guest}.qcow2"
    receipt = output / f"receipts/{guest}.json"
    image_sha = hashlib.sha256(image.read_bytes()).hexdigest()
    receipt_sha = hashlib.sha256(receipt.read_bytes()).hexdigest()
    manifest["derived_images"][key] = {
        "path": f"/mnt/data/libvirt/images/{guest}.qcow2",
        "sha256": image_sha,
        "virtual_size_gib": size,
        "receipt_sha256": receipt_sha,
    }
    manifest["verification"]["result_receipts"][key] = {
        "path": f"/var/lib/ken-actions/receipts/{guest}.json",
        "sha256": receipt_sha,
    }
manifest["readiness"] = {
    "state": "ready",
    "live_apply_allowed": True,
    "ready_marker": "receipts-verified",
    "blockers": [],
}
ready = output / "guest-image-manifest.ready.yaml"
ready.write_text(yaml.safe_dump(manifest, sort_keys=False))
ready.chmod(0o600)
PY
  cp "${contract}" "${output_root}/guest-install-contract.json"
  chmod 0600 "${output_root}/guest-install-contract.json"
  cleanup_offline_build
  trap - EXIT
  printf 'OFFLINE_BUILD_OK contract_sha256=%s\n' "${contract_sha}"
}

validate_apply_ready() {
  local manifest="$1" lock="$2" policy="$3" build_root="$4" approval="$5"
  python3 - "${manifest}" "${lock}" "${policy}" "${build_root}" "${approval}" <<'PY'
import hashlib
import json
import math
import os
import re
import stat
import sys
from pathlib import Path

import yaml


class StrictLoader(yaml.SafeLoader):
    pass


def yaml_mapping(loader, node, deep=False):
    seen = set()
    for key_node, _ in node.value:
        key = loader.construct_object(key_node, deep=False)
        if key in seen:
            raise SystemExit(f"duplicate YAML key: {key}")
        seen.add(key)
    return yaml.SafeLoader.construct_mapping(loader, node, deep=deep)


StrictLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, yaml_mapping)


def duplicate_json(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def invalid_constant(value):
    raise ValueError(f"invalid numeric constant: {value}")


def read_file(path, label, *, approval=False):
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise SystemExit(f"{label} is missing or unsafe") from error
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise SystemExit(f"{label} is not regular")
        mode = stat.S_IMODE(metadata.st_mode)
        if approval and mode != 0o600:
            raise SystemExit("approval evidence must be mode 0600")
        if not approval and mode & 0o022:
            raise SystemExit(f"{label} has unsafe mode")
        test_owner = os.environ.get("PROVISION_VMS_COMMAND_TEST") == "1" and os.environ.get("PROVISION_VMS_TEST_ALLOW_CURRENT_OWNER") == "1"
        if approval and metadata.st_uid != 0 and not (test_owner and metadata.st_uid == os.getuid()):
            raise SystemExit("approval evidence must be root-owned mode 0600")
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = -1
            return stream.read()
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def exact(value, keys, message):
    if type(value) is not dict or set(value) != set(keys):
        raise SystemExit(message)


def sha(value, message):
    if type(value) is not str or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise SystemExit(message)


manifest_path, lock_path, policy_path, build_root, approval_path = map(Path, sys.argv[1:])
if not build_root.is_dir() or build_root.is_symlink():
    raise SystemExit("build root is missing or unsafe")
manifest_bytes = read_file(manifest_path, "ready guest manifest")
lock_bytes = read_file(lock_path, "runtime lock")
policy_bytes = read_file(policy_path, "broker policy")
approval_bytes = read_file(approval_path, "approval evidence", approval=True)
contract_bytes = read_file(build_root / "guest-install-contract.json", "ready install contract")
try:
    manifest = yaml.load(manifest_bytes.decode(), Loader=StrictLoader)
    evidence = json.loads(approval_bytes, object_pairs_hook=duplicate_json, parse_constant=invalid_constant)
    contract = json.loads(contract_bytes, object_pairs_hook=duplicate_json, parse_constant=invalid_constant)
except (UnicodeError, yaml.YAMLError, json.JSONDecodeError, ValueError) as error:
    raise SystemExit(f"approval or manifest is malformed: {error}") from error

exact(evidence, {
    "schema_version", "approval_phrase", "combined_approval_verified", "host",
    "host_memory_available_gib", "firewall_generation_verified",
    "artifact_authority", "vms",
}, "approval evidence schema mismatch")
if type(evidence["schema_version"]) is not int or evidence["schema_version"] != 1:
    raise SystemExit("approval evidence schema mismatch")
if evidence["approval_phrase"] != "Task 4/6 approved and 1Password ready" or evidence["combined_approval_verified"] is not True:
    raise SystemExit("combined Task 4/6 approval evidence is missing")
if evidence["host"] != "root@167.235.8.250" or evidence["firewall_generation_verified"] is not True:
    raise SystemExit("approval host or firewall evidence mismatch")
memory = evidence["host_memory_available_gib"]
if isinstance(memory, bool) or not isinstance(memory, (int, float)) or not math.isfinite(memory) or memory < 32:
    raise SystemExit("approval host memory evidence is below 32 GiB")
exact(evidence["artifact_authority"], {
    "task6_runtime_lock_sha256", "action_transport_lock_sha256",
    "firewall_endpoint_policy_sha256", "firewall_endpoint_generation_sha256",
    "firewall_endpoint_generation_receipt_sha256", "onepassword_canary_receipt_sha256",
    "guest_install_contract_sha256", "guest_image_manifest_sha256", "derived_images",
}, "approval artifact authority schema mismatch")
exact(evidence["artifact_authority"]["derived_images"], {"ken-ci", "ken-deploy"}, "approval image authority schema mismatch")
exact(evidence["vms"], {"ken-ci", "ken-deploy"}, "approval VM authority schema mismatch")

if type(manifest) is not dict or type(manifest.get("schema_version")) is not int or manifest["schema_version"] != 1:
    raise SystemExit("ready guest manifest schema mismatch")
authority = manifest.get("authority") or {}
for key in (
    "plan_sha256", "runner_platform_sha256", "broker_runtime_lock_sha256", "op_broker_policy_sha256",
    "action_transport_lock_sha256", "firewall_endpoint_policy_sha256",
    "firewall_endpoint_generation_sha256", "firewall_endpoint_generation_receipt_sha256",
    "onepassword_canary_receipt_sha256", "guest_install_contract_sha256",
    "immutable_payload_manifest_sha256", "platform_payload_manifest_sha256",
):
    sha(authority.get(key), f"ready guest manifest authority malformed: {key}")
if hashlib.sha256(contract_bytes).hexdigest() != authority["guest_install_contract_sha256"]:
    raise SystemExit("ready install contract digest mismatch")
contract_authority = contract.get("authority") if type(contract) is dict else None
if type(contract_authority) is not dict or any(
        contract_authority.get(key) != authority.get(key)
        for key in contract_authority):
    raise SystemExit("ready install contract authority mismatch")
host_transport = (contract.get("task4_runtime") or {}).get("host_transport")
expected_host_transport = {
    "libvirt/ken-ci.xml", "libvirt/ken-deploy.xml",
    "cloud-init/ken-ci-user-data.yaml", "cloud-init/ken-deploy-user-data.yaml",
    "proxy/ken-actions-artifact-proxy-deploy.conf", "proxy/ken-actions-artifact-proxy-runtime.yaml",
    "systemd/ken-actions-artifact-proxy-deploy.service", "systemd/ken-actions-vm-firewall.service",
    "systemd/ken-actions-vm-firewall.timer", "systemd/ken-actions-vms.service",
    "scripts/lib/vm-firewall.sh", "scripts/provision-vms.sh", "inventory/runner-platform.yaml",
}
if type(host_transport) is not dict or set(host_transport) != expected_host_transport:
    raise SystemExit("ready host transport authority mismatch")
for relative, digest in host_transport.items():
    sha(digest, f"ready host transport digest malformed: {relative}")
    path = build_root / "host-transport" / relative
    value = read_file(path, f"ready host transport: {relative}")
    if hashlib.sha256(value).hexdigest() != digest:
        raise SystemExit(f"ready host transport digest mismatch: {relative}")
guest_install_plans = (contract.get("task4_runtime") or {}).get("guest_install_plans")
if type(guest_install_plans) is not dict or set(guest_install_plans) != {"ken-ci", "ken-deploy"}:
    raise SystemExit("ready guest install-plan authority mismatch")
for guest, digest_value in guest_install_plans.items():
    sha(digest_value, f"ready guest install-plan digest malformed: {guest}")
    plan_value = read_file(build_root / "guest-install-plans" / f"{guest}.json", f"ready guest install plan: {guest}")
    if hashlib.sha256(plan_value).hexdigest() != digest_value:
        raise SystemExit(f"ready guest install-plan digest mismatch: {guest}")
if hashlib.sha256(lock_bytes).hexdigest() != authority["broker_runtime_lock_sha256"] or hashlib.sha256(policy_bytes).hexdigest() != authority["op_broker_policy_sha256"]:
    raise SystemExit("ready guest manifest Task 6 authority mismatch")
if manifest.get("readiness") != {"state": "ready", "live_apply_allowed": True, "ready_marker": "receipts-verified", "blockers": []}:
    raise SystemExit("ready guest manifest state mismatch")
if manifest.get("firewall") != {
    "status": "ready", "blocker": None, "refresh_interval_seconds": 900,
    "generation_ttl_seconds": 3600,
    "host_generation_path": "/var/lib/ken-actions/authority/firewall-endpoint-generation.json",
    "guest_generation_path": "/etc/ken-actions/firewall-endpoint-generation.json",
    "guest_base_path": "/etc/ken-actions/guest-base.nft",
    "guest_resolver_path": "/usr/local/libexec/ken-actions-firewall-endpoint-resolve",
}:
    raise SystemExit("ready firewall contract mismatch")
firewall_files = {
    "firewall_endpoint_policy_sha256": build_root / "firewall-endpoint-policy.yaml",
    "firewall_endpoint_generation_sha256": build_root / "firewall-endpoint-generation.json",
    "firewall_endpoint_generation_receipt_sha256": build_root / "firewall-endpoint-generation.receipt.json",
    "action_transport_lock_sha256": build_root / "action-transport.lock.yaml",
    "onepassword_canary_receipt_sha256": build_root / "onepassword-linux-canary.json",
}
firewall_bytes = {}
for key, path in firewall_files.items():
    value = read_file(path, key)
    if hashlib.sha256(value).hexdigest() != authority[key]:
        raise SystemExit(f"ready firewall artifact digest mismatch: {key}")
    firewall_bytes[key] = value
try:
    generation = json.loads(firewall_bytes["firewall_endpoint_generation_sha256"], object_pairs_hook=duplicate_json, parse_constant=invalid_constant)
    generation_receipt = json.loads(firewall_bytes["firewall_endpoint_generation_receipt_sha256"], object_pairs_hook=duplicate_json, parse_constant=invalid_constant)
except (UnicodeError, json.JSONDecodeError, ValueError) as error:
    raise SystemExit(f"ready firewall artifact malformed: {error}") from error
now = int(os.environ.get("KEN_ACTIONS_FIREWALL_NOW_EPOCH", "0"))
if (type(generation.get("generated_at_epoch")) is not int or type(generation.get("expires_at_epoch")) is not int
        or now < generation["generated_at_epoch"] or now >= generation["expires_at_epoch"]):
    raise SystemExit("ready firewall generation is future or expired")
if (type(generation_receipt.get("schema_version")) is not int or generation_receipt["schema_version"] != 1
        or (generation_receipt.get("generation") or {}).get("sha256") != authority["firewall_endpoint_generation_sha256"]):
    raise SystemExit("ready firewall generation receipt mismatch")
derived = manifest.get("derived_images")
exact(derived, {"status", "ci", "deploy"}, "ready derived-image schema mismatch")
if derived["status"] != "ready":
    raise SystemExit("ready derived-image status mismatch")
receipts = (manifest.get("verification") or {}).get("result_receipts")
exact(receipts, {"ci", "deploy"}, "ready result-receipt schema mismatch")

for guest, key, size in (("ken-ci", "ci", 750), ("ken-deploy", "deploy", 80)):
    image_record = derived[key]
    receipt_record = receipts[key]
    exact(image_record, {"path", "sha256", "virtual_size_gib", "receipt_sha256"}, f"ready image schema mismatch: {guest}")
    exact(receipt_record, {"path", "sha256"}, f"ready receipt schema mismatch: {guest}")
    if image_record["path"] != f"/mnt/data/libvirt/images/{guest}.qcow2" or type(image_record["virtual_size_gib"]) is not int or image_record["virtual_size_gib"] != size:
        raise SystemExit(f"ready image contract mismatch: {guest}")
    image_path = build_root / f"{guest}.qcow2"
    receipt_path = build_root / f"receipts/{guest}.json"
    image_bytes = read_file(image_path, f"{guest} image")
    receipt_bytes = read_file(receipt_path, f"{guest} receipt")
    if hashlib.sha256(image_bytes).hexdigest() != image_record["sha256"]:
        raise SystemExit(f"ready image digest mismatch: {guest}")
    receipt_sha = hashlib.sha256(receipt_bytes).hexdigest()
    if receipt_sha != image_record["receipt_sha256"] or receipt_sha != receipt_record["sha256"] or receipt_record["path"] != f"/var/lib/ken-actions/receipts/{guest}.json":
        raise SystemExit(f"ready receipt digest mismatch: {guest}")
    try:
        receipt = json.loads(receipt_bytes, object_pairs_hook=duplicate_json, parse_constant=invalid_constant)
    except (UnicodeError, json.JSONDecodeError, ValueError) as error:
        raise SystemExit(f"ready receipt malformed: {guest}") from error
    exact(receipt, {"schema_version", "guest", "authority", "image", "verification", "observed_runtime"}, f"ready receipt schema mismatch: {guest}")
    if type(receipt["schema_version"]) is not int or receipt["schema_version"] != 1 or receipt["guest"] != guest:
        raise SystemExit(f"ready receipt identity mismatch: {guest}")
    if receipt["image"] != {"path": image_record["path"], "sha256": image_record["sha256"], "virtual_size_gib": size}:
        raise SystemExit(f"ready receipt image mismatch: {guest}")
    if receipt["authority"].get("guest_install_contract_sha256") != authority["guest_install_contract_sha256"]:
        raise SystemExit(f"ready receipt install-contract mismatch: {guest}")
    approved_digest = evidence["artifact_authority"]["derived_images"].get(guest)
    if approved_digest != image_record["sha256"]:
        raise SystemExit(f"approval evidence image digest mismatch: {guest}")
    vm = evidence["vms"].get(guest)
    exact(vm, {"healthy", "isolation_verified", "memory_gib", "memory_health_verified"}, f"approval VM schema mismatch: {guest}")
    expected_memory = 112 if guest == "ken-ci" else 12
    if vm != {"healthy": True, "isolation_verified": True, "memory_gib": expected_memory, "memory_health_verified": True}:
        raise SystemExit(f"approval VM evidence mismatch: {guest}")

artifact = evidence["artifact_authority"]
if artifact["guest_install_contract_sha256"] != authority["guest_install_contract_sha256"]:
    raise SystemExit("approval install contract digest mismatch")
if artifact["task6_runtime_lock_sha256"] != authority["broker_runtime_lock_sha256"]:
    raise SystemExit("approval runtime-lock digest mismatch")
for key, message in (
    ("action_transport_lock_sha256", "approval action transport digest mismatch"),
    ("firewall_endpoint_policy_sha256", "approval firewall endpoint policy digest mismatch"),
    ("firewall_endpoint_generation_sha256", "approval firewall endpoint generation digest mismatch"),
    ("firewall_endpoint_generation_receipt_sha256", "approval firewall endpoint generation receipt digest mismatch"),
    ("onepassword_canary_receipt_sha256", "approval 1Password canary receipt digest mismatch"),
):
    if artifact[key] != authority[key]:
        raise SystemExit(message)
if artifact["guest_image_manifest_sha256"] != hashlib.sha256(manifest_bytes).hexdigest():
    raise SystemExit("approval guest-manifest digest mismatch")
print("APPLY_AUTHORITY_OK")
PY
}

validate_transport_response() {
  local operation="$1" response="$2"
  python3 - "${operation}" "${response}" <<'PY'
import json
import sys

operation, raw = sys.argv[1:]
try:
    value = json.loads(raw)
except json.JSONDecodeError as error:
    raise SystemExit(f"{operation} response malformed: {error}") from error
if type(value) is not dict:
    raise SystemExit(f"{operation} response schema mismatch")
if operation == "preflight":
    if set(value) != {"status", "memory_available_gib", "protected_services", "mount"}:
        raise SystemExit("preflight response mismatch")
    memory = value["memory_available_gib"]
    if value["status"] != "ready" or isinstance(memory, bool) or not isinstance(memory, (int, float)) or memory < 32 or value["protected_services"] != 6 or value["mount"] != "/mnt/data":
        raise SystemExit("preflight response mismatch")
elif operation == "apply":
    if set(value) != {"status", "created", "changed"} or value["status"] != "applied" or type(value["created"]) is not int or type(value["changed"]) is not int:
        raise SystemExit("apply response mismatch")
elif operation == "readback":
    if value != {"status":"verified", "domains":["ken-ci","ken-deploy"], "firewall":"verified", "proxy":"verified", "protected_services":6}:
        raise SystemExit("readback response mismatch")
else:
    raise SystemExit("unknown transport response")
PY
}

host_path() {
  local path="$1" root="${PROVISION_VMS_HOST_ROOT:-}"
  [[ "${path}" == /* && "${root}" != / ]] || die 'host path mapping is unsafe'
  printf '%s%s\n' "${root}" "${path}"
}

host_validate_authority() {
  local layout="$1" root="$2" host_root="${PROVISION_VMS_HOST_ROOT:-}"
  python3 - "${layout}" "${root}" "${host_root}" "${PROVISION_VMS_COMMAND_TEST:-0}" <<'PY'
import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path

import yaml


class StrictLoader(yaml.SafeLoader):
    pass


def yaml_mapping(loader, node, deep=False):
    seen = set()
    for key_node, _ in node.value:
        key = loader.construct_object(key_node, deep=False)
        if key in seen:
            raise SystemExit(f"duplicate YAML key: {key}")
        seen.add(key)
    return yaml.SafeLoader.construct_mapping(loader, node, deep=deep)


StrictLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, yaml_mapping)


def json_mapping(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise SystemExit(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def invalid_constant(value):
    raise SystemExit(f"invalid JSON number: {value}")


def read(path, label, mode=None):
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise SystemExit(f"{label} is missing or unsafe") from error
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise SystemExit(f"{label} is not regular")
        if mode is not None and stat.S_IMODE(metadata.st_mode) != mode:
            raise SystemExit(f"{label} mode mismatch")
        if metadata.st_uid != 0 and not (test_mode and metadata.st_uid == os.getuid()):
            raise SystemExit(f"{label} owner mismatch")
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = -1
            return stream.read()
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def exact(value, keys, message):
    if type(value) is not dict or set(value) != set(keys):
        raise SystemExit(message)


def digest(value, message):
    if type(value) is not str or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise SystemExit(message)


layout, raw_root, raw_host_root, raw_test = sys.argv[1:]
test_mode = raw_test == "1"
root = Path(raw_root)
host_root = Path(raw_host_root) if raw_host_root else Path("/")
if layout == "stage":
    paths = {
        "manifest": root / "guest-image-manifest.ready.yaml",
        "contract": root / "guest-install-contract.json",
        "lock": root / "broker-runtime.lock.yaml",
        "policy": root / "op-broker-policy.yaml",
        "runner": root / "runner-platform.yaml",
        "endpoint_policy": root / "firewall-endpoint-policy.yaml",
        "generation": root / "firewall-endpoint-generation.json",
        "generation_receipt": root / "firewall-endpoint-generation.receipt.json",
        "task7": root / "action-transport.lock.yaml",
        "onepassword_receipt": root / "onepassword-linux-canary.json",
        "approval": root / "approval.json",
        "ci_receipt": root / "receipts/ken-ci.json",
        "deploy_receipt": root / "receipts/ken-deploy.json",
        "ci_image": root / "ken-ci.qcow2",
        "deploy_image": root / "ken-deploy.qcow2",
    }
elif layout == "installed":
    authority = host_root / "var/lib/ken-actions/authority"
    paths = {
        "manifest": authority / "guest-image-manifest.yaml",
        "contract": authority / "guest-install-contract.json",
        "lock": authority / "broker-runtime.lock.yaml",
        "policy": authority / "op-broker-policy.yaml",
        "runner": authority / "runner-platform.yaml",
        "endpoint_policy": authority / "firewall-endpoint-policy.yaml",
        "generation": authority / "firewall-endpoint-generation.json",
        "generation_receipt": host_root / "var/lib/ken-actions/receipts/firewall-endpoint-generation.json",
        "task7": authority / "action-transport.lock.yaml",
        "onepassword_receipt": host_root / "var/lib/ken-actions/receipts/onepassword-linux-canary.json",
        "approval": authority / "approval.json",
        "ci_receipt": host_root / "var/lib/ken-actions/receipts/ken-ci.json",
        "deploy_receipt": host_root / "var/lib/ken-actions/receipts/ken-deploy.json",
        "ci_image": host_root / "mnt/data/libvirt/images/ken-ci.qcow2",
        "deploy_image": host_root / "mnt/data/libvirt/images/ken-deploy.qcow2",
    }
else:
    raise SystemExit("host authority layout invalid")

manifest_bytes = read(paths["manifest"], "guest manifest", 0o600)
contract_bytes = read(paths["contract"], "guest install contract", 0o600)
lock_bytes = read(paths["lock"], "runtime lock", 0o600)
policy_bytes = read(paths["policy"], "broker policy", 0o600)
runner_bytes = read(paths["runner"], "runner platform", 0o600)
endpoint_policy_bytes = read(paths["endpoint_policy"], "firewall endpoint policy", 0o600)
generation_bytes = read(paths["generation"], "firewall endpoint generation", 0o600)
generation_receipt_bytes = read(paths["generation_receipt"], "firewall endpoint generation receipt", 0o600)
task7_bytes = read(paths["task7"], "action transport lock", 0o600)
onepassword_receipt_bytes = read(paths["onepassword_receipt"], "1Password Linux canary receipt", 0o600)
approval_bytes = read(paths["approval"], "approval evidence", 0o600)
try:
    manifest = yaml.load(manifest_bytes.decode(), Loader=StrictLoader)
    contract = yaml.load(contract_bytes.decode(), Loader=StrictLoader)
    approval = json.loads(approval_bytes, object_pairs_hook=json_mapping, parse_constant=invalid_constant)
except (UnicodeError, yaml.YAMLError, json.JSONDecodeError) as error:
    raise SystemExit(f"host authority malformed: {error}") from error

exact(manifest, {"schema_version", "authority", "base_image", "common_runtime", "ci_image", "deploy_image", "remote_pinned_build_inputs", "provenance_only", "generated_files", "verification", "derived_images", "firewall", "readiness"}, "host guest manifest schema mismatch")
if type(manifest["schema_version"]) is not int or manifest["schema_version"] != 1 or manifest["readiness"] != {"state":"ready", "live_apply_allowed":True, "ready_marker":"receipts-verified", "blockers":[]}:
    raise SystemExit("host guest manifest readiness mismatch")
authority = manifest["authority"]
for key in (
    "plan_sha256", "runner_platform_sha256", "broker_runtime_lock_sha256", "op_broker_policy_sha256",
    "action_transport_lock_sha256", "firewall_endpoint_policy_sha256",
    "firewall_endpoint_generation_sha256", "firewall_endpoint_generation_receipt_sha256",
    "onepassword_canary_receipt_sha256", "guest_install_contract_sha256",
    "immutable_payload_manifest_sha256", "platform_payload_manifest_sha256",
):
    digest(authority.get(key), f"host manifest authority malformed: {key}")
if (
    hashlib.sha256(contract_bytes).hexdigest() != authority["guest_install_contract_sha256"]
    or hashlib.sha256(lock_bytes).hexdigest() != authority["broker_runtime_lock_sha256"]
    or hashlib.sha256(policy_bytes).hexdigest() != authority["op_broker_policy_sha256"]
    or hashlib.sha256(runner_bytes).hexdigest() != authority["runner_platform_sha256"]
    or hashlib.sha256(endpoint_policy_bytes).hexdigest() != authority["firewall_endpoint_policy_sha256"]
    or hashlib.sha256(generation_bytes).hexdigest() != authority["firewall_endpoint_generation_sha256"]
    or hashlib.sha256(generation_receipt_bytes).hexdigest() != authority["firewall_endpoint_generation_receipt_sha256"]
    or hashlib.sha256(task7_bytes).hexdigest() != authority["action_transport_lock_sha256"]
    or hashlib.sha256(onepassword_receipt_bytes).hexdigest() != authority["onepassword_canary_receipt_sha256"]
):
    raise SystemExit("host immutable authority digest mismatch")
exact(contract, {"schema_version", "authority", "base_image", "common_runtime", "guest_images", "remote_pinned_build_inputs", "generated_files", "task4_runtime", "verification"}, "host install contract schema mismatch")
if type(contract["schema_version"]) is not int or contract["schema_version"] != 1 or contract["authority"].get("broker_runtime_lock_sha256") != authority["broker_runtime_lock_sha256"]:
    raise SystemExit("host install contract authority mismatch")
host_transport = (contract.get("task4_runtime") or {}).get("host_transport")
expected_host_transport = {
    "libvirt/ken-ci.xml", "libvirt/ken-deploy.xml",
    "cloud-init/ken-ci-user-data.yaml", "cloud-init/ken-deploy-user-data.yaml",
    "proxy/ken-actions-artifact-proxy-deploy.conf", "proxy/ken-actions-artifact-proxy-runtime.yaml",
    "systemd/ken-actions-artifact-proxy-deploy.service", "systemd/ken-actions-vm-firewall.service",
    "systemd/ken-actions-vm-firewall.timer", "systemd/ken-actions-vms.service",
    "scripts/lib/vm-firewall.sh", "scripts/provision-vms.sh", "inventory/runner-platform.yaml",
}
if type(host_transport) is not dict or set(host_transport) != expected_host_transport:
    raise SystemExit("host transport authority mismatch")
if layout == "stage":
    for relative, expected_sha in host_transport.items():
        digest(expected_sha, f"host transport digest malformed: {relative}")
        staged_path = root / relative
        if hashlib.sha256(read(staged_path, f"host transport: {relative}")).hexdigest() != expected_sha:
            raise SystemExit(f"host transport digest mismatch: {relative}")
exact(approval, {"schema_version", "approval_phrase", "combined_approval_verified", "host", "host_memory_available_gib", "firewall_generation_verified", "artifact_authority", "vms"}, "host approval schema mismatch")
if type(approval["schema_version"]) is not int or approval["schema_version"] != 1 or approval["combined_approval_verified"] is not True or approval["host"] != "root@167.235.8.250":
    raise SystemExit("host approval evidence mismatch")
artifact = approval["artifact_authority"]
exact(artifact, {
    "task6_runtime_lock_sha256", "action_transport_lock_sha256",
    "firewall_endpoint_policy_sha256", "firewall_endpoint_generation_sha256",
    "firewall_endpoint_generation_receipt_sha256", "onepassword_canary_receipt_sha256",
    "guest_install_contract_sha256", "guest_image_manifest_sha256", "derived_images",
}, "host approval artifact schema mismatch")
if (artifact.get("guest_image_manifest_sha256") != hashlib.sha256(manifest_bytes).hexdigest()
        or artifact.get("guest_install_contract_sha256") != authority["guest_install_contract_sha256"]
        or artifact.get("task6_runtime_lock_sha256") != authority["broker_runtime_lock_sha256"]):
    raise SystemExit("host approval artifact binding mismatch")
for key in (
    "action_transport_lock_sha256", "firewall_endpoint_policy_sha256",
    "firewall_endpoint_generation_sha256", "firewall_endpoint_generation_receipt_sha256",
    "onepassword_canary_receipt_sha256",
):
    if artifact.get(key) != authority[key]:
        raise SystemExit(f"host approval firewall binding mismatch: {key}")
try:
    generation = json.loads(generation_bytes, object_pairs_hook=json_mapping, parse_constant=invalid_constant)
    generation_receipt = json.loads(generation_receipt_bytes, object_pairs_hook=json_mapping, parse_constant=invalid_constant)
except (UnicodeError, json.JSONDecodeError) as error:
    raise SystemExit(f"host firewall authority malformed: {error}") from error
if (type(generation.get("generated_at_epoch")) is not int or type(generation.get("expires_at_epoch")) is not int
        or generation["expires_at_epoch"] - generation["generated_at_epoch"] != 3600
        or type(generation_receipt.get("schema_version")) is not int or generation_receipt["schema_version"] != 1
        or (generation_receipt.get("generation") or {}).get("sha256") != authority["firewall_endpoint_generation_sha256"]):
    raise SystemExit("host firewall generation readiness mismatch")

derived = manifest["derived_images"]
receipts = manifest["verification"]["result_receipts"]
if derived.get("status") != "ready":
    raise SystemExit("host derived-image readiness mismatch")
for guest, key, size in (("ken-ci", "ci", 750), ("ken-deploy", "deploy", 80)):
    image_bytes = read(paths[f"{key}_image"], f"{guest} image")
    receipt_bytes = read(paths[f"{key}_receipt"], f"{guest} receipt", 0o600)
    image_sha = hashlib.sha256(image_bytes).hexdigest()
    receipt_sha = hashlib.sha256(receipt_bytes).hexdigest()
    image = derived[key]
    if image != {"path":f"/mnt/data/libvirt/images/{guest}.qcow2", "sha256":image_sha, "virtual_size_gib":size, "receipt_sha256":receipt_sha}:
        raise SystemExit(f"host image authority mismatch: {guest}")
    if receipts[key] != {"path":f"/var/lib/ken-actions/receipts/{guest}.json", "sha256":receipt_sha}:
        raise SystemExit(f"host receipt authority mismatch: {guest}")
    if artifact.get("derived_images", {}).get(guest) != image_sha:
        raise SystemExit(f"host approval image binding mismatch: {guest}")
    try:
        receipt = json.loads(receipt_bytes, object_pairs_hook=json_mapping, parse_constant=invalid_constant)
    except json.JSONDecodeError as error:
        raise SystemExit(f"host receipt malformed: {guest}") from error
    if type(receipt.get("schema_version")) is not int or receipt["schema_version"] != 1 or receipt.get("guest") != guest or receipt.get("image") != {"path":image["path"], "sha256":image_sha, "virtual_size_gib":size} or receipt.get("authority", {}).get("guest_install_contract_sha256") != authority["guest_install_contract_sha256"]:
        raise SystemExit(f"host receipt binding mismatch: {guest}")
print("HOST_AUTHORITY_OK")
PY
}

host_record_target() {
  local state="$1" absolute="$2" target backup
  target="$(host_path "${absolute}")"
  backup="${state}/backup${absolute}"
  if [[ -e "${target}" || -L "${target}" ]]; then
    [[ -f "${target}" && ! -L "${target}" ]] || die "host transaction target is unsafe: ${absolute}"
    install -d -m 0700 "$(dirname "${backup}")"
    cp -p "${target}" "${backup}"
    printf 'present\t%s\n' "${absolute}" >>"${state}/targets.tsv"
  else
    printf 'absent\t%s\n' "${absolute}" >>"${state}/targets.tsv"
  fi
}

HOST_TRANSACTION_CREATED=0
HOST_TRANSACTION_CHANGED=0

host_install_file() {
  local source="$1" absolute="$2" mode="$3" target candidate
  target="$(host_path "${absolute}")"
  if [[ -f "${target}" && ! -L "${target}" ]] && cmp -s "${source}" "${target}" && [[ "$(stat -c %a "${target}")" == "${mode#0}" ]]; then
    return 0
  fi
  install -d -m 0755 "$(dirname "${target}")"
  candidate="$(mktemp "$(dirname "${target}")/.ken-actions-candidate.XXXXXX")"
  if [[ "${PROVISION_VMS_COMMAND_TEST:-0}" == 1 ]]; then
    install -m "${mode}" "${source}" "${candidate}"
  else
    install -m "${mode}" -o root -g root "${source}" "${candidate}"
  fi
  if [[ -e "${target}" ]]; then
    HOST_TRANSACTION_CHANGED=$((HOST_TRANSACTION_CHANGED + 1))
  else
    HOST_TRANSACTION_CREATED=$((HOST_TRANSACTION_CREATED + 1))
  fi
  mv -f -- "${candidate}" "${target}"
}

host_capture_domain() {
  local state="$1" guest="$2" status=absent active=no autostart=no
  install -d -m 0700 "${state}/domains"
  if virsh dominfo "${guest}" >/dev/null 2>&1; then
    status=present
    virsh dumpxml "${guest}" >"${state}/domains/${guest}.xml"
    chmod 0600 "${state}/domains/${guest}.xml"
    [[ "$(virsh domstate "${guest}" | tr '[:upper:]' '[:lower:]' | xargs)" == running ]] && active=yes
    virsh dominfo "${guest}" | awk -F: '/^Autostart:/ {gsub(/[[:space:]]/, "", $2); print tolower($2)}' | grep -qx enable && autostart=yes || true
    if [[ "${active}" == yes ]]; then
      virsh destroy "${guest}" >/dev/null
    fi
  fi
  printf '%s\t%s\t%s\t%s\n' "${guest}" "${status}" "${active}" "${autostart}" >>"${state}/domains.tsv"
}

host_capture_custom_services() {
  local state="$1" service enabled active
  : >"${state}/services.tsv"
  chmod 0600 "${state}/services.tsv"
  for service in \
    ken-actions-vm-firewall.service \
    ken-actions-vm-firewall.timer \
    ken-actions-artifact-proxy-deploy.service \
    ken-actions-vms.service; do
    enabled="$(systemctl is-enabled "${service}" 2>/dev/null || true)"
    active="$(systemctl is-active "${service}" 2>/dev/null || true)"
    [[ -n "${enabled}" ]] || enabled=not-found
    [[ -n "${active}" ]] || active=inactive
    case "${enabled}" in enabled|disabled|masked|static|indirect|not-found) ;; *) die "custom service enablement state unsupported: ${service}" ;; esac
    case "${active}" in active|inactive|failed) ;; *) die "custom service active state unsupported: ${service}" ;; esac
    printf '%s\t%s\t%s\n' "${service}" "${enabled}" "${active}" >>"${state}/services.tsv"
  done
}

host_ensure_proxy_runtime() {
  local stage="$1" runtime
  local package_root package name filename expected_sha actual_sha
  runtime="${stage}/proxy/ken-actions-artifact-proxy-runtime.yaml"
  python3 - "${runtime}" <<'PY'
from pathlib import Path
import sys
import yaml
value = yaml.safe_load(Path(sys.argv[1]).read_text())
expected = {
    "schema_version": 1,
    "account": {"name":"ken-actions-proxy","uid":22900,"gid":22900,"home":"/var/lib/ken-actions-artifact-proxy","shell":"/usr/sbin/nologin"},
    "apt_authority": {
        "suite":"noble-security","component":"main",
        "packages_index_sha256":"36ba4de53741fc834cf35328891c9311f81cb98a8273e683ff274cf5c05e5e23",
        "inrelease_sha256":"72e28abc589872680f910a4eead774cb7a829e4f0015923edd8fc5ca530cdb29",
        "archive_keyring_sha256":"80a36b0a6de2f69f49d2df75ef473ccde121e9e190b9ea01d20a4f63778d5c31",
        "signer_fingerprint":"F6ECB3762474EDA9D21B7022871920D1991BC93C",
    },
    "packages": [
        {"name":"squid","version":"6.14-0ubuntu0.24.04.4","architecture":"amd64","filename":"squid_6.14-0ubuntu0.24.04.4_amd64.deb","sha256":"da7e7ee3bf12b23e21ef99b21e7a90daf86d8a0d4bd119e97255d124760592ba"},
        {"name":"squid-common","version":"6.14-0ubuntu0.24.04.4","architecture":"all","filename":"squid-common_6.14-0ubuntu0.24.04.4_all.deb","sha256":"e2f5d967ef71db67db1080a4f4aba0e2a6560e584318b3bf867e7fa84494bc12"},
    ],
    "distribution_units_masked": ["squid.service"],
    "custom_service": "ken-actions-artifact-proxy-deploy.service",
}
if value != expected or type(value.get("schema_version")) is not int:
    raise SystemExit("pinned proxy runtime authority mismatch")
PY
  [[ "${PROVISION_VMS_COMMAND_TEST:-0}" != 1 ]] || return 0

  # Mask the distribution service before package scripts can observe it. The
  # custom, UID-scoped unit is the only authority allowed to start Squid.
  systemctl mask squid.service >/dev/null
  [[ "$(systemctl is-enabled squid.service 2>/dev/null || true)" == masked ]] || die 'distribution Squid service is not masked'

  if getent group ken-actions-proxy >/dev/null; then
    [[ "$(getent group ken-actions-proxy | cut -d: -f3)" == 22900 ]] || die 'proxy group GID drift'
  else
    groupadd --system --gid 22900 ken-actions-proxy
  fi
  if getent passwd ken-actions-proxy >/dev/null; then
    IFS=: read -r _ _ observed_uid observed_gid _ observed_home observed_shell < <(getent passwd ken-actions-proxy)
    [[ "${observed_uid}" == 22900 && "${observed_gid}" == 22900 && "${observed_home}" == /var/lib/ken-actions-artifact-proxy && "${observed_shell}" == /usr/sbin/nologin ]] || die 'proxy account authority drift'
  else
    useradd --system --uid 22900 --gid 22900 --home-dir /var/lib/ken-actions-artifact-proxy --shell /usr/sbin/nologin --no-create-home ken-actions-proxy
  fi

  if [[ "$(dpkg-query -W -f='${Version}' squid 2>/dev/null || true)" != 6.14-0ubuntu0.24.04.4 || \
        "$(dpkg-query -W -f='${Version}' squid-common 2>/dev/null || true)" != 6.14-0ubuntu0.24.04.4 ]]; then
    package_root="$(mktemp -d /var/tmp/ken-actions-squid.XXXXXX)"
    trap 'rm -rf -- "${package_root}"' RETURN
    (
      cd "${package_root}"
      apt-get download squid=6.14-0ubuntu0.24.04.4 squid-common=6.14-0ubuntu0.24.04.4
    )
    while IFS='|' read -r name _ filename expected_sha; do
      package="${package_root}/${filename}"
      [[ -f "${package}" && ! -L "${package}" ]] || die "pinned proxy package missing: ${name}"
      actual_sha="$(sha256sum "${package}" | awk '{print $1}')"
      [[ "${actual_sha}" == "${expected_sha}" ]] || die "pinned proxy package digest mismatch: ${name}"
    done <<'EOF'
squid|6.14-0ubuntu0.24.04.4|squid_6.14-0ubuntu0.24.04.4_amd64.deb|da7e7ee3bf12b23e21ef99b21e7a90daf86d8a0d4bd119e97255d124760592ba
squid-common|6.14-0ubuntu0.24.04.4|squid-common_6.14-0ubuntu0.24.04.4_all.deb|e2f5d967ef71db67db1080a4f4aba0e2a6560e584318b3bf867e7fa84494bc12
EOF
    apt-get install -y --no-install-recommends \
      "${package_root}/squid-common_6.14-0ubuntu0.24.04.4_all.deb" \
      "${package_root}/squid_6.14-0ubuntu0.24.04.4_amd64.deb"
    rm -rf -- "${package_root}"
    trap - RETURN
  fi
  [[ "$(dpkg-query -W -f='${Version}' squid)" == 6.14-0ubuntu0.24.04.4 ]] || die 'installed Squid version drift'
  [[ "$(dpkg-query -W -f='${Version}' squid-common)" == 6.14-0ubuntu0.24.04.4 ]] || die 'installed squid-common version drift'
  [[ -x /usr/sbin/squid ]] || die 'installed Squid executable missing'
  systemctl mask squid.service >/dev/null
  [[ "$(systemctl is-enabled squid.service 2>/dev/null || true)" == masked ]] || die 'distribution Squid service mask drift'
}

host_rollback() {
  local state="$1" presence absolute target backup guest presence_domain active autostart service enabled service_active
  [[ -d "${state}" && ! -L "${state}" && -f "${state}/targets.tsv" && ! -L "${state}/targets.tsv" ]] || die 'host rollback state is missing or unsafe'
  while IFS=$'\t' read -r presence absolute; do
    [[ "${absolute}" == /* && "${absolute}" != / ]] || die 'host rollback target is unsafe'
    target="$(host_path "${absolute}")"
    backup="${state}/backup${absolute}"
    case "${presence}" in
      present)
        [[ -f "${backup}" && ! -L "${backup}" ]] || die "host rollback backup missing: ${absolute}"
        install -d -m 0755 "$(dirname "${target}")"
        if [[ "${PROVISION_VMS_COMMAND_TEST:-0}" == 1 ]]; then
          install -m "$(stat -c %a "${backup}")" "${backup}" "${target}"
        else
          install -m "$(stat -c %a "${backup}")" -o root -g root "${backup}" "${target}"
        fi
        ;;
      absent)
        [[ ! -d "${target}" ]] || die "host rollback refuses directory target: ${absolute}"
        rm -f -- "${target}"
        ;;
      *) die 'host rollback target manifest invalid' ;;
    esac
  done <"${state}/targets.tsv"
  if [[ -f "${state}/domains.tsv" && ! -L "${state}/domains.tsv" ]]; then
    while IFS=$'\t' read -r guest presence_domain active autostart; do
      [[ "${guest}" == ken-ci || "${guest}" == ken-deploy ]] || die 'host rollback domain manifest invalid'
      if virsh dominfo "${guest}" >/dev/null 2>&1; then
        [[ "$(virsh domstate "${guest}" | tr '[:upper:]' '[:lower:]' | xargs)" != running ]] || virsh destroy "${guest}" >/dev/null
        virsh undefine "${guest}" >/dev/null
      fi
      if [[ "${presence_domain}" == present ]]; then
        virsh define "${state}/domains/${guest}.xml" >/dev/null
        [[ "${autostart}" == yes ]] && virsh autostart "${guest}" >/dev/null || true
        [[ "${active}" == yes ]] && virsh start "${guest}" >/dev/null || true
      elif [[ "${presence_domain}" != absent ]]; then
        die 'host rollback domain state invalid'
      fi
    done <"${state}/domains.tsv"
  fi
  systemctl daemon-reload
  if [[ -f "${state}/services.tsv" && ! -L "${state}/services.tsv" ]]; then
    for service in \
      ken-actions-vms.service \
      ken-actions-artifact-proxy-deploy.service \
      ken-actions-vm-firewall.timer \
      ken-actions-vm-firewall.service; do
      systemctl stop "${service}" >/dev/null 2>&1 || true
    done
    while IFS=$'\t' read -r service enabled service_active; do
      case "${enabled}" in
        enabled) systemctl unmask "${service}" >/dev/null 2>&1 || true; systemctl enable "${service}" >/dev/null ;;
        disabled) systemctl unmask "${service}" >/dev/null 2>&1 || true; systemctl disable "${service}" >/dev/null ;;
        masked) systemctl mask "${service}" >/dev/null ;;
        static|indirect|not-found) systemctl disable "${service}" >/dev/null 2>&1 || true ;;
        *) die 'host rollback service manifest invalid' ;;
      esac
      if [[ "${service_active}" == active ]]; then
        systemctl start "${service}" >/dev/null
      else
        systemctl stop "${service}" >/dev/null 2>&1 || true
        [[ "${service_active}" != failed ]] || systemctl reset-failed "${service}" >/dev/null 2>&1 || true
      fi
    done <"${state}/services.tsv"
  fi
  printf '%s\n' rolled-back >"${state}/status"
  chmod 0600 "${state}/status"
}

# Invoked by the EXIT trap installed in host_transaction_apply.
# shellcheck disable=SC2329
host_transaction_abort() {
  local exit_status="$?" state="$1"
  trap - EXIT
  if [[ "${exit_status}" -ne 0 && -n "${state}" ]]; then
    host_rollback "${state}"
  fi
  exit "${exit_status}"
}

host_transaction_apply() {
  local stage="$1" stage_id state state_root key_file guest source absolute image expected_size info virtual_size
  local transaction_state=''
  local -a file_bindings=(
    'guest-image-manifest.ready.yaml|/var/lib/ken-actions/authority/guest-image-manifest.yaml|0600'
    'guest-install-contract.json|/var/lib/ken-actions/authority/guest-install-contract.json|0600'
    'broker-runtime.lock.yaml|/var/lib/ken-actions/authority/broker-runtime.lock.yaml|0600'
    'op-broker-policy.yaml|/var/lib/ken-actions/authority/op-broker-policy.yaml|0600'
    'runner-platform.yaml|/var/lib/ken-actions/authority/runner-platform.yaml|0600'
    'firewall-endpoint-policy.yaml|/var/lib/ken-actions/authority/firewall-endpoint-policy.yaml|0600'
    'firewall-endpoint-generation.json|/var/lib/ken-actions/authority/firewall-endpoint-generation.json|0600'
    'action-transport.lock.yaml|/var/lib/ken-actions/authority/action-transport.lock.yaml|0600'
    'approval.json|/var/lib/ken-actions/authority/approval.json|0600'
    'firewall-endpoint-generation.receipt.json|/var/lib/ken-actions/receipts/firewall-endpoint-generation.json|0600'
    'onepassword-linux-canary.json|/var/lib/ken-actions/receipts/onepassword-linux-canary.json|0600'
    'receipts/ken-ci.json|/var/lib/ken-actions/receipts/ken-ci.json|0600'
    'receipts/ken-deploy.json|/var/lib/ken-actions/receipts/ken-deploy.json|0600'
    'ken-ci.qcow2|/mnt/data/libvirt/images/ken-ci.qcow2|0600'
    'ken-deploy.qcow2|/mnt/data/libvirt/images/ken-deploy.qcow2|0600'
    'proxy/ken-actions-artifact-proxy-deploy.conf|/etc/ken-actions/ken-actions-artifact-proxy-deploy.conf|0644'
    'proxy/ken-actions-artifact-proxy-runtime.yaml|/var/lib/ken-actions/authority/artifact-proxy-runtime.yaml|0600'
    'systemd/ken-actions-artifact-proxy-deploy.service|/etc/systemd/system/ken-actions-artifact-proxy-deploy.service|0644'
    'systemd/ken-actions-vm-firewall.service|/etc/systemd/system/ken-actions-vm-firewall.service|0644'
    'systemd/ken-actions-vm-firewall.timer|/etc/systemd/system/ken-actions-vm-firewall.timer|0644'
    'systemd/ken-actions-vms.service|/etc/systemd/system/ken-actions-vms.service|0644'
    'scripts/lib/vm-firewall.sh|/usr/local/sbin/ken-actions-vm-firewall|0755'
    'host-transaction|/usr/local/sbin/ken-actions-vm-authority-verify|0755'
  )
  if [[ "${PROVISION_VMS_COMMAND_TEST:-0}" == 1 ]]; then
    [[ -d "${stage}" && ! -L "${stage}" ]] || die 'test host stage is unsafe'
  else
    [[ "${stage}" =~ ^/var/tmp/ken-actions-vm-stage[.][0-9a-f]{64}$ && -d "${stage}" && ! -L "${stage}" ]] || die 'host stage is unsafe'
    [[ "$(stat -c %u "${stage}")" == 0 && "$(stat -c %a "${stage}")" == 700 ]] || die 'host stage owner or mode invalid'
  fi
  host_validate_authority stage "${stage}" >/dev/null
  if [[ "${PROVISION_VMS_COMMAND_TEST:-0}" != 1 ]]; then
    findmnt -rn -T /mnt/data -o TARGET,FSTYPE,OPTIONS | awk '$1 == "/mnt/data" && $2 == "ext4" && $3 ~ /(^|,)rw(,|$)/ { found=1 } END { exit !found }' || die 'host apply /mnt/data mount mismatch'
  fi
  key_file="$(host_path /var/lib/ken-actions/guest-admin-authorized-key)"
  [[ -f "${key_file}" && ! -L "${key_file}" && "$(stat -c %a "${key_file}")" == 600 ]] || die 'guest administrator public key authority is missing or unsafe'
  grep -Eq '^ssh-(ed25519|rsa) [A-Za-z0-9+/]+={0,3}( [^[:cntrl:]]+)?$' "${key_file}" || die 'guest administrator public key authority is malformed'
  [[ "$(wc -l <"${key_file}" | tr -d ' ')" == 1 ]] || die 'guest administrator public key authority must contain one key'

  stage_id="$(sha256sum "${stage}/guest-image-manifest.ready.yaml" | awk '{print $1}')"
  state_root="$(host_path /var/lib/ken-actions/transactions)"
  state="${state_root}/${stage_id}"
  install -d -m 0700 "${state_root}"
  if [[ -f "${state}/status" && ! -L "${state}/status" ]] && grep -qx committed "${state}/status"; then
    host_validate_authority installed / >/dev/null
    printf '%s\n' '{"status":"applied","created":0,"changed":0}'
    return 0
  fi
  [[ ! -e "${state}" ]] || die 'unfinished host transaction requires explicit rollback'
  install -d -m 0700 "${state}"
  : >"${state}/targets.tsv"
  chmod 0600 "${state}/targets.tsv"
  printf '%s\n' pending >"${state}/status"
  chmod 0600 "${state}/status"
  transaction_state="${state}"
  # `die` exits explicitly, which does not reliably trigger an ERR trap. Keep
  # rollback on the process EXIT path until the transaction is committed so
  # every failure after journaling restores files, domains, and unit state.
  trap 'host_transaction_abort "${transaction_state}"' EXIT

  host_capture_custom_services "${state}"
  host_ensure_proxy_runtime "${stage}"

  for binding in "${file_bindings[@]}"; do
    IFS='|' read -r source absolute mode <<<"${binding}"
    [[ -f "${stage}/${source}" && ! -L "${stage}/${source}" ]] || die "staged host input missing: ${source}"
    host_record_target "${state}" "${absolute}"
  done
  for guest in ken-ci ken-deploy; do
    host_record_target "${state}" "/mnt/data/libvirt/seed/${guest}-seed.img"
    host_capture_domain "${state}" "${guest}"
  done

  for guest in ken-ci ken-deploy; do
    image="${stage}/${guest}.qcow2"
    expected_size=80
    [[ "${guest}" == ken-ci ]] && expected_size=750
    qemu-img check "${image}" >/dev/null
    info="$(qemu-img info --output=json "${image}")"
    virtual_size="$(python3 -c 'import json,sys; print(json.load(sys.stdin).get("virtual-size", -1))' <<<"${info}")"
    [[ "${virtual_size}" == "$((expected_size * 1024 * 1024 * 1024))" ]] || die "staged ${guest} virtual size mismatch"
  done

  for binding in "${file_bindings[@]}"; do
    IFS='|' read -r source absolute mode <<<"${binding}"
    host_install_file "${stage}/${source}" "${absolute}" "${mode}"
  done
  if [[ "${PROVISION_VMS_HOST_INJECT_FAILURE:-}" == after-files ]]; then
    printf '%s\n' 'injected host transaction failure: after-files' >&2
    false
  fi

  for guest in ken-ci ken-deploy; do
    user_data="${state}/${guest}-user-data.yaml"
    metadata="${state}/${guest}-meta-data"
    seed_candidate="${state}/${guest}-seed.img"
    python3 - "${stage}/cloud-init/${guest}-user-data.yaml" "${key_file}" "${user_data}" <<'PY'
from pathlib import Path
import sys
template, key_file, output = map(Path, sys.argv[1:])
text = template.read_text()
key = key_file.read_text().strip()
if text.count("__HOST_ADMIN_SSH_KEY__") != 1:
    raise SystemExit("guest SSH-key placeholder cardinality invalid")
output.write_text(text.replace("__HOST_ADMIN_SSH_KEY__", key))
output.chmod(0o600)
PY
    printf 'instance-id: %s-%s\nlocal-hostname: %s\n' "${guest}" "${stage_id}" "${guest}" >"${metadata}"
    chmod 0600 "${metadata}"
    cloud-localds "${seed_candidate}" "${user_data}" "${metadata}"
    chmod 0600 "${seed_candidate}"
    host_install_file "${seed_candidate}" "/mnt/data/libvirt/seed/${guest}-seed.img" 0600
  done

  for guest in ken-ci ken-deploy; do
    virsh define "${stage}/libvirt/${guest}.xml" >/dev/null
    virsh autostart "${guest}" >/dev/null
  done
  systemctl daemon-reload
  systemctl start ken-actions-vm-firewall.service
  systemctl enable ken-actions-vm-firewall.timer
  systemctl start ken-actions-vm-firewall.timer
  [[ "${PROVISION_VMS_HOST_INJECT_FAILURE:-}" != after-firewall-timer-enable ]] || die 'injected host transaction failure: after-firewall-timer-enable'
  systemctl enable ken-actions-artifact-proxy-deploy.service
  systemctl start ken-actions-artifact-proxy-deploy.service
  [[ "${PROVISION_VMS_HOST_INJECT_FAILURE:-}" != after-proxy-start ]] || die 'injected host transaction failure: after-proxy-start'
  systemctl enable ken-actions-vms.service
  systemctl start ken-actions-vms.service
  [[ "${PROVISION_VMS_HOST_INJECT_FAILURE:-}" != after-vms-start ]] || die 'injected host transaction failure: after-vms-start'
  host_validate_authority installed / >/dev/null
  [[ "${PROVISION_VMS_HOST_INJECT_FAILURE:-}" != after-final-readback ]] || die 'injected host transaction failure: after-final-readback'
  printf '%s\n' committed >"${state}/status"
  chmod 0600 "${state}/status"
  transaction_state=''
  trap - EXIT
  printf '{"status":"applied","created":%d,"changed":%d}\n' "${HOST_TRANSACTION_CREATED}" "${HOST_TRANSACTION_CHANGED}"
}

host_transaction_readback() {
  local service guest state
  local -a protected_services=(
    actions.runner.Ken-Technology-ken-agents.hetzner-grok-review-ken-agents.service
    actions.runner.Ken-Technology-ken-ai-mcp.hetzner-grok-review-ken-ai-mcp.service
    actions.runner.Ken-Technology-ken-backend.hetzner-grok-review-ken-backend.service
    actions.runner.Ken-Technology-ken-frontend.hetzner-grok-review-ken-frontend.service
    actions.runner.Ken-Technology-ken-scraping.hetzner-grok-review-ken-scraping.service
    actions.runner.Ken-Technology-ken-search.hetzner-grok-review-ken-search.service
  )
  host_validate_authority installed / >/dev/null
  for service in ken-actions-vm-firewall.service ken-actions-artifact-proxy-deploy.service ken-actions-vms.service "${protected_services[@]}"; do
    systemctl is-active --quiet "${service}" || die "host readback service inactive: ${service}"
  done
  nft list table inet ken_actions_vms | grep -Fq 'managed-by=ken-actions' || die 'host firewall readback mismatch'
  for guest in ken-ci ken-deploy; do
    state="$(virsh domstate "${guest}" | tr '[:upper:]' '[:lower:]' | xargs)"
    [[ "${state}" == running ]] || die "host guest is not running: ${guest}"
    virsh qemu-agent-command "${guest}" '{"execute":"guest-ping"}' | grep -Fq 'return' || die "host guest agent did not answer: ${guest}"
  done
  printf '%s\n' '{"status":"verified","domains":["ken-ci","ken-deploy"],"firewall":"verified","proxy":"verified","protected_services":6}'
}

host_transaction() {
  local operation="$1" stage="$2" memory_kib memory_gib service stage_id guest state
  local -a protected_services=(
    actions.runner.Ken-Technology-ken-agents.hetzner-grok-review-ken-agents.service
    actions.runner.Ken-Technology-ken-ai-mcp.hetzner-grok-review-ken-ai-mcp.service
    actions.runner.Ken-Technology-ken-backend.hetzner-grok-review-ken-backend.service
    actions.runner.Ken-Technology-ken-frontend.hetzner-grok-review-ken-frontend.service
    actions.runner.Ken-Technology-ken-scraping.hetzner-grok-review-ken-scraping.service
    actions.runner.Ken-Technology-ken-search.hetzner-grok-review-ken-search.service
  )
  [[ "${EUID}" == 0 || "${PROVISION_VMS_COMMAND_TEST:-0}" == 1 ]] || die 'host transaction requires root'
  case "${operation}" in
    preflight)
      [[ "${stage}" == / ]] || die 'preflight stage sentinel invalid'
      for command in virsh qemu-img cloud-localds nft systemctl findmnt; do
        command -v "${command}" >/dev/null || die "host preflight command missing: ${command}"
      done
      findmnt -rn -T /mnt/data -o TARGET,FSTYPE,OPTIONS | awk '$1 == "/mnt/data" && $2 == "ext4" && $3 ~ /(^|,)rw(,|$)/ { found=1 } END { exit !found }' || die 'host preflight /mnt/data mount mismatch'
      memory_kib="$(awk '/^MemAvailable:/ {print $2}' /proc/meminfo)"
      [[ "${memory_kib}" =~ ^[0-9]+$ ]] || die 'host preflight memory evidence invalid'
      memory_gib="$(python3 -c 'import sys; print(round(int(sys.argv[1]) / 1024 / 1024, 3))' "${memory_kib}")"
      python3 -c 'import sys; raise SystemExit(0 if float(sys.argv[1]) >= 32 else 1)' "${memory_gib}" || die 'host preflight memory below 32 GiB'
      for service in "${protected_services[@]}"; do
        systemctl is-active --quiet "${service}" || die "protected service is not active: ${service}"
      done
      python3 - "${memory_gib}" <<'PY'
import json
import sys
print(json.dumps({"status":"ready", "memory_available_gib":float(sys.argv[1]), "protected_services":6, "mount":"/mnt/data"}, separators=(",", ":")))
PY
      ;;
    apply)
      host_transaction_apply "${stage}"
      ;;
    readback)
      host_transaction_readback
      ;;
    rollback)
      [[ "${PROVISION_VMS_COMMAND_TEST:-0}" == 1 || "${stage}" =~ ^/var/tmp/ken-actions-vm-stage[.][0-9a-f]{64}$ ]] || die 'host rollback stage is unsafe'
      stage_id="$(sha256sum "${stage}/guest-image-manifest.ready.yaml" | awk '{print $1}')"
      host_rollback "$(host_path "/var/lib/ken-actions/transactions/${stage_id}")"
      printf '%s\n' '{"status":"rolled-back"}'
      ;;
    start-vms)
      [[ "${stage}" == / ]] || die 'host VM start sentinel invalid'
      host_validate_authority installed / >/dev/null
      for guest in ken-ci ken-deploy; do
        virsh net-info "${guest}-net" >/dev/null
        state="$(virsh domstate "${guest}" 2>/dev/null | tr '[:upper:]' '[:lower:]' | xargs || true)"
        [[ "${state}" == running ]] || virsh start "${guest}" >/dev/null
      done
      ;;
    stop-vms)
      [[ "${stage}" == / ]] || die 'host VM stop sentinel invalid'
      for guest in ken-ci ken-deploy; do
        state="$(virsh domstate "${guest}" 2>/dev/null | tr '[:upper:]' '[:lower:]' | xargs || true)"
        [[ "${state}" != running ]] || virsh shutdown "${guest}" >/dev/null
      done
      ;;
    *) die 'host transaction operation invalid' ;;
  esac
}

apply_ready() {
  local manifest="$1" lock="$2" policy="$3" build_root="$4" approval="$5" target="$6"
  local ssh_bin="${PROVISION_VMS_SSH_BIN:-ssh}" response stage_id stage_dir transport_root
  [[ "${target}" == "${APPROVED_TARGET}" ]] || die "target must be ${APPROVED_TARGET}"
  validate_apply_ready "${manifest}" "${lock}" "${policy}" "${build_root}" "${approval}"
  validate_runtime_authority "${manifest}" "${lock}" "${policy}" >/dev/null
  stage_id="$(python3 -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1], "rb").read()).hexdigest())' "${manifest}")"
  stage_dir="/var/tmp/ken-actions-vm-stage.${stage_id}"

  response="$("${ssh_bin}" "${target}" -- /bin/bash -s -- --host-transaction preflight / <"${BASH_SOURCE[0]}")"
  validate_transport_response preflight "${response}"

  transport_root="$(mktemp -d)"
  cp "${build_root}/host-transport/scripts/provision-vms.sh" "${transport_root}/host-transaction"
  cp "${lock}" "${transport_root}/broker-runtime.lock.yaml"
  cp "${policy}" "${transport_root}/op-broker-policy.yaml"
  cp "${build_root}/host-transport/inventory/runner-platform.yaml" "${transport_root}/runner-platform.yaml"
  cp "${approval}" "${transport_root}/approval.json"
  chmod 0700 "${transport_root}/host-transaction"
  chmod 0600 "${transport_root}/broker-runtime.lock.yaml" "${transport_root}/op-broker-policy.yaml" "${transport_root}/runner-platform.yaml" "${transport_root}/approval.json"

  # The quoted remote program is intentionally expanded by the remote shell.
  # shellcheck disable=SC2016
  tar -cf - \
    -C "${transport_root}" host-transaction broker-runtime.lock.yaml op-broker-policy.yaml runner-platform.yaml approval.json \
    -C "${build_root}" ken-ci.qcow2 ken-deploy.qcow2 guest-image-manifest.ready.yaml guest-install-contract.json receipts firewall-endpoint-policy.yaml firewall-endpoint-generation.json firewall-endpoint-generation.receipt.json action-transport.lock.yaml onepassword-linux-canary.json \
    -C "${build_root}/host-transport" libvirt cloud-init proxy systemd scripts inventory \
    | "${ssh_bin}" "${target}" -- /bin/bash -c 'set -euo pipefail; operation="$1"; stage="$2"; [[ "${operation}" == stage && "${stage}" == /var/tmp/ken-actions-vm-stage.* ]]; umask 077; install -d -m 0700 -o root -g root "${stage}"; tar --no-same-owner -C "${stage}" -xf -; printf "%s\n" STAGED' _ stage "${stage_dir}" >/dev/null
  rm -rf -- "${transport_root}"

  response="$("${ssh_bin}" "${target}" -- "${stage_dir}/host-transaction" apply "${stage_dir}")"
  validate_transport_response apply "${response}"
  response="$("${ssh_bin}" "${target}" -- "${stage_dir}/host-transaction" readback "${stage_dir}")"
  validate_transport_response readback "${response}"
  printf 'LIVE_TRANSACTION_OK stage=%s\n' "${stage_id}"
}

solve_closure() {
  local base="$1" staged="$2" roots="$3" architecture="$4"
  python3 - "${base}" "${staged}" "${roots}" "${architecture}" <<'PY'
import re
import sys
from functools import cmp_to_key
from pathlib import Path


def parse_control(path):
    records = []
    current = {}
    active = None
    for raw in Path(path).read_text(encoding="utf-8").splitlines() + [""]:
        if not raw.strip():
            if current:
                records.append(current)
            current = {}
            active = None
            continue
        if raw[:1].isspace():
            if active is None:
                raise SystemExit(f"malformed package inventory: {path}")
            current[active] += " " + raw.strip()
            continue
        if ":" not in raw:
            raise SystemExit(f"malformed package inventory: {path}")
        active, value = raw.split(":", 1)
        if active in current:
            raise SystemExit(f"duplicate package field: {active}")
        current[active] = value.strip()
    return records


def version_parts(value):
    epoch = 0
    if ":" in value:
        raw_epoch, value = value.split(":", 1)
        epoch = int(raw_epoch)
    upstream, separator, revision = value.rpartition("-")
    if not separator:
        upstream, revision = value, "0"

    def tokenize(part):
        return [int(piece) if piece.isdigit() else piece for piece in re.findall(r"[0-9]+|[A-Za-z]+|~|[^A-Za-z0-9~]+", part)]

    return epoch, tokenize(upstream), tokenize(revision)


def compare(left, right):
    lparts = version_parts(left)
    rparts = version_parts(right)
    if lparts[0] != rparts[0]:
        return -1 if lparts[0] < rparts[0] else 1
    for lpart, rpart in zip(lparts[1:], rparts[1:]):
        for index in range(max(len(lpart), len(rpart))):
            ltoken = lpart[index] if index < len(lpart) else ""
            rtoken = rpart[index] if index < len(rpart) else ""
            if ltoken == rtoken:
                continue
            if ltoken == "~":
                return -1
            if rtoken == "~":
                return 1
            if ltoken == "":
                return -1
            if rtoken == "":
                return 1
            if isinstance(ltoken, int) and isinstance(rtoken, int):
                return -1 if ltoken < rtoken else 1
            return -1 if str(ltoken) < str(rtoken) else 1
    return 0


def parse_relation(raw):
    raw = raw.strip()
    match = re.fullmatch(r"([A-Za-z0-9][A-Za-z0-9+.-]*)(?::[A-Za-z0-9-]+)?(?:\s*\((<<|<=|=|>=|>>)\s*([^()]+)\))?", raw)
    if not match:
        raise SystemExit(f"unsupported dependency relation: {raw}")
    return match.group(1), match.group(2), match.group(3)


def satisfies(version, operator, wanted):
    if not operator:
        return True
    result = compare(version, wanted)
    return {"<<": result < 0, "<=": result <= 0, "=": result == 0, ">=": result >= 0, ">>": result > 0}[operator]


architecture = sys.argv[4]
records = parse_control(sys.argv[1]) + parse_control(sys.argv[2])
by_name = {}
providers = {}
for record in records:
    required = {"Package", "Version", "Architecture", "Source-Class"}
    if not required.issubset(record):
        raise SystemExit("package inventory record missing required field")
    if record["Source-Class"] not in {"base-image", "staged-runtime"}:
        raise SystemExit(f"unsupported package source class: {record['Source-Class']}")
    if record["Architecture"] not in {architecture, "all"}:
        continue
    name = record["Package"]
    if record["Source-Class"] == "staged-runtime" and not re.fullmatch(r"[0-9a-f]{64}", record.get("SHA256", "")):
        raise SystemExit(f"staged package missing SHA256: {name}")
    candidates = by_name.setdefault(name, [])
    if any(
        item["Version"] == record["Version"]
        and item["Architecture"] == record["Architecture"]
        and item["Source-Class"] == record["Source-Class"]
        for item in candidates
    ):
        raise SystemExit(f"duplicate package authority: {name}")
    candidates.append(record)
    for provided in record.get("Provides", "").split(","):
        if not provided.strip():
            continue
        virtual_name, operator, provided_version = parse_relation(provided.strip())
        if operator not in {None, "="}:
            raise SystemExit(f"unsupported versioned Provides relation: {provided.strip()}")
        providers.setdefault(virtual_name, []).append((record, provided_version))


def candidate_order(left, right):
    left_rank = 0 if left["Source-Class"] == "staged-runtime" else 1
    right_rank = 0 if right["Source-Class"] == "staged-runtime" else 1
    if left_rank != right_rank:
        return -1 if left_rank < right_rank else 1
    result = compare(left["Version"], right["Version"])
    if result:
        return -result
    left_key = (left["Architecture"], left["Package"])
    right_key = (right["Architecture"], right["Package"])
    return -1 if left_key < right_key else (1 if left_key > right_key else 0)


def choose_relation(name, operator, wanted):
    direct = [
        record for record in by_name.get(name, [])
        if satisfies(record["Version"], operator, wanted)
    ]
    if direct:
        return sorted(direct, key=cmp_to_key(candidate_order))[0]
    provided = []
    for record, provided_version in providers.get(name, []):
        if operator and provided_version is None:
            continue
        if satisfies(provided_version or record["Version"], operator, wanted):
            provided.append(record)
    if provided:
        return sorted(provided, key=cmp_to_key(candidate_order))[0]
    return None


def selected_satisfies(record, name, operator, wanted):
    if record["Package"] == name:
        return satisfies(record["Version"], operator, wanted)
    for provided in record.get("Provides", "").split(","):
        if not provided.strip():
            continue
        virtual_name, provided_operator, provided_version = parse_relation(provided.strip())
        if virtual_name != name or provided_operator not in {None, "="}:
            continue
        if operator and provided_version is None:
            return False
        return satisfies(provided_version or record["Version"], operator, wanted)
    return False

selected = {}
queue = [line.strip() for line in Path(sys.argv[3]).read_text(encoding="utf-8").splitlines() if line.strip()]
while queue:
    expression = queue.pop(0)
    alternatives = [parse_relation(item) for item in expression.split("|")]
    chosen = None
    already_satisfied = False
    for name, operator, wanted in alternatives:
        existing = next(
            (record for record in selected.values() if selected_satisfies(record, name, operator, wanted)),
            None,
        )
        if existing:
            chosen = existing
            already_satisfied = True
            break
        candidate = choose_relation(name, operator, wanted)
        if candidate:
            chosen = candidate
            break
    if chosen is None:
        raise SystemExit(f"unsatisfied dependency: {expression}")
    if already_satisfied:
        continue
    name = chosen["Package"]
    if name in selected:
        raise SystemExit(f"selected package conflicts with dependency: {expression}")
    selected[name] = chosen
    for field in ("Pre-Depends", "Depends"):
        for dependency in chosen.get(field, "").split(","):
            if dependency.strip():
                queue.append(dependency.strip())

for owner in selected.values():
    for field in ("Conflicts", "Breaks"):
        for expression in owner.get(field, "").split(","):
            expression = expression.strip()
            if not expression:
                continue
            for raw_relation in expression.split("|"):
                relation_name, operator, wanted = parse_relation(raw_relation)
                conflict = next(
                    (
                        record
                        for record in selected.values()
                        if record["Package"] != owner["Package"]
                        and selected_satisfies(record, relation_name, operator, wanted)
                    ),
                    None,
                )
                if conflict is not None:
                    verb = "conflicts with" if field == "Conflicts" else "breaks"
                    raise SystemExit(
                        f"selected package conflict: {owner['Package']} {verb} {conflict['Package']}"
                    )

for name in sorted(selected):
    record = selected[name]
    print(f"{name}={record['Version']}:{record['Source-Class']}")
PY
}

fake_tree_digest() {
  local path="$1"
  python3 - "${path}" <<'PY'
import hashlib
import stat
import sys
from pathlib import Path

root = Path(sys.argv[1])
digest = hashlib.sha256()
for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
    relative = path.relative_to(root).as_posix()
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode):
        raise SystemExit(f"symlink forbidden in fake image: {relative}")
    if path.is_dir():
        digest.update(f"d 0755 {relative}\n".encode())
        continue
    if not path.is_file():
        raise SystemExit(f"non-regular fake image entry: {relative}")
    content_hash = hashlib.sha256(path.read_bytes()).hexdigest()
    digest.update(f"f {stat.S_IMODE(info.st_mode):04o} {info.st_size} {content_hash} {relative}\n".encode())
print(digest.hexdigest())
PY
}

fake_image_transaction() {
  local source="$1" destination="$2" parent candidate journal digest existing_digest
  [[ -d "${source}" && ! -L "${source}" ]] || die "fake image source must be a real directory"
  [[ "${destination}" == /* ]] || die "fake image destination must be absolute"
  [[ "${destination}" != / && "${destination}" != "${HOME:-/__unset_home__}" ]] || die "unsafe fake image destination"
  parent="$(dirname "${destination}")"
  [[ -d "${parent}" && ! -L "${parent}" ]] || die "fake image destination parent must be a real directory"
  candidate="$(mktemp -d "${parent}/.ken-actions-candidate.XXXXXX")"
  journal="$(mktemp "${parent}/.ken-actions-journal.XXXXXX")"
  # shellcheck disable=SC2329
  cleanup_fake_transaction() {
    rm -rf -- "${candidate}"
    rm -f -- "${journal}"
  }
  trap cleanup_fake_transaction EXIT
  printf 'destination=%s\n' "${destination}" >"${journal}"
  if [[ "${KEN_ACTIONS_INJECT_FAILURE:-}" == after-journal ]]; then
    die 'injected failure: after-journal'
  fi
  cp -a "${source}/." "${candidate}/"
  if [[ "${KEN_ACTIONS_INJECT_FAILURE:-}" == after-copy ]]; then
    die 'injected failure: after-copy'
  fi
  digest="$(fake_tree_digest "${candidate}")"
  if [[ "${KEN_ACTIONS_INJECT_FAILURE:-}" == before-commit ]]; then
    die 'injected failure: before-commit'
  fi
  if [[ -e "${destination}" ]]; then
    [[ -d "${destination}" && ! -L "${destination}" ]] || die "existing fake image is not a real directory"
    existing_digest="$(fake_tree_digest "${destination}")"
    [[ "${existing_digest}" == "${digest}" ]] || die "existing fake image differs from candidate"
  else
    mv -- "${candidate}" "${destination}"
    candidate="${parent}/.ken-actions-candidate.committed"
  fi
  printf '%s\n' "${digest}" >"${destination}.receipt.sha256"
  printf '%s\n' "${digest}"
  cleanup_fake_transaction
  trap - EXIT
}

print_plan() {
  local ci_vcpu ci_memory_gib ci_disk_gib deploy_vcpu deploy_memory_gib deploy_disk_gib
  IFS='|' read -r ci_vcpu ci_memory_gib ci_disk_gib < <(read_vm_contract ken-ci)
  IFS='|' read -r deploy_vcpu deploy_memory_gib deploy_disk_gib < <(read_vm_contract ken-deploy)
  cat <<'EOF'
Approved VM plan:
EOF
  printf '  ken-ci: %s vCPU, %s GiB RAM, %s GiB qcow2, ken-ci-net only\n' "${ci_vcpu}" "${ci_memory_gib}" "${ci_disk_gib}"
  printf '  ken-deploy: %s vCPU, %s GiB RAM, %s GiB qcow2, ken-deploy-net only\n' "${deploy_vcpu}" "${deploy_memory_gib}" "${deploy_disk_gib}"
  cat <<'EOF'
  image: Ubuntu 24.04 authority and offline payload closure must be manifest-pinned
  storage: /mnt/data/libvirt/images and /mnt/data/libvirt/seed only
  access: host-managed SSH keys; no credentials in definitions or seed templates
  isolation: dedicated host and guest nftables tables with fail-closed readiness gates
EOF
}

case "${1:-}" in
  --verify-host-authority)
    [[ $# == 2 && ( "$2" == proxy || "$2" == firewall || "$2" == vms ) ]] || die '--verify-host-authority requires proxy, firewall, or vms'
    host_validate_authority installed / >/dev/null
    exit 0
    ;;
  --host-transaction)
    [[ $# == 3 ]] || die '--host-transaction requires OPERATION STAGE'
    host_transaction "$2" "$3"
    exit 0
    ;;
  --verify-static)
    [[ $# == 1 ]] || die '--verify-static accepts no additional arguments'
    verify_static
    exit 0
    ;;
  --check-readiness)
    [[ $# == 1 ]] || die '--check-readiness accepts no additional arguments'
    check_readiness
    exit 0
    ;;
  --validate-runtime-authority)
    [[ $# == 4 ]] || die '--validate-runtime-authority requires MANIFEST LOCK POLICY'
    validate_runtime_authority "$2" "$3" "$4"
    exit 0
    ;;
  --resolve-firewall-endpoints)
    [[ $# == 7 || $# == 8 ]] || die '--resolve-firewall-endpoints requires ENDPOINT_POLICY RUNNER LOCK POLICY TASK7_LOCK OUTPUT [RECEIPT]'
    resolve_firewall_endpoints "$2" "$3" "$4" "$5" "$6" "$7" "${8:-}"
    exit 0
    ;;
  --validate-platform-extension)
    [[ $# == 3 ]] || die '--validate-platform-extension requires MANIFEST EXTENSION_ROOT'
    validate_platform_extension "$2" "$3"
    exit 0
    ;;
  --build-offline)
    [[ $# == 11 ]] || die '--build-offline requires MANIFEST LOCK POLICY ENDPOINT_POLICY GENERATION GENERATION_RECEIPT TASK7_LOCK ONEPASSWORD_RECEIPT PAYLOAD_ROOT OUTPUT_ROOT'
    build_offline "$2" "$3" "$4" "$5" "$6" "$7" "$8" "$9" "${10}" "${11}"
    exit 0
    ;;
  --apply-ready)
    [[ $# == 7 ]] || die '--apply-ready requires MANIFEST LOCK POLICY BUILD_ROOT APPROVAL TARGET'
    apply_ready "$2" "$3" "$4" "$5" "$6" "$7"
    exit 0
    ;;
  --solve-closure)
    [[ $# == 5 ]] || die '--solve-closure requires BASE STAGED ROOTS ARCH'
    solve_closure "$2" "$3" "$4" "$5"
    exit 0
    ;;
  --fake-image-transaction)
    [[ $# == 3 ]] || die '--fake-image-transaction requires SOURCE DESTINATION'
    fake_image_transaction "$2" "$3"
    exit 0
    ;;
  -h|--help)
    usage
    exit 0
    ;;
esac

dry_run=0
if [[ "${1:-}" == --dry-run ]]; then
  dry_run=1
  shift
fi
[[ $# == 1 ]] || {
  usage >&2
  exit 2
}
target="$1"
[[ "${target}" == "${APPROVED_TARGET}" ]] || die "target must be ${APPROVED_TARGET}"

verify_static >/dev/null
print_plan
if (( dry_run == 1 )); then
  echo 'No host or guest changes were requested.'
  exit 0
fi

# A future reviewed descendant may add the approved live transport. The current
# offline implementation always reaches this gate before any SSH invocation.
check_readiness
die 'live VM apply is unavailable in the offline Task 4 implementation'
