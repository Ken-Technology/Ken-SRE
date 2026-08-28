#!/usr/bin/env bash
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd -P)"
GA_ROOT="${ROOT}/infra/github-actions"
PROVISION="${GA_ROOT}/scripts/provision-vms.sh"
FIREWALL="${GA_ROOT}/scripts/lib/vm-firewall.sh"
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

check() {
  local label="$1"
  shift
  if "$@"; then
    pass "${label}"
  else
    fail "${label}"
  fi
}

expect_failure() {
  local label="$1" expected="$2"
  shift 2
  local output status
  output="$({ "$@"; } 2>&1)"
  status=$?
  if (( status != 0 )) && grep -Fq -- "${expected}" <<<"${output}"; then
    pass "${label}"
  else
    printf '%s\n' "${output}" >&2
    fail "${label}"
  fi
}

expect_success() {
  local label="$1" expected="$2"
  shift 2
  local output status
  output="$({ "$@"; } 2>&1)"
  status=$?
  if (( status == 0 )) && grep -Fq -- "${expected}" <<<"${output}"; then
    pass "${label}"
  else
    printf '%s\n' "${output}" >&2
    fail "${label}"
  fi
}

tmp_root="$(mktemp -d)"
trap 'rm -rf "${tmp_root}"' EXIT

echo '== required Task 4 files =='
required=(
  inventory/guest-image-manifest.yaml
  inventory/firewall-endpoint-policy.yaml
  proxy/ken-actions-artifact-proxy-deploy.conf
  proxy/ken-actions-artifact-proxy-runtime.yaml
  systemd/ken-actions-artifact-proxy-deploy.service
  systemd/ken-actions-vm-firewall.service
  systemd/ken-actions-vm-firewall.timer
  systemd/ken-actions-vms.service
)
for relative in "${required[@]}"; do
  if [[ -f "${GA_ROOT}/${relative}" && ! -L "${GA_ROOT}/${relative}" ]]; then
    pass "${relative} exists as a regular file"
  else
    fail "${relative} exists as a regular file"
  fi
done

echo '== firewall endpoint authority =='
endpoint_policy="${GA_ROOT}/inventory/firewall-endpoint-policy.yaml"
endpoint_generation="${tmp_root}/firewall-endpoint-generation.json"
endpoint_generation_receipt="${tmp_root}/firewall-endpoint-generation.receipt.json"
expect_failure 'blocked endpoint authority cannot produce a numeric generation' 'missing-final-firewall-endpoint-generation' \
  bash "${PROVISION}" --resolve-firewall-endpoints "${endpoint_policy}" "${GA_ROOT}/inventory/runner-platform.yaml" /dev/null /dev/null /dev/null "${endpoint_generation}"

echo '== machine-readable static contract =='
check 'manifest, VM, cloud-init, proxy, unit, and Task 5 contracts' \
  python3 - "${GA_ROOT}" <<'PY'
import hashlib
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import yaml

ga = Path(sys.argv[1])
errors = []


class StrictLoader(yaml.SafeLoader):
    pass


def construct_mapping(loader, node, deep=False):
    seen = set()
    for key_node, _ in node.value:
        key = loader.construct_object(key_node, deep=False)
        if key in seen:
            raise ValueError(f"duplicate YAML key: {key}")
        seen.add(key)
    return yaml.SafeLoader.construct_mapping(loader, node, deep=deep)


StrictLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, construct_mapping
)


def load_yaml(path):
    with path.open(encoding="utf-8") as stream:
        return yaml.load(stream, Loader=StrictLoader)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require(condition, message):
    if not condition:
        errors.append(message)


manifest_path = ga / "inventory/guest-image-manifest.yaml"
if not manifest_path.is_file():
    raise SystemExit("guest image manifest missing")
manifest = load_yaml(manifest_path)
runner_path = ga / "inventory/runner-platform.yaml"
runner = load_yaml(runner_path)

require(
    type(manifest.get("schema_version")) is int
    and manifest.get("schema_version") == 1,
    "manifest schema_version",
)
required_sections = {
    "authority",
    "base_image",
    "common_runtime",
    "ci_image",
    "deploy_image",
    "remote_pinned_build_inputs",
    "provenance_only",
    "generated_files",
    "verification",
    "derived_images",
    "firewall",
    "readiness",
}
require(set(manifest) == required_sections | {"schema_version"}, "manifest exact sections")
authority = manifest.get("authority") or {}
require(authority.get("plan_sha256") == "75715a5a3973f3ed9813e66c809d76ec1281d537afae0c08d66b02684583a658", "plan digest")
require(authority.get("task5_integrated_commit") == "e2b3b2b50890be01601288f5294ac847fb575e71", "Task 5 integrated commit")
require(authority.get("runner_platform_sha256") == sha(runner_path), "runner platform digest")
runtime_lock_path = ga / authority.get("broker_runtime_lock_path", "")
broker_policy_path = ga / authority.get("op_broker_policy_path", "")
task7_path = ga / authority.get("action_transport_lock_path", "")
endpoint_policy_path = ga / authority.get("firewall_endpoint_policy_path", "")
require(authority.get("task6_commit") == "a7c554536e5c90092ecccdcacad3db5b2e01b1cf", "Task 6 final commit")
require(authority.get("broker_runtime_lock_sha256") == sha(runtime_lock_path), "Task 6 lock digest")
require(authority.get("op_broker_policy_sha256") == sha(broker_policy_path), "Task 6 policy digest")
require(authority.get("task7_commit") == "25aa8bf32c3d5e3e4d33eac5fdd78cc97307f2d4", "Task 7 final manifest commit")
require(authority.get("action_transport_lock_sha256") == "d82ac42ac8101915fb107f9141edc3547635c3456e9b676bec8bbfce34ccbe76", "Task 7 transport digest")
require(authority.get("action_transport_lock_sha256") == sha(task7_path), "Task 7 transport file digest")
require(authority.get("firewall_endpoint_policy_sha256") == sha(endpoint_policy_path), "endpoint policy digest")
require(authority.get("firewall_endpoint_generation_sha256") is None, "numeric generation digest must remain null")
require(authority.get("firewall_endpoint_generation_receipt_sha256") is None, "numeric generation receipt digest must remain null")
require(authority.get("onepassword_canary_receipt_sha256") is None, "1Password canary receipt digest must remain null")
require(authority.get("guest_install_contract_sha256") is None, "guest install contract must remain null")
require(authority.get("platform_payload_manifest_sha256") == "dd26525559aa26532fc58658ea4c668f72df73b6cd77a60eef7ec5cb73c2a8c0", "platform payload manifest digest")
readiness = manifest.get("readiness") or {}
blockers = readiness.get("blockers") or []
require(readiness.get("state") == "blocked", "manifest readiness must be blocked")
require(readiness.get("live_apply_allowed") is False, "live apply must be false")
require("missing-final-task6-lock" not in blockers, "stale Task 6 lock blocker")
require("missing-final-task6-policy-and-identities" not in blockers, "stale Task 6 identities blocker")
require("missing-final-task7-transport-manifest" not in blockers, "stale Task 7 transport blocker")
require("missing-single-stop-production-target-readback" in blockers, "missing target readback blocker")
require("missing-approved-onepassword-endpoint-canary" in blockers, "missing 1Password canary blocker")
require("missing-final-firewall-endpoint-generation" in blockers, "missing numeric generation blocker")
require("missing-both-guest-runtime-receipts" in blockers, "missing guest receipt blocker")
require("missing-user-approval" in blockers, "missing user approval blocker")
require("missing-task5-consumer-hard-dependencies" not in blockers, "resolved Task 5 dependency blocker remains")
require(readiness.get("ready_marker") is None, "ready marker must be null")
require((manifest.get("common_runtime") or {}).get("required_checks") == [
    "op-version",
    "python-isolated-mode",
    "strict-yaml-duplicate-key-rejection",
    "jose-rs256-known-answer",
    "cryptography-import-origin-and-hash",
    "elf-soname-abi",
    "ca-bundle-generation-and-hash",
], "common runtime verification list")
require((manifest.get("base_image") or {}).get("status") == "ready", "base_image status")
for section in ("common_runtime", "ci_image", "deploy_image", "remote_pinned_build_inputs", "generated_files"):
    require((manifest.get(section) or {}).get("status") == "ready", f"{section} status")
require((manifest.get("derived_images") or {}).get("status") == "blocked", "derived_images status")
runtime_lock = load_yaml(runtime_lock_path)
require(len(runtime_lock.get("components") or []) == 17, "Task 6 component cardinality")
require(len(runtime_lock.get("installed_files") or []) == 52, "Task 6 installed-file cardinality")
components = runtime_lock["components"]
component_by_id = {item["id"]: item for item in components}
common_component_ids = ["1password-cli", "python", "pyyaml", "pyjwt", "cryptography", "ca-certificates", "git", "systemd", "zip-safety"]
deploy_toolchain_ids = ["buildkit", "rootlesskit", "buildkit-rootless-prerequisites", "node", "corepack", "pnpm", "oci-image-tools"]
require(manifest["common_runtime"].get("payloads") == common_component_ids, "common runtime payload inventory")
require(manifest["common_runtime"].get("installed_files") == [item["path"] for item in runtime_lock["installed_files"] if item["source"].startswith("component:") and item["source"].removeprefix("component:") in common_component_ids], "common runtime installed-file inventory")
require(manifest["deploy_image"].get("deploy_toolchain_payloads") == deploy_toolchain_ids, "deploy toolchain inventory")
require(manifest["remote_pinned_build_inputs"].get("inputs") == [component_by_id["node-build-base"]], "remote pinned input inventory")
require(manifest["provenance_only"].get("inputs") == runtime_lock.get("provenance_payloads"), "provenance-only inventory")
require((manifest.get("ci_image") or {}).get("installed_files") == [item["path"] for item in runtime_lock["installed_files"] if "ken-ci" in item["hosts"]], "CI installed-file inventory")
require((manifest.get("deploy_image") or {}).get("installed_files") == [item["path"] for item in runtime_lock["installed_files"] if "ken-deploy" in item["hosts"]], "deploy installed-file inventory")
require((manifest.get("ci_image") or {}).get("task6_ci_files") == [item["path"] for item in runtime_lock["installed_files"] if item["source"].startswith("repo:") and "ken-ci" in item["hosts"]], "CI Task 6 files")
require((manifest.get("deploy_image") or {}).get("task6_deploy_files") == [item["path"] for item in runtime_lock["installed_files"] if item["source"].startswith("repo:") and "ken-deploy" in item["hosts"]], "deploy Task 6 files")
transport = load_yaml(task7_path)
require((transport.get("task6_final") or {}).get("status") == "reviewed-final-bindings", "Task 7 final Task 6 status")
require((transport.get("task6_final") or {}).get("commit_sha") == "a7c554536e5c90092ecccdcacad3db5b2e01b1cf", "Task 7 Task 6 commit binding")
require((transport.get("task6_final") or {}).get("tree_sha") == "1f918bf0d5d58e61ce0b76d587233e02597b8ea6", "Task 7 Task 6 tree binding")
require(manifest.get("firewall") == {
    "status": "blocked",
    "blocker": "missing-final-firewall-endpoint-generation",
    "refresh_interval_seconds": 900,
    "generation_ttl_seconds": 3600,
    "host_generation_path": "/var/lib/ken-actions/authority/firewall-endpoint-generation.json",
    "guest_generation_path": "/etc/ken-actions/firewall-endpoint-generation.json",
    "guest_base_path": "/etc/ken-actions/guest-base.nft",
    "guest_resolver_path": "/usr/local/libexec/ken-actions-firewall-endpoint-resolve",
}, "blocked firewall manifest contract")

runners = runner.get("runners") or []
enabled = [entry for entry in runners if entry.get("enabled")]
disabled = [entry for entry in runners if not entry.get("enabled")]
require([entry["uid"] for entry in enabled] == [21001,21002,21003,21004,21005,21006,21007,21008,21011,21012,21013,21014], "exact enabled Task 5 UIDs")
require([entry["uid"] for entry in disabled] == [21009,21010], "exact disabled Task 5 UIDs")
require(all(entry.get("slice") is None for entry in disabled), "disabled reservations have no slice")

for name, want in {
    "ken-ci": (32, 112, 750, "ken-ci-net"),
    "ken-deploy": (4, 12, 80, "ken-deploy-net"),
}.items():
    domain = ET.parse(ga / f"libvirt/{name}.xml").getroot()
    contract = domain.find("./metadata/{urn:ken-actions:v1}vm-contract")
    interfaces = domain.findall("./devices/interface/source")
    disks = domain.findall("./devices/disk/source")
    require(domain.attrib.get("type") == "kvm", f"{name} KVM")
    require(domain.find("./cpu").attrib.get("mode") == "host-passthrough", f"{name} host CPU")
    require(int(domain.findtext("vcpu", "0")) == want[0], f"{name} vCPU")
    require(int(domain.findtext("memory", "0")) == want[1] * 1024 * 1024, f"{name} memory")
    require(contract is not None and int(contract.attrib.get("disk-capacity-gib", "0")) == want[2], f"{name} disk")
    require([item.attrib.get("network") for item in interfaces] == [want[3]], f"{name} network")
    require(all((item.attrib.get("file") or "").startswith("/mnt/data/libvirt/") for item in disks), f"{name} storage root")

for guest in ("ken-ci", "ken-deploy"):
    path = ga / f"cloud-init/{guest}-user-data.yaml"
    data = load_yaml(path)
    text = path.read_text()
    require(data.get("package_update") is False and data.get("package_upgrade") is False, f"{guest} package network disabled")
    require(not data.get("packages"), f"{guest} no cloud-init package install")
    require("flush ruleset" not in text, f"{guest} preserves unrelated nftables")
    require("path: /etc/ken-actions/guest-base.nft" not in text, f"{guest} cloud-init preserves image-bound firewall base")
    require("nft delete table inet ken_actions_guest" not in text, f"{guest} no delete/apply gap")
    require(not re.search(r"\b(apt(-get)?|curl|wget|pip|npm|docker pull|corepack prepare)\b", text), f"{guest} no network installer")
    require("ken-actions-guest-firewall.service" in text, f"{guest} firewall gate")
    require("ken-actions-guest-firewall-refresh.service" in text, f"{guest} firewall refresh service")
    require("ken-actions-guest-firewall-refresh.timer" in text and "OnUnitActiveSec=15min" in text, f"{guest} 15-minute firewall refresh timer")
    require("ken-actions-guest-runtime-verify.service" in text, f"{guest} runtime gate")
    require("/usr/local/bin/op" in text, f"{guest} exact op path")
    require("/usr/local/libexec/ken-actions/runtime-known-answer.py" in text, f"{guest} fixed runtime known answer")
    require("installed_files" in text and "sha256" in text, f"{guest} manifest file hash verification")
    require("wrong-host-runtime-file-present" in text, f"{guest} rejects wrong-host runtime files")
    require("generated_files" in text, f"{guest} generated file hash verification")
    require("guest_images" in text, f"{guest} Task 4 installed file hash verification")
    require('type(manifest.get("schema_version")) is not int' in text, f"{guest} exact manifest schema type")
    require("/etc/ken-actions/guest-install-contract.yaml" in text, f"{guest} immutable install contract authority")
    require("/etc/ken-actions/guest-image-manifest.yaml" not in text, f"{guest} no future-state manifest self-reference")
    require('set(manifest) != {"schema_version", "authority", "base_image", "common_runtime", "guest_images", "remote_pinned_build_inputs", "generated_files", "task4_runtime", "verification"}' in text, f"{guest} exact install contract schema")
    require('"readiness"' not in text, f"{guest} install verifier has no future-state readiness dependency")
    require("policy drop" in text, f"{guest} default drop output")
    names = [user.get("name") for user in (data.get("users") or []) if isinstance(user, dict)]
    files = {item.get("path"): item for item in (data.get("write_files") or []) if isinstance(item, dict)}
    require((files.get("/etc/ken-actions/guest-class") or {}).get("content", "").strip() == guest, f"{guest} exact guest class")
    firewall_wrapper = (files.get("/usr/local/sbin/ken-actions-guest-firewall") or {}).get("content", "")
    require("phase|refresh" in firewall_wrapper and "/usr/local/libexec/ken-actions-guest-firewall" in firewall_wrapper, f"{guest} phase and refresh delegate to locked firewall runtime")
    authority_check = (files.get("/usr/local/sbin/ken-actions-guest-authority-check") or {}).get("content", "")
    for authority_path in ("/etc/ken-actions/firewall-endpoint-policy.yaml", "/etc/ken-actions/firewall-endpoint-generation.json", "/etc/ken-actions/action-transport.lock.yaml"):
        require(authority_path in authority_check, f"{guest} authority check binds {authority_path}")
    require("ken-ci-runner" not in names and "ken-deploy-runner" not in names, f"{guest} no generic runner")
    require("ghr-ci-s09" not in text and "ghr-ci-s10" not in text, f"{guest} no disabled reservation")

proxy = (ga / "proxy/ken-actions-artifact-proxy-deploy.conf").read_text()
proxy_runtime = load_yaml(ga / "proxy/ken-actions-artifact-proxy-runtime.yaml")
require(proxy_runtime == {
    "schema_version": 1,
    "account": {"name": "ken-actions-proxy", "uid": 22900, "gid": 22900, "home": "/var/lib/ken-actions-artifact-proxy", "shell": "/usr/sbin/nologin"},
    "apt_authority": {
        "suite": "noble-security", "component": "main",
        "packages_index_sha256": "36ba4de53741fc834cf35328891c9311f81cb98a8273e683ff274cf5c05e5e23",
        "inrelease_sha256": "72e28abc589872680f910a4eead774cb7a829e4f0015923edd8fc5ca530cdb29",
        "archive_keyring_sha256": "80a36b0a6de2f69f49d2df75ef473ccde121e9e190b9ea01d20a4f63778d5c31",
        "signer_fingerprint": "F6ECB3762474EDA9D21B7022871920D1991BC93C",
    },
    "packages": [
        {"name": "squid", "version": "6.14-0ubuntu0.24.04.4", "architecture": "amd64", "filename": "squid_6.14-0ubuntu0.24.04.4_amd64.deb", "sha256": "da7e7ee3bf12b23e21ef99b21e7a90daf86d8a0d4bd119e97255d124760592ba"},
        {"name": "squid-common", "version": "6.14-0ubuntu0.24.04.4", "architecture": "all", "filename": "squid-common_6.14-0ubuntu0.24.04.4_all.deb", "sha256": "e2f5d967ef71db67db1080a4f4aba0e2a6560e584318b3bf867e7fa84494bc12"},
    ],
    "distribution_units_masked": ["squid.service"],
    "custom_service": "ken-actions-artifact-proxy-deploy.service",
}, "pinned Squid package, account, and default-service mask authority")
require("http_port 192.168.211.1:3128" in proxy, "proxy exact bind")
require("acl CONNECT method CONNECT" in proxy, "proxy CONNECT only")
require("acl SSL_ports port 443" in proxy, "proxy port 443")
require("^[a-z0-9]{3,24}[.]blob[.]core[.]windows[.]net$" in proxy, "proxy exact Blob grammar")
require("^[a-z0-9]{3,24}[.]blob[.]core[.]windows[.]net:443$" in proxy, "proxy exact Blob CONNECT authority")
require("dns_nameservers 127.0.0.53" in proxy, "proxy exact host resolver")
for forbidden in ("ssl_bump", "cache_dir aufs", "cache_dir ufs", "http_access allow all", "http_port 0.0.0.0"):
    require(forbidden not in proxy, f"proxy forbids {forbidden}")
require("http_access deny all" in proxy, "proxy default deny")

unit_expectations = {
    "ken-actions-artifact-proxy-deploy.service": ["Requires=ken-actions-vm-firewall.service", "User=ken-actions-proxy", "RestrictAddressFamilies=AF_UNIX AF_INET"],
    "ken-actions-vm-firewall.service": ["Type=oneshot", "ExecStart=/usr/local/sbin/ken-actions-vm-firewall refresh"],
    "ken-actions-vm-firewall.timer": ["OnUnitActiveSec=15min", "Unit=ken-actions-vm-firewall.service"],
    "ken-actions-vms.service": ["Requires=libvirtd.service", "Requires=ken-actions-vm-firewall.service", "Requires=ken-actions-artifact-proxy-deploy.service"],
}
for unit, fragments in unit_expectations.items():
    text = (ga / "systemd" / unit).read_text()
    for fragment in fragments:
        require(fragment in text, f"{unit}: {fragment}")

if errors:
    for error in errors:
        print(error)
    raise SystemExit(1)
print("STATIC_CONTRACT_OK")
PY

echo '== provisioner fail-closed gates =='
static_output="$({ bash "${PROVISION}" --verify-static; } 2>&1)"
static_status=$?
if (( static_status == 0 )) && grep -Fq 'STATIC_OK readiness=blocked blocker=missing-single-stop-production-target-readback' <<<"${static_output}"; then
  pass 'static verifier accepts only the explicit blocked state'
else
  printf '%s\n' "${static_output}" >&2
  fail 'static verifier accepts only the explicit blocked state'
fi
expect_failure 'guest readiness rejects the external target handoff' 'missing-single-stop-production-target-readback' \
  bash "${PROVISION}" --check-readiness

fake_bin="${tmp_root}/fake-bin"
mkdir -p "${fake_bin}"
cat >"${fake_bin}/ssh" <<'SH'
#!/usr/bin/env bash
echo ssh-called >&2
exit 99
SH
chmod +x "${fake_bin}/ssh"
dry_output="$(PATH="${fake_bin}:/usr/bin:/bin" bash "${PROVISION}" --dry-run root@167.235.8.250 2>&1)"
dry_status=$?
if (( dry_status == 0 )) && grep -Fq 'No host or guest changes were requested.' <<<"${dry_output}" && ! grep -Fq 'ssh-called' <<<"${dry_output}"; then
  pass 'dry run is SSH-free and target-guarded'
else
  printf '%s\n' "${dry_output}" >&2
  fail 'dry run is SSH-free and target-guarded'
fi
expect_failure 'wrong live target is rejected locally' 'target must be root@167.235.8.250' \
  env PATH="${fake_bin}:/usr/bin:/bin" bash "${PROVISION}" --dry-run root@192.0.2.10
expect_failure 'live apply is blocked before SSH' 'missing-single-stop-production-target-readback' \
  env PATH="${fake_bin}:/usr/bin:/bin" bash "${PROVISION}" root@167.235.8.250

echo '== authority mutation rejection =='
copy_ga_for_mutation() {
  local name="$1" copy
  copy="${tmp_root}/mutation-${name}"
  mkdir -p "${copy}"
  cp -R "${GA_ROOT}/." "${copy}/"
  printf '%s\n' "${copy}"
}

mutation_root="$(copy_ga_for_mutation duplicate-yaml)"
printf '\nreadiness: {}\n' >>"${mutation_root}/inventory/guest-image-manifest.yaml"
expect_failure 'duplicate manifest keys fail before classification' 'duplicate YAML key: readiness' \
  env PROVISION_VMS_GA_ROOT="${mutation_root}" bash "${PROVISION}" --verify-static

mutation_root="$(copy_ga_for_mutation boolean-schema-version)"
perl -0pi -e 's/^schema_version: 1$/schema_version: true/m' "${mutation_root}/inventory/guest-image-manifest.yaml"
expect_failure 'boolean manifest schema version is rejected' 'unsupported guest manifest schema' \
  env PROVISION_VMS_GA_ROOT="${mutation_root}" bash "${PROVISION}" --verify-static

mutation_root="$(copy_ga_for_mutation float-schema-version)"
perl -0pi -e 's/^schema_version: 1$/schema_version: 1.0/m' "${mutation_root}/inventory/guest-image-manifest.yaml"
expect_failure 'floating-point manifest schema version is rejected' 'unsupported guest manifest schema' \
  env PROVISION_VMS_GA_ROOT="${mutation_root}" bash "${PROVISION}" --verify-static

mutation_root="$(copy_ga_for_mutation writable-authority)"
chmod 0664 "${mutation_root}/inventory/guest-image-manifest.yaml"
expect_failure 'group-writable manifest authority is rejected' 'group- or world-writable authority input' \
  env PROVISION_VMS_GA_ROOT="${mutation_root}" bash "${PROVISION}" --verify-static

mutation_root="$(copy_ga_for_mutation task5-drift)"
printf '\n# injected runner drift\n' >>"${mutation_root}/inventory/runner-platform.yaml"
expect_failure 'Task 5 desired-state digest drift is rejected' 'runner platform digest drift' \
  env PROVISION_VMS_GA_ROOT="${mutation_root}" bash "${PROVISION}" --verify-static

mutation_root="$(copy_ga_for_mutation manifest-section)"
printf '\nunreviewed_section: {}\n' >>"${mutation_root}/inventory/guest-image-manifest.yaml"
expect_failure 'extra manifest section is rejected' 'guest manifest section drift' \
  env PROVISION_VMS_GA_ROOT="${mutation_root}" bash "${PROVISION}" --verify-static

mutation_root="$(copy_ga_for_mutation nested-authority-section)"
perl -0pi -e 's/(  generated_at_input_epoch: [0-9]+\n)/$1  unreviewed_authority: forbidden\n/' "${mutation_root}/inventory/guest-image-manifest.yaml"
expect_failure 'extra nested manifest authority field is rejected' 'guest manifest authority schema drift' \
  env PROVISION_VMS_GA_ROOT="${mutation_root}" bash "${PROVISION}" --verify-static

mutation_root="$(copy_ga_for_mutation boolean-input-epoch)"
perl -0pi -e 's/(  generated_at_input_epoch:) [0-9]+/$1 true/' "${mutation_root}/inventory/guest-image-manifest.yaml"
expect_failure 'boolean manifest input epoch is rejected' 'guest manifest generated epoch type drift' \
  env PROVISION_VMS_GA_ROOT="${mutation_root}" bash "${PROVISION}" --verify-static

mutation_root="$(copy_ga_for_mutation removed-required-blocker)"
perl -0pi -e 's/^    - missing-single-stop-production-target-readback\n//m' "${mutation_root}/inventory/guest-image-manifest.yaml"
expect_failure 'blocked manifest requires the exact blocker set' 'guest manifest blocker set drift' \
  env PROVISION_VMS_GA_ROOT="${mutation_root}" bash "${PROVISION}" --verify-static

mutation_root="$(copy_ga_for_mutation boolean-ready-authority)"
perl -0pi -e 's/(  task6_commit:) [0-9a-f]+/$1 true/; s/(  broker_runtime_lock_sha256:) [0-9a-f]+/$1 true/; s/(  op_broker_policy_sha256:) [0-9a-f]+/$1 true/; s/(  state:) blocked/$1 ready/; s/(  live_apply_allowed:) false/$1 true/' "${mutation_root}/inventory/guest-image-manifest.yaml"
expect_failure 'readiness rejects Boolean commit and digest authority' 'guest manifest Task 6 commit type drift' \
  env PROVISION_VMS_GA_ROOT="${mutation_root}" bash "${PROVISION}" --check-readiness

mutation_root="$(copy_ga_for_mutation forged-derived-evidence)"
perl -0pi -e 's/status: blocked\n  ci:/status: ready\n  ci:/' "${mutation_root}/inventory/guest-image-manifest.yaml"
expect_failure 'unobserved derived-image readiness is rejected' 'unobserved derived-image status' \
  env PROVISION_VMS_GA_ROOT="${mutation_root}" bash "${PROVISION}" --verify-static

mutation_root="$(copy_ga_for_mutation xml-drift)"
perl -0pi -e "s/disk-capacity-gib='750'/disk-capacity-gib='751'/" "${mutation_root}/libvirt/ken-ci.xml"
expect_failure 'VM size mutation is rejected' 'ken-ci disk drift' \
  env PROVISION_VMS_GA_ROOT="${mutation_root}" bash "${PROVISION}" --verify-static

mutation_root="$(copy_ga_for_mutation network-fallback)"
perl -0pi -e 's/final_message:/# apt update\nfinal_message:/' "${mutation_root}/cloud-init/ken-ci-user-data.yaml"
expect_failure 'first-boot network fallback is rejected' 'ken-ci network installer present' \
  env PROVISION_VMS_GA_ROOT="${mutation_root}" bash "${PROVISION}" --verify-static

mutation_root="$(copy_ga_for_mutation proxy-wildcard)"
perl -0pi -e 's/http_port 192[.]168[.]211[.]1:3128/http_port 0.0.0.0:3128/' "${mutation_root}/proxy/ken-actions-artifact-proxy-deploy.conf"
expect_failure 'wildcard proxy listener is rejected' 'proxy bind drift' \
  env PROVISION_VMS_GA_ROOT="${mutation_root}" bash "${PROVISION}" --verify-static

echo '== strict Task 6 runtime authority consumer =='
runtime_authority="${tmp_root}/runtime-authority"
mkdir -p "${runtime_authority}"
cp "${GA_ROOT}/inventory/broker-runtime.lock.yaml" "${runtime_authority}/lock.yaml"
cp "${GA_ROOT}/inventory/op-broker-policy.yaml" "${runtime_authority}/policy.yaml"
cp "${GA_ROOT}/inventory/guest-image-manifest.yaml" "${runtime_authority}/manifest.yaml"
python3 - "${runtime_authority}" <<'PY'
import hashlib
import json
from pathlib import Path
import sys
import yaml

root = Path(sys.argv[1])
manifest = yaml.safe_load((root / "manifest.yaml").read_text())
lock = yaml.safe_load((root / "lock.yaml").read_text())
manifest["authority"]["plan_sha256"] = lock["plan_sha256"]
manifest["authority"]["task6_commit"] = "a7c554536e5c90092ecccdcacad3db5b2e01b1cf"
manifest["authority"]["broker_runtime_lock_sha256"] = hashlib.sha256((root / "lock.yaml").read_bytes()).hexdigest()
manifest["authority"]["op_broker_policy_sha256"] = hashlib.sha256((root / "policy.yaml").read_bytes()).hexdigest()
(root / "manifest.yaml").write_text(yaml.safe_dump(manifest, sort_keys=False))
PY
expect_success 'strict Task 6 lock and policy validate as one consumed authority' 'RUNTIME_AUTHORITY_OK components=17 installed_files=52 principals=10' \
  bash "${PROVISION}" --validate-runtime-authority "${runtime_authority}/manifest.yaml" "${runtime_authority}/lock.yaml" "${runtime_authority}/policy.yaml"

runtime_manifest_for_lock() {
  local lock_file="$1" name="$2" output
  output="${tmp_root}/runtime-manifest-${name}.yaml"
  cp "${runtime_authority}/manifest.yaml" "${output}"
  python3 - "${output}" "${lock_file}" <<'PY'
import hashlib
from pathlib import Path
import sys
import yaml

manifest_path, lock_path = map(Path, sys.argv[1:])
manifest = yaml.safe_load(manifest_path.read_text())
manifest["authority"]["broker_runtime_lock_sha256"] = hashlib.sha256(lock_path.read_bytes()).hexdigest()
manifest_path.write_text(yaml.safe_dump(manifest, sort_keys=False))
PY
  printf '%s\n' "${output}"
}

runtime_mutation="${tmp_root}/runtime-lock-duplicate.yaml"
cp "${runtime_authority}/lock.yaml" "${runtime_mutation}"
printf '\nschema_version: 1\n' >>"${runtime_mutation}"
runtime_manifest="$(runtime_manifest_for_lock "${runtime_mutation}" duplicate)"
expect_failure 'duplicate runtime lock key is rejected' 'duplicate YAML key: schema_version' \
  bash "${PROVISION}" --validate-runtime-authority "${runtime_manifest}" "${runtime_mutation}" "${runtime_authority}/policy.yaml"

runtime_mutation="${tmp_root}/runtime-lock-boolean-version.yaml"
cp "${runtime_authority}/lock.yaml" "${runtime_mutation}"
perl -0pi -e 's/^schema_version: 1$/schema_version: true/m' "${runtime_mutation}"
runtime_manifest="$(runtime_manifest_for_lock "${runtime_mutation}" boolean-version)"
expect_failure 'Boolean runtime lock schema version is rejected' 'runtime lock schema version invalid' \
  bash "${PROVISION}" --validate-runtime-authority "${runtime_manifest}" "${runtime_mutation}" "${runtime_authority}/policy.yaml"

runtime_mutation="${tmp_root}/runtime-lock-extra.yaml"
cp "${runtime_authority}/lock.yaml" "${runtime_mutation}"
printf '\nunreviewed: true\n' >>"${runtime_mutation}"
runtime_manifest="$(runtime_manifest_for_lock "${runtime_mutation}" extra)"
expect_failure 'extra runtime lock top-level field is rejected' 'runtime lock top-level schema drift' \
  bash "${PROVISION}" --validate-runtime-authority "${runtime_manifest}" "${runtime_mutation}" "${runtime_authority}/policy.yaml"

runtime_mutation="${tmp_root}/runtime-lock-bad-host.yaml"
cp "${runtime_authority}/lock.yaml" "${runtime_mutation}"
perl -0pi -e 's/- ken-ci\n/- attacker-host\n/' "${runtime_mutation}"
runtime_manifest="$(runtime_manifest_for_lock "${runtime_mutation}" bad-host)"
expect_failure 'runtime payload host scope is exact' 'runtime component host scope invalid' \
  bash "${PROVISION}" --validate-runtime-authority "${runtime_manifest}" "${runtime_mutation}" "${runtime_authority}/policy.yaml"

runtime_mutation="${tmp_root}/runtime-lock-duplicate-path.yaml"
cp "${runtime_authority}/lock.yaml" "${runtime_mutation}"
python3 - "${runtime_mutation}" <<'PY'
from pathlib import Path
import sys
import yaml

p = Path(sys.argv[1])
d = yaml.safe_load(p.read_text())
d["installed_files"].append(dict(d["installed_files"][0]))
p.write_text(yaml.safe_dump(d, sort_keys=False))
PY
runtime_manifest="$(runtime_manifest_for_lock "${runtime_mutation}" duplicate-path)"
expect_failure 'duplicate installed runtime path is rejected' 'runtime installed-file path duplicate' \
  bash "${PROVISION}" --validate-runtime-authority "${runtime_manifest}" "${runtime_mutation}" "${runtime_authority}/policy.yaml"

runtime_mutation="${tmp_root}/runtime-lock-insecure-source.yaml"
cp "${runtime_authority}/lock.yaml" "${runtime_mutation}"
perl -0pi -e 's#source_url: https://#source_url: http://#' "${runtime_mutation}"
runtime_manifest="$(runtime_manifest_for_lock "${runtime_mutation}" insecure-source)"
expect_failure 'non-HTTPS runtime payload source is rejected' 'runtime component source URL invalid' \
  bash "${PROVISION}" --validate-runtime-authority "${runtime_manifest}" "${runtime_mutation}" "${runtime_authority}/policy.yaml"

runtime_mutation="${tmp_root}/runtime-lock-bool-count.yaml"
cp "${runtime_authority}/lock.yaml" "${runtime_mutation}"
perl -0pi -e 's/(  payload_count:) [0-9]+/$1 true/' "${runtime_mutation}"
runtime_manifest="$(runtime_manifest_for_lock "${runtime_mutation}" bool-count)"
expect_failure 'Boolean runtime payload count is rejected' 'runtime payload count type invalid' \
  bash "${PROVISION}" --validate-runtime-authority "${runtime_manifest}" "${runtime_mutation}" "${runtime_authority}/policy.yaml"

runtime_runner_manifest() {
  local runner_file="$1" name="$2" output
  output="${tmp_root}/runtime-runner-manifest-${name}.yaml"
  cp "${runtime_authority}/manifest.yaml" "${output}"
  python3 - "${output}" "${runner_file}" <<'PY'
import hashlib
from pathlib import Path
import sys
import yaml

manifest_path, runner_path = map(Path, sys.argv[1:])
manifest = yaml.safe_load(manifest_path.read_text())
manifest["authority"]["runner_platform_sha256"] = hashlib.sha256(runner_path.read_bytes()).hexdigest()
manifest_path.write_text(yaml.safe_dump(manifest, sort_keys=False))
PY
  printf '%s\n' "${output}"
}

runtime_runner="${tmp_root}/runner-principal-collision.yaml"
cp "${GA_ROOT}/inventory/runner-platform.yaml" "${runtime_runner}"
perl -0pi -e 's/(  uid:) 21001/$1 22001/; s/(  gid:) 21001/$1 22001/' "${runtime_runner}"
runtime_manifest="$(runtime_runner_manifest "${runtime_runner}" principal-collision)"
expect_failure 'Task 5 and Task 6 principal IDs cannot overlap' 'runner and runtime principal identity collision' \
  env PROVISION_VMS_RUNNER_PLATFORM="${runtime_runner}" bash "${PROVISION}" --validate-runtime-authority "${runtime_manifest}" "${runtime_authority}/lock.yaml" "${runtime_authority}/policy.yaml"

runtime_runner="${tmp_root}/runner-subid-collision.yaml"
cp "${GA_ROOT}/inventory/runner-platform.yaml" "${runtime_runner}"
perl -0pi -e 's/(  subuid_start:) 1000000/$1 300000/; s/(  subgid_start:) 1000000/$1 300000/' "${runtime_runner}"
runtime_manifest="$(runtime_runner_manifest "${runtime_runner}" subid-collision)"
expect_failure 'Task 5 and Task 6 subordinate-ID ranges cannot overlap' 'runner and runtime subordinate-ID collision' \
  env PROVISION_VMS_RUNNER_PLATFORM="${runtime_runner}" bash "${PROVISION}" --validate-runtime-authority "${runtime_manifest}" "${runtime_authority}/lock.yaml" "${runtime_authority}/policy.yaml"

runtime_runner="${tmp_root}/runner-bool-subid-count.yaml"
cp "${GA_ROOT}/inventory/runner-platform.yaml" "${runtime_runner}"
perl -0pi -e 's/(  subid_count:) 65536/$1 true/' "${runtime_runner}"
runtime_manifest="$(runtime_runner_manifest "${runtime_runner}" bool-subid-count)"
expect_failure 'Boolean Task 5 subordinate-ID count is rejected' 'runner identity or subordinate-ID type invalid' \
  env PROVISION_VMS_RUNNER_PLATFORM="${runtime_runner}" bash "${PROVISION}" --validate-runtime-authority "${runtime_manifest}" "${runtime_authority}/lock.yaml" "${runtime_authority}/policy.yaml"

endpoint_ready_root="${tmp_root}/endpoint-ready"
mkdir -p "${endpoint_ready_root}"
cp "${endpoint_policy}" "${endpoint_ready_root}/policy.yaml"
cp "${GA_ROOT}/inventory/action-transport.lock.yaml" "${endpoint_ready_root}/task7.yaml"
cp "${runtime_authority}/lock.yaml" "${endpoint_ready_root}/lock.yaml"
cp "${runtime_authority}/policy.yaml" "${endpoint_ready_root}/broker-policy.yaml"
endpoint_runtime_lock="${endpoint_ready_root}/lock.yaml"
endpoint_broker_policy="${endpoint_ready_root}/broker-policy.yaml"
python3 - "${endpoint_ready_root}" "${GA_ROOT}/inventory/runner-platform.yaml" "${endpoint_runtime_lock}" "${endpoint_broker_policy}" <<'PY'
import hashlib
import json
from pathlib import Path
import sys
import yaml

root = Path(sys.argv[1]); runner, lock, broker = map(Path, sys.argv[2:])
task7_path = root / "task7.yaml"
path = root / "policy.yaml"; policy = yaml.safe_load(path.read_text())
policy["authority"].update({
    "runner_platform_sha256": hashlib.sha256(runner.read_bytes()).hexdigest(),
    "broker_runtime_lock_sha256": hashlib.sha256(lock.read_bytes()).hexdigest(),
    "op_broker_policy_sha256": hashlib.sha256(broker.read_bytes()).hexdigest(),
    "action_transport_lock_sha256": hashlib.sha256(task7_path.read_bytes()).hexdigest(),
})
policy["endpoint_catalog"].extend([
    {"id":"vexa-ssh","fqdn":"vexa.example.com","protocol":"tcp","port":22,"source":"single-stop-target-readback"},
    {"id":"vexa-public-health","fqdn":"vexa.example.com","protocol":"tcp","port":443,"source":"single-stop-target-readback"},
    {"id":"website-ssh","fqdn":"website.example.com","protocol":"tcp","port":22,"source":"single-stop-target-readback"},
    {"id":"ken-so-public-health","fqdn":"ken.so","protocol":"tcp","port":443,"source":"single-stop-target-readback"},
    {"id":"getken-ai-separation","fqdn":"getken.ai","protocol":"tcp","port":443,"source":"single-stop-target-readback"},
    {"id":"frontend-deploy","fqdn":"frontend.example.com","protocol":"tcp","port":22,"source":"single-stop-target-readback"},
    {"id":"frontend-public-health","fqdn":"frontend.example.com","protocol":"tcp","port":443,"source":"single-stop-target-readback"},
])
policy["ci_runner_egress"]["denied_endpoint_ids"].extend([
    "vexa-ssh", "vexa-public-health", "website-ssh", "ken-so-public-health",
    "getken-ai-separation", "frontend-deploy", "frontend-public-health",
])
policy["profiles"]["vexa-production-fixed-target"]["phases"] = {
    "vexa-ssh":{"uids":[22101],"targets":["vexa-ssh"],"activation":"request-bound"},
    "vexa-public-health":{"uids":[22101],"targets":["vexa-public-health"],"activation":"request-bound"},
}
policy["profiles"]["website-production-fixed-target"]["phases"] = {
    "website-ssh":{"uids":[22103],"targets":["website-ssh"],"activation":"request-bound"},
    "ken-so-public-health":{"uids":[22103],"targets":["ken-so-public-health"],"activation":"request-bound"},
    "getken-ai-separation":{"uids":[22103],"targets":["getken-ai-separation"],"activation":"request-bound"},
}
policy["profiles"]["frontend-production-digest-deploy"]["phases"].update({
    "frontend-deploy":{"uids":[22203],"targets":["frontend-deploy"],"activation":"request-bound"},
    "frontend-public-health":{"uids":[22203],"targets":["frontend-public-health"],"activation":"request-bound"},
})
policy["onepassword_endpoint_authority"]["status"] = "ready"
canary_path = root / "onepassword-linux-canary.json"
canary_path.write_text(json.dumps({
    "schema_version": 1,
    "status": "ready",
    "commands": ["op-read", "op-inject", "op-run"],
    "cache": False,
    "fresh_config": True,
    "direct_egress": "denied",
    "observed_relay_authorities": ["ken-ai.1password.com:443"],
}, sort_keys=True, separators=(",", ":")) + "\n")
canary_path.chmod(0o600)
policy["onepassword_endpoint_authority"]["linux_canary"].update({
    "status":"ready",
    "receipt_path":"/var/lib/ken-actions/receipts/onepassword-linux-canary.json",
    "receipt_sha256":hashlib.sha256(canary_path.read_bytes()).hexdigest(),
})
policy["unresolved_targets"] = []
policy["generation"] = {"status":"resolution-required","receipt_path":None,"receipt_sha256":None}
policy["readiness"] = {"state":"resolution-ready","blockers":[]}
path.write_text(yaml.safe_dump(policy, sort_keys=False))
PY
endpoint_test_ips="$(python3 - "${endpoint_ready_root}/policy.yaml" <<'PY'
import sys,yaml
policy=yaml.safe_load(open(sys.argv[1])); fqdns=sorted({item["fqdn"] for item in policy["endpoint_catalog"]})
addresses=["1.1.1.1","8.8.8.8","9.9.9.9","93.184.216.34"]
print(",".join(f"{fqdn}={addresses[index % len(addresses)]}" for index,fqdn in enumerate(fqdns)))
PY
)"
expect_failure 'ready endpoint authority rejects a missing 1Password canary receipt' '1Password endpoint canary receipt is missing or unsafe' \
  env PROVISION_VMS_COMMAND_TEST=1 KEN_ACTIONS_FIREWALL_GENERATED_AT_EPOCH=1787225400 KEN_ACTIONS_FIREWALL_TEST_IPS="${endpoint_test_ips}" \
  bash "${PROVISION}" --resolve-firewall-endpoints "${endpoint_ready_root}/policy.yaml" "${GA_ROOT}/inventory/runner-platform.yaml" "${endpoint_runtime_lock}" "${endpoint_broker_policy}" "${endpoint_ready_root}/task7.yaml" "${endpoint_generation}"
expect_success 'ready endpoint authority resolves one exact numeric generation' 'FIREWALL_ENDPOINTS_OK endpoints=22 profiles=9' \
  env PROVISION_VMS_COMMAND_TEST=1 KEN_ACTIONS_ONEPASSWORD_CANARY_RECEIPT="${endpoint_ready_root}/onepassword-linux-canary.json" KEN_ACTIONS_FIREWALL_GENERATED_AT_EPOCH=1787225400 KEN_ACTIONS_FIREWALL_TEST_IPS="${endpoint_test_ips}" \
  bash "${PROVISION}" --resolve-firewall-endpoints "${endpoint_ready_root}/policy.yaml" "${GA_ROOT}/inventory/runner-platform.yaml" "${endpoint_runtime_lock}" "${endpoint_broker_policy}" "${endpoint_ready_root}/task7.yaml" "${endpoint_generation}" "${endpoint_generation_receipt}"
check 'numeric generation binds profiles, UIDs, bridges, ports, and expiry' python3 - "${endpoint_generation}" <<'PY'
import ipaddress,json,sys
value=json.load(open(sys.argv[1])); assert value["generated_at_epoch"] == 1787225400 and value["expires_at_epoch"] == 1787229000 and value["refresh_interval_seconds"] == 900
assert value["profiles"]["vexa-production-fixed-target"]["phases"]["vexa-ssh"]["uids"] == [22101]
assert value["profiles"]["vexa-production-fixed-target"]["phases"]["vexa-ssh"]["routes"][0]["port"] == 22
assert value["profiles"]["beehiiv-api-fixed-target"]["phases"]["beehiiv-api"]["uids"] == [22102]
assert value["profiles"]["github-ssh-ken-website-fixed-target"]["phases"]["github-ssh"]["routes"][0]["port"] == 22
assert value["profiles"]["frontend-production-digest-deploy"]["phases"]["ghcr-write"]["uids"] == [22003]
assert set(value["profiles"]["frontend-production-digest-deploy"]["phases"]) == {
    "node-base-read", "package-read", "build-offline", "posthog-upload",
    "ghcr-write", "frontend-deploy", "frontend-public-health",
}
assert value["ci_runner_egress"]["uids"] == [21001,21002,21003,21004,21005,21006,21007,21008,21011,21012]
assert value["ci_runner_egress"]["ports"] == [80,443]
assert value["ci_runner_egress"]["proxy_access"] == "denied" and value["ci_runner_egress"]["ipv6"] == "denied"
assert set(value["ci_runner_egress"]["denied_endpoint_ids"]) == {"onepassword-service-account","vexa-ssh","vexa-public-health","website-ssh","ken-so-public-health","getken-ai-separation","frontend-deploy","frontend-public-health"}
assert set(value["ci_runner_egress"]["denied_ipv4"])
assert value["proxy"] == {
    "included_in_targets":False,"included_in_bridge_direct_unions":False,
    "listen_interface":"virbr-deploy","listen_address":"192.168.211.1",
    "listen_port":3128,"protocol":"tcp","connect_port":443,
    "fqdn_regex":"^[a-z0-9]{3,24}[.]blob[.]core[.]windows[.]net$",
    "ipv4_only":True,"public_only":True,
    "resolver_addresses":["127.0.0.53"],"resolver_protocols":["udp","tcp"],
    "resolver_port":53,
}
assert {route["port"] for route in value["bridges"]["virbr-ci"]} == {443}
assert {route["port"] for route in value["bridges"]["virbr-deploy"]} == {22,443}
assert all(ipaddress.ip_address(address).is_global for routes in value["bridges"].values() for route in routes for address in route["ipv4"])
print("ENDPOINT_GENERATION_OK")
PY
check 'numeric generation receipt binds exact authority and verified output digest' python3 - "${endpoint_generation}" "${endpoint_generation_receipt}" <<'PY'
import hashlib,json,sys
generation_bytes=open(sys.argv[1],"rb").read(); generation=json.loads(generation_bytes); receipt=json.load(open(sys.argv[2]))
assert set(receipt) == {"schema_version","authority","generation","verification"}
assert type(receipt["schema_version"]) is int and receipt["schema_version"] == 1
assert receipt["authority"] == generation["authority"]
assert receipt["generation"] == {
    "path":"/var/lib/ken-actions/authority/firewall-endpoint-generation.json",
    "sha256":hashlib.sha256(generation_bytes).hexdigest(),
    "generated_at_epoch":generation["generated_at_epoch"],
    "expires_at_epoch":generation["expires_at_epoch"],
}
assert receipt["verification"] == {"public_ipv4_only":True,"exact_profiles":True,"exact_bridge_unions":True,"onepassword_canary_bound":True}
PY
python3 - "${endpoint_generation}" "${endpoint_ready_root}" <<'PY'
import copy
import json
from pathlib import Path
import sys

source = json.loads(Path(sys.argv[1]).read_text())
root = Path(sys.argv[2])

mutations = {}
value = copy.deepcopy(source)
value["onepassword_endpoint_authority"]["fqdn"] = "events.1password.com"
mutations["numeric-onepassword-drift.json"] = value
value = copy.deepcopy(source)
value["ci_runner_egress"]["denied_endpoint_ids"] = value["ci_runner_egress"]["denied_endpoint_ids"][:-1]
mutations["numeric-denied-endpoint-drift.json"] = value
value = copy.deepcopy(source)
value["ci_runner_egress"]["denied_networks"] = value["ci_runner_egress"]["denied_networks"][:-1]
mutations["numeric-denied-network-drift.json"] = value
value = copy.deepcopy(source)
value["bridges"]["virbr-deploy"].append({"protocol": "tcp", "port": 22, "ipv4": ["8.8.4.4"]})
mutations["numeric-duplicate-port.json"] = value
value = copy.deepcopy(source)
value["proxy"]["resolver_addresses"] = ["8.8.8.8"]
mutations["numeric-proxy-resolver-drift.json"] = value

for name, value in mutations.items():
    (root / name).write_text(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n")
PY
# shellcheck disable=SC2016
expect_failure 'numeric renderer rejects 1Password endpoint authority drift' 'numeric 1Password endpoint authority drift' \
  env KEN_ACTIONS_FIREWALL_NOW_EPOCH=1787226000 bash -c 'set -euo pipefail; source "$1"; render_ken_actions_numeric_generation host none none none "$2" "$3" 29999' _ "${FIREWALL}" "${endpoint_ready_root}/numeric-onepassword-drift.json" "${endpoint_ready_root}/rejected-onepassword.nft"
# shellcheck disable=SC2016
expect_failure 'numeric renderer rejects missing CI denied endpoint authority' 'numeric CI denied endpoint authority drift' \
  env KEN_ACTIONS_FIREWALL_NOW_EPOCH=1787226000 bash -c 'set -euo pipefail; source "$1"; render_ken_actions_numeric_generation host none none none "$2" "$3" 29999' _ "${FIREWALL}" "${endpoint_ready_root}/numeric-denied-endpoint-drift.json" "${endpoint_ready_root}/rejected-denied-endpoint.nft"
# shellcheck disable=SC2016
expect_failure 'numeric renderer rejects missing CI denied network authority' 'numeric CI denied network authority drift' \
  env KEN_ACTIONS_FIREWALL_NOW_EPOCH=1787226000 bash -c 'set -euo pipefail; source "$1"; render_ken_actions_numeric_generation host none none none "$2" "$3" 29999' _ "${FIREWALL}" "${endpoint_ready_root}/numeric-denied-network-drift.json" "${endpoint_ready_root}/rejected-denied-network.nft"
# shellcheck disable=SC2016
expect_failure 'numeric renderer rejects duplicate deploy bridge port authority' 'numeric deploy bridge port authority duplicated' \
  env KEN_ACTIONS_FIREWALL_NOW_EPOCH=1787226000 bash -c 'set -euo pipefail; source "$1"; render_ken_actions_numeric_generation host none none none "$2" "$3" 29999' _ "${FIREWALL}" "${endpoint_ready_root}/numeric-duplicate-port.json" "${endpoint_ready_root}/rejected-duplicate-port.nft"
# shellcheck disable=SC2016
expect_failure 'numeric renderer rejects alternate proxy resolver authority' 'numeric firewall proxy boundary drift' \
  env KEN_ACTIONS_FIREWALL_NOW_EPOCH=1787226000 bash -c 'set -euo pipefail; source "$1"; render_ken_actions_numeric_generation host none none none "$2" "$3" 29999' _ "${FIREWALL}" "${endpoint_ready_root}/numeric-proxy-resolver-drift.json" "${endpoint_ready_root}/rejected-proxy-resolver.nft"
numeric_host_rules="${endpoint_ready_root}/host.nft"
numeric_ci_rules="${endpoint_ready_root}/ci.nft"
numeric_deploy_rules="${endpoint_ready_root}/deploy.nft"
numeric_vexa_rules="${endpoint_ready_root}/vexa.nft"
numeric_offline_rules="${endpoint_ready_root}/build-offline.nft"
# shellcheck disable=SC2016
expect_success 'numeric host generation renders CI public web and exact deploy unions' 'NUMERIC_FIREWALL_OK mode=host' \
  env KEN_ACTIONS_FIREWALL_NOW_EPOCH=1787226000 bash -c 'set -euo pipefail; source "$1"; render_ken_actions_numeric_generation host none none none "$2" "$3" 29999' _ "${FIREWALL}" "${endpoint_generation}" "${numeric_host_rules}"
# shellcheck disable=SC2016
expect_success 'numeric CI guest generation renders standing runner and broker rules' 'NUMERIC_FIREWALL_OK mode=guest-base' \
  env KEN_ACTIONS_FIREWALL_NOW_EPOCH=1787226000 bash -c 'set -euo pipefail; source "$1"; render_ken_actions_numeric_generation guest-base ken-ci none none "$2" "$3"' _ "${FIREWALL}" "${endpoint_generation}" "${numeric_ci_rules}"
# shellcheck disable=SC2016
expect_success 'numeric deploy guest generation renders standing runners, brokers, and proxy' 'NUMERIC_FIREWALL_OK mode=guest-base' \
  env KEN_ACTIONS_FIREWALL_NOW_EPOCH=1787226000 bash -c 'set -euo pipefail; source "$1"; render_ken_actions_numeric_generation guest-base ken-deploy none none "$2" "$3"' _ "${FIREWALL}" "${endpoint_generation}" "${numeric_deploy_rules}"
# shellcheck disable=SC2016
expect_success 'numeric Vexa request renders exact executor SSH phase' 'NUMERIC_FIREWALL_OK mode=guest-phase' \
  env KEN_ACTIONS_FIREWALL_NOW_EPOCH=1787226000 bash -c 'set -euo pipefail; source "$1"; render_ken_actions_numeric_generation guest-phase ken-deploy vexa-production-fixed-target vexa-ssh "$2" "$3"' _ "${FIREWALL}" "${endpoint_generation}" "${numeric_vexa_rules}"
# shellcheck disable=SC2016
expect_success 'numeric frontend offline build phase renders no target rules' 'NUMERIC_FIREWALL_OK mode=guest-phase' \
  env KEN_ACTIONS_FIREWALL_NOW_EPOCH=1787226000 bash -c 'set -euo pipefail; source "$1"; render_ken_actions_numeric_generation guest-phase ken-deploy frontend-production-digest-deploy build-offline "$2" "$3"' _ "${FIREWALL}" "${endpoint_generation}" "${numeric_offline_rules}"
if grep -Fq 'profile=frontend-production-digest-deploy phase=build-offline' "${numeric_offline_rules}" && \
   ! grep -Fq 'meta skuid 22201 ip daddr' "${numeric_offline_rules}"; then
  pass 'numeric offline build keeps UID 22201 network dark'
else
  fail 'numeric offline build keeps UID 22201 network dark'
fi
check 'two-layer numeric rules keep CI broad web separate from deploy and executor authority' python3 - "${endpoint_generation}" "${numeric_host_rules}" "${numeric_ci_rules}" "${numeric_deploy_rules}" "${numeric_vexa_rules}" <<'PY'
import json,sys
generation=json.load(open(sys.argv[1])); host,ci,deploy,vexa=[open(path).read() for path in sys.argv[2:]]
assert 'iifname "virbr-ci" tcp dport { 80, 443 } accept' in host
assert 'iifname "virbr-ci" ip daddr @ci_denied_endpoint_v4 drop' in host
assert 'iifname "virbr-deploy" ip daddr @deploy_tcp_22_v4 tcp dport 22 accept' in host
assert 'iifname "virbr-deploy" ip daddr @deploy_tcp_443_v4 tcp dport 443 accept' in host
assert 'iifname "virbr-deploy" tcp dport { 80, 443 } accept' not in host
for uid in [21001,21002,21003,21004,21005,21006,21007,21008,21011,21012]:
    assert f'meta skuid {uid} tcp dport {{ 80, 443 }} accept' in ci
    assert f'meta skuid {uid} ip daddr @ci_denied_endpoint_v4 drop' in ci
    assert f'meta skuid {uid} ip daddr 192.168.210.1 meta l4proto {{ tcp, udp }} th dport 53 accept' in ci
for uid in [21009,21010,21013,21014,22101,22102,22103,22104,22201,22202,22203]:
    assert f'meta skuid {uid} tcp dport {{ 80, 443 }} accept' not in ci
assert 'meta skuid 21013 ip daddr 192.168.211.1 tcp dport 3128 accept' in deploy
assert 'meta skuid 21014 ip daddr 192.168.211.1 tcp dport 3128 accept' in deploy
assert 'meta skuid 21001 ip daddr 192.168.211.1 tcp dport 3128 accept' not in deploy
assert '    ip daddr 192.168.210.1 meta l4proto { tcp, udp } th dport 53 accept' not in ci
assert '    ip daddr 192.168.211.1 meta l4proto { tcp, udp } th dport 53 accept' not in deploy
assert 'meta skuid 0 ip daddr 192.168.211.1 meta l4proto { tcp, udp } th dport 53 accept' in deploy
for uid in [21013,21014,22001,22002,22003,22101,22102,22103,22104,22201,22202,22203]:
    assert f'meta skuid {uid} ip daddr 192.168.211.1 meta l4proto {{ tcp, udp }} th dport 53 accept' not in deploy
assert 'meta skuid 22101 ip daddr @phase_target_22_v4 tcp dport 22 accept' in vexa
assert 'tcp dport 443 accept' not in vexa
assert 'meta skuid 22101 ip daddr 192.168.211.1 meta l4proto { tcp, udp } th dport 53 accept' not in vexa
assert 'set proxy_resolver_v4 {' in host and 'elements = { 127.0.0.53 }' in host
resolver_rule = 'meta skuid 29999 ip daddr @proxy_resolver_v4 meta l4proto { tcp, udp } th dport 53 accept'
assert resolver_rule in host
assert host.index(resolver_rule) < host.index('meta skuid 29999 ip daddr @denied_private_v4 drop')
assert 'meta skuid 29999 meta l4proto { tcp, udp } th dport 53 accept' not in host
print('NUMERIC_LAYERING_OK')
PY
request_phase_root="${endpoint_ready_root}/request-phases"
mkdir -p "${request_phase_root}"
check 'every request-bound deploy phase is DNS-dark and numeric-target-only' python3 - "${FIREWALL}" "${endpoint_generation}" "${request_phase_root}" <<'PY'
import json
from pathlib import Path
import subprocess
import sys

firewall, generation_path, output_root = Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3])
generation = json.loads(generation_path.read_text())
for profile, profile_record in generation["profiles"].items():
    if profile_record["guest"] != "ken-deploy":
        continue
    for phase, phase_record in profile_record["phases"].items():
        if phase_record["activation"] != "request-bound":
            continue
        output = output_root / f"{profile}--{phase}.nft"
        result = subprocess.run([
            "/bin/bash", "-c",
            'set -euo pipefail; source "$1"; render_ken_actions_numeric_generation guest-phase ken-deploy "$2" "$3" "$4" "$5"',
            "_", str(firewall), profile, phase, str(generation_path), str(output),
        ], text=True, capture_output=True, env={"PATH":"/usr/bin:/bin", "KEN_ACTIONS_FIREWALL_NOW_EPOCH":"1787226000"})
        assert result.returncode == 0, result.stderr
        text = output.read_text()
        for uid in phase_record["uids"]:
            assert f"meta skuid {uid} ip daddr 192.168.211.1 meta l4proto {{ tcp, udp }} th dport 53 accept" not in text, (profile, phase)
        grouped = {}
        for route in phase_record["routes"]:
            grouped.setdefault(route["port"], set()).update(route["ipv4"])
        for port, addresses in grouped.items():
            assert all(address in text for address in addresses), (profile, phase, port)
            for uid in phase_record["uids"]:
                assert f"meta skuid {uid} ip daddr @phase_target_{port}_v4 tcp dport {port} accept" in text
print("REQUEST_PHASE_DNS_DARK_OK")
PY
check 'proxy hostname resolution permits only public Blob CONNECT on 443 through the exact resolver' \
  python3 - "${GA_ROOT}/proxy/ken-actions-artifact-proxy-deploy.conf" "${numeric_host_rules}" <<'PY'
import ipaddress
from pathlib import Path
import re
import sys

proxy, host = [Path(path).read_text() for path in sys.argv[1:]]
assert "dns_nameservers 127.0.0.53" in proxy
assert "acl CONNECT method CONNECT" in proxy and "acl SSL_ports port 443" in proxy
assert "http_access deny !CONNECT" in proxy and "http_access deny !SSL_ports" in proxy
assert "http_access deny !blob_host" in proxy and "http_access deny private_v4" in proxy
assert "http_access deny !blob_authority" in proxy
assert "http_access deny ipv6_dst" in proxy and "http_access deny all" in proxy
assert "meta skuid 29999 ip daddr @proxy_resolver_v4 meta l4proto { tcp, udp } th dport 53 accept" in host
assert "meta skuid 29999 tcp dport 443 accept" in host and "meta skuid 29999 drop" in host

blob = re.compile(r"^[a-z0-9]{3,24}[.]blob[.]core[.]windows[.]net$")
def allowed(method, host_name, port, address):
    ip = ipaddress.ip_address(address)
    return method == "CONNECT" and port == 443 and bool(blob.fullmatch(host_name)) and ip.version == 4 and ip.is_global

assert allowed("CONNECT", "approvedacct.blob.core.windows.net", 443, "93.184.216.34")
assert not allowed("CONNECT", "8.8.8.8", 443, "8.8.8.8")
assert not allowed("CONNECT", "approvedacct.blob.core.windows.net", 443, "10.0.0.8")
assert not allowed("CONNECT", "approvedacct.blob.core.windows.net", 443, "2001:4860:4860::8888")
assert not allowed("CONNECT", "approvedacct.blob.core.windows.net", 80, "93.184.216.34")
assert "8.8.8.8" not in host.split("set proxy_resolver_v4", 1)[1].split("}", 1)[0]
print("PROXY_RESOLUTION_BOUNDARY_OK")
PY
expired_generation="${endpoint_ready_root}/expired-generation.json"
cp "${endpoint_generation}" "${expired_generation}"
# shellcheck disable=SC2016
expect_failure 'expired numeric generation fails before nft rendering' 'numeric firewall generation is future or expired' \
  env KEN_ACTIONS_FIREWALL_NOW_EPOCH=1787229000 bash -c 'set -euo pipefail; source "$1"; render_ken_actions_numeric_generation host none none none "$2" "$3" 29999' _ "${FIREWALL}" "${expired_generation}" "${endpoint_ready_root}/expired.nft"
host_refresh_root="${endpoint_ready_root}/host-refresh"
host_refresh_bin="${host_refresh_root}/bin"
host_refresh_runtime="${host_refresh_root}/runtime"
host_refresh_state="${host_refresh_root}/state"
host_refresh_live="${host_refresh_root}/live.nft"
mkdir -p "${host_refresh_bin}" "${host_refresh_runtime}" "${host_refresh_state}"
chmod 0700 "${host_refresh_runtime}" "${host_refresh_state}"
cp "${FIREWALL}" "${host_refresh_bin}/ken-actions-vm-firewall"
chmod +x "${host_refresh_bin}/ken-actions-vm-firewall"
cat >"${host_refresh_bin}/nft" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
printf 'nft %s\n' "$*" >>"${KEN_ACTIONS_NFT_LOG:?}"
if [[ "${1:-}" == -c && "${2:-}" == -f ]]; then
  exit 0
elif [[ "${1:-}" == -f ]]; then
  cp "$2" "${KEN_ACTIONS_NFT_LIVE:?}"
elif [[ "${1:-}" == list && "${2:-}" == table ]]; then
  cat "${KEN_ACTIONS_NFT_LIVE:?}"
else
  exit 64
fi
SH
chmod +x "${host_refresh_bin}/nft"
host_refresh_env=(
  env PATH="${host_refresh_bin}:/usr/bin:/bin"
  KEN_ACTIONS_FIREWALL_COMMAND_TEST=1
  KEN_ACTIONS_FIREWALL_RUNTIME_ROOT="${host_refresh_runtime}"
  KEN_ACTIONS_FIREWALL_STATE_ROOT="${host_refresh_state}"
  KEN_ACTIONS_PROXY_UID=29999
  KEN_ACTIONS_NFT_LOG="${host_refresh_root}/nft.log"
  KEN_ACTIONS_NFT_LIVE="${host_refresh_live}"
)
expect_success 'host refresh atomically installs a fresh numeric generation' 'HOST_FIREWALL_OK source=fresh' \
  "${host_refresh_env[@]}" KEN_ACTIONS_FIREWALL_NOW_EPOCH=1787226000 KEN_ACTIONS_FIREWALL_GENERATION_SOURCE="${endpoint_generation}" \
  "${host_refresh_bin}/ken-actions-vm-firewall" refresh
expect_success 'resolver failure retains an unexpired exact LKG' 'HOST_FIREWALL_LKG_OK' \
  "${host_refresh_env[@]}" KEN_ACTIONS_FIREWALL_NOW_EPOCH=1787227000 KEN_ACTIONS_FIREWALL_GENERATION_SOURCE="${host_refresh_root}/missing.json" \
  "${host_refresh_bin}/ken-actions-vm-firewall" refresh
if grep -Fq 'generation=1787225400' "${host_refresh_live}" && [[ -f "${host_refresh_state}/firewall-endpoint-generation.lkg.json" ]]; then
  pass 'unexpired LKG refresh preserves exact numeric rules and authority'
else
  fail 'unexpired LKG refresh preserves exact numeric rules and authority'
fi
expect_failure 'expired LKG installs the blocked host generation' 'LKG expired or missing' \
  "${host_refresh_env[@]}" KEN_ACTIONS_FIREWALL_NOW_EPOCH=1787229000 KEN_ACTIONS_FIREWALL_GENERATION_SOURCE="${host_refresh_root}/missing.json" \
  "${host_refresh_bin}/ken-actions-vm-firewall" refresh
if grep -Fq 'readiness=blocked reason=expired-or-missing-generation' "${host_refresh_live}" && ! grep -Fq 'tcp dport { 80, 443 } accept' "${host_refresh_live}"; then
  pass 'expired LKG removes CI/deploy/proxy egress instead of broadening'
else
  fail 'expired LKG removes CI/deploy/proxy egress instead of broadening'
fi
guest_refresh_root="${endpoint_ready_root}/guest-refresh"
guest_refresh_bin="${guest_refresh_root}/bin"
guest_refresh_runtime="${guest_refresh_root}/runtime"
guest_refresh_state="${guest_refresh_root}/state"
guest_refresh_live="${guest_refresh_root}/live.nft"
guest_refresh_base="${guest_refresh_root}/guest-base.nft"
guest_refresh_generation="${guest_refresh_root}/firewall-endpoint-generation.json"
mkdir -p "${guest_refresh_bin}" "${guest_refresh_runtime}" "${guest_refresh_state}/active-requests"
chmod 0700 "${guest_refresh_runtime}" "${guest_refresh_state}" "${guest_refresh_state}/active-requests"
cp "${FIREWALL}" "${guest_refresh_bin}/ken-actions-guest-firewall"
chmod +x "${guest_refresh_bin}/ken-actions-guest-firewall"
cp "${numeric_deploy_rules}" "${guest_refresh_base}"
cp "${endpoint_generation}" "${guest_refresh_generation}"
printf '%s\n' ken-deploy >"${guest_refresh_root}/guest-class"
cat >"${guest_refresh_bin}/nft" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
printf 'nft %s\n' "$*" >>"${KEN_ACTIONS_NFT_LOG:?}"
if [[ "${1:-}" == -c && "${2:-}" == -f ]]; then
  exit 0
elif [[ "${1:-}" == -f ]]; then
  cp "$2" "${KEN_ACTIONS_NFT_LIVE:?}"
elif [[ "${1:-}" == list && "${2:-}" == table ]]; then
  cat "${KEN_ACTIONS_NFT_LIVE:?}"
else
  exit 64
fi
SH
chmod +x "${guest_refresh_bin}/nft"
guest_refresh_env=(
  env PATH="${guest_refresh_bin}:/usr/bin:/bin"
  KEN_ACTIONS_FIREWALL_COMMAND_TEST=1
  KEN_ACTIONS_FIREWALL_RUNTIME_ROOT="${guest_refresh_runtime}"
  KEN_ACTIONS_FIREWALL_STATE_ROOT="${guest_refresh_state}"
  KEN_ACTIONS_FIREWALL_BASE_FILE="${guest_refresh_base}"
  KEN_ACTIONS_FIREWALL_ENDPOINT_GENERATION_FILE="${guest_refresh_generation}"
  KEN_ACTIONS_FIREWALL_GUEST_CLASS_FILE="${guest_refresh_root}/guest-class"
  KEN_ACTIONS_FIREWALL_POLICY_FILE="${endpoint_broker_policy}"
  KEN_ACTIONS_FIREWALL_RUNNER_FILE="${GA_ROOT}/inventory/runner-platform.yaml"
  KEN_ACTIONS_NFT_LOG="${guest_refresh_root}/nft.log"
  KEN_ACTIONS_NFT_LIVE="${guest_refresh_live}"
)
expect_success 'guest refresh atomically installs a fresh numeric generation' 'GUEST_FIREWALL_OK source=fresh guest=ken-deploy' \
  "${guest_refresh_env[@]}" KEN_ACTIONS_FIREWALL_NOW_EPOCH=1787226000 KEN_ACTIONS_FIREWALL_GENERATION_SOURCE="${endpoint_generation}" \
  "${guest_refresh_bin}/ken-actions-guest-firewall" refresh
refresh_request_id=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
printf '%s\n' "{\"schema_version\":1,\"request_id\":\"${refresh_request_id}\",\"profile\":\"vexa-production-fixed-target\",\"phase\":\"vexa-ssh\"}" >"${guest_refresh_state}/active-requests/${refresh_request_id}.json"
chmod 0600 "${guest_refresh_state}/active-requests/${refresh_request_id}.json"
expect_success 'guest refresh atomically recomputes an active request union' 'GUEST_FIREWALL_OK source=fresh guest=ken-deploy' \
  "${guest_refresh_env[@]}" KEN_ACTIONS_FIREWALL_NOW_EPOCH=1787226000 KEN_ACTIONS_FIREWALL_GENERATION_SOURCE="${endpoint_generation}" \
  "${guest_refresh_bin}/ken-actions-guest-firewall" refresh
if grep -Fq "requests=${refresh_request_id}" "${guest_refresh_live}" && grep -Fq 'meta skuid 22101' "${guest_refresh_live}"; then
  pass 'guest endpoint refresh preserves active per-request phase authority'
else
  fail 'guest endpoint refresh preserves active per-request phase authority'
fi
expect_success 'guest resolver failure retains an unexpired exact LKG' 'GUEST_FIREWALL_LKG_OK guest=ken-deploy' \
  "${guest_refresh_env[@]}" KEN_ACTIONS_FIREWALL_NOW_EPOCH=1787227000 KEN_ACTIONS_FIREWALL_GENERATION_SOURCE="${guest_refresh_root}/missing.json" \
  "${guest_refresh_bin}/ken-actions-guest-firewall" refresh
if grep -Fq "requests=${refresh_request_id}" "${guest_refresh_live}" && grep -Fq 'meta skuid 22101' "${guest_refresh_live}" && [[ -f "${guest_refresh_state}/firewall-endpoint-generation.lkg.json" ]]; then
  pass 'guest LKG refresh preserves exact standing numeric rules'
else
  fail 'guest LKG refresh preserves exact standing numeric rules'
fi
expect_failure 'expired guest LKG installs a blocked guest generation' 'guest firewall endpoint generation unavailable and LKG expired or missing' \
  "${guest_refresh_env[@]}" KEN_ACTIONS_FIREWALL_NOW_EPOCH=1787229000 KEN_ACTIONS_FIREWALL_GENERATION_SOURCE="${guest_refresh_root}/missing.json" \
  "${guest_refresh_bin}/ken-actions-guest-firewall" refresh
if grep -Fq 'blocker=expired-or-missing-generation' "${guest_refresh_live}" && \
   ! grep -Fq 'meta skuid 21013' "${guest_refresh_live}" && \
   grep -Fq 'meta skuid 0 ip daddr 192.168.211.1 meta l4proto { tcp, udp } th dport 53 accept' "${guest_refresh_live}"; then
  pass 'expired guest LKG removes runner, broker, and executor egress but preserves root DNS refresh'
else
  fail 'expired guest LKG removes runner, broker, and executor egress but preserves root DNS refresh'
fi
private_generation="${endpoint_ready_root}/private-answer.json"
private_ips="$(python3 - "${endpoint_test_ips}" <<'PY'
import sys
items=sys.argv[1].split(','); name=items[0].split('=',1)[0]
print(','.join([f'{name}=10.0.0.1',*items[1:]]))
PY
)"
expect_failure 'private endpoint answer rejects the whole candidate' 'firewall endpoint answer is not public IPv4' \
  env PROVISION_VMS_COMMAND_TEST=1 KEN_ACTIONS_ONEPASSWORD_CANARY_RECEIPT="${endpoint_ready_root}/onepassword-linux-canary.json" KEN_ACTIONS_FIREWALL_GENERATED_AT_EPOCH=1787225400 KEN_ACTIONS_FIREWALL_TEST_IPS="${private_ips}" \
  bash "${PROVISION}" --resolve-firewall-endpoints "${endpoint_ready_root}/policy.yaml" "${GA_ROOT}/inventory/runner-platform.yaml" "${endpoint_runtime_lock}" "${endpoint_broker_policy}" "${endpoint_ready_root}/task7.yaml" "${private_generation}"
if [[ ! -e "${private_generation}" ]]; then pass 'unsafe partial resolution leaves no generation'; else fail 'unsafe partial resolution leaves no generation'; fi

endpoint_swapped="${endpoint_ready_root}/swapped.yaml"
cp "${endpoint_ready_root}/policy.yaml" "${endpoint_swapped}"
python3 - "${endpoint_swapped}" <<'PY'
from pathlib import Path
import sys,yaml
p=Path(sys.argv[1]); value=yaml.safe_load(p.read_text())
value["bridge_profiles"]["virbr-ci"],value["bridge_profiles"]["virbr-deploy"]=value["bridge_profiles"]["virbr-deploy"],value["bridge_profiles"]["virbr-ci"]
p.write_text(yaml.safe_dump(value,sort_keys=False))
PY
expect_failure 'CI/deploy endpoint profile swap is rejected' 'CI bridge endpoint profile drift' \
  env PROVISION_VMS_COMMAND_TEST=1 KEN_ACTIONS_ONEPASSWORD_CANARY_RECEIPT="${endpoint_ready_root}/onepassword-linux-canary.json" KEN_ACTIONS_FIREWALL_GENERATED_AT_EPOCH=1787225400 KEN_ACTIONS_FIREWALL_TEST_IPS="${endpoint_test_ips}" \
  bash "${PROVISION}" --resolve-firewall-endpoints "${endpoint_swapped}" "${GA_ROOT}/inventory/runner-platform.yaml" "${endpoint_runtime_lock}" "${endpoint_broker_policy}" "${endpoint_ready_root}/task7.yaml" "${private_generation}"

endpoint_bool_port="${endpoint_ready_root}/bool-port.yaml"
cp "${endpoint_ready_root}/policy.yaml" "${endpoint_bool_port}"
perl -0pi -e 's/(port: 443)/port: true/' "${endpoint_bool_port}"
expect_failure 'Boolean endpoint port is rejected' 'firewall endpoint protocol or port invalid' \
  env PROVISION_VMS_COMMAND_TEST=1 KEN_ACTIONS_ONEPASSWORD_CANARY_RECEIPT="${endpoint_ready_root}/onepassword-linux-canary.json" KEN_ACTIONS_FIREWALL_GENERATED_AT_EPOCH=1787225400 KEN_ACTIONS_FIREWALL_TEST_IPS="${endpoint_test_ips}" \
  bash "${PROVISION}" --resolve-firewall-endpoints "${endpoint_bool_port}" "${GA_ROOT}/inventory/runner-platform.yaml" "${endpoint_runtime_lock}" "${endpoint_broker_policy}" "${endpoint_ready_root}/task7.yaml" "${private_generation}"

endpoint_uid_swap="${endpoint_ready_root}/uid-swap.yaml"
cp "${endpoint_ready_root}/policy.yaml" "${endpoint_uid_swap}"
perl -0pi -e 's/(posthog-upload:\n        uids:\n        -) 22202/$1 22003/' "${endpoint_uid_swap}"
expect_failure 'PostHog/GHCR UID ownership swap is rejected' 'frontend firewall phase UID ownership drift' \
  env PROVISION_VMS_COMMAND_TEST=1 KEN_ACTIONS_ONEPASSWORD_CANARY_RECEIPT="${endpoint_ready_root}/onepassword-linux-canary.json" KEN_ACTIONS_FIREWALL_GENERATED_AT_EPOCH=1787225400 KEN_ACTIONS_FIREWALL_TEST_IPS="${endpoint_test_ips}" \
  bash "${PROVISION}" --resolve-firewall-endpoints "${endpoint_uid_swap}" "${GA_ROOT}/inventory/runner-platform.yaml" "${endpoint_runtime_lock}" "${endpoint_broker_policy}" "${endpoint_ready_root}/task7.yaml" "${private_generation}"

endpoint_hash_drift="${endpoint_ready_root}/task7-drift.yaml"
cp "${endpoint_ready_root}/task7.yaml" "${endpoint_hash_drift}"
printf '\n# drift\n' >>"${endpoint_hash_drift}"
expect_failure 'Task 7 endpoint authority hash drift is rejected' 'Task 7 transport digest mismatch' \
  env PROVISION_VMS_COMMAND_TEST=1 KEN_ACTIONS_ONEPASSWORD_CANARY_RECEIPT="${endpoint_ready_root}/onepassword-linux-canary.json" KEN_ACTIONS_FIREWALL_GENERATED_AT_EPOCH=1787225400 KEN_ACTIONS_FIREWALL_TEST_IPS="${endpoint_test_ips}" \
  bash "${PROVISION}" --resolve-firewall-endpoints "${endpoint_ready_root}/policy.yaml" "${GA_ROOT}/inventory/runner-platform.yaml" "${endpoint_runtime_lock}" "${endpoint_broker_policy}" "${endpoint_hash_drift}" "${private_generation}"

echo '== reviewed platform payload adapter =='
platform_root=/private/tmp/ken-offline-payloads.WtdFkz/platform-extension
platform_manifest="${platform_root}/platform-payload-manifest.json"
platform_guest_manifest="${tmp_root}/platform-guest-manifest.yaml"
cp "${runtime_authority}/manifest.yaml" "${platform_guest_manifest}"
python3 - "${platform_guest_manifest}" "${platform_manifest}" "${platform_root}" <<'PY'
import hashlib
import json
from pathlib import Path
import sys
import yaml
manifest_path, platform_path, platform_root = map(Path, sys.argv[1:])
manifest = yaml.safe_load(manifest_path.read_text())
platform = json.loads(platform_path.read_text())
base = next(item for item in platform["payloads"] if item["role"] == "ubuntu_noble_qcow2_base")
manifest["authority"]["platform_payload_manifest_sha256"] = hashlib.sha256(platform_path.read_bytes()).hexdigest()
manifest["base_image"]["url"] = (platform_root / base["path"]).as_uri()
manifest["base_image"]["sha256"] = base["sha256"]
manifest_path.write_text(yaml.safe_dump(manifest, sort_keys=False))
PY
expect_success 'platform adapter binds all 16 payloads, 953103751 bytes, and 10 rootless identities' 'PLATFORM_PAYLOADS_OK payloads=16 bytes=953103751 rootless=10' \
  bash "${PROVISION}" --validate-platform-extension "${platform_guest_manifest}" "${platform_root}"

platform_mutation="${tmp_root}/platform-bool-count.json"
cp "${platform_manifest}" "${platform_mutation}"
perl -0pi -e 's/"payload_count": 16/"payload_count": true/' "${platform_mutation}"
python3 - "${platform_guest_manifest}" "${platform_mutation}" <<'PY'
import hashlib
from pathlib import Path
import sys
import yaml
manifest_path, platform_path = map(Path, sys.argv[1:])
manifest = yaml.safe_load(manifest_path.read_text())
manifest["authority"]["platform_payload_manifest_sha256"] = hashlib.sha256(platform_path.read_bytes()).hexdigest()
manifest_path.write_text(yaml.safe_dump(manifest, sort_keys=False))
PY
expect_failure 'Boolean platform payload count is rejected' 'platform payload cardinality invalid' \
  env PROVISION_VMS_COMMAND_TEST=1 PROVISION_VMS_PLATFORM_MANIFEST="${platform_mutation}" bash "${PROVISION}" --validate-platform-extension "${platform_guest_manifest}" "${platform_root}"

echo '== offline dependency closure =='
closure_dir="${tmp_root}/closure"
mkdir -p "${closure_dir}"
cat >"${closure_dir}/base.packages" <<'EOF'
Package: libc6
Version: 2.39-0ubuntu8
Architecture: amd64
Source-Class: base-image

Package: ca-certificates
Version: 20240203
Architecture: all
Depends: openssl (>= 3.0)
Source-Class: base-image

Package: openssl
Version: 3.0.13-0ubuntu3
Architecture: amd64
Depends: libc6 (>= 2.38)
Source-Class: base-image
EOF
cat >"${closure_dir}/staged.packages" <<'EOF'
Package: 1password-cli
Version: 2.32.0
Architecture: amd64
Pre-Depends: libc6 (>= 2.38)
Depends: ca-certificates | untrusted-fallback
Source-Class: staged-runtime
SHA256: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
EOF
printf '%s\n' '1password-cli (= 2.32.0)' >"${closure_dir}/roots.txt"
closure_output="$({ bash "${PROVISION}" --solve-closure "${closure_dir}/base.packages" "${closure_dir}/staged.packages" "${closure_dir}/roots.txt" amd64; } 2>&1)"
closure_status=$?
if (( closure_status == 0 )) && [[ "${closure_output}" == $'1password-cli=2.32.0:staged-runtime\nca-certificates=20240203:base-image\nlibc6=2.39-0ubuntu8:base-image\nopenssl=3.0.13-0ubuntu3:base-image' ]]; then
  pass 'recursive Depends and Pre-Depends closure is deterministic'
else
  printf '%s\n' "${closure_output}" >&2
  fail 'recursive Depends and Pre-Depends closure is deterministic'
fi
sed '/Package: openssl/,/^$/d' "${closure_dir}/base.packages" >"${closure_dir}/base-missing.packages"
expect_failure 'unsatisfied offline closure fails without fallback' 'unsatisfied dependency: openssl (>= 3.0)' \
  bash "${PROVISION}" --solve-closure "${closure_dir}/base-missing.packages" "${closure_dir}/staged.packages" "${closure_dir}/roots.txt" amd64

cat >"${closure_dir}/base-upgrade.packages" <<'EOF'
Package: libc6
Version: 2.39-0ubuntu8
Architecture: amd64
Source-Class: base-image

Package: runtime-engine
Version: 1.0-1
Architecture: amd64
Depends: libc6 (>= 2.38)
Source-Class: base-image
EOF
cat >"${closure_dir}/staged-upgrade.packages" <<'EOF'
Package: runtime-engine
Version: 2.0-1
Architecture: amd64
Depends: libc6 (>= 2.38)
Source-Class: staged-runtime
SHA256: bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
EOF
printf '%s\n' 'runtime-engine (= 2.0-1)' >"${closure_dir}/upgrade-roots.txt"
upgrade_output="$({ bash "${PROVISION}" --solve-closure "${closure_dir}/base-upgrade.packages" "${closure_dir}/staged-upgrade.packages" "${closure_dir}/upgrade-roots.txt" amd64; } 2>&1)"
upgrade_status=$?
if (( upgrade_status == 0 )) && [[ "${upgrade_output}" == $'libc6=2.39-0ubuntu8:base-image\nruntime-engine=2.0-1:staged-runtime' ]]; then
  pass 'staged exact version deterministically replaces base package authority'
else
  printf '%s\n' "${upgrade_output}" >&2
  fail 'staged exact version deterministically replaces base package authority'
fi

cat >"${closure_dir}/base-virtual.packages" <<'EOF'
Package: mawk
Version: 1.3.4.20240123-1build1
Architecture: amd64
Provides: awk
Source-Class: base-image
EOF
cat >"${closure_dir}/staged-virtual.packages" <<'EOF'
Package: report-tool
Version: 1.0-1
Architecture: all
Depends: awk
Source-Class: staged-runtime
SHA256: cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
EOF
printf '%s\n' report-tool >"${closure_dir}/virtual-roots.txt"
virtual_output="$({ bash "${PROVISION}" --solve-closure "${closure_dir}/base-virtual.packages" "${closure_dir}/staged-virtual.packages" "${closure_dir}/virtual-roots.txt" amd64; } 2>&1)"
virtual_status=$?
if (( virtual_status == 0 )) && [[ "${virtual_output}" == $'mawk=1.3.4.20240123-1build1:base-image\nreport-tool=1.0-1:staged-runtime' ]]; then
  pass 'virtual package dependencies resolve to one deterministic provider'
else
  printf '%s\n' "${virtual_output}" >&2
  fail 'virtual package dependencies resolve to one deterministic provider'
fi

cat >"${closure_dir}/staged-conflict.packages" <<'EOF'
Package: runtime-engine
Version: 2.0-1
Architecture: amd64
Source-Class: staged-runtime
SHA256: dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd

Package: legacy-consumer
Version: 1.0-1
Architecture: amd64
Depends: runtime-engine (<< 2.0)
Source-Class: staged-runtime
SHA256: eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee
EOF
printf '%s\n' 'runtime-engine (= 2.0-1)' legacy-consumer >"${closure_dir}/conflict-roots.txt"
expect_failure 'conflicting dependency constraints fail closed' 'selected package conflicts with dependency: runtime-engine (<< 2.0)' \
  bash "${PROVISION}" --solve-closure "${closure_dir}/base-upgrade.packages" "${closure_dir}/staged-conflict.packages" "${closure_dir}/conflict-roots.txt" amd64

cat >"${closure_dir}/staged-declared-conflict.packages" <<'EOF'
Package: runtime-engine
Version: 2.0-1
Architecture: amd64
Depends: helper
Conflicts: helper
Source-Class: staged-runtime
SHA256: ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff

Package: helper
Version: 1.0-1
Architecture: amd64
Source-Class: staged-runtime
SHA256: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
EOF
printf '%s\n' runtime-engine >"${closure_dir}/declared-conflict-roots.txt"
expect_failure 'declared Conflicts relation rejects the selected closure' 'selected package conflict: runtime-engine conflicts with helper' \
  bash "${PROVISION}" --solve-closure "${closure_dir}/base-upgrade.packages" "${closure_dir}/staged-declared-conflict.packages" "${closure_dir}/declared-conflict-roots.txt" amd64

perl -0pi -e 's/^Conflicts: helper$/Breaks: helper/m' "${closure_dir}/staged-declared-conflict.packages"
expect_failure 'declared Breaks relation rejects the selected closure' 'selected package conflict: runtime-engine breaks helper' \
  bash "${PROVISION}" --solve-closure "${closure_dir}/base-upgrade.packages" "${closure_dir}/staged-declared-conflict.packages" "${closure_dir}/declared-conflict-roots.txt" amd64

cat >"${closure_dir}/provenance-only.packages" <<'EOF'
Package: ubuntu-archive-keyring
Version: 2023.11.28.1
Architecture: all
Source-Class: provenance-only
EOF
printf '%s\n' ubuntu-archive-keyring >"${closure_dir}/provenance-roots.txt"
expect_failure 'provenance-only package cannot enter guest closure' 'unsupported package source class: provenance-only' \
  bash "${PROVISION}" --solve-closure "${closure_dir}/provenance-only.packages" /dev/null "${closure_dir}/provenance-roots.txt" amd64

echo '== fake offline image transaction =='
source_tree="${tmp_root}/source-image"
output_tree="${tmp_root}/output"
mkdir -p "${source_tree}/etc" "${output_tree}"
printf '%s\n' base >"${source_tree}/etc/base-release"
first="$({ bash "${PROVISION}" --fake-image-transaction "${source_tree}" "${output_tree}/ken-ci"; } 2>&1)"
first_status=$?
second="$({ bash "${PROVISION}" --fake-image-transaction "${source_tree}" "${output_tree}/ken-ci"; } 2>&1)"
second_status=$?
if (( first_status == 0 && second_status == 0 )) && [[ "${first}" == "${second}" ]] && [[ -f "${output_tree}/ken-ci/etc/base-release" && -f "${output_tree}/ken-ci.receipt.sha256" ]]; then
  pass 'fake network-disabled transaction is byte-idempotent'
else
  printf 'first=%s\nsecond=%s\n' "${first}" "${second}" >&2
  fail 'fake network-disabled transaction is byte-idempotent'
fi
printf '%s\n' preserved >"${output_tree}/sentinel"
for failure_point in after-journal after-copy before-commit; do
  expect_failure "fake transaction rolls back at ${failure_point}" "injected failure: ${failure_point}" \
    env KEN_ACTIONS_INJECT_FAILURE="${failure_point}" bash "${PROVISION}" --fake-image-transaction "${source_tree}" "${output_tree}/failed-${failure_point}"
  if [[ "$(cat "${output_tree}/sentinel")" == preserved ]] && ! find "${output_tree}" -maxdepth 1 \( -name '.ken-actions-candidate.*' -o -name '.ken-actions-journal.*' \) | grep -q .; then
    pass "${failure_point} preserves unrelated state and clears journal"
  else
    fail "${failure_point} preserves unrelated state and clears journal"
  fi
done

echo '== deterministic offline qcow2 build and receipts =='
build_root="${tmp_root}/offline-build"
build_bin="${build_root}/bin"
build_output="${build_root}/output"
build_log="${build_root}/transport.log"
mkdir -p "${build_bin}" "${build_output}"
printf '%s\n' 'fake Ubuntu 24.04 qcow2 authority' >"${build_root}/ubuntu.qcow2"
cp "${runtime_authority}/manifest.yaml" "${build_root}/manifest.yaml"
python3 - "${build_root}" "${endpoint_ready_root}/policy.yaml" "${endpoint_generation}" "${endpoint_generation_receipt}" "${endpoint_ready_root}/task7.yaml" "${endpoint_ready_root}/onepassword-linux-canary.json" "${endpoint_runtime_lock}" "${endpoint_broker_policy}" <<'PY'
import hashlib
from pathlib import Path
import sys
import yaml

root, endpoint_policy, generation, generation_receipt, task7, onepassword_receipt, runtime_lock, broker_policy = map(Path, sys.argv[1:])
manifest_path = root / "manifest.yaml"
manifest = yaml.safe_load(manifest_path.read_text())
base = root / "ubuntu.qcow2"
manifest["base_image"].update({
    "status": "ready",
    "blocker": None,
    "url": base.as_uri(),
    "sha256": hashlib.sha256(base.read_bytes()).hexdigest(),
    "signed_checksum_file_sha256": "b" * 64,
    "signature_sha256": "c" * 64,
    "signer_fingerprint": "F6ECB3762474EDA9D21B7022871920D1991BC93C",
    "dpkg_inventory_sha256": "d" * 64,
})
manifest["common_runtime"].update({"status": "ready", "blocker": None})
manifest["authority"]["platform_payload_manifest_sha256"] = "e" * 64
manifest["authority"].update({
    "plan_sha256": "75715a5a3973f3ed9813e66c809d76ec1281d537afae0c08d66b02684583a658",
    "broker_runtime_lock_sha256": hashlib.sha256(runtime_lock.read_bytes()).hexdigest(),
    "op_broker_policy_sha256": hashlib.sha256(broker_policy.read_bytes()).hexdigest(),
    "action_transport_lock_sha256": hashlib.sha256(task7.read_bytes()).hexdigest(),
    "firewall_endpoint_policy_sha256": hashlib.sha256(endpoint_policy.read_bytes()).hexdigest(),
    "firewall_endpoint_generation_sha256": hashlib.sha256(generation.read_bytes()).hexdigest(),
    "firewall_endpoint_generation_receipt_sha256": hashlib.sha256(generation_receipt.read_bytes()).hexdigest(),
    "onepassword_canary_receipt_sha256": hashlib.sha256(onepassword_receipt.read_bytes()).hexdigest(),
})
manifest["firewall"].update({"status": "ready", "blocker": None})
manifest["ci_image"].update({"status": "ready", "common_runtime_included": True})
manifest["deploy_image"].update({
    "status": "ready",
    "common_runtime_included": True,
    "task6_principals": [22001, 22002, 22003, 22101, 22102, 22103, 22104, 22201, 22202, 22203],
    "builder_subuid_range": "300000:65536",
    "builder_subgid_range": "300000:65536",
})
manifest["remote_pinned_build_inputs"].update({"status": "ready", "blocker": None})
manifest["generated_files"]["status"] = "ready"
manifest["readiness"] = {
    "state": "build-ready",
    "live_apply_allowed": False,
    "ready_marker": None,
    "blockers": ["missing-both-guest-runtime-receipts"],
}
manifest_path.write_text(yaml.safe_dump(manifest, sort_keys=False))
PY
cat >"${build_bin}/qemu-img" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
printf 'qemu-img %s\n' "$*" >>"${KEN_ACTIONS_TEST_TRANSPORT_LOG:?}"
case "${1:-}" in
  convert) cp "${@: -2:1}" "${@: -1}" ;;
  resize|check) ;;
  info)
    image="${@: -1}"
    if [[ "${image}" == *ken-ci* ]]; then size=$((750 * 1024 * 1024 * 1024)); else size=$((80 * 1024 * 1024 * 1024)); fi
    printf '{"format":"qcow2","virtual-size":%s}\n' "${size}"
    ;;
  *) exit 64 ;;
esac
SH
cat >"${build_bin}/virt-customize" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
printf 'virt-customize %s\n' "$*" >>"${KEN_ACTIONS_TEST_TRANSPORT_LOG:?}"
[[ " $* " == *' --no-network '* ]] || exit 65
image=''
while (($#)); do
  if [[ "$1" == -a ]]; then image="$2"; break; fi
  shift
done
[[ -n "${image}" ]]
if [[ "${image}" == *ken-ci* ]]; then printf '%s\n' customized-ci >>"${image}"; else printf '%s\n' customized-deploy >>"${image}"; fi
SH
cat >"${build_bin}/virt-cat" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
printf 'virt-cat %s\n' "$*" >>"${KEN_ACTIONS_TEST_TRANSPORT_LOG:?}"
base_json="$(cat <<'JSON'
{"schema_version":1,"ca_bundle_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","op_version":"2.39.0","imports":{"cryptography":{"path":"/usr/lib/python3/dist-packages/cryptography/__init__.py","sha256":"8953e50655d64c9ca215e45e77171b30f8721c1df8be238cd7477bdaf1a75ae1","version":"41.0.7"},"jwt":{"path":"/usr/lib/python3/dist-packages/jwt/__init__.py","sha256":"c5137e5b90fbe633067b2992d4eff45f7e8e047970a46bd090a088a3a5f5c438","version":"2.7.0"},"yaml":{"path":"/usr/lib/python3/dist-packages/yaml/__init__.py","sha256":"6e1974e6a49e3bed59c654918c6aef9769bd9eb5dbd67f7e1906ad4cdd0caea7","version":"6.0.1"}},"native_objects":{"/usr/lib/python3/dist-packages/cryptography/hazmat/bindings/_rust.abi3.so":{"sha256":"c928893c3fd432d2aaf84a8db7162ac8a7e1d03a4d121ccd2aec8a7bc4a4b165","elf_machine":"Advanced Micro Devices X86-64","sonames":["libc.so.6"]},"/usr/lib/python3/dist-packages/yaml/_yaml.cpython-312-x86_64-linux-gnu.so":{"sha256":"43b3b0036fab5c1385d5dc2a5bc1a070f276a317a4d5aee42deac884f8ea57eb","elf_machine":"Advanced Micro Devices X86-64","sonames":["libyaml-0.so.2"]}},"platform":{"runner_archive":{"path":"/opt/ken-actions/payloads/actions-runner-linux-x64-2.336.0.tar.gz","sha256":"04cf0be1aff4c3ec3554466c39124ca250e3effd8873bb7e8d68535aa9505d5d","mode":"0444"},"package_versions":{"containerd.io":"2.3.3-1~ubuntu.24.04~noble","docker-buildx-plugin":"0.36.1-1~ubuntu.24.04~noble","docker-ce":"5:29.7.2-1~ubuntu.24.04~noble","docker-ce-cli":"5:29.7.2-1~ubuntu.24.04~noble","docker-ce-rootless-extras":"5:29.7.2-1~ubuntu.24.04~noble","docker-compose-plugin":"5.5.0-1~ubuntu.24.04~noble","fuse-overlayfs":"1.13-1","liblttng-ust-common1t64":"2.13.7-1.1ubuntu2","liblttng-ust-ctl5t64":"2.13.7-1.1ubuntu2","liblttng-ust1t64":"2.13.7-1.1ubuntu2","libslirp0":"4.7.0-1ubuntu3.1","libsubid4":"1:4.13+dfsg1-4ubuntu3.2","slirp4netns":"1.2.1-1build2","uidmap":"1:4.13+dfsg1-4ubuntu3.2"},"newuidmap":{"path":"/usr/bin/newuidmap","mode":"4755"},"newgidmap":{"path":"/usr/bin/newgidmap","mode":"4755"},"rootful_services_masked":true}}
JSON
)"
image=''
while (($#)); do
  if [[ "$1" == -a ]]; then image="$2"; shift 2; continue; fi
  shift
done
[[ -n "${image}" ]]
if [[ "${image}" == *ken-ci* ]]; then guest=ken-ci; else guest=ken-deploy; fi
BASE_JSON="${base_json}" python3 - "${KEN_ACTIONS_TEST_RUNTIME_LOCK:?}" "${guest}" <<'PY'
import json
import os
from pathlib import Path
import sys
import yaml

lock = yaml.safe_load(Path(sys.argv[1]).read_text())
guest = sys.argv[2]
value = json.loads(os.environ["BASE_JSON"])
value["runtime_scope"] = {
    "present": {item["path"]: item["sha256"] for item in lock["installed_files"] if guest in item["hosts"]},
    "absent": sorted(item["path"] for item in lock["installed_files"] if guest not in item["hosts"]),
}
if os.environ.get("KEN_ACTIONS_TEST_RUNTIME_SCOPE_MUTATION") == "drop-deploy-sentinel" and guest == "ken-ci":
    value["runtime_scope"]["absent"].remove("/usr/local/bin/ken-actions-artifact-download")
print(json.dumps(value, sort_keys=True, separators=(",", ":")))
PY
SH
cat >"${build_bin}/sha256sum" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == -c ]]; then
  shift
  exec /usr/bin/shasum -a 256 -c "$@"
fi
exec /usr/bin/shasum -a 256 "$@"
SH
chmod +x "${build_bin}/qemu-img" "${build_bin}/virt-customize" "${build_bin}/virt-cat" "${build_bin}/sha256sum"

build_ga_root="${build_root}/ga-root"
mkdir -p "${build_ga_root}"
cp -R "${GA_ROOT}/." "${build_ga_root}/"

build_command=(bash "${PROVISION}" --build-offline \
  "${build_root}/manifest.yaml" "${endpoint_runtime_lock}" "${endpoint_broker_policy}" \
  "${endpoint_ready_root}/policy.yaml" "${endpoint_generation}" "${endpoint_generation_receipt}" \
  "${endpoint_ready_root}/task7.yaml" "${endpoint_ready_root}/onepassword-linux-canary.json" \
  /private/tmp/ken-offline-payloads.WtdFkz "${build_output}")

receipt_drift_root="${build_root}/receipt-drift"
receipt_drift_log="${receipt_drift_root}/transport.log"
mkdir -p "${receipt_drift_root}"
cp "${build_root}/manifest.yaml" "${receipt_drift_root}/manifest.yaml"
cp "${endpoint_generation_receipt}" "${receipt_drift_root}/generation-receipt.json"
python3 - "${receipt_drift_root}/manifest.yaml" "${receipt_drift_root}/generation-receipt.json" <<'PY'
import hashlib
import json
from pathlib import Path
import sys
import yaml

manifest_path, receipt_path = map(Path, sys.argv[1:])
receipt = json.loads(receipt_path.read_text())
receipt["generation"]["path"] = "/var/lib/ken-actions/authority/not-the-approved-generation.json"
receipt_path.write_text(json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n")
receipt_path.chmod(0o600)
manifest = yaml.safe_load(manifest_path.read_text())
manifest["authority"]["firewall_endpoint_generation_receipt_sha256"] = hashlib.sha256(receipt_path.read_bytes()).hexdigest()
manifest_path.write_text(yaml.safe_dump(manifest, sort_keys=False))
PY
expect_failure 'offline build rejects firewall generation receipt path drift before image transport' 'firewall generation receipt authority mismatch' \
  env PATH="${build_bin}:/usr/bin:/bin" KEN_ACTIONS_TEST_TRANSPORT_LOG="${receipt_drift_log}" \
  KEN_ACTIONS_FIREWALL_NOW_EPOCH=1787226000 PROVISION_VMS_COMMAND_TEST=1 PROVISION_VMS_ALLOW_INCOMPLETE_PLATFORM_TEST=1 \
  bash "${PROVISION}" --build-offline \
    "${receipt_drift_root}/manifest.yaml" "${endpoint_runtime_lock}" "${endpoint_broker_policy}" \
    "${endpoint_ready_root}/policy.yaml" "${endpoint_generation}" "${receipt_drift_root}/generation-receipt.json" \
    "${endpoint_ready_root}/task7.yaml" "${endpoint_ready_root}/onepassword-linux-canary.json" \
    /private/tmp/ken-offline-payloads.WtdFkz "${receipt_drift_root}/output"
if [[ ! -s "${receipt_drift_log}" ]]; then
  pass 'firewall generation receipt path drift leaves qemu and customization transports untouched'
else
  fail 'firewall generation receipt path drift leaves qemu and customization transports untouched'
fi

build_result="$({ PATH="${build_bin}:/usr/bin:/bin" PROVISION_VMS_GA_ROOT="${build_ga_root}" KEN_ACTIONS_TEST_TRANSPORT_LOG="${build_log}" KEN_ACTIONS_TEST_RUNTIME_LOCK="${endpoint_runtime_lock}" KEN_ACTIONS_FIREWALL_NOW_EPOCH=1787226000 PROVISION_VMS_COMMAND_TEST=1 PROVISION_VMS_ALLOW_INCOMPLETE_PLATFORM_TEST=1 "${build_command[@]}"; } 2>&1)"
build_status=$?
if (( build_status == 0 )) && grep -Fq 'OFFLINE_BUILD_OK' <<<"${build_result}" && \
   [[ -f "${build_output}/ken-ci.qcow2" && -f "${build_output}/ken-deploy.qcow2" && \
      -f "${build_output}/receipts/ken-ci.json" && -f "${build_output}/receipts/ken-deploy.json" && \
      -f "${build_output}/guest-image-manifest.ready.yaml" ]]; then
  pass 'ready authority reaches a two-image offline qcow2 build and final manifest'
else
  printf '%s\n' "${build_result}" >&2
  fail 'ready authority reaches a two-image offline qcow2 build and final manifest'
fi
check 'deploy-only repo sentinel is absent from CI transport and present in deploy transport' python3 - "${build_log}" <<'PY'
from pathlib import Path
import sys

lines = [line for line in Path(sys.argv[1]).read_text().splitlines() if line.startswith("virt-customize ")]
ci = next(line for line in lines if "/.ken-ci.candidate." in line)
deploy = next(line for line in lines if "/.ken-deploy.candidate." in line)
sentinel = "/usr/local/bin/ken-actions-artifact-download"
assert sentinel not in ci
assert sentinel in deploy
print("REPO_UPLOAD_SCOPE_OK")
PY
scope_mutation_output="${build_root}/scope-mutation-output"
expect_failure 'observed CI image must prove the deploy-only sentinel absent' 'observed runtime host scope mismatch' \
  env PATH="${build_bin}:/usr/bin:/bin" PROVISION_VMS_GA_ROOT="${build_ga_root}" KEN_ACTIONS_TEST_TRANSPORT_LOG="${build_root}/scope-mutation.log" \
  KEN_ACTIONS_TEST_RUNTIME_LOCK="${endpoint_runtime_lock}" KEN_ACTIONS_TEST_RUNTIME_SCOPE_MUTATION=drop-deploy-sentinel \
  KEN_ACTIONS_FIREWALL_NOW_EPOCH=1787226000 PROVISION_VMS_COMMAND_TEST=1 PROVISION_VMS_ALLOW_INCOMPLETE_PLATFORM_TEST=1 \
  bash "${PROVISION}" --build-offline \
    "${build_root}/manifest.yaml" "${endpoint_runtime_lock}" "${endpoint_broker_policy}" \
    "${endpoint_ready_root}/policy.yaml" "${endpoint_generation}" "${endpoint_generation_receipt}" \
    "${endpoint_ready_root}/task7.yaml" "${endpoint_ready_root}/onepassword-linux-canary.json" \
    /private/tmp/ken-offline-payloads.WtdFkz "${scope_mutation_output}"
check 'qcow2 receipts bind exact authority, paths, sizes, and runtime verification' python3 - "${build_output}" "${runtime_authority}" <<'PY'
import hashlib
import json
from pathlib import Path
import sys
import yaml

output, authority = map(Path, sys.argv[1:])
manifest = yaml.safe_load((output / "guest-image-manifest.ready.yaml").read_text())
contract = json.loads((output / "guest-install-contract.json").read_text())
host_transport = contract["task4_runtime"]["host_transport"]
expected_host_transport = {
    "libvirt/ken-ci.xml", "libvirt/ken-deploy.xml",
    "cloud-init/ken-ci-user-data.yaml", "cloud-init/ken-deploy-user-data.yaml",
    "proxy/ken-actions-artifact-proxy-deploy.conf", "proxy/ken-actions-artifact-proxy-runtime.yaml",
    "systemd/ken-actions-artifact-proxy-deploy.service", "systemd/ken-actions-vm-firewall.service",
    "systemd/ken-actions-vm-firewall.timer", "systemd/ken-actions-vms.service",
    "scripts/lib/vm-firewall.sh", "scripts/provision-vms.sh", "inventory/runner-platform.yaml",
}
assert set(host_transport) == expected_host_transport
for relative, digest in host_transport.items():
    staged = output / "host-transport" / relative
    assert staged.is_file() and not staged.is_symlink()
    assert hashlib.sha256(staged.read_bytes()).hexdigest() == digest
for guest in ("ken-ci", "ken-deploy"):
    plan_path = output / "guest-install-plans" / f"{guest}.json"
    plan = json.loads(plan_path.read_text())
    assert hashlib.sha256(plan_path.read_bytes()).hexdigest() == contract["task4_runtime"]["guest_install_plans"][guest]
    assert "ubuntu-keyring_2023.11.28.1_all.deb" in plan["provenance_only"]
    assert all("ubuntu-keyring" not in item for item in plan["debs"])
    expected_repo = [
        entry for entry in yaml.safe_load((authority / "lock.yaml").read_text())["installed_files"]
        if entry["source"].startswith("repo:") and guest in entry["hosts"]
    ]
    assert plan["repo_installed_files"] == expected_repo
    assert contract["task4_runtime"]["guest_repo_installed_files"][guest] == expected_repo
deploy_only = {"buildkit", "rootlesskit", "node", "corepack", "pnpm", "oci-image-tools"}
ci_plan = json.loads((output / "guest-install-plans/ken-ci.json").read_text())
deploy_plan = json.loads((output / "guest-install-plans/ken-deploy.json").read_text())
assert not (set(ci_plan["archives"]) & deploy_only)
assert deploy_only <= set(deploy_plan["archives"])
deploy_only_repo_paths = {entry["path"] for entry in deploy_plan["repo_installed_files"]} - {entry["path"] for entry in ci_plan["repo_installed_files"]}
assert "/usr/local/bin/ken-actions-artifact-download" in deploy_only_repo_paths
assert not deploy_only_repo_paths & {entry["path"] for entry in ci_plan["repo_installed_files"]}
assert manifest["readiness"] == {"state": "ready", "live_apply_allowed": True, "ready_marker": "receipts-verified", "blockers": []}
assert manifest["derived_images"]["status"] == "ready"
assert manifest["firewall"]["status"] == "ready" and manifest["firewall"]["blocker"] is None
for guest, key, size in (("ken-ci", "ci", 750), ("ken-deploy", "deploy", 80)):
    receipt_path = output / f"receipts/{guest}.json"
    receipt = json.loads(receipt_path.read_text())
    assert set(receipt) == {"schema_version", "guest", "authority", "image", "verification", "observed_runtime"}
    assert type(receipt["schema_version"]) is int and receipt["schema_version"] == 1
    assert receipt["guest"] == guest
    assert receipt["image"]["path"] == f"/mnt/data/libvirt/images/{guest}.qcow2"
    assert receipt["image"]["virtual_size_gib"] == size
    assert receipt["image"]["sha256"] == hashlib.sha256((output / f"{guest}.qcow2").read_bytes()).hexdigest()
    assert receipt["verification"] == {
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
    }
    observed = receipt["observed_runtime"]
    lock = yaml.safe_load((authority / "lock.yaml").read_text())
    assert observed["runtime_scope"] == {
        "present": {entry["path"]: entry["sha256"] for entry in lock["installed_files"] if guest in entry["hosts"]},
        "absent": sorted(entry["path"] for entry in lock["installed_files"] if guest not in entry["hosts"]),
    }
    assert observed["op_version"] == "2.39.0"
    assert set(observed["imports"]) == {"yaml", "jwt", "cryptography"}
    assert all(value["path"].startswith("/usr/lib/python3/dist-packages/") for value in observed["imports"].values())
    assert all(len(value["sha256"]) == 64 for value in observed["imports"].values())
    assert set(observed["native_objects"]) == {
        "/usr/lib/python3/dist-packages/yaml/_yaml.cpython-312-x86_64-linux-gnu.so",
        "/usr/lib/python3/dist-packages/cryptography/hazmat/bindings/_rust.abi3.so",
    }
    assert all(value["elf_machine"] == "Advanced Micro Devices X86-64" and value["sonames"] for value in observed["native_objects"].values())
    assert len(observed["ca_bundle_sha256"]) == 64
    assert observed["platform"]["runner_archive"] == {
        "path": "/opt/ken-actions/payloads/actions-runner-linux-x64-2.336.0.tar.gz",
        "sha256": "04cf0be1aff4c3ec3554466c39124ca250e3effd8873bb7e8d68535aa9505d5d",
        "mode": "0444",
    }
    assert observed["platform"]["package_versions"] == {
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
    assert observed["platform"]["newuidmap"] == {"path": "/usr/bin/newuidmap", "mode": "4755"}
    assert observed["platform"]["newgidmap"] == {"path": "/usr/bin/newgidmap", "mode": "4755"}
    assert observed["platform"]["rootful_services_masked"] is True
    derived = manifest["derived_images"][key]
    assert derived["path"] == receipt["image"]["path"]
    assert derived["sha256"] == receipt["image"]["sha256"]
    assert derived["receipt_sha256"] == hashlib.sha256(receipt_path.read_bytes()).hexdigest()
    assert manifest["verification"]["result_receipts"][key]["sha256"] == derived["receipt_sha256"]
assert manifest["authority"]["guest_install_contract_sha256"]
for name in ("firewall-endpoint-policy.yaml", "firewall-endpoint-generation.json", "firewall-endpoint-generation.receipt.json", "action-transport.lock.yaml", "onepassword-linux-canary.json"):
    assert (output / name).is_file()
print("QCOW2_RECEIPTS_OK")
PY
if grep -Fq 'virt-customize --no-network' "${build_log}" && grep -Fq 'virt-cat -a' "${build_log}" && \
   grep -Fq ":/usr/local/libexec/ken-actions-guest-firewall" "${build_log}" && \
   grep -Fq ":/usr/local/libexec/ken-actions-firewall-endpoint-resolve" "${build_log}" && \
   grep -Fq ":/etc/ken-actions/firewall-endpoint-generation.json" "${build_log}" && \
   grep -Fq ":/etc/ken-actions/guest-base.nft" "${build_log}" && \
   grep -Fq ":/etc/ken-actions/runner-platform.yaml" "${build_log}" && \
   ! grep -Eq '(^| )(curl|wget|apt(-get)?|pip|npm)( |$)' "${build_log}"; then
  pass 'offline image transport installs bound guest firewall authority with no network fallback'
else
  fail 'offline image transport installs bound guest firewall authority with no network fallback'
fi
first_ready_hash="$(shasum -a 256 "${build_output}/guest-image-manifest.ready.yaml" | awk '{print $1}')"
first_ci_hash="$(shasum -a 256 "${build_output}/ken-ci.qcow2" | awk '{print $1}')"
second_result="$({ PATH="${build_bin}:/usr/bin:/bin" PROVISION_VMS_GA_ROOT="${build_ga_root}" KEN_ACTIONS_TEST_TRANSPORT_LOG="${build_log}" KEN_ACTIONS_TEST_RUNTIME_LOCK="${endpoint_runtime_lock}" KEN_ACTIONS_FIREWALL_NOW_EPOCH=1787226000 PROVISION_VMS_COMMAND_TEST=1 PROVISION_VMS_ALLOW_INCOMPLETE_PLATFORM_TEST=1 "${build_command[@]}"; } 2>&1)"
second_status=$?
if (( second_status == 0 )) && [[ "${first_ready_hash}" == "$(shasum -a 256 "${build_output}/guest-image-manifest.ready.yaml" | awk '{print $1}')" ]] && \
   [[ "${first_ci_hash}" == "$(shasum -a 256 "${build_output}/ken-ci.qcow2" | awk '{print $1}')" ]]; then
  pass 'offline qcow2 build converges byte-identically on exact rerun'
else
  printf '%s\n' "${second_result}" >&2
  fail 'offline qcow2 build converges byte-identically on exact rerun'
fi

blocked_build_root="${tmp_root}/blocked-build"
mkdir -p "${blocked_build_root}"
blocked_log="${blocked_build_root}/transport.log"
expect_failure 'committed externally blocked authority refuses before qemu transport' 'missing or malformed build authority: firewall_endpoint_generation_sha256' \
  env PATH="${build_bin}:/usr/bin:/bin" KEN_ACTIONS_TEST_TRANSPORT_LOG="${blocked_log}" \
  bash "${PROVISION}" --build-offline \
    "${GA_ROOT}/inventory/guest-image-manifest.yaml" "${endpoint_runtime_lock}" "${endpoint_broker_policy}" \
    "${endpoint_ready_root}/policy.yaml" "${endpoint_generation}" "${endpoint_generation_receipt}" \
    "${endpoint_ready_root}/task7.yaml" "${endpoint_ready_root}/onepassword-linux-canary.json" \
    /private/tmp/ken-offline-payloads.WtdFkz "${blocked_build_root}/output"
if [[ ! -s "${blocked_log}" ]]; then
  pass 'blocked offline build leaves qemu and customization transports untouched'
else
  fail 'blocked offline build leaves qemu and customization transports untouched'
fi

echo '== approval-bound fake live transaction =='
live_root="${tmp_root}/live-transaction"
live_bin="${live_root}/bin"
live_log="${live_root}/transport.log"
local_mutation_log="${live_root}/local-mutation.log"
mkdir -p "${live_bin}"
python3 - "${build_output}" "${live_root}/approval.json" <<'PY'
import hashlib
import json
from pathlib import Path
import sys
import yaml

output, approval_path = map(Path, sys.argv[1:])
manifest_path = output / "guest-image-manifest.ready.yaml"
manifest = yaml.safe_load(manifest_path.read_text())
evidence = {
    "schema_version": 1,
    "approval_phrase": "Task 4/6 approved and 1Password ready",
    "combined_approval_verified": True,
    "host": "root@167.235.8.250",
    "host_memory_available_gib": 64,
    "firewall_generation_verified": True,
    "artifact_authority": {
        "task6_runtime_lock_sha256": manifest["authority"]["broker_runtime_lock_sha256"],
        "action_transport_lock_sha256": manifest["authority"]["action_transport_lock_sha256"],
        "firewall_endpoint_policy_sha256": manifest["authority"]["firewall_endpoint_policy_sha256"],
        "firewall_endpoint_generation_sha256": manifest["authority"]["firewall_endpoint_generation_sha256"],
        "firewall_endpoint_generation_receipt_sha256": manifest["authority"]["firewall_endpoint_generation_receipt_sha256"],
        "onepassword_canary_receipt_sha256": manifest["authority"]["onepassword_canary_receipt_sha256"],
        "guest_install_contract_sha256": manifest["authority"]["guest_install_contract_sha256"],
        "guest_image_manifest_sha256": hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
        "derived_images": {
            "ken-ci": manifest["derived_images"]["ci"]["sha256"],
            "ken-deploy": manifest["derived_images"]["deploy"]["sha256"],
        },
    },
    "vms": {
        "ken-ci": {"healthy": True, "isolation_verified": True, "memory_gib": 112, "memory_health_verified": True},
        "ken-deploy": {"healthy": True, "isolation_verified": True, "memory_gib": 12, "memory_health_verified": True},
    },
}
approval_path.write_text(json.dumps(evidence, sort_keys=True, separators=(",", ":")) + "\n")
approval_path.chmod(0o600)
PY
cat >"${live_bin}/ssh" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
operation='unknown'
for value in "$@"; do
  case "${value}" in preflight|stage|apply|readback) operation="${value}" ;; esac
done
printf 'ssh %s\n' "${operation}" >>"${KEN_ACTIONS_TEST_TRANSPORT_LOG:?}"
case "${operation}" in
  preflight)
    body="$(cat)"
    [[ "${body}" == *'--host-transaction'* ]]
    printf '%s\n' 'preflight-body:host-transaction' >>"${KEN_ACTIONS_TEST_TRANSPORT_LOG:?}"
    printf '%s\n' '{"status":"ready","memory_available_gib":64,"protected_services":6,"mount":"/mnt/data"}'
    ;;
  stage)
    tar -tf - | sed 's#^#archive:#' >>"${KEN_ACTIONS_TEST_TRANSPORT_LOG:?}"
    printf '%s\n' STAGED
    ;;
  apply) printf '%s\n' '{"status":"applied","created":2,"changed":6}' ;;
  readback) printf '%s\n' '{"status":"verified","domains":["ken-ci","ken-deploy"],"firewall":"verified","proxy":"verified","protected_services":6}' ;;
  *) exit 64 ;;
esac
SH
for command in systemctl virsh; do
  cat >"${live_bin}/${command}" <<'SH'
#!/usr/bin/env bash
printf '%s %s\n' "$(basename "$0")" "$*" >>"${KEN_ACTIONS_LOCAL_MUTATION_LOG:?}"
exit 99
SH
  chmod +x "${live_bin}/${command}"
done
chmod +x "${live_bin}/ssh"
live_command=(bash "${PROVISION}" --apply-ready "${build_output}/guest-image-manifest.ready.yaml" "${endpoint_runtime_lock}" "${endpoint_broker_policy}" "${build_output}" "${live_root}/approval.json" root@167.235.8.250)
live_result="$({ PATH="${live_bin}:/usr/bin:/bin" PROVISION_VMS_SSH_BIN="${live_bin}/ssh" PROVISION_VMS_COMMAND_TEST=1 PROVISION_VMS_TEST_ALLOW_CURRENT_OWNER=1 KEN_ACTIONS_FIREWALL_NOW_EPOCH=1787226000 KEN_ACTIONS_TEST_TRANSPORT_LOG="${live_log}" KEN_ACTIONS_LOCAL_MUTATION_LOG="${local_mutation_log}" "${live_command[@]}"; } 2>&1)"
live_status=$?
if (( live_status == 0 )) && grep -Fq 'LIVE_TRANSACTION_OK' <<<"${live_result}" && \
   [[ "$(sed -n 's/^ssh //p' "${live_log}" | tr '\n' ' ')" == 'preflight stage apply readback ' ]] && \
   grep -Fq 'preflight-body:host-transaction' "${live_log}" && grep -Fq 'archive:host-transaction' "${live_log}" && \
   [[ ! -s "${local_mutation_log}" ]]; then
  pass 'ready fake live transaction is approval-bound, ordered, and locally mutation-free'
else
  printf '%s\n' "${live_result}" >&2
  fail 'ready fake live transaction is approval-bound, ordered, and locally mutation-free'
fi

assert_live_pretransport_rejection() {
  local label="$1" expected="$2" approval="$3"
  local candidate_build_root="${4:-${build_output}}"
  local candidate_manifest="${5:-${candidate_build_root}/guest-image-manifest.ready.yaml}"
  : >"${live_log}"
  : >"${local_mutation_log}"
  expect_failure "${label}" "${expected}" env \
    PATH="${live_bin}:/usr/bin:/bin" PROVISION_VMS_SSH_BIN="${live_bin}/ssh" \
    PROVISION_VMS_COMMAND_TEST=1 PROVISION_VMS_TEST_ALLOW_CURRENT_OWNER=1 \
    KEN_ACTIONS_FIREWALL_NOW_EPOCH=1787226000 \
    KEN_ACTIONS_TEST_TRANSPORT_LOG="${live_log}" KEN_ACTIONS_LOCAL_MUTATION_LOG="${local_mutation_log}" \
    bash "${PROVISION}" --apply-ready "${candidate_manifest}" "${endpoint_runtime_lock}" "${endpoint_broker_policy}" "${candidate_build_root}" "${approval}" root@167.235.8.250
  if [[ ! -s "${live_log}" && ! -s "${local_mutation_log}" ]]; then
    pass "${label} leaves SSH, systemctl, and virsh untouched"
  else
    fail "${label} leaves SSH, systemctl, and virsh untouched"
  fi
}

unsafe_approval="${live_root}/unsafe-mode.json"
cp "${live_root}/approval.json" "${unsafe_approval}"
chmod 0644 "${unsafe_approval}"
assert_live_pretransport_rejection 'unsafe approval mode is rejected' 'approval evidence must be mode 0600' "${unsafe_approval}"

unsafe_approval="${live_root}/symlink.json"
ln -s "${live_root}/approval.json" "${unsafe_approval}"
assert_live_pretransport_rejection 'symlink approval is rejected' 'approval evidence is missing or unsafe' "${unsafe_approval}"

unsafe_approval="${live_root}/boolean-version.json"
cp "${live_root}/approval.json" "${unsafe_approval}"
perl -0pi -e 's/"schema_version":1/"schema_version":true/' "${unsafe_approval}"
assert_live_pretransport_rejection 'Boolean approval schema version is rejected' 'approval evidence schema mismatch' "${unsafe_approval}"

unsafe_approval="${live_root}/image-mismatch.json"
cp "${live_root}/approval.json" "${unsafe_approval}"
perl -0pi -e 's/("ken-ci":")[0-9a-f]{64}/$1bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb/' "${unsafe_approval}"
assert_live_pretransport_rejection 'approval image digest mismatch is rejected' 'approval evidence image digest mismatch: ken-ci' "${unsafe_approval}"

unsafe_approval="${live_root}/firewall-generation-mismatch.json"
cp "${live_root}/approval.json" "${unsafe_approval}"
perl -0pi -e 's/("firewall_endpoint_generation_sha256":")[0-9a-f]{64}/$1cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc/' "${unsafe_approval}"
assert_live_pretransport_rejection 'approval numeric firewall digest mismatch is rejected' 'approval firewall endpoint generation digest mismatch' "${unsafe_approval}"

contract_drift_root="${live_root}/contract-authority-drift"
contract_drift_approval="${contract_drift_root}/approval.json"
cp -R "${build_output}" "${contract_drift_root}"
cp "${live_root}/approval.json" "${contract_drift_approval}"
python3 - "${contract_drift_root}" "${contract_drift_approval}" <<'PY'
import hashlib
import json
from pathlib import Path
import sys
import yaml

root, approval_path = map(Path, sys.argv[1:])
manifest_path = root / "guest-image-manifest.ready.yaml"
contract_path = root / "guest-install-contract.json"
manifest = yaml.safe_load(manifest_path.read_text())
contract = json.loads(contract_path.read_text())
contract["authority"]["onepassword_canary_receipt_sha256"] = "f" * 64
contract_path.write_text(json.dumps(contract, sort_keys=True, separators=(",", ":")) + "\n")
contract_path.chmod(0o600)
manifest["authority"]["guest_install_contract_sha256"] = hashlib.sha256(contract_path.read_bytes()).hexdigest()
for guest, key in (("ken-ci", "ci"), ("ken-deploy", "deploy")):
    receipt_path = root / "receipts" / f"{guest}.json"
    receipt = json.loads(receipt_path.read_text())
    receipt["authority"]["guest_install_contract_sha256"] = manifest["authority"]["guest_install_contract_sha256"]
    receipt_path.write_text(json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n")
    receipt_path.chmod(0o600)
    receipt_sha = hashlib.sha256(receipt_path.read_bytes()).hexdigest()
    manifest["derived_images"][key]["receipt_sha256"] = receipt_sha
    manifest["verification"]["result_receipts"][key]["sha256"] = receipt_sha
manifest_path.write_text(yaml.safe_dump(manifest, sort_keys=False))
approval = json.loads(approval_path.read_text())
approval["artifact_authority"]["guest_image_manifest_sha256"] = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
approval_path.write_text(json.dumps(approval, sort_keys=True, separators=(",", ":")) + "\n")
approval_path.chmod(0o600)
PY
assert_live_pretransport_rejection 'install contract authority drift is rejected' 'ready install contract authority mismatch' \
  "${contract_drift_approval}" "${contract_drift_root}"

host_transport_drift_root="${live_root}/host-transport-drift"
cp -R "${build_output}" "${host_transport_drift_root}"
printf '\n# post-approval drift\n' >>"${host_transport_drift_root}/host-transport/cloud-init/ken-ci-user-data.yaml"
assert_live_pretransport_rejection 'post-approval host transport drift is rejected' 'ready host transport digest mismatch: cloud-init/ken-ci-user-data.yaml' \
  "${live_root}/approval.json" "${host_transport_drift_root}"


echo '== fake persistent host transaction =='
host_tx_root="${tmp_root}/host-transaction"
host_tx_stage="${host_tx_root}/stage"
host_tx_fs="${host_tx_root}/root"
host_tx_bin="${host_tx_root}/bin"
host_tx_state="${host_tx_root}/state"
mkdir -p "${host_tx_stage}" "${host_tx_fs}/var/lib/ken-actions" "${host_tx_bin}" "${host_tx_state}"
cp "${build_output}/ken-ci.qcow2" "${build_output}/ken-deploy.qcow2" "${build_output}/guest-image-manifest.ready.yaml" "${build_output}/guest-install-contract.json" "${host_tx_stage}/"
cp -R "${build_output}/receipts" "${host_tx_stage}/receipts"
cp "${endpoint_runtime_lock}" "${host_tx_stage}/broker-runtime.lock.yaml"
cp "${endpoint_broker_policy}" "${host_tx_stage}/op-broker-policy.yaml"
cp "${build_output}/host-transport/inventory/runner-platform.yaml" "${host_tx_stage}/runner-platform.yaml"
cp "${build_output}/firewall-endpoint-policy.yaml" "${build_output}/firewall-endpoint-generation.json" \
  "${build_output}/firewall-endpoint-generation.receipt.json" "${build_output}/action-transport.lock.yaml" \
  "${build_output}/onepassword-linux-canary.json" "${host_tx_stage}/"
cp "${live_root}/approval.json" "${host_tx_stage}/approval.json"
cp "${build_output}/host-transport/scripts/provision-vms.sh" "${host_tx_stage}/host-transaction"
cp -R "${build_output}/host-transport/libvirt" "${build_output}/host-transport/cloud-init" "${build_output}/host-transport/proxy" "${build_output}/host-transport/systemd" "${build_output}/host-transport/scripts" "${build_output}/host-transport/inventory" "${host_tx_stage}/"
chmod 0700 "${host_tx_stage}/host-transaction"
chmod 0600 "${host_tx_stage}/guest-image-manifest.ready.yaml" "${host_tx_stage}/guest-install-contract.json" "${host_tx_stage}/broker-runtime.lock.yaml" "${host_tx_stage}/op-broker-policy.yaml" "${host_tx_stage}/runner-platform.yaml" "${host_tx_stage}/firewall-endpoint-policy.yaml" "${host_tx_stage}/firewall-endpoint-generation.json" "${host_tx_stage}/firewall-endpoint-generation.receipt.json" "${host_tx_stage}/action-transport.lock.yaml" "${host_tx_stage}/onepassword-linux-canary.json" "${host_tx_stage}/approval.json" "${host_tx_stage}/receipts/ken-ci.json" "${host_tx_stage}/receipts/ken-deploy.json"
printf '%s\n' 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA task4-test' >"${host_tx_fs}/var/lib/ken-actions/guest-admin-authorized-key"
chmod 0600 "${host_tx_fs}/var/lib/ken-actions/guest-admin-authorized-key"
cat >"${host_tx_bin}/stat" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
[[ "$1" == -c ]]
case "$2" in
  %a) /usr/bin/stat -f %Lp "$3" ;;
  %u) /usr/bin/stat -f %u "$3" ;;
  *) exit 64 ;;
esac
SH
cat >"${host_tx_bin}/qemu-img" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
case "$1" in
  check) exit 0 ;;
  info)
    image="${@: -1}"
    if [[ "${image}" == *ken-ci* ]]; then size=$((750 * 1024 * 1024 * 1024)); else size=$((80 * 1024 * 1024 * 1024)); fi
    printf '{"format":"qcow2","virtual-size":%s}\n' "${size}"
    ;;
  *) exit 64 ;;
esac
SH
cat >"${host_tx_bin}/sha256sum" <<'SH'
#!/usr/bin/env bash
exec shasum -a 256 "$@"
SH
cat >"${host_tx_bin}/cloud-localds" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
printf 'seed\n' >"$1"
sha256sum "$2" "$3" >>"$1"
SH
cat >"${host_tx_bin}/virsh" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
root="${KEN_ACTIONS_HOST_TEST_STATE:?}"
mkdir -p "${root}/domains"
command="$1"
shift
guest="${1:-}"
case "${command}" in
  dominfo)
    [[ -f "${root}/domains/${guest}.xml" ]] || exit 1
    printf 'Name: %s\nAutostart: enable\n' "${guest}"
    ;;
  dumpxml) cat "${root}/domains/${guest}.xml" ;;
  domstate)
    [[ -f "${root}/domains/${guest}.xml" ]] || exit 1
    if [[ -f "${root}/domains/${guest}.running" ]]; then printf 'running\n'; else printf 'shut off\n'; fi
    ;;
  destroy|shutdown) rm -f "${root}/domains/${guest}.running" ;;
  undefine) rm -f "${root}/domains/${guest}.xml" "${root}/domains/${guest}.running" ;;
  define)
    xml="$guest"
    name="$(sed -n 's:.*<name>\([^<]*\)</name>.*:\1:p' "${xml}" | head -n1)"
    cp "${xml}" "${root}/domains/${name}.xml"
    ;;
  autostart) ;;
  start) touch "${root}/domains/${guest}.running" ;;
  net-info) printf 'Active: yes\n' ;;
  qemu-agent-command) printf '%s\n' '{"return":{}}' ;;
  *) echo "unsupported fake virsh: ${command} $*" >&2; exit 64 ;;
esac
SH
cat >"${host_tx_bin}/systemctl" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
root="${KEN_ACTIONS_HOST_TEST_STATE:?}"
mkdir -p "${root}/services" "${root}/domains"
command="$1"; shift
service="${*: -1}"
case "${command}" in
  daemon-reload|reset-failed) exit 0 ;;
  is-enabled)
    [[ -f "${root}/services/${service}.enabled" ]] || { printf 'disabled\n'; exit 1; }
    cat "${root}/services/${service}.enabled"
    [[ "$(cat "${root}/services/${service}.enabled")" == enabled ]]
    ;;
  is-active)
    if [[ "${service}" == actions.runner.* ]]; then [[ "${1:-}" == --quiet ]] || printf 'active\n'; exit 0; fi
    [[ -f "${root}/services/${service}.active" ]] || { [[ "${1:-}" == --quiet ]] || printf 'inactive\n'; exit 3; }
    [[ "${1:-}" == --quiet ]] || printf 'active\n'
    ;;
  enable) printf 'enabled\n' >"${root}/services/${service}.enabled" ;;
  disable) rm -f "${root}/services/${service}.enabled" ;;
  mask) printf 'masked\n' >"${root}/services/${service}.enabled" ;;
  unmask) [[ ! -f "${root}/services/${service}.enabled" ]] || grep -qx masked "${root}/services/${service}.enabled" && rm -f "${root}/services/${service}.enabled" || true ;;
  start)
    touch "${root}/services/${service}.active"
    if [[ "${service}" == ken-actions-vms.service ]]; then
      touch "${root}/domains/ken-ci.running" "${root}/domains/ken-deploy.running"
    fi
    ;;
  stop) rm -f "${root}/services/${service}.active" ;;
  *) echo "unsupported fake systemctl: ${command} $*" >&2; exit 64 ;;
esac
SH
cat >"${host_tx_bin}/nft" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
if [[ "$*" == 'list table inet ken_actions_vms' ]]; then printf '%s\n' 'table inet ken_actions_vms { comment "managed-by=ken-actions"; }'; exit 0; fi
exit 0
SH
chmod +x "${host_tx_bin}/"*

host_tx_env=(env PATH="${host_tx_bin}:/usr/bin:/bin" PROVISION_VMS_COMMAND_TEST=1 PROVISION_VMS_HOST_ROOT="${host_tx_fs}" KEN_ACTIONS_HOST_TEST_STATE="${host_tx_state}" KEN_ACTIONS_FIREWALL_NOW_EPOCH=1787226000)
expect_success 'fake persistent host apply installs exact staged authority and domains' '"status":"applied"' \
  "${host_tx_env[@]}" bash "${PROVISION}" --host-transaction apply "${host_tx_stage}"
if [[ -f "${host_tx_fs}/var/lib/ken-actions/authority/firewall-endpoint-generation.json" && \
      -f "${host_tx_fs}/var/lib/ken-actions/authority/action-transport.lock.yaml" && \
      -f "${host_tx_fs}/var/lib/ken-actions/authority/runner-platform.yaml" && \
      -f "${host_tx_fs}/var/lib/ken-actions/receipts/firewall-endpoint-generation.json" && \
      -f "${host_tx_fs}/var/lib/ken-actions/receipts/onepassword-linux-canary.json" ]]; then
  pass 'persistent host transaction installs complete firewall refresh authority'
else
  fail 'persistent host transaction installs complete firewall refresh authority'
fi
expect_success 'fake persistent host readback verifies authority, services, firewall, and guests' '"status":"verified"' \
  "${host_tx_env[@]}" bash "${PROVISION}" --host-transaction readback "${host_tx_stage}"
expect_success 'fake persistent host apply is idempotent on exact rerun' '"created":0,"changed":0' \
  "${host_tx_env[@]}" bash "${PROVISION}" --host-transaction apply "${host_tx_stage}"

rollback_fs="${host_tx_root}/rollback-root"
rollback_state="${host_tx_root}/rollback-state"
mkdir -p "${rollback_fs}/var/lib/ken-actions" "${rollback_fs}/mnt/data/libvirt/images" "${rollback_state}"
cp "${host_tx_fs}/var/lib/ken-actions/guest-admin-authorized-key" "${rollback_fs}/var/lib/ken-actions/guest-admin-authorized-key"
printf '%s\n' preserved-ci >"${rollback_fs}/mnt/data/libvirt/images/ken-ci.qcow2"
chmod 0600 "${rollback_fs}/mnt/data/libvirt/images/ken-ci.qcow2"
expect_failure 'injected persistent host failure executes rollback' 'injected host transaction failure: after-files' \
  env PATH="${host_tx_bin}:/usr/bin:/bin" PROVISION_VMS_COMMAND_TEST=1 PROVISION_VMS_HOST_ROOT="${rollback_fs}" KEN_ACTIONS_HOST_TEST_STATE="${rollback_state}" KEN_ACTIONS_FIREWALL_NOW_EPOCH=1787226000 PROVISION_VMS_HOST_INJECT_FAILURE=after-files \
  bash "${PROVISION}" --host-transaction apply "${host_tx_stage}"
if [[ "$(cat "${rollback_fs}/mnt/data/libvirt/images/ken-ci.qcow2")" == preserved-ci ]] && \
   [[ ! -e "${rollback_fs}/var/lib/ken-actions/authority/guest-image-manifest.yaml" ]]; then
  pass 'persistent host rollback restores prior image and removes transaction-created authority'
else
  fail 'persistent host rollback restores prior image and removes transaction-created authority'
fi
for failure_point in after-firewall-timer-enable after-proxy-start after-vms-start after-final-readback; do
  service_fs="${host_tx_root}/service-rollback-${failure_point}-root"
  service_state="${host_tx_root}/service-rollback-${failure_point}-state"
  mkdir -p "${service_fs}/var/lib/ken-actions" "${service_state}/services" "${service_state}/domains"
  cp "${host_tx_fs}/var/lib/ken-actions/guest-admin-authorized-key" "${service_fs}/var/lib/ken-actions/guest-admin-authorized-key"
  chmod 0600 "${service_fs}/var/lib/ken-actions/guest-admin-authorized-key"
  printf 'enabled\n' >"${service_state}/services/ken-actions-vm-firewall.service.enabled"
  touch "${service_state}/services/ken-actions-vm-firewall.service.active"
  printf 'masked\n' >"${service_state}/services/ken-actions-artifact-proxy-deploy.service.enabled"
  printf 'enabled\n' >"${service_state}/services/ken-actions-vms.service.enabled"
  touch "${service_state}/services/ken-actions-vms.service.active"
  expect_failure "${failure_point} executes rollback" "injected host transaction failure: ${failure_point}" \
    env PATH="${host_tx_bin}:/usr/bin:/bin" PROVISION_VMS_COMMAND_TEST=1 PROVISION_VMS_HOST_ROOT="${service_fs}" \
    KEN_ACTIONS_HOST_TEST_STATE="${service_state}" KEN_ACTIONS_FIREWALL_NOW_EPOCH=1787226000 PROVISION_VMS_HOST_INJECT_FAILURE="${failure_point}" \
    bash "${PROVISION}" --host-transaction apply "${host_tx_stage}"
  if [[ "$(cat "${service_state}/services/ken-actions-vm-firewall.service.enabled")" == enabled && \
        -f "${service_state}/services/ken-actions-vm-firewall.service.active" && \
        ! -e "${service_state}/services/ken-actions-vm-firewall.timer.enabled" && \
        ! -e "${service_state}/services/ken-actions-vm-firewall.timer.active" && \
        "$(cat "${service_state}/services/ken-actions-artifact-proxy-deploy.service.enabled")" == masked && \
        ! -e "${service_state}/services/ken-actions-artifact-proxy-deploy.service.active" && \
        "$(cat "${service_state}/services/ken-actions-vms.service.enabled")" == enabled && \
        -f "${service_state}/services/ken-actions-vms.service.active" ]]; then
    pass "${failure_point} restores exact custom-service enablement and active states"
  else
    fail "${failure_point} restores exact custom-service enablement and active states"
  fi
done

echo '== firewall renderers =='
host_rules="${tmp_root}/host.nft"
guest_ci_rules="${tmp_root}/guest-ci.nft"
guest_deploy_rules="${tmp_root}/guest-deploy.nft"
if bash -c 'set -euo pipefail; source "$1"; KEN_ACTIONS_PROXY_UID=22900 render_ken_actions_host_base "$2" 1.1.1.1 8.8.8.8' _ "${FIREWALL}" "${host_rules}" && \
   bash -c 'set -euo pipefail; source "$1"; render_ken_actions_guest_base ci "$2"' _ "${FIREWALL}" "${guest_ci_rules}" && \
   bash -c 'set -euo pipefail; source "$1"; render_ken_actions_guest_base deploy "$2"' _ "${FIREWALL}" "${guest_deploy_rules}"; then
  check 'host and guest rules enforce the blocked base policy' python3 - "${host_rules}" "${guest_ci_rules}" "${guest_deploy_rules}" <<'PY'
import sys
from pathlib import Path

host, ci, deploy = [Path(path).read_text() for path in sys.argv[1:]]
checks = [
    "table inet ken_actions_vms" in host,
    "destroy table inet ken_actions_vms" in host,
    "flush ruleset" not in host + ci + deploy,
    'iifname "virbr-deploy" ip daddr 192.168.211.1 tcp dport 3128 accept' in host,
    'iifname "virbr-ci" ip daddr 192.168.211.1 tcp dport 3128 drop' in host,
    "meta skuid 22900" in host,
    "proxy_uid=22900" in host,
    "policy drop" in ci,
    "policy drop" in deploy,
    "udp sport 68 udp dport 67 accept" in ci,
    "udp sport 67 udp dport 68 accept" in ci,
    "udp sport 68 udp dport 67 accept" in deploy,
    "udp sport 67 udp dport 68 accept" in deploy,
    "21009" not in ci and "21010" not in ci,
    "missing-final-task6-policy-and-identities" in ci,
    "missing-final-task6-policy-and-identities" in deploy,
]
raise SystemExit(0 if all(checks) else 1)
PY
else
  fail 'host and guest firewall renderers execute'
fi
# shellcheck disable=SC2016
expect_failure 'unknown guest class is rejected' 'unknown guest class' \
  bash -c 'set -euo pipefail; source "$1"; render_ken_actions_guest_base wrong "$2"' _ "${FIREWALL}" "${tmp_root}/wrong.nft"
# shellcheck disable=SC2016
expect_failure 'disabled production action cannot open a firewall phase' 'firewall action disabled' \
  env KEN_ACTIONS_FIREWALL_POLICY_FILE="/private/tmp/ken-sre-task6-broker-runtime-sol/infra/github-actions/inventory/op-broker-policy.yaml" \
  KEN_ACTIONS_FIREWALL_RUNNER_FILE="${GA_ROOT}/inventory/runner-platform.yaml" \
  bash -c 'set -euo pipefail; source "$1"; render_ken_actions_guest_phase deploy production ghcr-write "$2"' _ "${FIREWALL}" "${tmp_root}/phase.nft"

enabled_policy="${tmp_root}/enabled-firewall-policy.yaml"
cp /private/tmp/ken-sre-task6-broker-runtime-sol/infra/github-actions/inventory/op-broker-policy.yaml "${enabled_policy}"
python3 - "${enabled_policy}" <<'PY'
from pathlib import Path
import sys
import yaml
p = Path(sys.argv[1])
policy = yaml.safe_load(p.read_text())
action = next(item for item in policy["actions"] if item["action_id"] == "ken-frontend-production-release")
action["enabled"] = True
action["blocked_reason_code"] = None
action["deferred_bindings"] = []
action["production_build"]["phase_transport_sha256"] = "f" * 64
p.write_text(yaml.safe_dump(policy, sort_keys=False))
PY
# shellcheck disable=SC2016
expect_success 'enabled frozen authority renders the exact GHCR phase' 'phase=ghcr-write uid=22003' \
  env KEN_ACTIONS_FIREWALL_POLICY_FILE="${enabled_policy}" KEN_ACTIONS_FIREWALL_RUNNER_FILE="${GA_ROOT}/inventory/runner-platform.yaml" \
  KEN_ACTIONS_FIREWALL_COMMAND_TEST=1 KEN_ACTIONS_FIREWALL_TEST_IPS='ghcr.io=1.1.1.1,pkg-containers.githubusercontent.com=8.8.8.8' \
  bash -c 'set -euo pipefail; source "$1"; render_ken_actions_guest_phase deploy production ghcr-write "$2"' _ "${FIREWALL}" "${tmp_root}/phase.nft"
if grep -Fq 'meta skuid 22003 ip daddr @phase_target_v4 tcp dport 443 accept' "${tmp_root}/phase.nft" && \
   grep -Fq 'elements = { 1.1.1.1, 8.8.8.8 }' "${tmp_root}/phase.nft" && grep -Fq 'policy drop' "${tmp_root}/phase.nft" && \
   ! grep -Fq 'blob.core.windows.net' "${tmp_root}/phase.nft"; then
  pass 'GHCR phase is UID/IP/port-scoped, default-deny, and excludes direct Blob'
else
  fail 'GHCR phase is UID/IP/port-scoped, default-deny, and excludes direct Blob'
fi
# shellcheck disable=SC2016
expect_success 'offline build phase remains network dark' 'phase=build-offline uid=22201' \
  env KEN_ACTIONS_FIREWALL_POLICY_FILE="${enabled_policy}" KEN_ACTIONS_FIREWALL_RUNNER_FILE="${GA_ROOT}/inventory/runner-platform.yaml" KEN_ACTIONS_FIREWALL_COMMAND_TEST=1 \
  bash -c 'set -euo pipefail; source "$1"; render_ken_actions_guest_phase deploy production build-offline "$2"' _ "${FIREWALL}" "${tmp_root}/offline-phase.nft"
if grep -Fq 'policy drop' "${tmp_root}/offline-phase.nft" && ! grep -Fq 'tcp dport 443 accept' "${tmp_root}/offline-phase.nft"; then
  pass 'offline build phase has no network allow rule'
else
  fail 'offline build phase has no network allow rule'
fi
# shellcheck disable=SC2016
expect_failure 'CI cannot request a deploy production phase' 'guest class and trust class mismatch' \
  env KEN_ACTIONS_FIREWALL_POLICY_FILE="${enabled_policy}" \
  KEN_ACTIONS_FIREWALL_RUNNER_FILE="${GA_ROOT}/inventory/runner-platform.yaml" \
  bash -c 'set -euo pipefail; source "$1"; render_ken_actions_guest_phase ci production ghcr-write "$2"' _ "${FIREWALL}" "${tmp_root}/wrong-class.nft"
# shellcheck disable=SC2016
expect_failure 'unknown firewall phase is rejected' 'unsupported firewall phase' \
  env KEN_ACTIONS_FIREWALL_POLICY_FILE="${enabled_policy}" \
  KEN_ACTIONS_FIREWALL_RUNNER_FILE="${GA_ROOT}/inventory/runner-platform.yaml" \
  bash -c 'set -euo pipefail; source "$1"; render_ken_actions_guest_phase deploy production arbitrary "$2"' _ "${FIREWALL}" "${tmp_root}/unknown-phase.nft"

phase_runtime="${tmp_root}/phase-runtime"
phase_state="${tmp_root}/phase-state"
phase_bin="${tmp_root}/phase-bin"
phase_requests="${phase_runtime}/requests"
phase_active_requests="${phase_state}/active-requests"
phase_live="${tmp_root}/phase-live.nft"
phase_guest_class="${tmp_root}/guest-class"
phase_base="${tmp_root}/guest-base.nft"
mkdir -p "${phase_requests}" "${phase_state}" "${phase_bin}"
chmod 0700 "${phase_runtime}" "${phase_requests}" "${phase_state}"
printf 'ken-deploy\n' >"${phase_guest_class}"
cp "${numeric_deploy_rules}" "${phase_base}"
cp "${FIREWALL}" "${phase_bin}/ken-actions-guest-firewall"
chmod +x "${phase_bin}/ken-actions-guest-firewall"
cat >"${phase_bin}/nft" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
printf 'nft %s\n' "$*" >>"${KEN_ACTIONS_NFT_LOG:?}"
if [[ "${1:-}" == -c && "${2:-}" == -f ]]; then
  exit 0
elif [[ "${1:-}" == -f ]]; then
  cp "$2" "${KEN_ACTIONS_NFT_LIVE:?}"
elif [[ "${1:-}" == list && "${2:-}" == table ]]; then
  if [[ "${KEN_ACTIONS_NFT_CORRUPT_READBACK:-0}" == 1 && ! -e "${KEN_ACTIONS_NFT_CORRUPT_MARKER:?}" ]]; then
    : >"${KEN_ACTIONS_NFT_CORRUPT_MARKER}"
    printf 'table inet broken { comment "corrupt"; }\n'
  else
    cat "${KEN_ACTIONS_NFT_LIVE:?}"
  fi
else
  exit 64
fi
SH
chmod +x "${phase_bin}/nft"
phase_request_id="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
python3 - "${phase_requests}/${phase_request_id}.json" "${phase_request_id}" <<'PY'
import json
from pathlib import Path
import sys
path, request_id = Path(sys.argv[1]), sys.argv[2]
path.write_text(json.dumps({
    "schema_version": 1,
    "request_id": request_id,
    "profile": "vexa-production-fixed-target",
    "phase": "vexa-ssh",
}, sort_keys=True, separators=(",", ":")) + "\n")
path.chmod(0o600)
PY
phase_env=(
  env PATH="${phase_bin}:/usr/bin:/bin"
  KEN_ACTIONS_FIREWALL_COMMAND_TEST=1
  KEN_ACTIONS_FIREWALL_NOW_EPOCH=1787226000
  KEN_ACTIONS_FIREWALL_ENDPOINT_GENERATION_FILE="${endpoint_generation}"
  KEN_ACTIONS_FIREWALL_TEST_IPS='ghcr.io=1.1.1.1,pkg-containers.githubusercontent.com=8.8.8.8,us.posthog.com=9.9.9.9'
  KEN_ACTIONS_FIREWALL_POLICY_FILE="${enabled_policy}"
  KEN_ACTIONS_FIREWALL_RUNNER_FILE="${GA_ROOT}/inventory/runner-platform.yaml"
  KEN_ACTIONS_FIREWALL_GUEST_CLASS_FILE="${phase_guest_class}"
  KEN_ACTIONS_FIREWALL_REQUEST_ROOT="${phase_requests}"
  KEN_ACTIONS_FIREWALL_RUNTIME_ROOT="${phase_runtime}"
  KEN_ACTIONS_FIREWALL_STATE_ROOT="${phase_state}"
  KEN_ACTIONS_FIREWALL_BASE_FILE="${phase_base}"
  KEN_ACTIONS_NFT_LOG="${tmp_root}/phase-nft.log"
  KEN_ACTIONS_NFT_LIVE="${phase_live}"
  KEN_ACTIONS_NFT_CORRUPT_MARKER="${tmp_root}/phase-corrupt-used"
)
expect_success 'root-bound phase request activates through check/apply/readback' 'GUEST_FIREWALL_PHASE_OK state=activate' \
  "${phase_env[@]}" "${phase_bin}/ken-actions-guest-firewall" phase --request-id "${phase_request_id}" --profile vexa-production-fixed-target --phase vexa-ssh --state activate
if grep -Fq "requests=${phase_request_id}" "${phase_live}" && [[ -f "${phase_active_requests}/${phase_request_id}.json" ]]; then
  pass 'phase activation records the exact request generation'
else
  fail 'phase activation records the exact request generation'
fi
second_phase_request_id="dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
python3 - "${phase_requests}/${second_phase_request_id}.json" "${second_phase_request_id}" <<'PY'
import json
from pathlib import Path
import sys
path, request_id = Path(sys.argv[1]), sys.argv[2]
path.write_text(json.dumps({
    "schema_version": 1,
    "request_id": request_id,
    "profile": "website-production-fixed-target",
    "phase": "website-ssh",
}, sort_keys=True, separators=(",", ":")) + "\n")
path.chmod(0o600)
PY
expect_success 'second ordinary request activates without replacing the first' 'GUEST_FIREWALL_PHASE_OK state=activate' \
  "${phase_env[@]}" "${phase_bin}/ken-actions-guest-firewall" phase --request-id "${second_phase_request_id}" --profile website-production-fixed-target --phase website-ssh --state activate
if grep -Fq "${phase_request_id}" "${phase_live}" && grep -Fq "${second_phase_request_id}" "${phase_live}" && \
   grep -Fq 'meta skuid 22101' "${phase_live}" && grep -Fq 'meta skuid 22103' "${phase_live}" && \
   [[ -f "${phase_active_requests}/${phase_request_id}.json" && -f "${phase_active_requests}/${second_phase_request_id}.json" ]]; then
  pass 'two ordinary requests hold one atomic safe rule union'
else
  fail 'two ordinary requests hold one atomic safe rule union'
fi
frontend_request_id="eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
python3 - "${phase_requests}/${frontend_request_id}.json" "${frontend_request_id}" <<'PY'
import json
from pathlib import Path
import sys
path, request_id = Path(sys.argv[1]), sys.argv[2]
path.write_text(json.dumps({
    "schema_version": 1,
    "request_id": request_id,
    "profile": "frontend-production-digest-deploy",
    "phase": "posthog-upload",
}, sort_keys=True, separators=(",", ":")) + "\n")
path.chmod(0o600)
PY
nft_count_before="$(wc -l <"${tmp_root}/phase-nft.log" | tr -d ' ')"
expect_failure 'frontend writer phase cannot overlap ordinary slot phases' 'frontend firewall phases are exclusive' \
  "${phase_env[@]}" "${phase_bin}/ken-actions-guest-firewall" phase --request-id "${frontend_request_id}" --profile frontend-production-digest-deploy --phase posthog-upload --state activate
nft_count_after="$(wc -l <"${tmp_root}/phase-nft.log" | tr -d ' ')"
if [[ "${nft_count_before}" == "${nft_count_after}" && ! -e "${phase_active_requests}/${frontend_request_id}.json" ]]; then
  pass 'frontend overlap rejection leaves nft and active state untouched'
else
  fail 'frontend overlap rejection leaves nft and active state untouched'
fi
rm -f -- "${phase_requests}/${frontend_request_id}.json"
cross_profile_request_id="ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
python3 - "${phase_requests}/${cross_profile_request_id}.json" "${cross_profile_request_id}" <<'PY'
import json
from pathlib import Path
import sys
path, request_id = Path(sys.argv[1]), sys.argv[2]
path.write_text(json.dumps({
    "schema_version": 1,
    "request_id": request_id,
    "profile": "vexa-production-fixed-target",
    "phase": "vexa-ssh",
}, sort_keys=True, separators=(",", ":")) + "\n")
path.chmod(0o600)
PY
nft_count_before="$(wc -l <"${tmp_root}/phase-nft.log" | tr -d ' ')"
expect_failure 'request cannot be replayed under a different profile' 'phase request authority mismatch' \
  "${phase_env[@]}" "${phase_bin}/ken-actions-guest-firewall" phase --request-id "${cross_profile_request_id}" --profile website-production-fixed-target --phase website-ssh --state activate
nft_count_after="$(wc -l <"${tmp_root}/phase-nft.log" | tr -d ' ')"
if [[ "${nft_count_before}" == "${nft_count_after}" ]]; then pass 'cross-profile rejection is pre-transport'; else fail 'cross-profile rejection is pre-transport'; fi
rm -f -- "${phase_requests}/${cross_profile_request_id}.json"
nft_count_before="$(wc -l <"${tmp_root}/phase-nft.log" | tr -d ' ')"
expect_failure 'missing root phase request fails before nft mutation' 'phase request is missing or unsafe' \
  "${phase_env[@]}" "${phase_bin}/ken-actions-guest-firewall" phase --request-id bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb --profile frontend-production-digest-deploy --phase ghcr-write --state activate
nft_count_after="$(wc -l <"${tmp_root}/phase-nft.log" | tr -d ' ')"
if [[ "${nft_count_before}" == "${nft_count_after}" ]]; then
  pass 'missing phase request leaves nft transport untouched'
else
  fail 'missing phase request leaves nft transport untouched'
fi
expect_success 'matching phase request deactivates to fail-closed base' 'GUEST_FIREWALL_PHASE_OK state=deactivate' \
  "${phase_env[@]}" "${phase_bin}/ken-actions-guest-firewall" phase --request-id "${phase_request_id}" --profile vexa-production-fixed-target --phase vexa-ssh --state deactivate
if grep -Fq "requests=${second_phase_request_id}" "${phase_live}" && ! grep -Fq "${phase_request_id}" "${phase_live}" && \
   [[ ! -e "${phase_active_requests}/${phase_request_id}.json" && -f "${phase_active_requests}/${second_phase_request_id}.json" && ! -e "${phase_requests}/${phase_request_id}.json" ]]; then
  pass 'phase teardown removes only the matching request and recomputes the union'
else
  fail 'phase teardown removes only the matching request and recomputes the union'
fi
expect_success 'last matching request deactivates to fail-closed base' 'GUEST_FIREWALL_PHASE_OK state=deactivate' \
  "${phase_env[@]}" "${phase_bin}/ken-actions-guest-firewall" phase --request-id "${second_phase_request_id}" --profile website-production-fixed-target --phase website-ssh --state deactivate
if grep -Fq 'generation=1787225400' "${phase_live}" && ! grep -Fq 'requests=' "${phase_live}" && \
   [[ ! -e "${phase_active_requests}/${second_phase_request_id}.json" && ! -e "${phase_requests}/${second_phase_request_id}.json" ]]; then
  pass 'last request teardown restores base and consumes its request'
else
  fail 'last request teardown restores base and consumes its request'
fi
rollback_request_id="cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
python3 - "${phase_requests}/${rollback_request_id}.json" "${rollback_request_id}" <<'PY'
import json
from pathlib import Path
import sys
path, request_id = Path(sys.argv[1]), sys.argv[2]
path.write_text(json.dumps({
    "schema_version": 1,
    "request_id": request_id,
    "profile": "vexa-production-fixed-target",
    "phase": "vexa-ssh",
}, sort_keys=True, separators=(",", ":")) + "\n")
path.chmod(0o600)
PY
expect_failure 'phase readback failure restores the last-known-good generation' 'firewall generation readback failed' \
  "${phase_env[@]}" KEN_ACTIONS_NFT_CORRUPT_READBACK=1 "${phase_bin}/ken-actions-guest-firewall" phase --request-id "${rollback_request_id}" --profile vexa-production-fixed-target --phase vexa-ssh --state activate
if grep -Fq 'generation=1787225400' "${phase_live}" && \
   grep -Fq 'generation=1787225400' "${phase_state}/guest-active.nft" && \
   [[ ! -e "${phase_active_requests}/${rollback_request_id}.json" && -f "${phase_requests}/${rollback_request_id}.json" ]]; then
  pass 'phase rollback retains blocked LKG and leaves the request retryable'
else
  fail 'phase rollback retains blocked LKG and leaves the request retryable'
fi

crash_first_id="1111111111111111111111111111111111111111111111111111111111111111"
crash_second_id="2222222222222222222222222222222222222222222222222222222222222222"
python3 - "${phase_requests}" "${crash_first_id}" "${crash_second_id}" <<'PY'
import json
from pathlib import Path
import sys
root=Path(sys.argv[1])
for request_id,profile,phase in [
    (sys.argv[2],"vexa-production-fixed-target","vexa-ssh"),
    (sys.argv[3],"website-production-fixed-target","website-ssh"),
]:
    path=root/f"{request_id}.json"
    path.write_text(json.dumps({"schema_version":1,"request_id":request_id,"profile":profile,"phase":phase},sort_keys=True,separators=(",",":"))+"\n")
    path.chmod(0o600)
PY
expect_success 'crash test establishes one active request' 'GUEST_FIREWALL_PHASE_OK state=activate' \
  "${phase_env[@]}" "${phase_bin}/ken-actions-guest-firewall" phase --request-id "${crash_first_id}" --profile vexa-production-fixed-target --phase vexa-ssh --state activate
expect_failure 'injected post-apply crash leaves a recoverable transaction journal' 'injected guest firewall failure after apply' \
  "${phase_env[@]}" KEN_ACTIONS_FIREWALL_INJECT_FAILURE=after-apply "${phase_bin}/ken-actions-guest-firewall" phase --request-id "${crash_second_id}" --profile website-production-fixed-target --phase website-ssh --state activate
if [[ -f "${phase_state}/phase-transaction.json" && -f "${phase_active_requests}/${crash_first_id}.json" && ! -e "${phase_active_requests}/${crash_second_id}.json" ]] && \
   grep -Fq "${crash_second_id}" "${phase_live}"; then
  pass 'post-apply crash exposes journal while preserving committed request state'
else
  fail 'post-apply crash exposes journal while preserving committed request state'
fi
expect_success 'next valid transition recovers LKG before recomputing the request union' 'GUEST_FIREWALL_PHASE_OK state=activate' \
  "${phase_env[@]}" "${phase_bin}/ken-actions-guest-firewall" phase --request-id "${crash_first_id}" --profile vexa-production-fixed-target --phase vexa-ssh --state activate
if [[ ! -e "${phase_state}/phase-transaction.json" && -f "${phase_active_requests}/${crash_first_id}.json" && ! -e "${phase_active_requests}/${crash_second_id}.json" ]] && \
   grep -Fq "${crash_first_id}" "${phase_live}" && ! grep -Fq "${crash_second_id}" "${phase_live}"; then
  pass 'crash recovery restores exact LKG state and removes only uncommitted rules'
else
  fail 'crash recovery restores exact LKG state and removes only uncommitted rules'
fi
expect_success 'crash test matching teardown restores standing base' 'GUEST_FIREWALL_PHASE_OK state=deactivate' \
  "${phase_env[@]}" "${phase_bin}/ken-actions-guest-firewall" phase --request-id "${crash_first_id}" --profile vexa-production-fixed-target --phase vexa-ssh --state deactivate
rm -f -- "${phase_requests}/${crash_second_id}.json" "${phase_requests}/${rollback_request_id}.json"

echo '== executable systemd authority gates =='
check 'host and guest units fail hard instead of condition-skipping' python3 - "${GA_ROOT}" <<'PY'
import sys
from pathlib import Path
import yaml

ga = Path(sys.argv[1])
host_units = [
    "ken-actions-artifact-proxy-deploy.service",
    "ken-actions-vm-firewall.service",
    "ken-actions-vms.service",
]
errors = []
for name in host_units:
    text = (ga / "systemd" / name).read_text()
    if "ConditionPathExists=" in text:
        errors.append(f"{name}: condition skip remains")
    if "ExecStartPre=/usr/local/sbin/ken-actions-vm-authority-verify" not in text and "ExecStartPre=+/usr/local/sbin/ken-actions-vm-authority-verify" not in text:
        errors.append(f"{name}: executable authority gate missing")
timer = (ga / "systemd/ken-actions-vm-firewall.timer").read_text()
if "ConditionPathExists=" in timer:
    errors.append("firewall timer: condition skip remains")
vms = (ga / "systemd/ken-actions-vms.service").read_text()
if "RequiresMountsFor=/mnt/data/libvirt" not in vms:
    errors.append("vms: hard libvirt mount requirement missing")
protected = [
    "actions.runner.Ken-Technology-ken-agents.hetzner-grok-review-ken-agents.service",
    "actions.runner.Ken-Technology-ken-ai-mcp.hetzner-grok-review-ken-ai-mcp.service",
    "actions.runner.Ken-Technology-ken-backend.hetzner-grok-review-ken-backend.service",
    "actions.runner.Ken-Technology-ken-frontend.hetzner-grok-review-ken-frontend.service",
    "actions.runner.Ken-Technology-ken-scraping.hetzner-grok-review-ken-scraping.service",
    "actions.runner.Ken-Technology-ken-search.hetzner-grok-review-ken-search.service",
]
after = next((line for line in vms.splitlines() if line.startswith("After=")), "")
for unit in protected:
    if f"Requires={unit}" not in vms or unit not in after:
        errors.append(f"vms: protected dependency incomplete: {unit}")
for guest in ("ken-ci", "ken-deploy"):
    data = yaml.safe_load((ga / f"cloud-init/{guest}-user-data.yaml").read_text())
    files = {entry["path"]: entry["content"] for entry in data.get("write_files", [])}
    runtime = files["/etc/systemd/system/ken-actions-guest-runtime-verify.service"]
    if "ConditionPathExists=" in runtime:
        errors.append(f"{guest}: runtime verifier can condition-skip")
    if "ExecStartPre=/usr/local/sbin/ken-actions-guest-authority-check" not in runtime:
        errors.append(f"{guest}: executable guest authority check missing")
if errors:
    print("\n".join(errors))
    raise SystemExit(1)
print("SYSTEMD_AUTHORITY_GATES_OK")
PY

echo '== syntax and repository hygiene =='
check 'embedded guest Bash and Python syntax' python3 - "${GA_ROOT}" <<'PY'
import subprocess
import sys
from pathlib import Path

import yaml

ga = Path(sys.argv[1])
for guest in ("ken-ci", "ken-deploy"):
    data = yaml.safe_load((ga / f"cloud-init/{guest}-user-data.yaml").read_text())
    for entry in data.get("write_files") or []:
        content = entry.get("content") or ""
        if content.startswith("#!/usr/bin/env bash\n"):
            result = subprocess.run(
                ["bash", "-n"], input=content, text=True, capture_output=True, check=False
            )
            if result.returncode:
                print(f"{guest}:{entry['path']}: {result.stderr}")
                raise SystemExit(1)
            marker = "<<'PY'\n"
            if marker in content:
                python_source = content.split(marker, 1)[1].split("\nPY\n", 1)[0]
                compile(python_source, f"{guest}:{entry['path']}:embedded", "exec")
print("EMBEDDED_SYNTAX_OK")
PY
check 'Task 4 shell syntax' bash -n "${PROVISION}" "${FIREWALL}" "${GA_ROOT}/tests/test-vms.sh"
if command -v shellcheck >/dev/null 2>&1; then
  check 'Task 4 ShellCheck' shellcheck "${PROVISION}" "${FIREWALL}" "${GA_ROOT}/tests/test-vms.sh"
else
  pass 'ShellCheck unavailable locally; syntax gate still ran'
fi
if git -C "${ROOT}" diff --check; then
  pass 'git diff --check'
else
  fail 'git diff --check'
fi

echo
if (( FAILED == 0 )); then
  printf 'vm definitions: %s assertions passed\n' "${RAN}"
  exit 0
fi
printf 'vm definitions: %s failed / %s assertions\n' "${FAILED}" "${RAN}"
exit 1
