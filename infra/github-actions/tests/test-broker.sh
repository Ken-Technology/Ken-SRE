#!/usr/bin/env bash
set -u
export PYTHONDONTWRITEBYTECODE=1

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd -P)"
GA_ROOT="${ROOT}/infra/github-actions"
BIN="${GA_ROOT}/bin"
INV="${GA_ROOT}/inventory"
SYSTEMD="${GA_ROOT}/systemd"
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

run_check() {
  local name="$1"
  shift
  if "$@"; then
    pass "${name}"
  else
    fail "${name}"
  fi
}

require_files() {
  local path missing=0
  for path in \
    "${INV}/broker-runtime.lock.yaml" \
    "${INV}/op-broker-policy.yaml" \
    "${GA_ROOT}/scripts/install-1password-credentials.sh" \
    "${BIN}/ken-op-exec" \
    "${BIN}/ken-op-broker" \
    "${BIN}/ken-actions-artifact-download" \
    "${BIN}/ken-frontend-production-release" \
    "${BIN}/ken-frontend-source-map-upload" \
    "${BIN}/ken-vexa-mcp-auth-production-deploy" \
    "${BIN}/ken-website-production-deploy" \
    "${BIN}/ken-website-beehiiv-production-sync" \
    "${BIN}/ken-frontend-production-release-build" \
    "${BIN}/runtime-known-answer.py" \
    "${SYSTEMD}/ken-op-broker@.service" \
    "${SYSTEMD}/ken-op-broker@.socket" \
    "${SYSTEMD}/ken-op-broker@ci.service.d/override.conf"; do
    if [[ ! -f "${path}" || -L "${path}" ]]; then
      printf 'missing or symlinked: %s\n' "${path#"${ROOT}/"}" >&2
      missing=1
    fi
  done
  return "${missing}"
}

reject_unsupported_units() {
  local path unexpected=0
  for path in \
    "${SYSTEMD}/ken-op-executor@.service" \
    "${SYSTEMD}/ken-frontend-production-builder@.service" \
    "${SYSTEMD}/ken-frontend-source-map-uploader@.service" \
    "${SYSTEMD}/ken-frontend-deploy-executor@.service"; do
    if [[ -e "${path}" || -L "${path}" ]]; then
      printf 'unsupported unit is still claimed: %s\n' "${path#"${ROOT}/"}" >&2
      unexpected=1
    fi
  done
  return "${unexpected}"
}

echo '== Task 6 owned files =='
run_check 'all supported broker runtime files exist' require_files
run_check 'unsupported transaction and frontend phase units are absent' reject_unsupported_units
run_check 'authority generator did not create an unexpected root output' test ! -e "${ROOT}/--help"
run_check 'Task 6 tree contains no generated Python caches' bash -c '! find "$1" -type d -name __pycache__ -print -quit | grep -q . && ! find "$1" -type f -name "*.pyc" -print -quit | grep -q .' _ "${GA_ROOT}"

echo '== immutable inventory and strict broker policy =='
run_check '343/11 raw evidence and 297+11=308 handoff stay byte-exact' \
  python3 - "${INV}" <<'PY'
import hashlib
import sys
from pathlib import Path

import yaml

root = Path(sys.argv[1])
expected = {
    "secrets.yaml": "cd4aaa861064260e0857768361e301246681593b1dcf0c35950993f416c8587f",
    "secret-handoff.yaml": "71c386d3382c1db06b14332f6e86525debe625ec1dafc708c5f0298665b88834",
}
for name, digest in expected.items():
    actual = hashlib.sha256((root / name).read_bytes()).hexdigest()
    assert actual == digest, (name, actual)
secrets = yaml.safe_load((root / "secrets.yaml").read_text())
handoff = yaml.safe_load((root / "secret-handoff.yaml").read_text())
assert len(secrets["entries"]) == 343
assert len(secrets["direct_onepassword_entries"]) == 11
assert len(secrets["broker_actions"]) == 4
assert handoff["counts"]["rows"] == 308
assert handoff["counts"]["github_field_rows"] == 297
assert handoff["counts"]["direct_onepassword_rows"] == 11
assert len(handoff["rows"]) == 308
beehiiv = {
    row["environment_name"]: row.get("broker_action_phase")
    for row in secrets["direct_onepassword_entries"]
    if row.get("broker_action_id") == "ken-website-beehiiv-production-sync"
}
assert beehiiv == {
    "DEPLOY_SSH_KEY": "push",
    "BEEHIIV_API_KEY": "generate",
    "BEEHIIV_PUBLICATION_ID": "generate",
}
direct = {row["environment_name"]: row for row in secrets["direct_onepassword_entries"] if row["repository"] == "ken-website" and row["workflow"] == ".github/workflows/deploy.yml"}
assert direct["NEXT_PUBLIC_POSTHOG_PROJECT_TOKEN"]["disposition"] == "github-variable"
assert direct["NEXT_PUBLIC_POSTHOG_PROJECT_TOKEN"]["delivery"] == "github-actions-variable"
assert direct["NEXT_PUBLIC_POSTHOG_PROJECT_TOKEN"]["migration_action"] == "move-to-variable"
assert direct["POSTHOG_PERSONAL_API_KEY"]["disposition"] == "obsolete-unused"
assert direct["POSTHOG_PERSONAL_API_KEY"]["delivery"] == "none"
assert direct["POSTHOG_PERSONAL_API_KEY"]["migration_action"] == "remove-unused-reference-after-rg-proof"
assert all("broker_action_id" not in direct[name] for name in ("NEXT_PUBLIC_POSTHOG_PROJECT_TOKEN", "POSTHOG_PERSONAL_API_KEY"))
website = next(row for row in secrets["broker_actions"] if row["action_id"] == "ken-website-production-deploy")
assert [row["target_field"] for row in website["required_fields"]] == ["WEBSITE_HOST", "WEBSITE_PORT", "WEBSITE_SSH_KEY"]
handoff_direct = {row["environment_name"]: row for row in handoff["rows"] if row.get("reference_class") == "direct-onepassword" and row["repository"] == "ken-website" and row["workflow"] == ".github/workflows/deploy.yml"}
assert handoff_direct["NEXT_PUBLIC_POSTHOG_PROJECT_TOKEN"]["delivery"] == "github-actions-variable"
assert handoff_direct["POSTHOG_PERSONAL_API_KEY"]["delivery"] == "none"
PY

run_check 'runtime lock and policy use strict schemas, exact hashes, and no placeholders' \
  python3 - "${INV}" <<'PY'
import re
import hashlib
import sys
from pathlib import Path

import yaml

class StrictLoader(yaml.SafeLoader):
    pass

def construct_mapping(loader, node, deep=False):
    out = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in out:
            raise ValueError(f"duplicate key: {key}")
        out[key] = loader.construct_object(value_node, deep=deep)
    return out

StrictLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, construct_mapping)
root = Path(sys.argv[1])
lock_text = (root / "broker-runtime.lock.yaml").read_text()
policy_text = (root / "op-broker-policy.yaml").read_text()
for text in (lock_text, policy_text):
    assert not re.search(r"\b(TBD|TODO|FIXME|placeholder|fill[-_ ]?me|later|required)$", text, re.I | re.M)
    assert "task7-exact" not in text
lock = yaml.load(lock_text, Loader=StrictLoader)
policy = yaml.load(policy_text, Loader=StrictLoader)
assert lock["schema_version"] == 1
assert lock["plan_sha256"] == "75715a5a3973f3ed9813e66c809d76ec1281d537afae0c08d66b02684583a658"
required = {"1password-cli", "python", "pyyaml", "pyjwt", "cryptography", "ca-certificates", "git", "systemd", "buildkit", "node", "pnpm", "zip-safety"}
components = {x["id"]: x for x in lock["components"]}
assert required <= components.keys()
for component in components.values():
    assert component["version"]
    assert component["source_url"].startswith("https://")
    assert re.fullmatch(r"[0-9a-f]{64}", component["payload_sha256"])
    assert component["hosts"] in (["ken-ci", "ken-deploy"], ["ken-deploy"])
payload_names=set()
payload_rows={}
for component in components.values():
    if component.get("delivery_class") == "remote-pinned-build-input":
        continue
    entries=component.get("payloads") or [{"filename":component["payload_filename"],"sha256":component["payload_sha256"]}]
    for entry in entries:
        assert payload_rows.get(entry["filename"], entry["sha256"]) == entry["sha256"]
        payload_names.add(entry["filename"]); payload_rows[entry["filename"]]=entry["sha256"]
provenance=lock["provenance_payloads"]
assert provenance == [{"id":"ubuntu-archive-keyring","version":"2023.11.28.1","filename":"ubuntu-keyring_2023.11.28.1_all.deb","source_url":"https://archive.ubuntu.com/ubuntu/pool/main/u/ubuntu-keyring/ubuntu-keyring_2023.11.28.1_all.deb","sha256":"36de43b15853ccae0028e9a767613770c704833f82586f28eb262f0311adb8a8","install_on_guest":False,"purpose":"verify-signed-ubuntu-package-indexes-only"}]
assert provenance[0]["filename"] not in payload_names and len(payload_names | {provenance[0]["filename"]}) == 31
payload_rows[provenance[0]["filename"]]=provenance[0]["sha256"]
manifest="".join(f"{payload_rows[name]}  {name}\n" for name in sorted(payload_rows)).encode()
assert hashlib.sha256(manifest).hexdigest() == lock["compatibility"]["payload_manifest_sha256"] == "43a8d166b82c08197de6a975f4d14485c8bdae2da524db19f6f1ed1c7da8225f"
contract=lock["runtime_contract"]
assert contract["op_path"] == "/usr/local/bin/op" and contract["guest_payload_count"] == 30
assert contract["remote_build_inputs"] == ["node-build-base"] and len(contract["principals"]) == 10
principal_map = {principal["name"]: principal for principal in contract["principals"]}
assert principal_map["ken-beehiiv-generate"] == {"guest": "ken-deploy", "name": "ken-beehiiv-generate", "uid": 22102, "gid": 22102, "slice": None, "network_profile": "beehiiv-api-fixed-target"}
assert principal_map["ken-beehiiv-push"] == {"guest": "ken-deploy", "name": "ken-beehiiv-push", "uid": 22104, "gid": 22104, "slice": None, "network_profile": "github-ssh-ken-website-fixed-target"}
assert contract["subordinate_ids"] == [{"guest":"ken-deploy","name":"ken-fe-builder","uid":22201,"subuid_start":300000,"subuid_count":65536,"subgid_start":300000,"subgid_count":65536}]
assert lock["compatibility"]["artifact_class"] == "immutable-guest-install-contract"
assert lock["compatibility"]["installation_readiness"] == "verification-required-by-task4"
assert lock["compatibility"]["blocking_conditions"] == []
assert lock["compatibility"]["live_verification"] == "task4-owned-runtime-verify-receipt"
assert lock["verification"]["known_answer_status"] == "required-by-task4-runtime-verify"
assert contract["deferred_execution_transport"] == {
    "status": "unavailable",
    "binding": "executor.systemd_transaction_transport_sha256",
    "transaction_slices": ["ken-actions-deploy-transaction-1.slice", "ken-actions-deploy-transaction-2.slice"],
    "frontend_bindings": ["production_build.phase_transport_sha256", "production_build.deploy_contract_sha256"],
    "trusted_generation_bindings": [
        "trusted_generation.transport.dependency_acquisition_sha256",
        "trusted_generation.transport.generated_paths_manifest_sha256",
        "trusted_generation.transport.commit_input_contract_sha256",
        "trusted_generation.transport.cgroup_contract_sha256",
        "trusted_generation.transport.phase_transport_sha256",
    ],
}
assert all(principal["slice"] is None for principal in contract["principals"][3:])
installed = {item["path"]: item for item in lock["installed_files"]}
for unsupported in (
    "/etc/systemd/system/ken-op-executor@.service",
    "/etc/systemd/system/ken-frontend-production-builder@.service",
    "/etc/systemd/system/ken-frontend-source-map-uploader@.service",
    "/etc/systemd/system/ken-frontend-deploy-executor@.service",
):
    assert unsupported not in installed
for item in installed.values():
    if item["source"].startswith("repo:") or item["source"].startswith("repo-hard-copy:"):
        relative = item["source"].split(":", 1)[1]
        assert __import__("hashlib").sha256((root.parent / relative).read_bytes()).hexdigest() == item["sha256"], item["path"]
assert policy["schema_version"] == 1
assert policy["policy_version"]
assert policy["issuer"] == "https://token.actions.githubusercontent.com"
assert policy["credentials"]["command"] == ["/usr/local/bin/op", "inject"]
assert policy["firewall_phase_interface"]["profiles"]["beehiiv-api-fixed-target"] == ["beehiiv-api"]
assert policy["firewall_phase_interface"]["profiles"]["github-ssh-ken-website-fixed-target"] == ["github-ssh"]
actions = {x["action_id"]: x for x in policy["actions"]}
assert set(actions) == {
    "ken-frontend-production-release",
    "ken-vexa-mcp-auth-production-deploy",
    "ken-website-beehiiv-production-sync",
    "ken-website-production-deploy",
}
assert actions["ken-frontend-production-release"]["input_mode"] == "production_build"
frontend_build = actions["ken-frontend-production-release"]["production_build"]
assert frontend_build["firewall_phases"] == {
    "node-base-read": {"uid": 22201, "targets": ["node-registry", "node-registry-auth"]},
    "package-read": {"uid": 22201, "targets": ["package-read"]},
    "build-offline": {"uid": 22201, "targets": []},
    "posthog-upload": {"uid": 22202, "targets": ["posthog-upload"]},
    "ghcr-write": {"uid": 22003, "targets": ["ghcr", "ghcr-storage"]},
    "frontend-deploy": {"uid": 22203, "targets": ["frontend-deploy"]},
    "frontend-public-health": {"uid": 22203, "targets": ["frontend-public-health"]},
}
assert policy["firewall_phase_interface"]["profiles"]["frontend-production-digest-deploy"] == list(frontend_build["firewall_phases"])
assert frontend_build["receipt_contract"] == {
    "schema_version": 2,
    "plan_sha256": "75715a5a3973f3ed9813e66c809d76ec1281d537afae0c08d66b02684583a658",
    "policy_binding": "root-owned-runtime-policy-sha256",
    "contract_sha256": "d5ebeb58afb5f5e24bc1b6a6e74934ee3a22ae337b103a085d2df9a5776db63c",
    "action_id": "ken-frontend-production-release",
    "data_bytes_max": 16384,
    "receipt_bytes_max": 16384,
    "receipt_owner_uid": 0,
    "receipt_owner_gid": 0,
    "receipt_mode": "0600",
    "chain": "sha256-canonical-json-with-external-root-authority",
    "phase_authority": "root-owned-0600-canonical-json",
    "chronology": "one-boot-strict-monotonic",
    "runner_visible": False,
    "phases": ["source", "build", "scan", "upload", "registry", "token-destroy", "digest", "deploy-health", "cleanup"],
}
assert contract["firewall_phase_interface"]["frontend_phase_ownership"] == frontend_build["firewall_phases"]
beehiiv = actions["ken-website-beehiiv-production-sync"]
assert beehiiv["input_mode"] == "trusted_generation"
assert "source_is_deployable" not in beehiiv
assert "executes_repository_code" not in beehiiv
assert "template" not in beehiiv
generation = beehiiv["trusted_generation"]
assert set(generation) == {
    "authenticated_source", "dependency_acquisition", "phase_order", "phase_overlap",
    "verified_commit_input", "transaction_slices", "transport", "phases",
}
assert generation["authenticated_source"] == "protected-main-before-credentials"
assert generation["dependency_acquisition"] == "before-credentials"
assert generation["phase_order"] == ["generate", "push"] and generation["phase_overlap"] == "forbidden"
assert generation["verified_commit_input"] == "root-coordinator-sealed-read-only"
assert generation["transaction_slices"] == ["ken-actions-deploy-transaction-1.slice", "ken-actions-deploy-transaction-2.slice"]
transport = generation["transport"]
assert transport == {
    "wrapper": "/usr/local/libexec/ken-actions/ken-website-beehiiv-production-sync",
    "wrapper_sha256": installed["/usr/local/libexec/ken-actions/ken-website-beehiiv-production-sync"]["sha256"],
    "dependency_acquisition_sha256": None,
    "generated_paths_manifest_sha256": None,
    "commit_input_contract_sha256": None,
    "cgroup_contract_sha256": None,
    "phase_transport_sha256": None,
}
generate, push = generation["phases"]["generate"], generation["phases"]["push"]
assert generate["identity"] == {"name": "ken-beehiiv-generate", "uid": 22102, "gid": 22102}
assert push["identity"] == {"name": "ken-beehiiv-push", "uid": 22104, "gid": 22104}
assert generate["request_subdirectory"] == "generate" and push["request_subdirectory"] == "push"
assert generate["cgroup_template"] == "/ken-actions-deploy.slice/{transaction_slice}/ken-beehiiv-generate.scope"
assert push["cgroup_template"] == "/ken-actions-deploy.slice/{transaction_slice}/ken-beehiiv-push.scope"
assert generate["descriptor_set"] == ["authenticated-source-tree", "BEEHIIV_API_KEY", "BEEHIIV_PUBLICATION_ID"]
assert push["descriptor_set"] == ["root-verified-commit-input", "DEPLOY_SSH_KEY"]
assert generate["template"]["fields"] == ["BEEHIIV_API_KEY", "BEEHIIV_PUBLICATION_ID"]
assert push["template"]["fields"] == ["DEPLOY_SSH_KEY"]
assert generate["network_profile"] == "beehiiv-api-fixed-target"
assert push["network_profile"] == "github-ssh-ken-website-fixed-target"
assert generate["executes_repository_code"] is True and push["executes_repository_code"] is False
assert not set(generate["descriptor_set"]) & set(push["descriptor_set"])
assert not set(generate["template"]["fields"]) & set(push["template"]["fields"])
assert all(x["result_contract"] == "stable-code-only" for x in actions.values())
assert all(x["enabled"] is False and x["deferred_bindings"] for x in actions.values())
assert all("executor.systemd_transaction_transport_sha256" in x["deferred_bindings"] and x["executor"]["systemd_transaction_transport_sha256"] is None for x in actions.values() if x["input_mode"] != "trusted_generation")
assert actions["ken-frontend-production-release"]["blocked_reason_code"] == "frontend_task7_pins_phase_transport_deploy_required"
assert actions["ken-vexa-mcp-auth-production-deploy"]["blocked_reason_code"] == "vexa_host_key_runtime_identity_and_transaction_transport_required"
assert actions["ken-website-beehiiv-production-sync"]["blocked_reason_code"] == "beehiiv_sync_generation_and_transaction_transport_required"
assert actions["ken-website-production-deploy"]["blocked_reason_code"] == "website_host_key_runtime_identity_and_transaction_transport_required"
assert actions["ken-website-production-deploy"]["template"]["fields"] == ["WEBSITE_HOST", "WEBSITE_PORT", "WEBSITE_SSH_KEY"]
for action in actions.values():
    execution = action["trusted_generation"]["transport"] if action["input_mode"] == "trusted_generation" else action["executor"]
    wrapper = execution["wrapper"]
    assert installed[wrapper]["sha256"] == execution["wrapper_sha256"]
PY

echo '== protocol, OIDC, replay, inputs, privilege and lease behavior =='
if [[ -x "${BIN}/ken-op-broker" ]]; then
  run_check 'broker offline unit and mutation suite' \
    "${BIN}/ken-op-broker" self-test \
      --policy "${INV}/op-broker-policy.yaml" \
      --runtime-lock "${INV}/broker-runtime.lock.yaml"
else
  fail 'broker offline unit and mutation suite'
fi

run_check 'hermetic adversarial broker API tests' \
  python3 - "${BIN}" "${INV}/op-broker-policy.yaml" <<'PY'
import base64
import array
import copy
import errno
import hashlib
import importlib.machinery
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import socket
import struct
import sys
import tempfile
import time
import unittest
from unittest import mock
import zipfile
import yaml

bin_root = Path(sys.argv[1])
policy_path = Path(sys.argv[2])

def load(name, filename):
    path = bin_root / filename
    loader = importlib.machinery.SourceFileLoader(name, str(path))
    spec = importlib.util.spec_from_loader(name, loader)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    loader.exec_module(module)
    return module

broker = load("ken_op_broker_test", "ken-op-broker")
downloader = load("ken_artifact_download_test", "ken-actions-artifact-download")
frontend = load("ken_frontend_release_test", "ken-frontend-production-release")
uploader = load("ken_frontend_sourcemap_test", "ken-frontend-source-map-upload")

class ProtocolTests(unittest.TestCase):
    def test_frontend_source_authority_is_broker_rooted_and_rejects_object_alias(self):
        self.assertEqual(
            broker.FRONTEND_RECEIPT_CONTRACT_SHA256,
            frontend.RECEIPT_CONTRACT_SHA256,
        )
        policy = broker.load_policy(policy_path, allow_nonroot=True)
        action = policy.actions["ken-frontend-production-release"]
        raw = copy.deepcopy(action.raw)
        raw["production_build"]["variables_manifest_sha256"] = "a" * 64
        bound = broker.dataclasses.replace(action, raw=raw)
        source_sha = raw["repository"]["source_commit_sha"]
        aliased_tree = raw["repository"]["workflow_blob_sha"]
        with self.assertRaisesRegex(broker.Reject, "source_authority_invalid"):
            broker.write_source_phase_authority(
                Path("/not-opened"), "b" * 64, bound, source_sha,
                aliased_tree, "c" * 64,
            )

    def setUp(self):
        self.policy = broker.load_policy(policy_path, allow_nonroot=True)
        self.action = self.policy.actions["ken-frontend-production-release"]

    def test_strict_json_rejects_duplicate_unknown_and_oversize(self):
        with self.assertRaises(broker.Reject) as ctx:
            broker.parse_request(b'{"version":1,"version":1,"action_id":"x","oidc_jwt":"a","github_token":"b"}')
        self.assertEqual(ctx.exception.code, "request_duplicate_key")
        with self.assertRaises(broker.Reject):
            broker.parse_request(json.dumps({"version": 1, "action_id": "x", "oidc_jwt": "a", "github_token": "b", "command": "id"}).encode())
        with self.assertRaises(broker.Reject):
            broker.parse_request(json.dumps({"version": 1, "action_id": "valid-action", "oidc_jwt": "a.b.c", "github_token": "token-é"}).encode())
        with self.assertRaises(broker.Reject):
            broker.parse_request(b"x" * 65537)

    def test_request_version_requires_exact_json_integer_before_auth(self):
        valid = {"version": 1, "action_id": "valid-action", "oidc_jwt": "a.b.c", "github_token": "token"}
        self.assertEqual(broker.parse_request(json.dumps(valid).encode())["version"], 1)
        for version in (True, 1.0, "1", 2):
            packet = json.dumps({**valid, "version": version}).encode()
            with self.subTest(version=version):
                with self.assertRaises(broker.Reject) as caught:
                    broker.parse_request(packet)
                self.assertEqual(caught.exception.code, "request_schema_invalid")
        class PreAuthProbe(broker.BrokerDependencies):
            def __init__(self): self.authorization_calls = 0
            def verify_token(self, token, action): self.authorization_calls += 1; raise AssertionError("authorization reached")
        probe = PreAuthProbe()
        peer = broker.PeerIdentity(uid=self.action.runner.uid, gid=self.action.runner.gid, pid=42, start_time=99, cgroup=self.action.runner.cgroup, executable=self.action.runner.executable)
        with tempfile.TemporaryDirectory() as directory:
            for version in (True, 1.0, "1", 2):
                socket_type = socket.SOCK_SEQPACKET if sys.platform.startswith("linux") else socket.SOCK_DGRAM
                client, server = socket.socketpair(socket.AF_UNIX, socket_type)
                try:
                    packet = json.dumps({"version": version, "action_id": self.action.action_id, "oidc_jwt": "a.b.c", "github_token": "token"}).encode()
                    client.send(packet)
                    response = broker.process_connection(server, self.policy, "production", Path(directory) / "state", -1, probe, peer=peer, revalidate=lambda value: value)
                    self.assertEqual(response["reason_code"], "request_schema_invalid")
                finally:
                    client.close(); server.close()
        self.assertEqual(probe.authorization_calls, 0)

    def test_action_mode_schema_rejects_descriptor_mixups(self):
        request = {"version": 1, "action_id": self.action.action_id, "oidc_jwt": "a.b.c", "github_token": "g"}
        broker.validate_request_for_action(request, self.action, [])
        with self.assertRaises(broker.Reject):
            broker.validate_request_for_action({**request, "artifact_id": 1}, self.action, [])
        with self.assertRaises(broker.Reject):
            broker.validate_request_for_action(request, self.action, [3])

    def test_oidc_claim_schema_is_exact_and_scalar(self):
        now = 2_000_000_000
        claims = broker.synthetic_claims_for_action(self.action, now)
        broker.validate_claims(claims, self.action, now=now)
        mutations = {
            "aud": [claims["aud"]],
            "iss": "https://evil.invalid",
            "iat": now + 31,
            "nbf": now + 31,
            "exp": now + 601,
            "repository_visibility": "public",
            "ref_protected": "false",
            "runner_environment": "github-hosted",
            "sha": "A" * 40,
            "run_attempt": 0,
        }
        for key, value in mutations.items():
            with self.subTest(key=key), self.assertRaises(broker.Reject):
                broker.validate_claims({**claims, key: value}, self.action, now=now)
        with self.assertRaises(broker.Reject):
            broker.validate_claims({**claims, "unexpected": "x"}, self.action, now=now)

    def test_jose_header_rejects_confusion_and_embedded_authority(self):
        broker.validate_jose_header({"typ": "JWT", "alg": "RS256", "kid": "one"})
        for header in (
            {"typ": "JWT", "alg": "none", "kid": "one"},
            {"typ": "JWT", "alg": "HS256", "kid": "one"},
            {"typ": "JWT", "alg": "RS256", "kid": "one", "jku": "https://evil.invalid"},
            {"typ": "JWT", "alg": "RS256", "kid": "one", "crit": ["x"]},
            {"typ": "JWT", "alg": "RS256", "kid": "one", "jwk": {}},
        ):
            with self.assertRaises(broker.Reject):
                broker.validate_jose_header(header)

    def test_live_job_binding_requires_exact_runner_and_in_progress(self):
        claims = broker.synthetic_claims_for_action(self.action, 2_000_000_000)
        job = broker.synthetic_job_for_action(self.action, claims)
        broker.validate_live_job(job, claims, self.action)
        for key, value in {
            "id": job["id"] + 1,
            "run_id": job["run_id"] + 1,
            "head_sha": "0" * 40,
            "name": "other",
            "status": "completed",
            "runner_name": "other",
            "runner_id": job["runner_id"] + 1,
            "runner_group_id": job["runner_group_id"] + 1,
        }.items():
            with self.subTest(key=key), self.assertRaises(broker.Reject):
                broker.validate_live_job({**job, key: value}, claims, self.action)
        broker.validate_live_job({**job, "labels": list(reversed(job["labels"]))}, claims, self.action)
        with self.assertRaises(broker.Reject):
            broker.validate_live_job({**job, "labels": job["labels"] + [job["labels"][0]]}, claims, self.action)

    def test_live_repository_and_run_attempt_are_bound(self):
        claims = broker.synthetic_claims_for_action(self.action, 2_000_000_000)
        repo = self.action.raw["repository"]
        repository = {"id": repo["id"], "name": repo["name"], "full_name": f"{repo['owner']}/{repo['name']}", "private": True, "visibility": "private", "default_branch": "main", "owner": {"login": repo["owner"], "id": repo["owner_id"]}}
        run = {"id": claims["run_id"], "run_attempt": claims["run_attempt"], "head_sha": claims["sha"], "event": claims["event_name"], "status": "in_progress", "head_branch": "main", "path": ".github/workflows/deploy.yml", "repository": {"id": repo["id"], "full_name": f"{repo['owner']}/{repo['name']}"}, "head_repository": {"id": repo["id"], "full_name": f"{repo['owner']}/{repo['name']}"}}
        broker.validate_repository_record(repository, self.action)
        broker.validate_run_attempt(run, claims, self.action)
        with self.assertRaises(broker.Reject): broker.validate_repository_record({**repository, "id": repo["id"] + 1}, self.action)
        with self.assertRaises(broker.Reject): broker.validate_run_attempt({**run, "run_attempt": claims["run_attempt"] + 1}, claims, self.action)

    def test_jwks_cache_rejects_same_kid_substitution_and_keeps_overlap(self):
        discovery = {"issuer": "https://token.actions.githubusercontent.com", "jwks_uri": "https://token.actions.githubusercontent.com/.well-known/jwks", "id_token_signing_alg_values_supported": ["RS256"]}
        one = {"kty": "RSA", "use": "sig", "alg": "RS256", "kid": "one", "n": "AQ", "e": "AQAB"}
        two = {"kty": "RSA", "use": "sig", "alg": "RS256", "kid": "two", "n": "Ag", "e": "AQAB"}
        with tempfile.TemporaryDirectory() as td:
            cache = broker.JwksCache(Path(td) / "jwks.json")
            cache.update(discovery, {"keys": [one]}, max_age=301, now=1000)
            with self.assertRaises(broker.Reject):
                cache.update(discovery, {"keys": [{**one, "n": "changed"}]}, max_age=301, now=1001)
            cache.update(discovery, {"keys": [two]}, max_age=301, now=1001)
            self.assertEqual(cache.get("one", now=1002)["keys"][0]["kid"], "one")
            self.assertEqual(cache.get("two", now=1002)["keys"][0]["kid"], "two")
            with self.assertRaises(broker.Reject): cache.get("one", now=1302)

    def test_policy_deferred_bindings_are_exact_not_disabled_escape_hatches(self):
        raw = yaml.safe_load(policy_path.read_text())
        with tempfile.TemporaryDirectory() as td:
            target = Path(td) / "policy.yaml"
            for mutate in ("unlisted_zero", "invented_binding", "unknown_nested"):
                value = json.loads(json.dumps(raw))
                action = value["actions"][1]
                if mutate == "unlisted_zero": action["deferred_bindings"].remove("runner.id")
                elif mutate == "invented_binding": action["deferred_bindings"].append("template.sha256")
                else: action["runner"]["authority_escape"] = True
                target.write_text(yaml.safe_dump(value, sort_keys=False))
                with self.subTest(mutate=mutate), self.assertRaises(broker.Reject): broker.load_policy(target, allow_nonroot=True)
            for schema_version in (True, 1.0):
                value = copy.deepcopy(raw); value["schema_version"] = schema_version
                target.write_text(yaml.safe_dump(value, sort_keys=False))
                with self.subTest(schema_version=schema_version), self.assertRaises(broker.Reject): broker.load_policy(target, allow_nonroot=True)
            scalar_mutations = {
                "runner_uid_bool": lambda value: value["actions"][0]["runner"].__setitem__("uid", True),
                "executor_timeout_bool": lambda value: value["actions"][0]["executor"].__setitem__("timeout_seconds", True),
                "class_uid_bool": lambda value: value["classes"]["production"].__setitem__("broker_network_uid", True),
            }
            for name, mutate in scalar_mutations.items():
                value = copy.deepcopy(raw); mutate(value)
                target.write_text(yaml.safe_dump(value, sort_keys=False))
                with self.subTest(mutate=name), self.assertRaises(broker.Reject): broker.load_policy(target, allow_nonroot=True)
        for source in ("a: &x 1\nb: *x\n", "a: !!str value\n"):
            with self.subTest(source=source), self.assertRaises(broker.Reject): broker._strict_yaml(source)

    def test_immutable_install_contract_is_accepted_and_runtime_observations_are_rejected(self):
        lock_path = policy_path.parent / "broker-runtime.lock.yaml"
        broker.verify_runtime_lock(lock_path)
        original = yaml.safe_load(lock_path.read_text())
        mutations = []
        changed = copy.deepcopy(original); changed["components"][0]["payload_sha256"] = "0" * 64; mutations.append(changed)
        changed = copy.deepcopy(original); changed["components"][-1].pop("delivery_class"); mutations.append(changed)
        changed = copy.deepcopy(original); changed["runtime_contract"]["subordinate_ids"][0]["subuid_start"] = 22000; mutations.append(changed)
        changed = copy.deepcopy(original); changed["compatibility"]["artifact_class"] = "integration-evidence-not-guest-consumable"; mutations.append(changed)
        changed = copy.deepcopy(original); changed["compatibility"]["installation_readiness"] = "blocked"; mutations.append(changed)
        changed = copy.deepcopy(original); changed["compatibility"]["live_verification"] = "pending-offline-ubuntu-guest"; mutations.append(changed)
        changed = copy.deepcopy(original); changed["compatibility"]["live_verification"] = "passed-offline-ubuntu-guests"; mutations.append(changed)
        changed = copy.deepcopy(original); changed["verification"]["known_answer_status"] = "source-pinned-live-not-run"; mutations.append(changed)
        changed = copy.deepcopy(original); changed["verification"]["known_answer_status"] = "passed-on-both-offline-guests"; mutations.append(changed)
        changed = copy.deepcopy(original); changed["schema_version"] = True; mutations.append(changed)
        changed = copy.deepcopy(original); changed["schema_version"] = 1.0; mutations.append(changed)
        changed = copy.deepcopy(original); changed["compatibility"]["task4_consumer_contract"]["bind_exact_lock_sha256"] = 1; mutations.append(changed)
        changed = copy.deepcopy(original); changed["runtime_contract"]["firewall_phase_interface"]["frontend_phase_ownership"]["ghcr-write"]["uid"] = 22202; mutations.append(changed)
        changed = copy.deepcopy(original); changed["runtime_contract"]["firewall_phase_interface"]["frontend_phase_ownership"]["build-offline"]["targets"] = ["package-read"]; mutations.append(changed)
        changed = copy.deepcopy(original); changed["runtime_contract"]["firewall_phase_interface"]["frontend_phase_ownership"]["posthog-upload"]["extra"] = True; mutations.append(changed)
        with tempfile.TemporaryDirectory() as directory:
            for index, value in enumerate(mutations):
                target = Path(directory) / f"mutated-{index}.yaml"; target.write_text(yaml.safe_dump(value, sort_keys=False))
                with self.subTest(index=index), self.assertRaises(broker.Reject): broker.verify_runtime_lock(target)

    def test_production_build_fails_with_specific_deferred_transport_code(self):
        claims = broker.synthetic_claims_for_action(self.action, 2_000_000_000)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaises(broker.Reject) as ctx:
                broker.execute_fixed_action_live(self.action, root, root, claims, -1, (22201, 22201))
        self.assertEqual(ctx.exception.code, "production_build_transport_unavailable")

    def test_beehiiv_trusted_generation_is_not_source_and_refuses_without_transport(self):
        action = self.policy.actions["ken-website-beehiiv-production-sync"]
        generation = action.raw["trusted_generation"]
        generate, push = generation["phases"]["generate"], generation["phases"]["push"]
        self.assertEqual(action.input_mode, "trusted_generation")
        self.assertNotIn("source_is_deployable", action.raw)
        self.assertEqual(generation["phase_order"], ["generate", "push"])
        self.assertEqual(generation["phase_overlap"], "forbidden")
        self.assertNotEqual(generate["identity"]["uid"], push["identity"]["uid"])
        self.assertNotEqual(generate["request_subdirectory"], push["request_subdirectory"])
        self.assertNotEqual(generate["cgroup_template"], push["cgroup_template"])
        for phase in (generate, push):
            self.assertTrue(phase["cgroup_template"].startswith("/ken-actions-deploy.slice/{transaction_slice}/"))
        self.assertTrue(set(generate["descriptor_set"]).isdisjoint(push["descriptor_set"]))
        self.assertTrue(set(generate["template"]["fields"]).isdisjoint(push["template"]["fields"]))
        self.assertNotEqual(generate["network_profile"], push["network_profile"])
        with tempfile.TemporaryDirectory() as directory:
            claims = broker.synthetic_claims_for_action(action, 2_000_000_000)
            with self.assertRaises(broker.Reject) as ctx:
                broker.execute_fixed_action_live(action, Path(directory), Path(directory), claims, -1, (22102, 22102))
        self.assertEqual(ctx.exception.code, "trusted_generation_transport_unavailable")

    def test_beehiiv_phase_schema_rejects_credential_identity_network_and_transport_overlap(self):
        raw = yaml.safe_load(policy_path.read_text())
        index = next(index for index, item in enumerate(raw["actions"]) if item["action_id"] == "ken-website-beehiiv-production-sync")
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "policy.yaml"
            mutations = {
                "source_commit_marker": lambda action: action.__setitem__("source_is_deployable", True),
                "shared_uid": lambda action: action["trusted_generation"]["phases"]["push"]["identity"].__setitem__("uid", 22102),
                "shared_network": lambda action: action["trusted_generation"]["phases"]["push"].__setitem__("network_profile", "beehiiv-api-fixed-target"),
                "shared_directory": lambda action: action["trusted_generation"]["phases"]["push"].__setitem__("request_subdirectory", "generate"),
                "shared_cgroup": lambda action: action["trusted_generation"]["phases"]["push"].__setitem__("cgroup_template", "/ken-actions-deploy.slice/{transaction_slice}/ken-beehiiv-generate.scope"),
                "missing_cgroup": lambda action: action["trusted_generation"]["phases"]["generate"].pop("cgroup_template"),
                "wrong_cgroup_parent": lambda action: action["trusted_generation"]["phases"]["generate"].__setitem__("cgroup_template", "/system.slice/{transaction_slice}/ken-beehiiv-generate.scope"),
                "deploy_key_to_generator": lambda action: action["trusted_generation"]["phases"]["generate"]["descriptor_set"].append("DEPLOY_SSH_KEY"),
                "beehiiv_key_to_pusher": lambda action: action["trusted_generation"]["phases"]["push"]["descriptor_set"].append("BEEHIIV_API_KEY"),
                "phase_overlap": lambda action: action["trusted_generation"].__setitem__("phase_overlap", "allowed"),
                "transport_not_deferred": lambda action: action["deferred_bindings"].remove("trusted_generation.transport.phase_transport_sha256"),
                "uid_bool": lambda action: action["trusted_generation"]["phases"]["generate"]["identity"].__setitem__("uid", True),
                "action_code_false": lambda action: action.__setitem__("executes_repository_code", False),
                "action_code_string": lambda action: action.__setitem__("executes_repository_code", "ambiguous"),
            }
            for name, mutate in mutations.items():
                value = copy.deepcopy(raw); mutate(value["actions"][index])
                target.write_text(yaml.safe_dump(value, sort_keys=False))
                with self.subTest(name=name), self.assertRaises(broker.Reject):
                    broker.load_policy(target, allow_nonroot=True)
            value = copy.deepcopy(raw)
            other = value["actions"][1]
            other["input_mode"] = "trusted_generation"
            other["trusted_generation"] = copy.deepcopy(value["actions"][index]["trusted_generation"])
            other.pop("artifact_input")
            other.pop("executor")
            target.write_text(yaml.safe_dump(value, sort_keys=False))
            with self.assertRaises(broker.Reject): broker.load_policy(target, allow_nonroot=True)
            profile_mutations = (
                ["github-ssh"], ["beehiiv-api", "github-ssh"], [], "beehiiv-api",
            )
            for profile in profile_mutations:
                value = copy.deepcopy(raw)
                value["firewall_phase_interface"]["profiles"]["beehiiv-api-fixed-target"] = profile
                target.write_text(yaml.safe_dump(value, sort_keys=False))
                with self.subTest(profile=profile), self.assertRaises(broker.Reject): broker.load_policy(target, allow_nonroot=True)
            for profile in (["beehiiv-api"], ["github-ssh", "beehiiv-api"], [], "github-ssh"):
                value = copy.deepcopy(raw)
                value["firewall_phase_interface"]["profiles"]["github-ssh-ken-website-fixed-target"] = profile
                target.write_text(yaml.safe_dump(value, sort_keys=False))
                with self.subTest(push_profile=profile), self.assertRaises(broker.Reject): broker.load_policy(target, allow_nonroot=True)
            for field in ("dependency_acquisition_sha256", "generated_paths_manifest_sha256", "commit_input_contract_sha256", "cgroup_contract_sha256", "phase_transport_sha256"):
                for scalar in (False, 0, 1.0, "", "not-a-hash", "a" * 64):
                    value = copy.deepcopy(raw)
                    value["actions"][index]["trusted_generation"]["transport"][field] = scalar
                    target.write_text(yaml.safe_dump(value, sort_keys=False))
                    with self.subTest(field=field, scalar=scalar), self.assertRaises(broker.Reject): broker.load_policy(target, allow_nonroot=True)

    def test_frontend_policy_receipt_firewall_and_hash_schema_mutations_fail_closed(self):
        raw = yaml.safe_load(policy_path.read_text())
        index = next(index for index, item in enumerate(raw["actions"]) if item["action_id"] == "ken-frontend-production-release")
        mutations = {
            "ghcr_uid_crossover": lambda build: build["firewall_phases"]["ghcr-write"].__setitem__("uid", 22202),
            "uploader_uid_crossover": lambda build: build["firewall_phases"]["posthog-upload"].__setitem__("uid", 22003),
            "builder_uid_crossover": lambda build: build["firewall_phases"]["package-read"].__setitem__("uid", 22203),
            "offline_uid_crossover": lambda build: build["firewall_phases"]["build-offline"].__setitem__("uid", 22203),
            "offline_target": lambda build: build["firewall_phases"]["build-offline"]["targets"].append("package-read"),
            "receipt_extra_key": lambda build: build["receipt_contract"].__setitem__("signature", "caller"),
            "receipt_bool_version": lambda build: build["receipt_contract"].__setitem__("schema_version", True),
            "receipt_runner_visible": lambda build: build["receipt_contract"].__setitem__("runner_visible", True),
            "receipt_phase_reorder": lambda build: build["receipt_contract"]["phases"].reverse(),
            "receipt_limit_float": lambda build: build["receipt_contract"].__setitem__("data_bytes_max", 16384.0),
            "firewall_extra_key": lambda build: build["firewall_phases"]["ghcr-write"].__setitem__("profile", "broad"),
        }
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "policy.yaml"
            for name, mutate in mutations.items():
                value = copy.deepcopy(raw)
                mutate(value["actions"][index]["production_build"])
                target.write_text(yaml.safe_dump(value, sort_keys=False))
                with self.subTest(name=name), self.assertRaises(broker.Reject):
                    broker.load_policy(target, allow_nonroot=True)

    def test_website_wrapper_parses_only_reviewed_ssh_fields(self):
        argv = ["--broker-action", "ken-website-production-deploy", "--input-fd", "3", "--rendered-fd", "4"]
        with mock.patch.object(broker, "_read_executor_fd", return_value=b"ignored"), mock.patch.object(
            broker, "_parse_rendered_fields", side_effect=broker.Reject("schema-probe")
        ) as parse_fields:
            self.assertEqual(broker.fixed_wrapper_main("ken-website-production-deploy", argv), 1)
        self.assertEqual(parse_fields.call_args.args[1], ("WEBSITE_HOST", "WEBSITE_PORT", "WEBSITE_SSH_KEY"))

    def test_peer_identity_binds_uid_pid_start_cgroup_and_executable(self):
        peer = broker.PeerIdentity(uid=21014, gid=21014, pid=42, start_time=99, cgroup="/ken-actions-deploy.slice/ken-actions-deploy-listeners.slice/ken-runner@ken-deploy-production-01.service", executable="/usr/local/bin/ken-op-exec")
        expected = self.action.runner
        broker.validate_peer(peer, expected)
        for key, value in {
            "uid": 0,
            "pid": 43,
            "start_time": 100,
            "cgroup": "/docker.service",
            "executable": "/tmp/ken-op-exec",
        }.items():
            with self.subTest(key=key), self.assertRaises(broker.Reject):
                broker.validate_peer(broker.PeerIdentity(**{**peer.__dict__, key: value}), expected, peer)

    @unittest.skipUnless(sys.platform.startswith("linux") and os.geteuid() == 0, "Linux root /proc fixture")
    def test_linux_shebang_peer_binds_script_not_python_interpreter(self):
        with tempfile.TemporaryDirectory() as td:
            script = Path(td) / "launcher"
            script.write_text("#!/usr/bin/python3\nimport time\ntime.sleep(10)\n")
            script.chmod(0o500)
            child = subprocess.Popen([str(script)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                executable, identity = broker._peer_executable(child.pid)
                self.assertEqual(executable, str(script)); self.assertRegex(identity, r"^\d+:\d+:[0-9a-f]{64}$")
            finally:
                child.terminate(); child.wait(timeout=5)

    @unittest.skipUnless(sys.platform.startswith("linux") and os.geteuid() == 0, "Linux root dropped-FD fixture")
    def test_linux_dropped_executor_reads_only_preopened_payload_fd(self):
        with tempfile.TemporaryDirectory() as td:
            private = Path(td) / "root-only"; private.mkdir(mode=0o700)
            payload = private / "deploy.tar.gz"; payload.write_bytes(b"authenticated-payload"); payload.chmod(0o400)
            payload_fd = os.open(payload, os.O_RDONLY | os.O_CLOEXEC)
            read_fd, write_fd = os.pipe()
            child = os.fork()
            if child == 0:
                try:
                    os.setgroups([]); os.setresgid(65534,65534,65534); os.setresuid(65534,65534,65534)
                    value = Path(f"/proc/self/fd/{payload_fd}").read_bytes()
                    os.write(write_fd, value); os._exit(0)
                except BaseException: os._exit(2)
            os.close(write_fd); value = os.read(read_fd, 1024); os.close(read_fd); os.close(payload_fd)
            _, status = os.waitpid(child, 0)
            self.assertEqual(status, 0); self.assertEqual(value, b"authenticated-payload")

    def test_replay_state_is_durable_and_exact_retry_is_status_only(self):
        with tempfile.TemporaryDirectory() as td:
            state = broker.ReplayStore(Path(td))
            key = "1/2/3/4/action"
            state.authorize(key, "jti-a", 2_000_000_300, now=2_000_000_000)
            state.transition(key, "executing")
            reopened = broker.ReplayStore(Path(td))
            with self.assertRaises(broker.Reject) as ctx:
                reopened.authorize(key, "jti-b", 2_000_000_300, now=2_000_000_001)
            self.assertEqual(ctx.exception.code, "replay_uncertain_execution")
            with self.assertRaises(broker.Reject):
                reopened.authorize("other", "jti-a", 2_000_000_300, now=2_000_000_001)
            state.transition(key, "terminal", "succeeded")
            self.assertEqual(reopened.authorize(key, "fresh-jti", 2_000_000_300, now=2_000_000_002), {"state": "terminal", "reason_code": "succeeded"})
        artifact = self.policy.actions["ken-vexa-mcp-auth-production-deploy"]
        claims = broker.synthetic_claims_for_action(artifact, 2_000_000_000)
        self.assertNotEqual(broker._request_replay_key(claims, artifact, 1), broker._request_replay_key(claims, artifact, 2))

    def test_source_policy_rejects_build_restore_generate_and_remote_shell(self):
        forbidden = [
            ["dotnet", "publish"], ["pnpm", "build"], ["npm", "install"],
            ["docker", "build"], ["make", "package"], ["python", "-m", "build"],
            ["ssh", "host", "cd /srv && npm run build"],
        ]
        for argv in forbidden:
            with self.subTest(argv=argv), self.assertRaises(broker.Reject):
                broker.validate_source_argv(argv)
        broker.validate_source_argv(["rsync", "--archive", "--delete-delay", "./source/", "fixed-target:/srv/source/"])

    def test_source_materialization_rejects_links_gitlinks_and_collisions(self):
        with tempfile.TemporaryDirectory() as td:
            manifest, size = broker.materialize_git_entries([("100644", "blob", "src/app.txt", b"ok")], Path(td) / "good", max_files=2, max_blob_bytes=8, max_total_bytes=8)
            self.assertRegex(manifest, r"^[0-9a-f]{64}$"); self.assertEqual(size, 2)
        bad = [
            [("120000", "blob", "link", b"target")],
            [("160000", "commit", "submodule", b"")],
            [("100644", "blob", "A", b"x"), ("100644", "blob", "a", b"y")],
            [("100644", "blob", "../escape", b"x")],
        ]
        for entries in bad:
            with self.subTest(entries=entries), tempfile.TemporaryDirectory() as td, self.assertRaises(broker.Reject):
                broker.materialize_git_entries(entries, Path(td) / "bad", max_files=3, max_blob_bytes=8, max_total_bytes=16)

    def test_artifact_copy_hash_and_safe_extraction(self):
        payload = io.BytesIO()
        with zipfile.ZipFile(payload, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("manifest.json", '{"source_sha":"' + "a" * 40 + '","files":{"payload.txt":"' + hashlib.sha256(b"ok").hexdigest() + '"}}')
            zf.writestr("payload.txt", b"ok")
        data = payload.getvalue()
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "source.zip"
            src.write_bytes(data)
            fd = os.open(src, os.O_RDONLY)
            try:
                copied, digest = broker.copy_artifact_fd(fd, Path(td) / "request", len(data) + 1)
            finally:
                os.close(fd)
            self.assertEqual(digest, hashlib.sha256(data).hexdigest())
            extracted = broker.extract_authenticated_zip(copied, Path(td) / "out", max_entries=4, max_bytes=10000)
            self.assertEqual((extracted / "payload.txt").read_bytes(), b"ok")
            self.assertRegex(broker.verify_artifact_manifest(extracted, "a" * 40), r"^[0-9a-f]{64}$")
        for name in ("../escape", "/absolute", "A", "a"):
            pass

    def test_artifact_api_metadata_is_sha_and_run_bound(self):
        action = self.policy.actions["ken-vexa-mcp-auth-production-deploy"]
        claims = broker.synthetic_claims_for_action(action, 2_000_000_000)
        metadata = {"id": 44, "name": action.raw["artifact_input"]["name_prefix"] + claims["sha"], "expired": False, "size_in_bytes": 100, "digest": "sha256:" + "b" * 64, "workflow_run": {"id": claims["run_id"], "head_sha": claims["sha"], "head_branch": "main", "repository_id": action.raw["repository"]["id"]}}
        self.assertEqual(broker.validate_artifact_metadata(metadata, claims, action), "b" * 64)
        for key, value in (("name", "other"), ("expired", True), ("digest", "b" * 64)):
            with self.subTest(key=key), self.assertRaises(broker.Reject): broker.validate_artifact_metadata({**metadata, key: value}, claims, action)

    def test_zip_traversal_symlink_duplicate_and_case_collision_fail(self):
        fixtures = []
        for entries in ([('../escape', b'x')], [('A', b'x'), ('a', b'y')], [('dup', b'x'), ('dup', b'y')]):
            b = io.BytesIO()
            with zipfile.ZipFile(b, "w") as zf:
                for n, value in entries:
                    zf.writestr(n, value)
            fixtures.append(b.getvalue())
        b = io.BytesIO()
        with zipfile.ZipFile(b, "w") as zf:
            info = zipfile.ZipInfo("link")
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            zf.writestr(info, "target")
        fixtures.append(b.getvalue())
        for data in fixtures:
            with self.subTest(size=len(data)), tempfile.TemporaryDirectory() as td:
                archive = Path(td) / "bad.zip"
                archive.write_bytes(data)
                with self.assertRaises(broker.Reject):
                    broker.extract_authenticated_zip(archive, Path(td) / "out", max_entries=8, max_bytes=1000)

    def test_one_use_credential_pipe_never_enters_executor_environment(self):
        env = broker.executor_environment({"SOURCE_SHA": "a" * 40})
        self.assertEqual(env, {"HOME": "/nonexistent", "LANG": "C.UTF-8", "PATH": "/usr/bin:/bin", "SOURCE_SHA": "a" * 40})
        forbidden = {"OP_SERVICE_ACCOUNT_TOKEN", "CREDENTIALS_DIRECTORY", "GITHUB_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_TOKEN", "https_proxy", "HTTPS_PROXY"}
        self.assertFalse(forbidden & env.keys())
        token = bytearray(b"one-use-canary")
        fd = broker.one_use_secret_pipe(token)
        try: self.assertEqual(os.read(fd, 64), b"one-use-canary")
        finally: os.close(fd)
        self.assertEqual(token, bytearray(len(token)))

    def test_deploy_leases_exclusive_and_recoverable(self):
        with tempfile.TemporaryDirectory() as td:
            gate = broker.DeployLeaseGate(Path(td))
            one = gate.acquire("ordinary", "1" * 64, block=False)
            two = gate.acquire("ordinary", "2" * 64, block=False)
            with self.assertRaises(broker.Reject):
                gate.acquire("ordinary", "3" * 64, block=False)
            one.release(); two.release()
            exclusive = gate.acquire("production_build", "4" * 64, block=False)
            with self.assertRaises(broker.Reject):
                gate.acquire("ordinary", "5" * 64, block=False)
            exclusive.release()
            gate.recover()
            gate.acquire("ordinary", "6" * 64, block=False).release()

    def test_safe_response_and_log_redact_all_bearers_and_outputs(self):
        response = broker.safe_response("7" * 64, "rejected", "jwt_invalid")
        self.assertEqual(set(response), {"version", "request_id", "status", "reason_code"})
        canaries = ["jwt.canary.signature", "ghs_CANARY", "ops_CANARY", "rendered-CANARY", "stdout-CANARY"]
        text = broker.safe_log({"request_id": "req-123", "status": "rejected", "reason_code": "jwt_invalid", "oidc_jwt": canaries[0], "stdout": canaries[-1]})
        for value in canaries:
            self.assertNotIn(value, text)

    def _bound_policy(self, directory, selected_action, *, source_mode=False):
        raw = yaml.safe_load(policy_path.read_text())
        for action in raw["actions"]:
            if action["action_id"] != selected_action:
                continue
            if source_mode:
                action["input_mode"] = "source_commit"
                action["source_is_deployable"] = True
                action.pop("artifact_input", None)
            action["runner"].update({"id": 501, "group_id": 502, "listener_generation": 1})
            if action["executor"].get("operation_binding_sha256") is None:
                broker.OPERATION_BINDINGS[selected_action] = {"fixture": "fully-bound-operation"}
                action["executor"]["operation_binding_sha256"] = broker._operation_binding_sha256(selected_action)
            action["executor"]["systemd_transaction_transport_sha256"] = "f" * 64
            if "known_hosts_sha256" in action["executor"]:
                action["executor"]["known_hosts_sha256"] = "c" * 64
            action["deferred_bindings"] = []
            action["enabled"] = True
            action["blocked_reason_code"] = "none"
            if action["input_mode"] == "production_build":
                action["production_build"]["base_image_digest"] = "sha256:" + "a" * 64
                action["production_build"]["variables_manifest_sha256"] = "b" * 64
                action["production_build"]["phase_transport_sha256"] = "d" * 64
                action["production_build"]["deploy_contract_sha256"] = "e" * 64
        target = Path(directory) / "bound-policy.yaml"
        target.write_text(yaml.safe_dump(raw, sort_keys=False))
        return broker.load_policy(target, allow_nonroot=True)

    def _peer(self, action):
        return broker.PeerIdentity(uid=action.runner.uid, gid=action.runner.gid, pid=42, start_time=99, cgroup=action.runner.cgroup, executable=action.runner.executable)

    def test_bound_source_action_runs_full_socket_transaction_once(self):
        class Fixture(broker.BrokerDependencies):
            def __init__(self, action, claims): self.action=action; self.claims=claims; self.executions=0; self.calls=[]
            def verify_token(self, token, action): self.calls.append("jwt"); return self.claims
            def github_get(self, token, path, action):
                self.calls.append(path); repo=action.raw["repository"]
                if path.startswith("/repositories/"): return {"id":repo["id"],"name":repo["name"],"full_name":f"{repo['owner']}/{repo['name']}","private":True,"visibility":"private","default_branch":"main","owner":{"login":repo["owner"],"id":repo["owner_id"]}}
                if "/actions/runs/" in path: return {"id":self.claims["run_id"],"run_attempt":self.claims["run_attempt"],"head_sha":self.claims["sha"],"event":self.claims["event_name"],"status":"in_progress","head_branch":"main","path":".github/workflows/deploy.yml","repository":{"id":repo["id"],"full_name":f"{repo['owner']}/{repo['name']}"},"head_repository":{"id":repo["id"],"full_name":f"{repo['owner']}/{repo['name']}"}}
                if "/actions/jobs/" in path: return broker.synthetic_job_for_action(action,self.claims)
                if "/git/commits/" in path: return {"sha":self.claims["sha"],"tree":{"sha":"c"*40}}
                raise AssertionError(path)
            def materialize_source(self, token, claims, action, request_dir):
                source=request_dir/"input"; source.mkdir(); (source/"source.txt").write_text("authenticated")
                return source,"c"*40,"d"*64
            def execute(self, action, request_dir, input_path, claims, credential_fd):
                self.executions += 1
                try: self.assert_credential=os.read(credential_fd,64)
                finally: os.close(credential_fd)
                return "succeeded"
        with tempfile.TemporaryDirectory() as td:
            policy=self._bound_policy(td,"ken-website-production-deploy",source_mode=True); action=policy.actions["ken-website-production-deploy"]
            claims=broker.synthetic_claims_for_action(action,int(time.time())); fixture=Fixture(action,claims)
            credential=Path(td)/"credential"; credential.write_bytes(b"fixture-token"); os.chmod(credential,0o600); credential_fd=os.open(credential,os.O_RDONLY)
            packet=json.dumps({"version":1,"action_id":action.action_id,"oidc_jwt":"a.b.c","github_token":"ghs-fixture"},separators=(",",":")).encode()
            for _ in range(2):
                socket_type=socket.SOCK_SEQPACKET if sys.platform.startswith("linux") else socket.SOCK_DGRAM
                client,server=socket.socketpair(socket.AF_UNIX,socket_type)
                client.send(packet); broker.handle_connection(server,policy,"production",Path(td)/"state",credential_fd,fixture,peer=self._peer(action),revalidate=lambda value:value)
                response=json.loads(client.recv(4096)); client.close(); server.close()
                self.assertEqual(response["status"],"succeeded")
            os.close(credential_fd)
            self.assertEqual(fixture.executions,1); self.assertEqual(fixture.assert_credential,b"fixture-token")
            self.assertEqual(list((Path(td)/"state/requests").glob("*")),[])

    def test_bound_artifact_socket_transaction_authenticates_api_and_fd_bytes(self):
        class Fixture(broker.BrokerDependencies):
            def __init__(self, claims, digest, size): self.claims=claims; self.digest=digest; self.size=size; self.executions=0
            def verify_token(self, token, action): return self.claims
            def github_get(self, token, path, action):
                repo=action.raw["repository"]
                if path.startswith("/repositories/"): return {"id":repo["id"],"name":repo["name"],"full_name":f"{repo['owner']}/{repo['name']}","private":True,"visibility":"private","default_branch":"main","owner":{"login":repo["owner"],"id":repo["owner_id"]}}
                if "/actions/runs/" in path: return {"id":self.claims["run_id"],"run_attempt":self.claims["run_attempt"],"head_sha":self.claims["sha"],"event":self.claims["event_name"],"status":"in_progress","head_branch":"main","path":".github/workflows/deploy.yml","repository":{"id":repo["id"],"full_name":f"{repo['owner']}/{repo['name']}"},"head_repository":{"id":repo["id"],"full_name":f"{repo['owner']}/{repo['name']}"}}
                if "/actions/jobs/" in path: return broker.synthetic_job_for_action(action,self.claims)
                if "/actions/artifacts/" in path: return {"id":77,"name":action.raw["artifact_input"]["name_prefix"]+self.claims["sha"],"expired":False,"size_in_bytes":self.size,"digest":"sha256:"+self.digest,"workflow_run":{"id":self.claims["run_id"],"head_sha":self.claims["sha"],"head_branch":"main","repository_id":repo["id"]}}
                raise AssertionError(path)
            def materialize_source(self,*args): raise AssertionError("source mode")
            def execute(self, action, request_dir, input_path, claims, credential_fd): self.executions+=1; os.close(credential_fd); return "succeeded"
        with tempfile.TemporaryDirectory() as td:
            policy=self._bound_policy(td,"ken-vexa-mcp-auth-production-deploy"); action=policy.actions["ken-vexa-mcp-auth-production-deploy"]; claims=broker.synthetic_claims_for_action(action,int(time.time()))
            payload=io.BytesIO()
            with zipfile.ZipFile(payload,"w") as archive:
                archive.writestr("payload.txt",b"ok")
                archive.writestr("manifest.json",json.dumps({"source_sha":claims["sha"],"files":{"payload.txt":hashlib.sha256(b"ok").hexdigest()}},separators=(",",":")))
            data=payload.getvalue(); fixture=Fixture(claims,hashlib.sha256(data).hexdigest(),len(data))
            artifact=Path(td)/"artifact.zip"; artifact.write_bytes(data); artifact_fd=os.open(artifact,os.O_RDONLY)
            credential=Path(td)/"credential"; credential.write_bytes(b"fixture-token"); os.chmod(credential,0o600); credential_fd=os.open(credential,os.O_RDONLY)
            socket_type=socket.SOCK_SEQPACKET if sys.platform.startswith("linux") else socket.SOCK_DGRAM
            client,server=socket.socketpair(socket.AF_UNIX,socket_type)
            packet=json.dumps({"version":1,"action_id":action.action_id,"artifact_id":77,"oidc_jwt":"a.b.c","github_token":"ghs-fixture"},separators=(",",":")).encode()
            client.sendmsg([packet],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array("i",[artifact_fd]))]); broker.handle_connection(server,policy,"production",Path(td)/"state",credential_fd,fixture,peer=self._peer(action),revalidate=lambda value:value)
            response=json.loads(client.recv(4096)); client.close(); server.close(); os.close(artifact_fd); os.close(credential_fd)
            self.assertEqual(response["status"],"succeeded"); self.assertEqual(fixture.executions,1)

class DownloaderTests(unittest.TestCase):
    def test_redirect_contract_and_authorization_stripping(self):
        self.assertTrue(downloader.valid_blob_host("abc123.blob.core.windows.net"))
        for host in ("blob.core.windows.net", "ABC.blob.core.windows.net", "ab.blob.core.windows.net", "abc.blob.core.windows.net.", "abc.blob.core.windows.net.evil", "127.0.0.1", "[::1]"):
            self.assertFalse(downloader.valid_blob_host(host), host)
        headers = downloader.cross_host_headers({"Authorization": "Bearer canary", "Accept": "application/vnd.github+json"})
        self.assertNotIn("Authorization", headers)

class FrontendTests(unittest.TestCase):
    def test_frontend_root_runtime_and_authority_contract_is_not_caller_attested(self):
        import inspect
        self.assertEqual(broker.SAFE_REQUEST_ID.pattern, r"^[0-9a-f]{64}$")
        self.assertRegex(broker.new_request_id(), r"^[0-9a-f]{64}$")
        self.assertEqual(set(frontend.FRONTEND_FIREWALL_PHASES), {
            "node-base-read", "package-read", "build-offline", "posthog-upload", "ghcr-write",
            "frontend-deploy", "frontend-public-health",
        })
        self.assertNotIn("observation", inspect.signature(frontend.canonical_phase_data).parameters)
        self.assertTrue(callable(frontend.observe_phase_start))
        self.assertEqual(frontend.PLAN_SHA256, "75715a5a3973f3ed9813e66c809d76ec1281d537afae0c08d66b02684583a658")

    def test_frontend_runtime_observer_reads_systemd_proc_cgroup_and_firewall(self):
        request_id = "a" * 64
        source_sha = "b" * 40
        phase = "build"
        unit, slice_name, control_group, dedicated = frontend._expected_runtime(phase, request_id)
        self.assertEqual(control_group, f"/ken.slice/ken-actions.slice/ken-actions-deploy.slice/{slice_name}/{unit}")
        systemd_start = {
            "LoadState": "loaded", "ActiveState": "active", "SubState": "running",
            "Slice": slice_name, "ControlGroup": control_group, "User": "ken-fe-builder",
            "ExecMainPID": "4242", "ExecMainStartTimestampMonotonic": "100",
            "ExecMainExitTimestampMonotonic": "0", "Result": "success",
        }
        process = {
            "uid": frontend.RECEIPT_ACTOR_UIDS[phase],
            "boot_id": "12345678-1234-1234-1234-123456789abc",
            "start_ticks": 777, "control_group": control_group,
            "fd_set_sha256": "4" * 64,
        }
        captured = {}
        with mock.patch.object(frontend.os, "geteuid", return_value=frontend.RECEIPT_OWNER_UID), mock.patch.object(
            frontend, "_systemd_snapshot", return_value=systemd_start
        ) as systemd_read, mock.patch.object(frontend, "_proc_snapshot", return_value=process) as proc_read, mock.patch.object(
            frontend, "_firewall_request", return_value="5" * 64
        ) as firewall_read, mock.patch.object(
            frontend, "_publish_receipt", side_effect=lambda path, data: captured.update(path=path, data=data)
        ):
            frontend.observe_phase_start(
                request_id=request_id, source_sha=source_sha, phase=phase,
                actor_pid=4242, firewall_phase="build-offline", output=Path("/root/observation"),
            )
        systemd_read.assert_called_once_with(unit)
        proc_read.assert_called_once_with(4242)
        firewall_read.assert_called_once_with(request_id, "build-offline")
        observed = json.loads(captured["data"])
        self.assertEqual(observed["control_group"], control_group)
        self.assertEqual(observed["actor_start_ticks"], 777)

        records = [
            self._start_observation(phase, request_id, source_sha, name)
            for name in frontend.RECEIPT_FIREWALL_PHASES[phase]
        ]
        systemd_end = {**systemd_start, "ActiveState": "inactive", "SubState": "dead", "ControlGroup": "",
                       "ExecMainExitTimestampMonotonic": "200"}
        with mock.patch.object(frontend, "_proc_snapshot", side_effect=frontend.ReleaseError("gone")) as proc_end, mock.patch.object(
            frontend, "_firewall_request", return_value=None
        ) as firewall_end, mock.patch.object(frontend, "_systemd_snapshot", return_value=systemd_end), mock.patch.object(
            frontend, "_cgroup_empty", return_value=True
        ) as cgroup_end:
            finished = frontend._finish_root_observation(records, request_id=request_id, phase=phase)
        proc_end.assert_called_once_with(4242)
        firewall_end.assert_called_once_with(request_id, None)
        cgroup_end.assert_called_once_with(control_group)
        self.assertTrue(finished["process_reaped"])
        self.assertTrue(finished["cgroup_empty_after"])
        self.assertEqual([item["phase"] for item in finished["firewall_transitions"]], list(frontend.RECEIPT_FIREWALL_PHASES[phase]))

        with tempfile.TemporaryDirectory() as td, mock.patch.object(frontend, "PROC_ROOT", Path(td)), mock.patch.object(
            frontend, "_proc_snapshot", side_effect=frontend.ReleaseError("malformed")
        ):
            (Path(td) / "4242").mkdir()
            with self.assertRaisesRegex(frontend.ReleaseError, "runtime_process_not_reaped"):
                frontend._finish_root_observation(records, request_id=request_id, phase=phase)

        failed_end = {**systemd_end, "ActiveState": "failed"}
        drifted_end = {**systemd_end, "ExecMainStartTimestampMonotonic": "101"}
        for invalid_end in (failed_end, drifted_end):
            with tempfile.TemporaryDirectory() as td, mock.patch.object(frontend, "PROC_ROOT", Path(td)), mock.patch.object(
                frontend, "_proc_snapshot", side_effect=frontend.ReleaseError("gone")
            ), mock.patch.object(frontend, "_firewall_request", return_value=None), mock.patch.object(
                frontend, "_systemd_snapshot", return_value=invalid_end
            ), mock.patch.object(frontend, "_cgroup_empty", return_value=True):
                with self.assertRaisesRegex(frontend.ReleaseError, "runtime_end_readback_invalid"):
                    frontend._finish_root_observation(records, request_id=request_id, phase=phase)

    def test_frontend_firewall_readback_binds_active_rules_and_teardown(self):
        request_id = "a" * 64
        phase = "build-offline"
        with tempfile.TemporaryDirectory() as td:
            state = Path(td)
            active = state / "active-requests"
            active.mkdir(mode=0o700)
            request = active / f"{request_id}.json"
            request.write_text(json.dumps({
                "schema_version": 1, "request_id": request_id,
                "profile": "frontend-production-digest-deploy", "phase": phase,
            }, sort_keys=True, separators=(",", ":")) + "\n")
            rules = state / "guest-active.nft"
            rules.write_text(f'table inet ken_actions_guest {{ comment "requests={request_id}"; }}\n')
            os.chmod(request, 0o600); os.chmod(rules, 0o600)
            with mock.patch.object(frontend, "FIREWALL_ACTIVE_ROOT", active), mock.patch.object(
                frontend, "FIREWALL_ACTIVE_RULES", rules
            ), mock.patch.object(frontend, "RECEIPT_OWNER_UID", os.geteuid()), mock.patch.object(
                frontend, "RECEIPT_OWNER_GID", os.getegid()
            ):
                self.assertRegex(frontend._firewall_request(request_id, phase), r"^[0-9a-f]{64}$")
                rules.write_text('table inet ken_actions_guest { comment "managed-by=ken-actions"; }\n')
                with self.assertRaisesRegex(frontend.ReleaseError, "runtime_firewall_state_invalid"):
                    frontend._firewall_request(request_id, phase)
                request.unlink()
                self.assertIsNone(frontend._firewall_request(request_id, None))
                rules.write_text(f'table inet ken_actions_guest {{ comment "requests={request_id}"; }}\n')
                with self.assertRaisesRegex(frontend.ReleaseError, "runtime_firewall_state_invalid"):
                    frontend._firewall_request(request_id, None)

    def test_frontend_cli_is_silent_and_digest_uses_preopened_fd(self):
        import contextlib
        script = bin_root / "ken-frontend-production-release"
        for command in frontend.command_names():
            result = subprocess.run([str(script), command], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
            self.assertEqual((result.stdout, result.stderr), (b"", b""), command)
        result = subprocess.run([str(script), "unknown"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        self.assertEqual((result.stdout, result.stderr), (b"", b""))
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            manifest = root / "manifest.json"; manifest.write_text('{"schemaVersion":2}')
            output = root / "digest"; output.touch(); os.chmod(output, 0o600)
            fd = os.open(output, os.O_WRONLY)
            stdout, stderr = io.StringIO(), io.StringIO()
            with mock.patch.object(frontend, "RECEIPT_OWNER_UID", os.geteuid()), mock.patch.object(
                frontend, "RECEIPT_OWNER_GID", os.getegid()
            ), contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                self.assertEqual(frontend.main(["digest", str(manifest), "--output-fd", str(fd)]), 0)
            self.assertEqual((stdout.getvalue(), stderr.getvalue()), ("", ""))
            self.assertRegex(output.read_text(), r"^sha256:[0-9a-f]{64}$")

    def _phase_evidence(self, phase):
        digest = "a" * 64
        sha = "b" * 40
        tree_sha = "c" * 40
        self.assertNotEqual(sha, tree_sha)
        return {
            "source": {
                "repository_id": 1141163204, "commit_sha": sha, "tree_sha": tree_sha,
                "tree_manifest_sha256": digest,
                "workflow_blob_sha": frontend.SOURCE_BLOB_SHAS["workflow_blob_sha"],
                "dockerfile_blob_sha": frontend.SOURCE_BLOB_SHAS["dockerfile_blob_sha"],
                "lockfile_blob_sha": frontend.SOURCE_BLOB_SHAS["lockfile_blob_sha"],
                "variables_manifest_sha256": digest,
            },
            "build": {
                "source_sha": sha, "tree_sha": tree_sha,
                "tree_manifest_sha256": digest,
                "workflow_blob_sha": frontend.SOURCE_BLOB_SHAS["workflow_blob_sha"],
                "dockerfile_blob_sha": frontend.SOURCE_BLOB_SHAS["dockerfile_blob_sha"],
                "lockfile_blob_sha": frontend.SOURCE_BLOB_SHAS["lockfile_blob_sha"],
                "oci_layout_sha256": digest, "source_maps_sha256": digest,
                "oci_manifest_digest": "sha256:" + digest,
                "provenance_sha256": digest,
                "provenance_subject_digest": "sha256:" + digest,
                "build_log_sha256": digest, "cache_metadata_sha256": digest,
                "build_plan_sha256": frontend.BUILD_PLAN_SHA256,
                "buildkit_version": "0.24.0", "buildctl_version": "0.24.0",
                "node_version": "22.20.0", "pnpm_version": "10.28.2",
                "base_image_digest": "sha256:aa83e8f13963f17f7f6bd497085112bf12ea6f20b4b826d9b33f2d99594325b6",
                "platform": "linux/amd64", "variables_manifest_sha256": digest,
            },
            "scan": {
                "source_sha": sha, "tree_sha": tree_sha,
                "oci_layout_sha256": digest, "oci_manifest_digest": "sha256:" + digest,
                "provenance_sha256": digest,
                "provenance_subject_digest": "sha256:" + digest,
                "scan_evidence_sha256": digest,
                "leakage_encodings": ["raw", "canonical-base64", "lowercase-hex"],
            },
            "upload": {
                "source_maps_sha256": digest, "posthog_upload_sha256": digest,
            },
            "registry": {
                "registry": "ghcr.io/ken-technology/ken-frontend",
                "image_digest": "sha256:" + digest, "manifest_digest": "sha256:" + digest,
                "platform": "linux/amd64", "source_sha": sha, "tree_sha": tree_sha,
                "oci_layout_sha256": digest,
                "provenance_sha256": digest,
                "provenance_subject_digest": "sha256:" + digest,
                "media_type": "application/vnd.oci.image.manifest.v1+json",
                "readback_verified": True,
            },
            "token-destroy": {
                "source_sha": sha, "tree_sha": tree_sha,
                "image_digest": "sha256:" + digest, "provenance_sha256": digest,
                "token_descriptor_closed": True, "token_buffer_zeroed": True,
                "token_destroyed_monotonic_ns": 64000,
            },
            "digest": {
                "source_sha": sha, "tree_sha": tree_sha,
                "image_digest": "sha256:" + digest, "provenance_sha256": digest,
                "digest_state_sha256": digest,
                "state_key_sha256": digest, "fsynced": True,
                "durable_state_published_monotonic_ns": 73000,
                "durable_state_readback_monotonic_ns": 74000,
            },
            "deploy-health": {
                "source_sha": sha, "tree_sha": tree_sha,
                "image_digest": "sha256:" + digest, "provenance_sha256": digest,
                "deploy_receipt_sha256": digest,
                "health_receipt_sha256": digest,
                "deploy_completed_monotonic_ns": 80150,
                "health_started_monotonic_ns": 80200,
                "health_completed_monotonic_ns": 84000,
            },
            "cleanup": {
                "source_sha": sha, "tree_sha": tree_sha,
                "image_digest": "sha256:" + digest, "provenance_sha256": digest,
                "request_state_removed": True, "source_removed": True,
                "buildkit_removed": True, "oci_removed": True,
                "source_maps_removed": True, "secret_mount_removed": True,
                "descriptors_closed": True, "firewall_inactive": True,
                "cgroups_empty": True,
                "cleanup_completed_monotonic_ns": 94000,
            },
        }[phase]

    def _start_observation(self, phase, request_id, source_sha, firewall_phase=None):
        unit, slice_name, control_group, dedicated = frontend._expected_runtime(phase, request_id)
        base = (frontend.RECEIPT_PHASES.index(phase) + 1) * 10000
        subphase = (frontend.RECEIPT_FIREWALL_PHASES[phase].index(firewall_phase) + 1
                    if firewall_phase is not None else 1)
        return {
            "schema_version": 1, "plan_sha256": frontend.PLAN_SHA256,
            "receipt_contract_sha256": frontend.RECEIPT_CONTRACT_SHA256,
            "request_id": request_id, "source_sha": source_sha, "phase": phase,
            "unit": unit, "slice": slice_name, "control_group": control_group,
            "dedicated_unit": dedicated, "actor_pid": 4242,
            "observed_actor_uid": frontend.RECEIPT_ACTOR_UIDS[phase],
            "boot_id": "12345678-1234-1234-1234-123456789abc",
            "actor_start_ticks": 100, "fd_set_sha256": "1" * 64,
            "systemd_exec_start_monotonic_usec": 100,
            "firewall_phase": firewall_phase,
            "firewall_request_sha256": "2" * 64 if firewall_phase else None,
            "observed_monotonic_ns": base + subphase * 100,
        }

    def _finished_observation(self, records, request_id, phase):
        first = records[0]
        transitions = []
        for record in records:
            if record["firewall_phase"]:
                authority = frontend.FRONTEND_FIREWALL_PHASES[record["firewall_phase"]]
                transitions.append({
                    "phase": record["firewall_phase"], "uid": authority["uid"],
                    "targets": list(authority["targets"]),
                    "activate_readback_sha256": record["firewall_request_sha256"],
                    "activated_observed_monotonic_ns": record["observed_monotonic_ns"],
                    "deactivated": True,
                })
        dedicated = first["dedicated_unit"]
        return {
            "unit": first["unit"], "slice": first["slice"], "control_group": first["control_group"],
            "observed_actor_uid": first["observed_actor_uid"], "actor_pid": first["actor_pid"],
            "boot_id": first["boot_id"], "actor_start_ticks": first["actor_start_ticks"],
            "systemd_exec_start_monotonic_usec": 100,
            "systemd_exec_exit_monotonic_usec": 200 if dedicated else 0,
            "started_observed_monotonic_ns": first["observed_monotonic_ns"],
            "completed_observed_monotonic_ns": (frontend.RECEIPT_PHASES.index(phase) + 1) * 10000 + 9000,
            "process_reaped": True,
            "descriptor_snapshots_sha256": "3" * 64, "descriptors_closed": True,
            "network_authority": frontend._network_authority(phase),
            "firewall_transitions": transitions, "firewall_inactive_after": True,
            "cgroup_empty_after": dedicated,
        }

    def _write_observations(self, root, phase, request_id, source_sha):
        paths = []
        for index, firewall_phase in enumerate(frontend.RECEIPT_FIREWALL_PHASES[phase] or (None,)):
            path = root / f"{phase}-{index}.observation"
            value = self._start_observation(phase, request_id, source_sha, firewall_phase)
            path.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")))
            os.chmod(path, 0o600); paths.append(path)
        return paths

    def _write_authority(self, root, phase, request_id, source_sha, evidence):
        path = root / f"{phase}.authority"
        observed = (frontend.RECEIPT_PHASES.index(phase) + 1) * 10000 + 5000
        path.write_bytes(frontend.canonical_phase_authority(
            request_id, source_sha, phase, evidence, observed,
        ))
        os.chmod(path, 0o600)
        return path

    def _policy_copy(self, root):
        path = root / "op-broker-policy.yaml"
        path.write_bytes(policy_path.read_bytes()); os.chmod(path, 0o644)
        return path

    def test_frontend_receipt_chain_is_exact_bounded_and_identity_bound(self):
        request_id = "c" * 64
        source_sha = "d" * 40
        with mock.patch.object(frontend, "RECEIPT_OWNER_UID", os.geteuid()), mock.patch.object(
            frontend, "RECEIPT_OWNER_GID", os.getegid()
        ), mock.patch.dict(frontend.RECEIPT_ACTOR_UIDS, {phase: os.geteuid() for phase in frontend.RECEIPT_PHASES}, clear=True), mock.patch.object(
            frontend, "_finish_root_observation", side_effect=lambda records, request_id, phase: self._finished_observation(records, request_id, phase)
        ), tempfile.TemporaryDirectory() as td:
            root = Path(td)
            policy_copy = self._policy_copy(root)
            previous = None
            receipts = []
            authority_paths = []
            for phase in frontend.RECEIPT_PHASES:
                data = root / f"{phase}.data.json"
                evidence = self._phase_evidence(phase)
                if phase == "source": evidence["commit_sha"] = source_sha
                if phase in frontend.RECEIPT_PHASES:
                    if "source_sha" in evidence: evidence["source_sha"] = source_sha
                data.write_bytes(frontend.canonical_phase_data(
                    request_id, source_sha, phase, evidence,
                ))
                os.chmod(data, 0o600)
                observation_paths = self._write_observations(root, phase, request_id, source_sha)
                authority = self._write_authority(root, phase, request_id, source_sha, evidence)
                receipt = root / f"{len(receipts):02d}-{phase}.receipt.json"
                data_fd = os.open(data, os.O_RDONLY)
                previous_fd = os.open(previous, os.O_RDONLY) if previous else None
                frontend.seal_phase_receipt_from_fds(
                    request_id=request_id, source_sha=source_sha, phase=phase,
                    data_fd=data_fd, authority_fd=os.open(authority, os.O_RDONLY),
                    observation_fds=[os.open(path, os.O_RDONLY) for path in observation_paths],
                    policy_fd=os.open(policy_copy, os.O_RDONLY), previous_receipt_fd=previous_fd,
                    output=receipt,
                )
                with self.assertRaises(OSError): os.fstat(data_fd)
                if previous_fd is not None:
                    with self.assertRaises(OSError): os.fstat(previous_fd)
                receipts.append(receipt)
                authority_paths.append(authority)
                previous = receipt
            frontend.verify_receipt_chain(
                receipts, request_id=request_id, source_sha=source_sha,
                policy_fd=os.open(policy_copy, os.O_RDONLY),
                authority_fds=[os.open(path, os.O_RDONLY) for path in authority_paths],
            )
            self.assertEqual(
                frontend.receipt_sha256(receipts[-1]),
                hashlib.sha256(receipts[-1].read_bytes()).hexdigest(),
            )

            replay = root / "replay.json"
            replay.write_bytes(receipts[1].read_bytes())
            os.chmod(replay, 0o600)
            with self.assertRaises(frontend.ReleaseError):
                frontend.verify_receipt_chain(
                    [receipts[0], receipts[1], replay, *receipts[3:]], request_id=request_id,
                    source_sha=source_sha, policy_fd=os.open(policy_copy, os.O_RDONLY),
                    authority_fds=[os.open(path, os.O_RDONLY) for path in authority_paths],
                )
            mutated = root / "mutated.json"
            value = json.loads(receipts[2].read_text())
            value["previous_receipt_sha256"] = "f" * 64
            mutated.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")))
            os.chmod(mutated, 0o600)
            with self.assertRaises(frontend.ReleaseError):
                frontend.verify_receipt_chain(
                    [receipts[0], receipts[1], mutated, *receipts[3:]], request_id=request_id,
                    source_sha=source_sha, policy_fd=os.open(policy_copy, os.O_RDONLY),
                    authority_fds=[os.open(path, os.O_RDONLY) for path in authority_paths],
                )
            value = json.loads(receipts[2].read_text())
            value["caller_digest"] = "0" * 64
            mutated.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")))
            with self.assertRaises(frontend.ReleaseError):
                frontend.verify_receipt_chain(
                    [receipts[0], receipts[1], mutated, *receipts[3:]], request_id=request_id,
                    source_sha=source_sha, policy_fd=os.open(policy_copy, os.O_RDONLY),
                    authority_fds=[os.open(path, os.O_RDONLY) for path in authority_paths],
                )
            os.chmod(receipts[0], 0o640)
            with self.assertRaises(frontend.ReleaseError):
                frontend.verify_receipt_chain(
                    receipts, request_id=request_id, source_sha=source_sha,
                    policy_fd=os.open(policy_copy, os.O_RDONLY),
                    authority_fds=[os.open(path, os.O_RDONLY) for path in authority_paths],
                )

    def test_frontend_receipt_chain_rejects_cross_phase_and_policy_drift(self):
        request_id = "9" * 64
        source_sha = "8" * 40
        with mock.patch.object(frontend, "RECEIPT_OWNER_UID", os.geteuid()), mock.patch.object(
            frontend, "RECEIPT_OWNER_GID", os.getegid()
        ), mock.patch.dict(frontend.RECEIPT_ACTOR_UIDS, {phase: os.geteuid() for phase in frontend.RECEIPT_PHASES}, clear=True), mock.patch.object(
            frontend, "_finish_root_observation", side_effect=lambda records, request_id, phase: self._finished_observation(records, request_id, phase)
        ), tempfile.TemporaryDirectory() as td:
            root = Path(td)
            policy_copy = self._policy_copy(root)
            previous = None
            receipts = []
            authority_paths = []
            for phase in frontend.RECEIPT_PHASES:
                evidence = self._phase_evidence(phase)
                if phase == "source": evidence["commit_sha"] = source_sha
                if phase in frontend.RECEIPT_PHASES:
                    if "source_sha" in evidence: evidence["source_sha"] = source_sha
                data = root / f"{phase}.data"
                data.write_bytes(frontend.canonical_phase_data(
                    request_id, source_sha, phase, evidence,
                ))
                os.chmod(data, 0o600)
                observation_paths = self._write_observations(root, phase, request_id, source_sha)
                authority = self._write_authority(root, phase, request_id, source_sha, evidence)
                receipt = root / f"{len(receipts):02d}-{phase}.receipt"
                frontend.seal_phase_receipt_from_fds(
                    request_id=request_id, source_sha=source_sha, phase=phase,
                    data_fd=os.open(data, os.O_RDONLY), authority_fd=os.open(authority, os.O_RDONLY),
                    observation_fds=[os.open(path, os.O_RDONLY) for path in observation_paths],
                    policy_fd=os.open(policy_copy, os.O_RDONLY),
                    previous_receipt_fd=os.open(previous, os.O_RDONLY) if previous else None,
                    output=receipt,
                )
                receipts.append(receipt); authority_paths.append(authority); previous = receipt
            for phase, key in (("source", "commit_sha"), ("build", "tree_manifest_sha256"), ("scan", "oci_layout_sha256"), ("upload", "source_maps_sha256"), ("registry", "image_digest"), ("registry", "provenance_sha256")):
                index = frontend.RECEIPT_PHASES.index(phase)
                values = [json.loads(path.read_text()) for path in receipts]
                if key == "commit_sha":
                    values[index]["evidence"][key] = "7" * 40
                elif key == "image_digest":
                    values[index]["evidence"][key] = "sha256:" + "7" * 64
                    values[index]["evidence"]["manifest_digest"] = "sha256:" + "7" * 64
                    values[index]["evidence"]["provenance_subject_digest"] = "sha256:" + "7" * 64
                    for downstream_phase in ("token-destroy", "digest", "deploy-health", "cleanup"):
                        values[frontend.RECEIPT_PHASES.index(downstream_phase)]["evidence"]["image_digest"] = "sha256:" + "7" * 64
                elif phase == "registry" and key == "provenance_sha256":
                    values[index]["evidence"][key] = "7" * 64
                    for downstream_phase in ("token-destroy", "digest", "deploy-health", "cleanup"):
                        values[frontend.RECEIPT_PHASES.index(downstream_phase)]["evidence"]["provenance_sha256"] = "7" * 64
                else:
                    values[index]["evidence"][key] = "7" * 64
                changed_receipts = []
                previous_digest = None
                for ordinal, value in enumerate(values):
                    value["previous_receipt_sha256"] = previous_digest
                    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
                    changed = root / f"changed-{phase}-{ordinal}.receipt"
                    changed.write_bytes(encoded); os.chmod(changed, 0o600)
                    changed_receipts.append(changed)
                    previous_digest = hashlib.sha256(encoded).hexdigest()
                with self.subTest(phase=phase), self.assertRaises(frontend.ReleaseError):
                    frontend.verify_receipt_chain(
                        changed_receipts,
                        request_id=request_id, source_sha=source_sha,
                        policy_fd=os.open(policy_copy, os.O_RDONLY),
                        authority_fds=[os.open(path, os.O_RDONLY) for path in authority_paths],
                    )
            for header in ("plan_sha256", "receipt_contract_sha256", "policy_sha256"):
                values = [json.loads(path.read_text()) for path in receipts]
                previous_digest = None
                changed_receipts = []
                for ordinal, value in enumerate(values):
                    value[header] = "7" * 64
                    value["previous_receipt_sha256"] = previous_digest
                    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
                    changed = root / f"changed-{header}-{ordinal}.receipt"
                    changed.write_bytes(encoded); os.chmod(changed, 0o600)
                    changed_receipts.append(changed); previous_digest = hashlib.sha256(encoded).hexdigest()
                with self.subTest(header=header), self.assertRaises(frontend.ReleaseError):
                    frontend.verify_receipt_chain(
                        changed_receipts, request_id=request_id, source_sha=source_sha,
                        policy_fd=os.open(policy_copy, os.O_RDONLY),
                        authority_fds=[os.open(path, os.O_RDONLY) for path in authority_paths],
                    )

            # Rebuilding every related actor claim and every predecessor hash is
            # still rejected because the root authority files remain immutable.
            values = [json.loads(path.read_text()) for path in receipts]
            replacement_sha = "6" * 40
            replacement_hash = "6" * 64
            replacement_digest = "sha256:" + replacement_hash
            for value in values:
                evidence = value["evidence"]
                for key in ("tree_sha",):
                    if key in evidence: evidence[key] = replacement_sha
                for key in (
                    "tree_manifest_sha256", "variables_manifest_sha256", "oci_layout_sha256",
                    "source_maps_sha256", "build_log_sha256", "cache_metadata_sha256",
                    "provenance_sha256", "scan_evidence_sha256", "posthog_upload_sha256",
                    "digest_state_sha256", "state_key_sha256", "deploy_receipt_sha256",
                    "health_receipt_sha256",
                ):
                    if key in evidence: evidence[key] = replacement_hash
                for key in ("oci_manifest_digest", "provenance_subject_digest", "image_digest", "manifest_digest"):
                    if key in evidence: evidence[key] = replacement_digest
                value["phase_authority_sha256"] = replacement_hash
            substituted = []
            predecessor = None
            for ordinal, value in enumerate(values):
                value["previous_receipt_sha256"] = predecessor
                encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
                path = root / f"substituted-{ordinal}.receipt"
                path.write_bytes(encoded); os.chmod(path, 0o600)
                substituted.append(path); predecessor = hashlib.sha256(encoded).hexdigest()
            with self.assertRaises(frontend.ReleaseError):
                frontend.verify_receipt_chain(
                    substituted, request_id=request_id, source_sha=source_sha,
                    policy_fd=os.open(policy_copy, os.O_RDONLY),
                    authority_fds=[os.open(path, os.O_RDONLY) for path in authority_paths],
                )

    def test_frontend_root_observation_and_atomic_publish_fail_closed(self):
        request_id = "6" * 64
        source_sha = "5" * 40
        phase = "source"
        evidence = self._phase_evidence(phase); evidence["commit_sha"] = source_sha
        with mock.patch.object(frontend, "RECEIPT_OWNER_UID", os.geteuid()), mock.patch.object(
            frontend, "RECEIPT_OWNER_GID", os.getegid()
        ), mock.patch.dict(frontend.RECEIPT_ACTOR_UIDS, {name: os.geteuid() for name in frontend.RECEIPT_PHASES}, clear=True), mock.patch.object(
            frontend, "_finish_root_observation", side_effect=lambda records, request_id, phase: self._finished_observation(records, request_id, phase)
        ), tempfile.TemporaryDirectory() as td:
            root = Path(td)
            policy_copy = self._policy_copy(root)
            data = root / "data"
            data.write_bytes(frontend.canonical_phase_data(
                request_id, source_sha, phase, evidence,
            ))
            os.chmod(data, 0o600)
            observation_paths = self._write_observations(root, phase, request_id, source_sha)
            authority = self._write_authority(root, phase, request_id, source_sha, evidence)
            original_write = os.write
            with mock.patch.object(frontend.os, "write", side_effect=lambda fd, value: original_write(fd, value[:7])):
                output = root / "short-write.receipt"
                frontend.seal_phase_receipt_from_fds(
                    request_id=request_id, source_sha=source_sha, phase=phase,
                    data_fd=os.open(data, os.O_RDONLY), authority_fd=os.open(authority, os.O_RDONLY),
                    observation_fds=[os.open(path, os.O_RDONLY) for path in observation_paths],
                    policy_fd=os.open(policy_copy, os.O_RDONLY), previous_receipt_fd=None,
                    output=output,
                )
                self.assertEqual(json.loads(output.read_text())["phase"], phase)
            output = root / "failed-write.receipt"
            with mock.patch.object(frontend.os, "write", side_effect=OSError("write failed")), self.assertRaises(OSError):
                frontend.seal_phase_receipt_from_fds(
                    request_id=request_id, source_sha=source_sha, phase=phase,
                    data_fd=os.open(data, os.O_RDONLY), authority_fd=os.open(authority, os.O_RDONLY),
                    observation_fds=[os.open(path, os.O_RDONLY) for path in observation_paths],
                    policy_fd=os.open(policy_copy, os.O_RDONLY), previous_receipt_fd=None,
                    output=output,
                )
            self.assertFalse(output.exists())
            self.assertEqual(list(root.glob(".*.receipt.*.tmp")), [])

    def test_frontend_phase_data_and_receipt_mutations_fail_closed(self):
        request_id = "e" * 64
        source_sha = "b" * 40
        phase = "registry"
        evidence = self._phase_evidence(phase)
        evidence["source_sha"] = source_sha
        canonical = frontend.canonical_phase_data(request_id, source_sha, phase, evidence)
        parsed = frontend.parse_phase_data(canonical, request_id=request_id, source_sha=source_sha, phase=phase)
        self.assertEqual(parsed["actor_uid"], 22003)

        mutations = []
        base = json.loads(canonical)
        mutations.append({**base, "extra": True})
        mutations.append({**base, "request_id": "f" * 64})
        mutations.append({**base, "actor_uid": 22202})
        mutations.append({**base, "evidence": {**evidence, "repository": "other"}})
        mutations.append({**base, "evidence": {**evidence, "readback_verified": False}})
        for mutation in mutations:
            with self.subTest(mutation=mutation), self.assertRaises(frontend.ReleaseError):
                frontend.parse_phase_data(
                    json.dumps(mutation, separators=(",", ":")).encode(),
                    request_id=request_id, source_sha=source_sha, phase=phase,
                )
        with self.assertRaises(frontend.ReleaseError):
            frontend.parse_phase_data(b"x" * 16385, request_id=request_id, source_sha=source_sha, phase=phase)

        actor_supplied_observation = {**base, "root_observation": {"process_reaped": True}}
        with self.assertRaises(frontend.ReleaseError):
            frontend.parse_phase_data(
                json.dumps(actor_supplied_observation, sort_keys=True, separators=(",", ":")).encode(),
                request_id=request_id, source_sha=source_sha, phase=phase,
            )

        token_evidence = self._phase_evidence("token-destroy")
        for key in ("token_descriptor_closed", "token_buffer_zeroed"):
            with self.subTest(key=key), self.assertRaises(frontend.ReleaseError):
                frontend.canonical_phase_data(
                    request_id, source_sha, "token-destroy", {**token_evidence, key: False},
                )

    def test_frontend_receipt_commands_and_firewall_ownership_are_fixed(self):
        self.assertEqual(
            frontend.command_names(),
            {"scan", "digest", "observe-start", "seal-receipt", "verify-receipts"},
        )
        self.assertEqual(frontend.FRONTEND_FIREWALL_PHASES, {
            "node-base-read": {"uid": 22201, "targets": ("node-registry", "node-registry-auth")},
            "package-read": {"uid": 22201, "targets": ("package-read",)},
            "build-offline": {"uid": 22201, "targets": ()},
            "posthog-upload": {"uid": 22202, "targets": ("posthog-upload",)},
            "ghcr-write": {"uid": 22003, "targets": ("ghcr", "ghcr-storage")},
            "frontend-deploy": {"uid": 22203, "targets": ("frontend-deploy",)},
            "frontend-public-health": {"uid": 22203, "targets": ("frontend-public-health",)},
        })
        self.assertEqual(frontend.FRONTEND_FIREWALL_PHASES["build-offline"]["targets"], ())
        self.assertEqual(frontend.FRONTEND_FIREWALL_PHASES["ghcr-write"]["uid"], 22003)

    def test_frontend_final_policy_binding_is_acyclic_and_deploy_phases_are_predeclared(self):
        import inspect
        self.assertNotIn("EXPECTED_POLICY_SHA256", vars(frontend))
        self.assertRegex(frontend.RECEIPT_CONTRACT_SHA256, r"^[0-9a-f]{64}$")
        self.assertIn("authority_fd", inspect.signature(frontend.seal_phase_receipt_from_fds).parameters)
        self.assertIn("authority_fds", inspect.signature(frontend.verify_receipt_chain).parameters)
        self.assertEqual(frontend.RECEIPT_FIREWALL_PHASES["deploy-health"], (
            "frontend-deploy", "frontend-public-health",
        ))
        self.assertEqual(frontend.FRONTEND_FIREWALL_PHASES["frontend-deploy"], {
            "uid": 22203, "targets": ("frontend-deploy",),
        })
        self.assertEqual(frontend.FRONTEND_FIREWALL_PHASES["frontend-public-health"], {
            "uid": 22203, "targets": ("frontend-public-health",),
        })
        with tempfile.TemporaryDirectory() as td, mock.patch.object(
            frontend, "RECEIPT_OWNER_UID", os.geteuid()
        ), mock.patch.object(frontend, "RECEIPT_OWNER_GID", os.getegid()):
            policy_copy = self._policy_copy(Path(td))
            original = frontend._policy_sha256_from_fd(os.open(policy_copy, os.O_RDONLY))
            value = yaml.safe_load(policy_copy.read_text())
            action = next(item for item in value["actions"] if item["action_id"] == "ken-frontend-production-release")
            action["production_build"]["phase_transport_sha256"] = "7" * 64
            policy_copy.write_text(yaml.safe_dump(value, sort_keys=False))
            os.chmod(policy_copy, 0o644)
            changed = frontend._policy_sha256_from_fd(os.open(policy_copy, os.O_RDONLY))
            self.assertNotEqual(changed, original)

    def test_frontend_source_object_alias_and_unanchored_authority_fail_closed(self):
        request_id = "4" * 64
        source_sha = "5" * 40
        source = self._phase_evidence("source")
        source["commit_sha"] = source_sha
        source["tree_sha"] = frontend.SOURCE_BLOB_SHAS["workflow_blob_sha"]
        with self.assertRaises(frontend.ReleaseError):
            frontend.canonical_phase_data(request_id, source_sha, "source", source)
        self.assertTrue(callable(frontend.canonical_phase_authority))
        self.assertTrue(callable(broker.write_source_phase_authority))

    def test_frontend_chronology_requires_one_boot_and_strict_phase_order(self):
        records = {}
        for ordinal, phase in enumerate(frontend.RECEIPT_PHASES):
            records[phase] = {"root_observation": {
                "boot_id": "12345678-1234-1234-1234-123456789abc",
                "started_observed_monotonic_ns": 1000 + ordinal * 20,
                "completed_observed_monotonic_ns": 1010 + ordinal * 20,
            }}
        frontend.validate_receipt_chronology(records)
        reversed_records = json.loads(json.dumps(records))
        reversed_records["digest"]["root_observation"]["started_observed_monotonic_ns"] = 1
        with self.assertRaises(frontend.ReleaseError):
            frontend.validate_receipt_chronology(reversed_records)
        changed_boot = json.loads(json.dumps(records))
        changed_boot["cleanup"]["root_observation"]["boot_id"] = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        with self.assertRaises(frontend.ReleaseError):
            frontend.validate_receipt_chronology(changed_boot)
        build_records = [
            self._start_observation("build", "4" * 64, "5" * 40, name)
            for name in frontend.RECEIPT_FIREWALL_PHASES["build"]
        ]
        build_records[1]["observed_monotonic_ns"] = build_records[0]["observed_monotonic_ns"] - 1
        with self.assertRaisesRegex(frontend.ReleaseError, "runtime_observation_order_invalid"):
            frontend._finish_root_observation(
                build_records, request_id="4" * 64, phase="build",
            )

    def test_digest_state_is_no_replace_idempotent_and_short_write_safe(self):
        identity = {"repository_id": 1141163204, "run_id": 1, "run_attempt": 1,
                    "check_run_id": 2, "action_id": "ken-frontend-production-release",
                    "source_sha": "a" * 40}
        with tempfile.TemporaryDirectory() as td, mock.patch.object(
            frontend, "RECEIPT_OWNER_UID", os.geteuid()
        ), mock.patch.object(frontend, "RECEIPT_OWNER_GID", os.getegid()):
            root = Path(td); os.chmod(root, 0o700)
            state = root / "digest.json"
            original_write = os.write
            with mock.patch.object(frontend.os, "write", side_effect=lambda fd, value: original_write(fd, value[:7])):
                frontend.persist_digest_state(state, identity, "sha256:" + "b" * 64)
            expected = state.read_bytes()
            self.assertEqual(json.loads(expected)["image_digest"], "sha256:" + "b" * 64)
            frontend.persist_digest_state(state, identity, "sha256:" + "b" * 64)
            self.assertEqual(state.read_bytes(), expected)
            with self.assertRaises(frontend.ReleaseError):
                frontend.persist_digest_state(state, identity, "sha256:" + "c" * 64)
            self.assertEqual(state.read_bytes(), expected)
            failed = root / "failed.json"
            with mock.patch.object(frontend.os, "write", side_effect=OSError("forced")), self.assertRaises(OSError):
                frontend.persist_digest_state(failed, identity, "sha256:" + "d" * 64)
            self.assertFalse(failed.exists())
            self.assertEqual(list(root.glob(".digest.json.*.tmp")), [])
            self.assertEqual(list(root.glob(".failed.json.*.tmp")), [])

    def test_complete_oci_gate_unpacks_and_scans_all_authority_classes(self):
        secret=b"oci-canary"
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); oci=root/"oci"; (oci/"blobs/sha256").mkdir(parents=True)
            (oci/"oci-layout").write_text('{}'); (oci/"index.json").write_text('{}'); (oci/"blobs/sha256/config").write_text('history')
            maps=root/"maps"; maps.mkdir(); (maps/"app.map").write_text('map')
            log=root/"build.log"; log.write_text('log'); cache=root/"cache.meta"; cache.write_text('cache')
            def unpack(argv, **kwargs):
                bundle=Path(argv[-1]); (bundle/"rootfs").mkdir(parents=True); (bundle/"rootfs/layer").write_text('layer')
                return type("Result",(),{"returncode":0})()
            with mock.patch("subprocess.run", side_effect=unpack):
                self.assertRegex(frontend.complete_oci_leakage_gate(oci,"a"*40,secret,root/"scratch",maps,log,cache),r"^[0-9a-f]{64}$")
            # A canary in an uncompressed layer is fatal before any bearer can open.
            def unpack_canary(argv, **kwargs):
                bundle=Path(argv[-1]); (bundle/"rootfs").mkdir(parents=True); (bundle/"rootfs/layer").write_bytes(secret)
                return type("Result",(),{"returncode":0})()
            with mock.patch("subprocess.run", side_effect=unpack_canary):
                with self.assertRaises(frontend.ReleaseError): frontend.complete_oci_leakage_gate(oci,"a"*40,secret,root/"scratch2",maps,log,cache)

    def test_leakage_scan_rejects_raw_base64_and_hex(self):
        secret = b"Task6-Canary-Secret"
        for value in (secret, base64.b64encode(secret), secret.hex().encode()):
            with tempfile.TemporaryDirectory() as td:
                p = Path(td) / "layer"
                p.write_bytes(b"before" + value + b"after")
                with self.assertRaises(frontend.ReleaseError):
                    frontend.scan_paths([p], secret)

    def test_frontend_phase_order_token_gate_and_digest_binding(self):
        machine = frontend.ReleaseStateMachine(); bearer = frontend.EphemeralRegistryBearer(b"ghcr-canary")
        with self.assertRaises(frontend.ReleaseError): bearer.open_after_scan(machine)
        for phase in ("authorized", "source_authenticated", "dependencies_acquired", "secret_build_complete", "builder_reaped", "leakage_scan_passed", "source_maps_uploaded", "registry_pushed", "registry_read_back", "token_destroyed", "deployed", "health_passed", "cleaned"):
            machine.advance(phase, evidence_sha256="a"*64 if phase=="leakage_scan_passed" else None)
            if phase == "leakage_scan_passed": self.assertEqual(bearer.open_after_scan(machine),b"ghcr-canary")
            if phase == "registry_read_back": bearer.destroy()
        self.assertTrue(machine.complete)
        self.assertTrue(bearer.destroyed)
        with self.assertRaises(frontend.ReleaseError): bearer.open_after_scan(machine)
        with self.assertRaises(frontend.ReleaseError):
            frontend.ReleaseStateMachine().advance("registry_pushed")
        self.assertEqual(frontend.derived_tag("a" * 40), "sha-" + "a" * 40)
        with self.assertRaises(frontend.ReleaseError):
            frontend.validate_registry_request("DELETE", "ghcr.io", "/v2/ken-technology/ken-frontend/manifests/latest", "a" * 40)

    def test_build_plan_digest_state_cleanup_and_uid_boundaries(self):
        plan={"command":["pnpm","build"],"network":"none","secret_id":"NEXT_SERVER_ACTIONS_ENCRYPTION_KEY","secret_target":"/run/secrets/NEXT_SERVER_ACTIONS_ENCRYPTION_KEY","secret_mode":"0400","secret_required":True,"remote":False,"cache_export":False,"extra_secrets":[]}
        frontend.validate_build_plan(plan)
        for key,value in (("network","default"),("remote",True),("extra_secrets",["other"]),("command",["sh","-c","pnpm build"])):
            with self.subTest(key=key), self.assertRaises(frontend.ReleaseError): frontend.validate_build_plan({**plan,key:value})
        frontend.validate_identity_separation([21014,22003,22201,22202,22203])
        with self.assertRaises(frontend.ReleaseError): frontend.validate_identity_separation([21014,22003,22201,22201,22203])
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); request=root/"request"; request.mkdir(); (request/".ken-production-request").write_text("ok")
            state=root/"state/digest.json"; identity={"repository_id":1141163204,"run_id":1,"run_attempt":1,"check_run_id":2,"action_id":"ken-frontend-production-release","source_sha":"a"*40}
            with mock.patch.object(frontend, "RECEIPT_OWNER_UID", os.geteuid()), mock.patch.object(
                frontend, "RECEIPT_OWNER_GID", os.getegid()
            ):
                frontend.persist_digest_state(state,identity,"sha256:"+"b"*64)
            self.assertEqual(json.loads(state.read_text())["image_digest"],"sha256:"+"b"*64)
            frontend.guarded_cleanup(request,root); self.assertFalse(request.exists())

    def test_source_map_uploader_accepts_only_posthog_and_private_fds(self):
        uploader.validate_endpoint("https://us.posthog.com/api/projects/123/releases")
        with self.assertRaises(ValueError):
            uploader.validate_endpoint("https://evil.invalid/upload")
        with self.assertRaises(ValueError):
            uploader.validate_endpoint("http://us.posthog.com/upload")

if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0]], verbosity=2)
PY

echo '== units, installer and executable surfaces =='
run_check 'all Python and shell entry points parse' bash -c '
  set -e
  python3 - "$1" <<"PY"
import ast, sys
from pathlib import Path
for path in Path(sys.argv[1]).glob("*"):
    if path.is_file(): ast.parse(path.read_text(), filename=str(path))
PY
  bash -n "$2"
' _ "${BIN}" "${GA_ROOT}/scripts/install-1password-credentials.sh"

run_check 'fixed executor sources are action-specific and blocked ones are silent' \
  python3 - "${BIN}" "${INV}/broker-runtime.lock.yaml" <<'PY'
import hashlib, subprocess, sys, yaml
from pathlib import Path
root=Path(sys.argv[1]); lock=yaml.safe_load(Path(sys.argv[2]).read_text()); installed={x["path"]:x for x in lock["installed_files"]}
mapping={
 "ken-vexa-mcp-auth-production-deploy":"491b1505adb8a69056dbdb288392ddd73065be94daff08cb5113bc31626dc853",
 "ken-website-production-deploy":"3d87a23d40bdd6a217b46e0b7bebb5ca47b48bb2b686f84c55776cbce005a34a",
 "ken-website-beehiiv-production-sync":"1beb7a1564b661cfb48f551cfd84b95fca3f99d75950e196d6c9fe30399f5640",
 "ken-frontend-production-release-build":"ad8f98761590eb31670866c60dfe78484ff76eb0fe834b4966f99aea19c2da1c",
}
for name,digest in mapping.items():
 data=(root/name).read_bytes(); assert hashlib.sha256(data).hexdigest()==digest; assert installed["/usr/local/libexec/ken-actions/"+name]["sha256"]==digest
for name in ("ken-website-beehiiv-production-sync","ken-frontend-production-release-build"):
 result=subprocess.run([str(root/name)],capture_output=True,timeout=5); assert result.returncode==78 and result.stdout==b"" and result.stderr==b""
assert len(set(mapping.values()))==4
PY

run_check 'installer is interactive-only, value-blind, and systemd-creds based' \
  python3 - "${GA_ROOT}/scripts/install-1password-credentials.sh" <<'PY'
import re
import sys
from pathlib import Path
text = Path(sys.argv[1]).read_text()
required = ["/dev/tty", "stty -echo", "systemd-creds encrypt", "--interactive-all", "root@167.235.8.250", "/usr/local/bin/op", "ken-op-ci.token", "ken-op-nonproduction.token", "ken-op-production.token"]
assert all(x in text for x in required)
assert not re.search(r"--token|OP_SERVICE_ACCOUNT_TOKEN=\$|echo .*token|set -x|source ", text, re.I)
PY

run_check 'supported systemd units encode credentials, sockets, gates, limits, and hardening' \
  python3 - "${SYSTEMD}" <<'PY'
import sys
from pathlib import Path
root = Path(sys.argv[1])
broker = (root / "ken-op-broker@.service").read_text()
sock = (root / "ken-op-broker@.socket").read_text()
ci_override = (root / "ken-op-broker@ci.service.d/override.conf").read_text()
for token in ("LoadCredentialEncrypted=op-service-account-token:", "RuntimeDirectory=ken-op-broker/%i", "StateDirectory=ken-op-broker/%i", "Slice=ken-actions-deploy-brokers.slice", "NoNewPrivileges=yes", "ProtectSystem=strict", "CapabilityBoundingSet=CAP_CHOWN CAP_DAC_OVERRIDE CAP_FOWNER CAP_KILL CAP_SETGID CAP_SETUID"):
    assert token in broker, token
assert "ProtectProc=default" in broker and "Slice=system.slice" in ci_override
assert "ListenSequentialPacket=/run/ken-op-broker/%i.sock" in sock
assert "SocketMode=0660" in sock and "Backlog=16" in sock and "Accept=no" in sock
assert "Requires=" in broker and "ken-actions-guest-firewall.service" in broker and "ken-actions-guest-runtime-verify.service" in broker
assert "After=" in broker and "ken-actions-guest-firewall.service" in broker and "ken-actions-guest-runtime-verify.service" in broker
for unsupported in (
    "ken-op-executor@.service",
    "ken-frontend-production-builder@.service",
    "ken-frontend-source-map-uploader@.service",
    "ken-frontend-deploy-executor@.service",
):
    assert not (root / unsupported).exists()
PY

run_check 'claimed runtime has no invented plural transaction slice' \
  bash -c '! rg -n "ken-actions-deploy-transactions\\.slice" "$1" "$2" "$3" "$4"' _ \
    "${INV}/broker-runtime.lock.yaml" "${INV}/op-broker-policy.yaml" "${BIN}/ken-op-broker" "${SYSTEMD}"

echo '== secret and placeholder scans =='
run_check 'Task 6 owned files contain no credential-shaped values or unresolved prose' \
  python3 - "${GA_ROOT}" <<'PY'
import re
import sys
from pathlib import Path
root = Path(sys.argv[1])
paths = [root / "inventory/broker-runtime.lock.yaml", root / "inventory/op-broker-policy.yaml", root / "scripts/install-1password-credentials.sh"]
paths += list((root / "bin").glob("ken-*"))
paths += list((root / "systemd").glob("ken-op-*"))
paths += list((root / "systemd").glob("ken-frontend-*"))
paths = [path for path in paths if path.is_file()]
secret_patterns = [r"-----BEGIN [A-Z0-9 ]+PRIVATE KEY-----", r"\bgh[pousr]_[A-Za-z0-9]{20,}\b", r"\bgithub_pat_[A-Za-z0-9_]{20,}\b", r"\bops_[A-Za-z0-9]{20,}\b"]
placeholder = re.compile(r"\b(TBD|TODO|FIXME|task7-exact|placeholder|fill[-_ ]?me)\b", re.I)
for path in paths:
    text = path.read_text(errors="replace")
    assert not placeholder.search(text), path
    for pattern in secret_patterns:
        assert not re.search(pattern, text), path
PY

echo
if (( FAILED == 0 )); then
  printf 'broker: %s assertions passed\n' "${RAN}"
  exit 0
fi
printf 'broker: %s failed / %s assertions\n' "${FAILED}" "${RAN}"
exit 1
