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
    "${SYSTEMD}/ken-op-broker@ci.service.d/override.conf" \
    "${SYSTEMD}/ken-op-executor@.service" \
    "${SYSTEMD}/ken-frontend-production-builder@.service" \
    "${SYSTEMD}/ken-frontend-source-map-uploader@.service" \
    "${SYSTEMD}/ken-frontend-deploy-executor@.service"; do
    if [[ ! -f "${path}" || -L "${path}" ]]; then
      printf 'missing or symlinked: %s\n' "${path#"${ROOT}/"}" >&2
      missing=1
    fi
  done
  return "${missing}"
}

echo '== Task 6 owned files =='
run_check 'all broker runtime files and phase units exist' require_files
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
    "secrets.yaml": "810fae4897b1cba892e715927df2c0d34d1d231515be1ad89c59604e713e4e25",
    "secret-handoff.yaml": "9b6179a207182a2b9e8d3f174bb2633869c29e155ad8664064fd859547bf3f96",
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
assert re.fullmatch(r"[0-9a-f]{64}", lock["plan_sha256"])
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
assert contract["remote_build_inputs"] == ["node-build-base"] and len(contract["principals"]) == 9
assert contract["subordinate_ids"] == [{"guest":"ken-deploy","name":"ken-fe-builder","uid":22201,"subuid_start":300000,"subuid_count":65536,"subgid_start":300000,"subgid_count":65536}]
installed = {item["path"]: item for item in lock["installed_files"]}
for item in installed.values():
    if item["source"].startswith("repo:") or item["source"].startswith("repo-hard-copy:"):
        relative = item["source"].split(":", 1)[1]
        assert __import__("hashlib").sha256((root.parent / relative).read_bytes()).hexdigest() == item["sha256"], item["path"]
assert policy["schema_version"] == 1
assert policy["policy_version"]
assert policy["issuer"] == "https://token.actions.githubusercontent.com"
assert policy["credentials"]["command"] == ["/usr/local/bin/op", "inject"]
actions = {x["action_id"]: x for x in policy["actions"]}
assert set(actions) == {
    "ken-frontend-production-release",
    "ken-vexa-mcp-auth-production-deploy",
    "ken-website-beehiiv-production-sync",
    "ken-website-production-deploy",
}
assert actions["ken-frontend-production-release"]["input_mode"] == "production_build"
assert all(x["result_contract"] == "stable-code-only" for x in actions.values())
assert all(x["enabled"] is False and x["deferred_bindings"] for x in actions.values())
assert all("executor.systemd_transaction_transport_sha256" in x["deferred_bindings"] and x["executor"]["systemd_transaction_transport_sha256"] is None for x in actions.values())
assert actions["ken-frontend-production-release"]["blocked_reason_code"] == "frontend_task7_pins_phase_transport_deploy_required"
assert actions["ken-vexa-mcp-auth-production-deploy"]["blocked_reason_code"] == "vexa_host_key_runtime_identity_and_transaction_transport_required"
assert actions["ken-website-beehiiv-production-sync"]["blocked_reason_code"] == "beehiiv_sync_generation_and_transaction_transport_required"
assert actions["ken-website-production-deploy"]["blocked_reason_code"] == "website_host_key_runtime_identity_and_transaction_transport_required"
for action in actions.values():
    wrapper = action["executor"]["wrapper"]
    assert installed[wrapper]["sha256"] == action["executor"]["wrapper_sha256"]
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
        for source in ("a: &x 1\nb: *x\n", "a: !!str value\n"):
            with self.subTest(source=source), self.assertRaises(broker.Reject): broker._strict_yaml(source)

    def test_historical_lock_is_never_accepted_as_guest_ready(self):
        lock_path = policy_path.parent / "broker-runtime.lock.yaml"
        broker.verify_runtime_lock(lock_path)
        with self.assertRaises(broker.Reject): broker.verify_runtime_lock(lock_path, require_ready=True)
        original = yaml.safe_load(lock_path.read_text())
        mutations = []
        changed = copy.deepcopy(original); changed["components"][0]["payload_sha256"] = "0" * 64; mutations.append(changed)
        changed = copy.deepcopy(original); changed["components"][-1].pop("delivery_class"); mutations.append(changed)
        changed = copy.deepcopy(original); changed["runtime_contract"]["subordinate_ids"][0]["subuid_start"] = 22000; mutations.append(changed)
        with tempfile.TemporaryDirectory() as directory:
            for index, value in enumerate(mutations):
                target = Path(directory) / f"mutated-{index}.yaml"; target.write_text(yaml.safe_dump(value, sort_keys=False))
                with self.subTest(index=index), self.assertRaises(broker.Reject): broker.verify_runtime_lock(target)

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
            one = gate.acquire("ordinary", "one", block=False)
            two = gate.acquire("ordinary", "two", block=False)
            with self.assertRaises(broker.Reject):
                gate.acquire("ordinary", "three", block=False)
            one.release(); two.release()
            exclusive = gate.acquire("production_build", "prod", block=False)
            with self.assertRaises(broker.Reject):
                gate.acquire("ordinary", "late", block=False)
            exclusive.release()
            gate.recover()
            gate.acquire("ordinary", "after", block=False).release()

    def test_safe_response_and_log_redact_all_bearers_and_outputs(self):
        response = broker.safe_response("req-123", "rejected", "jwt_invalid")
        self.assertEqual(set(response), {"version", "request_id", "status", "reason_code"})
        canaries = ["jwt.canary.signature", "ghs_CANARY", "ops_CANARY", "rendered-CANARY", "stdout-CANARY"]
        text = broker.safe_log({"request_id": "req-123", "status": "rejected", "reason_code": "jwt_invalid", "oidc_jwt": canaries[0], "stdout": canaries[-1]})
        for value in canaries:
            self.assertNotIn(value, text)

    def _bound_policy(self, directory, selected_action):
        raw = yaml.safe_load(policy_path.read_text())
        for action in raw["actions"]:
            if action["action_id"] != selected_action:
                continue
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
                if "/actions/runs/" in path: return {"id":self.claims["run_id"],"run_attempt":self.claims["run_attempt"],"head_sha":self.claims["sha"],"event":self.claims["event_name"],"status":"in_progress","head_branch":"main","path":".github/workflows/beehiiv-sync.yml","repository":{"id":repo["id"],"full_name":f"{repo['owner']}/{repo['name']}"},"head_repository":{"id":repo["id"],"full_name":f"{repo['owner']}/{repo['name']}"}}
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
            policy=self._bound_policy(td,"ken-website-beehiiv-production-sync"); action=policy.actions["ken-website-beehiiv-production-sync"]
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

run_check 'systemd units encode credentials, sockets, slices, UIDs, limits, and hardening' \
  python3 - "${SYSTEMD}" <<'PY'
import sys
from pathlib import Path
root = Path(sys.argv[1])
broker = (root / "ken-op-broker@.service").read_text()
sock = (root / "ken-op-broker@.socket").read_text()
builder = (root / "ken-frontend-production-builder@.service").read_text()
uploader = (root / "ken-frontend-source-map-uploader@.service").read_text()
executor = (root / "ken-frontend-deploy-executor@.service").read_text()
ordinary = (root / "ken-op-executor@.service").read_text()
ci_override = (root / "ken-op-broker@ci.service.d/override.conf").read_text()
for token in ("LoadCredentialEncrypted=op-service-account-token:", "RuntimeDirectory=ken-op-broker/%i", "StateDirectory=ken-op-broker/%i", "Slice=ken-actions-deploy-brokers.slice", "NoNewPrivileges=yes", "ProtectSystem=strict", "CapabilityBoundingSet=CAP_CHOWN CAP_DAC_OVERRIDE CAP_FOWNER CAP_KILL CAP_SETGID CAP_SETUID"):
    assert token in broker, token
assert "ProtectProc=default" in broker and "Slice=system.slice" in ci_override
assert "ListenSequentialPacket=/run/ken-op-broker/%i.sock" in sock
assert "SocketMode=0660" in sock and "Backlog=16" in sock and "Accept=no" in sock
assert "Slice=ken-actions-deploy-builder.slice" in builder and "MemoryMax=8G" in builder and "CPUQuota=300%" in builder and "TasksMax=1024" in builder
assert "Slice=ken-actions-deploy-uploader.slice" in uploader and "MemoryMax=512M" in uploader and "CPUQuota=50%" in uploader
assert "Slice=ken-actions-deploy-executor.slice" in executor and "MemoryMax=1G" in executor and "CPUQuota=100%" in executor
assert "Slice=ken-actions-deploy-transactions.slice" in ordinary
assert "execute-transaction --transaction-id %i" in ordinary and "ken-action-%i" not in ordinary
for text in (broker, builder, uploader, executor, ordinary):
    assert "Requires=" in text and "ken-actions-guest-firewall.service" in text and "ken-actions-guest-runtime-verify.service" in text
    assert "After=" in text and "ken-actions-guest-firewall.service" in text and "ken-actions-guest-runtime-verify.service" in text
for text in (builder, uploader, executor, ordinary):
    assert "NoNewPrivileges=yes" in text
    assert "Environment=OP_SERVICE_ACCOUNT_TOKEN" not in text
    assert "LoadCredential" not in text
PY

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
