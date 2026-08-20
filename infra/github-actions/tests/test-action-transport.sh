#!/usr/bin/env bash
set -u
export PYTHONDONTWRITEBYTECODE=1

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd -P)"
GA_ROOT="${ROOT}/infra/github-actions"
TRANSPORT="${GA_ROOT}/bin/ken-actions-deploy-transaction"
MANIFEST="${GA_ROOT}/inventory/action-transport.lock.yaml"
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

require_owned_files() {
  local path missing=0
  for path in \
    "${TRANSPORT}" \
    "${MANIFEST}" \
    "${SYSTEMD}/ken-actions-deploy-transaction-1.service" \
    "${SYSTEMD}/ken-actions-deploy-transaction-2.service" \
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

echo '== Task 7 owned files =='
run_check 'all exact transport files exist as regular files' require_owned_files

echo '== immutable manifest and systemd boundaries =='
run_check 'manifest strictly binds reviewed authority and transport bytes' \
  python3 - "${GA_ROOT}" <<'PY'
from __future__ import annotations

import hashlib
import re
import sys
from pathlib import Path

import yaml


class StrictLoader(yaml.SafeLoader):
    pass


def construct_mapping(loader, node, deep=False):
    result = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in result:
            raise AssertionError(f"duplicate YAML key: {key}")
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


StrictLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, construct_mapping)
root = Path(sys.argv[1])
manifest_path = root / "inventory/action-transport.lock.yaml"
manifest = yaml.load(manifest_path.read_text(), Loader=StrictLoader)

assert type(manifest["schema_version"]) is int and manifest["schema_version"] == 1
assert manifest["transport_version"] == "2026-08-20.2"
assert manifest["status"] == "reviewed-transport-awaiting-task6-final-bindings"
assert manifest["enabled"] is False
assert manifest["installation_authorized"] is False
assert manifest["live_execution_authorized"] is False
assert manifest["authorities"] == {
    "plan_sha256": "75715a5a3973f3ed9813e66c809d76ec1281d537afae0c08d66b02684583a658",
    "matrix_sha256": "f471a1fe1633e8be3ea40b78bc07762bc14512e011a813ac628754d10e35f0b6",
}
assert manifest["task6_core"] == {
    "integrated_commit_sha": "63c9e0b17ae8e894b85152de6f1ea26b33481930",
    "integrated_tree_sha": "df327c0de3ab5444011c41028f9dc9bc0e4248dd",
    "reviewed_source_commit_sha": "1eb21d952c202d301a0252125f9a7b8fdc010ef6",
    "reviewed_source_tree_sha": "1673e50129214f1e00c9926803be30b270148dae",
    "broker_sha256": "8d1c7859a1d4108e507d2f9a32acee8a1e26a10c212186fc751ab39e1c47d22e",
    "policy_sha256": "b1e15a9b74e3330c32eb63143d65f51fd1ec595c8eeb3a36cfb46abcc27cc89b",
    "runtime_lock_sha256": "2aae227ff90d932c0d80ef71a23993e2819e911b83c7a9ed492647bae67d465f",
}
assert manifest["task6_receipts"] == {
    "reviewed_source_commit_sha": "45c55b6fc0cd2752d2869c4517475c86004a1e91",
    "reviewed_source_tree_sha": "e8da0e42c2593ff4bb284d7bc52320cefb1ba517",
    "helper_blob_sha": "ad56d39488c749a29486d2a842d713bbd838fa7d",
    "helper_path": "bin/ken-frontend-production-release",
    "helper_sha256": "8a611e251c69ee0af1f66043d508695461decf271cc32b76dbe224833a17f183",
    "contract_sha256": "d5ebeb58afb5f5e24bc1b6a6e74934ee3a22ae337b103a085d2df9a5776db63c",
    "phases": ["source", "build", "scan", "upload", "registry", "token-destroy", "digest", "deploy-health", "cleanup"],
    "actor_uids": {"source":22003,"build":22201,"scan":0,"upload":22202,"registry":22003,"token-destroy":22003,"digest":0,"deploy-health":22203,"cleanup":0},
    "firewall_phases": {
        "source": [], "build": ["node-base-read", "package-read", "build-offline"],
        "scan": [], "upload": ["posthog-upload"], "registry": ["ghcr-write"],
        "token-destroy": [], "digest": [],
        "deploy-health": ["frontend-deploy", "frontend-public-health"], "cleanup": [],
    },
    "task4_deploy_target_authority": "deferred-until-single-stop-readback",
}
assert manifest["task6_final"] == {
    "status": "unavailable",
    "commit_sha": None,
    "policy_sha256": None,
    "runtime_lock_sha256": None,
}
assert manifest["leases"] == {
    "ordinary_slots": [
        {"slot": 1, "unit": "ken-actions-deploy-transaction-1.service", "slice": "ken-actions-deploy-transaction-1.slice"},
        {"slot": 2, "unit": "ken-actions-deploy-transaction-2.service", "slice": "ken-actions-deploy-transaction-2.slice"},
    ],
    "writer_preference": True,
    "production_build_holds_both": True,
    "recovery": "stop-reap-cgroup-empty-cleanup-then-release",
}

sha = re.compile(r"^[0-9a-f]{64}$")
artifacts = manifest["artifacts"]
expected_paths = {
    "coordinator": "bin/ken-actions-deploy-transaction",
    "ordinary_slot_1": "systemd/ken-actions-deploy-transaction-1.service",
    "ordinary_slot_2": "systemd/ken-actions-deploy-transaction-2.service",
    "frontend_builder": "systemd/ken-frontend-production-builder@.service",
    "frontend_uploader": "systemd/ken-frontend-source-map-uploader@.service",
    "frontend_deploy": "systemd/ken-frontend-deploy-executor@.service",
}
assert set(artifacts) == set(expected_paths)
for name, relative in expected_paths.items():
    row = artifacts[name]
    assert set(row) == {"path", "sha256"}
    assert row["path"] == relative and sha.fullmatch(row["sha256"])
    assert hashlib.sha256((root / relative).read_bytes()).hexdigest() == row["sha256"]

bindings = manifest["task6_bindings"]
assert set(bindings) == {
    "ordinary_systemd_transaction_transport_sha256",
    "frontend_operation_binding_sha256",
    "frontend_phase_transport_sha256",
    "frontend_deploy_contract_sha256",
    "trusted_generation_dependency_acquisition_sha256",
    "trusted_generation_generated_paths_manifest_sha256",
    "trusted_generation_commit_input_contract_sha256",
    "trusted_generation_cgroup_contract_sha256",
    "trusted_generation_phase_transport_sha256",
}
assert all(type(value) is str and sha.fullmatch(value) for value in bindings.values())

bad = manifest_path.read_text() + "\nschema_version: 1\n"
try:
    yaml.load(bad, Loader=StrictLoader)
except AssertionError:
    pass
else:
    raise AssertionError("duplicate manifest keys were accepted")
PY

run_check 'service units bind fixed identities slices and fail-closed gates' \
  python3 - "${SYSTEMD}" <<'PY'
from pathlib import Path
import sys

root = Path(sys.argv[1])


def values(path):
    out = {}
    sections = []
    current = None
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            current = line[1:-1]
            sections.append(current)
            continue
        key, value = line.split("=", 1)
        out.setdefault((current, key), []).append(value)
    return sections, out


expected = {
    "ken-actions-deploy-transaction-1.service": {
        "User": "root",
        "Slice": "ken-actions-deploy-transaction-1.slice",
        "ExecStart": "/usr/local/libexec/ken-actions/ken-actions-deploy-transaction run-ordinary-slot --slot 1",
    },
    "ken-actions-deploy-transaction-2.service": {
        "User": "root",
        "Slice": "ken-actions-deploy-transaction-2.slice",
        "ExecStart": "/usr/local/libexec/ken-actions/ken-actions-deploy-transaction run-ordinary-slot --slot 2",
    },
    "ken-frontend-production-builder@.service": {
        "User": "ken-fe-builder",
        "Slice": "ken-actions-deploy-builder.slice",
        "ExecStart": "/usr/local/libexec/ken-actions/ken-actions-deploy-transaction run-frontend-phase --phase builder --request-id %i",
    },
    "ken-frontend-source-map-uploader@.service": {
        "User": "ken-fe-uploader",
        "Slice": "ken-actions-deploy-uploader.slice",
        "ExecStart": "/usr/local/libexec/ken-actions/ken-actions-deploy-transaction run-frontend-phase --phase uploader --request-id %i",
    },
    "ken-frontend-deploy-executor@.service": {
        "User": "ken-fe-deploy",
        "Slice": "ken-actions-deploy-executor.slice",
        "ExecStart": "/usr/local/libexec/ken-actions/ken-actions-deploy-transaction run-frontend-phase --phase deploy --request-id %i",
    },
}
gates = {"ken-actions-guest-firewall.service", "ken-actions-guest-runtime-verify.service"}
for filename, wanted in expected.items():
    path = root / filename
    sections, unit = values(path)
    assert "Install" not in sections, f"{filename}: transport must not auto-enable"
    assert not any(key == "ConditionPathExists" for (_, key) in unit), f"{filename}: fail-open condition"
    requires = set(" ".join(unit.get(("Unit", "Requires"), [])).split())
    after = set(" ".join(unit.get(("Unit", "After"), [])).split())
    assert gates <= requires and gates <= after
    assert unit[("Service", "Type")] == ["oneshot"]
    for key, value in wanted.items():
        assert unit[("Service", key)] == [value], (filename, key)
    for key, value in {
        "UMask": "0077",
        "PrivateTmp": "yes",
        "PrivateDevices": "yes",
        "ProtectSystem": "strict",
        "ProtectHome": "yes",
        "ProtectControlGroups": "yes",
        "ProtectKernelTunables": "yes",
        "ProtectKernelModules": "yes",
        "ProtectKernelLogs": "yes",
        "LockPersonality": "yes",
        "RestrictSUIDSGID": "yes",
        "MemorySwapMax": "0",
    }.items():
        assert unit[("Service", key)] == [value], (filename, key)

assert values(root / "ken-frontend-production-builder@.service")[1][("Service", "MemoryMax")] == ["8G"]
assert values(root / "ken-frontend-production-builder@.service")[1][("Service", "CPUQuota")] == ["300%"]
assert values(root / "ken-frontend-source-map-uploader@.service")[1][("Service", "MemoryMax")] == ["512M"]
assert values(root / "ken-frontend-deploy-executor@.service")[1][("Service", "MemoryMax")] == ["1G"]
for filename, phase in (
    ("ken-frontend-production-builder@.service", "builder"),
    ("ken-frontend-source-map-uploader@.service", "uploader"),
    ("ken-frontend-deploy-executor@.service", "deploy"),
):
    unit = values(root / filename)[1]
    assert ("Service", "RuntimeDirectory") not in unit, f"{filename}: phase directory must remain root-owned"
    phase_root = f"/run/ken-actions-deploy-phases/%i-{phase}"
    assert phase_root in unit[("Service", "ReadOnlyPaths")][0]
    assert unit[("Service", "ReadWritePaths")] == [phase_root + "/output"]
PY

echo '== coordinator behavior and adversarial contracts =='
run_check 'real coordinator enforces leases descriptors phases cgroups and recovery' \
  python3 - "${TRANSPORT}" <<'PY'
from __future__ import annotations

import contextlib
import copy
import hashlib
import importlib.machinery
import io
import json
import os
import tempfile
import unittest
from unittest import mock
from pathlib import Path

path = __import__("sys").argv[1]
transport = importlib.machinery.SourceFileLoader("ken_action_transport", path).load_module()


class TransportTests(unittest.TestCase):
    def test_request_schema_rejects_client_authority_and_numeric_confusion(self):
        valid = {
            "version": 1,
            "request_id": "a" * 64,
            "action_id": "ken-vexa-mcp-auth-production-deploy",
            "policy_sha256": "b" * 64,
            "source_sha": "c" * 40,
            "descriptors": ["artifact", "rendered"],
        }
        request = transport.TransportRequest.parse(json.dumps(valid).encode())
        self.assertEqual(request.request_id, "a" * 64)
        for mutation in (
            {**valid, "version": True},
            {**valid, "version": 1.0},
            {**valid, "version": "1"},
            {**valid, "command": "/bin/sh"},
            {**valid, "target": "example.com"},
            {**valid, "uid": 0},
            {**valid, "slice": "system.slice"},
            {**valid, "path": "/tmp/x"},
        ):
            with self.assertRaises(transport.TransportReject):
                transport.TransportRequest.parse(json.dumps(mutation).encode())
        with self.assertRaises(transport.TransportReject):
            transport.TransportRequest.parse((json.dumps(valid)[:-1] + ',"version":1}').encode())

    def test_descriptor_contracts_are_exact_for_all_ordinary_authorities(self):
        self.assertEqual(transport.descriptor_contract("artifact"), ("artifact", "rendered"))
        self.assertEqual(transport.descriptor_contract("source_commit"), ("source", "rendered"))
        self.assertEqual(transport.descriptor_contract("registry"), ("registry-state", "rendered"))
        for mode, descriptors in (
            ("artifact", ["source", "rendered"]),
            ("source_commit", ["source", "rendered", "artifact"]),
            ("registry", ["registry-state", "rendered", "digest"]),
            ("production_build", []),
            ("trusted_generation", []),
        ):
            with self.assertRaises(transport.TransportReject):
                transport.validate_descriptor_contract(mode, descriptors)

    def test_two_ordinary_slots_writer_preference_and_exclusive_release(self):
        with tempfile.TemporaryDirectory() as directory:
            scheduler = transport.LeaseScheduler(Path(directory))
            one = scheduler.acquire_ordinary("1" * 64)
            two = scheduler.acquire_ordinary("2" * 64)
            self.assertEqual((one.slots, two.slots), ((1,), (2,)))
            with self.assertRaises(transport.LeaseUnavailable):
                scheduler.acquire_ordinary("3" * 64)
            scheduler.announce_writer("f" * 64)
            with self.assertRaises(transport.LeaseUnavailable):
                scheduler.acquire_ordinary("4" * 64)
            with self.assertRaises(transport.LeaseUnavailable):
                scheduler.acquire_exclusive("f" * 64)
            scheduler.release(one, cleanup_verified=True)
            scheduler.release(two, cleanup_verified=True)
            exclusive = scheduler.acquire_exclusive("f" * 64)
            self.assertEqual(exclusive.slots, (1, 2))
            with self.assertRaises(transport.LeaseUnavailable):
                scheduler.acquire_ordinary("5" * 64)
            with self.assertRaises(transport.TransportReject):
                scheduler.release(exclusive, cleanup_verified=False)
            scheduler.release(exclusive, cleanup_verified=True)
            self.assertEqual(scheduler.acquire_ordinary("6" * 64).slots, (1,))

    def test_exclusive_writer_waits_then_acquires_or_cancels_marker(self):
        with tempfile.TemporaryDirectory() as directory:
            scheduler = transport.LeaseScheduler(Path(directory))
            occupied = scheduler.acquire_ordinary("1" * 64)
            waits = []
            def release_on_first_wait(seconds):
                waits.append(seconds)
                scheduler.release(occupied, cleanup_verified=True)
            exclusive = scheduler.wait_for_exclusive("f" * 64, timeout=1, wait=release_on_first_wait)
            self.assertEqual(exclusive.slots, (1, 2))
            self.assertEqual(len(waits), 1)
            scheduler.release(exclusive, cleanup_verified=True)

            occupied = scheduler.acquire_ordinary("2" * 64)
            with self.assertRaises(transport.LeaseUnavailable):
                scheduler.wait_for_exclusive("e" * 64, timeout=0, wait=lambda _: None)
            self.assertFalse(scheduler.writer_path.exists())
            scheduler.release(occupied, cleanup_verified=True)

    def test_later_ordinary_waits_behind_writer_and_queue_is_fifo_and_cancellable(self):
        with tempfile.TemporaryDirectory() as directory:
            scheduler = transport.LeaseScheduler(Path(directory))
            occupied = scheduler.acquire_ordinary("1" * 64)
            scheduler.announce_writer("f" * 64)
            events = []
            def finish_writer(_):
                events.append("wait")
                scheduler.release(occupied, cleanup_verified=True)
                exclusive = scheduler.acquire_exclusive("f" * 64)
                scheduler.release(exclusive, cleanup_verified=True)
            ordinary = scheduler.wait_for_ordinary("2" * 64, timeout=1, wait=finish_writer)
            self.assertEqual(ordinary.slots, (1,))
            self.assertEqual(events, ["wait"])
            scheduler.release(ordinary, cleanup_verified=True)

            first = scheduler.enqueue_ordinary("3" * 64)
            second = scheduler.enqueue_ordinary("4" * 64)
            with self.assertRaises(transport.LeaseUnavailable):
                scheduler.acquire_ordinary("4" * 64, from_queue=True)
            head = scheduler.acquire_ordinary("3" * 64, from_queue=True)
            self.assertLess(first, second)
            scheduler.release(head, cleanup_verified=True)
            scheduler.cancel_ordinary("4" * 64)
            self.assertEqual(scheduler.ordinary_waiters(), ())

            with self.assertRaises(transport.LeaseUnavailable):
                scheduler.wait_for_ordinary("5" * 64, timeout=0, wait=lambda _: None, cancelled=lambda: True)
            self.assertEqual(scheduler.ordinary_waiters(), ())

    def test_recovery_removes_only_abandoned_ordinary_waiters_after_request_cleanup(self):
        class Runtime:
            def __init__(self, cleanup):
                self.cleanup = cleanup; self.calls = []
            def stop_and_reap(self, lease):
                raise AssertionError("waiters do not own a running unit")
            def cleanup_request(self, lease):
                self.calls.append((lease.request_id, lease.kind)); return self.cleanup

        with tempfile.TemporaryDirectory() as directory:
            scheduler = transport.LeaseScheduler(Path(directory))
            request_id = "7" * 64
            scheduler.enqueue_ordinary(request_id)
            with mock.patch.object(transport, "_writer_alive", return_value=False):
                failed = Runtime(False)
                with self.assertRaises(transport.TransportReject):
                    scheduler.recover(failed)
                self.assertEqual(scheduler.ordinary_waiters(), (request_id,))

                recovered = Runtime(True)
                scheduler.recover(recovered)
            self.assertEqual(recovered.calls, [(request_id, "ordinary")])
            self.assertEqual(scheduler.ordinary_waiters(), ())

            scheduler.enqueue_ordinary("8" * 64)
            preserved = Runtime(True)
            with mock.patch.object(transport, "_writer_alive", return_value=True):
                scheduler.recover(preserved)
            self.assertEqual(scheduler.ordinary_waiters(), ("8" * 64,))
            self.assertEqual(preserved.calls, [])

    def test_recovery_stops_reaps_and_cleans_before_releasing(self):
        class Runtime:
            def __init__(self, reap=True, cleanup=True):
                self.reap = reap; self.cleanup = cleanup; self.calls = []
            def stop_and_reap(self, lease):
                self.calls.append(("reap", lease.request_id)); return self.reap
            def cleanup_request(self, lease):
                self.calls.append(("cleanup", lease.request_id)); return self.cleanup

        with tempfile.TemporaryDirectory() as directory:
            scheduler = transport.LeaseScheduler(Path(directory))
            lease = scheduler.acquire_ordinary("1" * 64)
            runtime = Runtime(reap=False)
            with self.assertRaises(transport.TransportReject):
                scheduler.recover(runtime)
            self.assertTrue(scheduler.active_leases())
            runtime = Runtime()
            scheduler.recover(runtime)
            self.assertEqual(runtime.calls, [("reap", lease.request_id), ("cleanup", lease.request_id)])
            self.assertEqual(scheduler.active_leases(), ())

    def test_normal_completion_reaps_and_cleans_before_releasing(self):
        class Runtime:
            def __init__(self, reap=True, cleanup=True):
                self.reap = reap; self.cleanup = cleanup; self.calls = []
            def stop_and_reap(self, lease):
                self.calls.append("reap"); return self.reap
            def cleanup_request(self, lease):
                self.calls.append("cleanup"); return self.cleanup

        with tempfile.TemporaryDirectory() as directory:
            scheduler = transport.LeaseScheduler(Path(directory))
            lease = scheduler.acquire_ordinary("1" * 64)
            runtime = Runtime(cleanup=False)
            with self.assertRaises(transport.TransportReject):
                transport.finish_transaction(scheduler, runtime, lease)
            self.assertEqual(runtime.calls, ["reap", "cleanup"])
            self.assertTrue(scheduler.active_leases())
            runtime = Runtime()
            transport.finish_transaction(scheduler, runtime, lease)
            self.assertEqual(runtime.calls, ["reap", "cleanup"])
            self.assertEqual(scheduler.active_leases(), ())

    def test_zero_prefix_production_recovery_completes_in_one_pass_without_receipt_root(self):
        request_id = "6" * 64
        parsed = transport.TransportRequest(1, request_id, "ken-frontend-production-release", "b" * 64, "c" * 40, ())
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)
            request = state / "requests" / request_id
            request.mkdir(parents=True, mode=0o700)
            runtime = transport.LiveRecoveryRuntime(state)
            lease = transport.LeaseHandle(request_id, (1, 2), "production_build")
            with mock.patch.object(transport, "_request_directory", return_value=request), mock.patch.object(
                transport, "_recover_firewall", return_value=True
            ), mock.patch.object(transport, "_load_request", return_value=(request, parsed)), mock.patch.object(
                transport, "_load_policy", return_value={}
            ), mock.patch.object(transport, "_action", return_value={}), mock.patch.object(
                transport, "require_frontend_receipt_transport", return_value=object()
            ):
                self.assertTrue(runtime.cleanup_request(lease))
            self.assertFalse(request.exists())
            self.assertFalse((state / "frontend-receipts" / request_id).exists())

    def test_cgroup_contract_rejects_wrong_parent_or_phase(self):
        transport.validate_cgroup(
            "/ken.slice/ken-actions.slice/ken-actions-deploy.slice/ken-actions-deploy-transaction.slice/ken-actions-deploy-transaction-1.slice/ken-actions-deploy-transaction-1.service",
            "ken-actions-deploy-transaction-1.slice",
        )
        transport.validate_cgroup(
            "/ken.slice/ken-actions.slice/ken-actions-deploy.slice/ken-actions-deploy-builder.slice/ken-frontend-production-builder@" + "a" * 64 + ".service",
            "ken-actions-deploy-builder.slice",
        )
        transport.validate_cgroup(
            "/ken.slice/ken-actions.slice/ken-actions-deploy.slice/ken-actions-deploy-transaction.slice/ken-actions-deploy-transaction-2.slice/ken-beehiiv-generate-slot-2.scope",
            "ken-actions-deploy-transaction-2.slice",
        )
        for path, expected in (
            ("/system.slice/x.service", "ken-actions-deploy-transaction-1.slice"),
            ("/ken.slice/ken-actions.slice/ken-actions-deploy.slice/ken-actions-deploy-transaction.slice/ken-actions-deploy-transaction-2.slice/x.service", "ken-actions-deploy-transaction-1.slice"),
            ("/ken.slice/ken-actions.slice/ken-actions-deploy.slice/ken-actions-deploy-uploader.slice/x.service", "ken-actions-deploy-builder.slice"),
            ("/ken-actions-deploy.slice/ken-actions-deploy.slice/ken-actions-deploy-transaction-1.slice/x.service", "ken-actions-deploy-transaction-1.slice"),
            ("/user.slice/ken.slice/ken-actions.slice/ken-actions-deploy.slice/ken-actions-deploy-builder.slice/x.service", "ken-actions-deploy-builder.slice"),
            ("/ken.slice/ken-actions.slice/ken-actions-deploy.slice/ken-actions-deploy-transaction.slice/ken-actions-deploy-transaction-1.slice/evil.service", "ken-actions-deploy-transaction-1.slice"),
            ("/ken.slice/ken-actions.slice/ken-actions-deploy.slice/ken-actions-deploy-builder.slice/ken-frontend-production-builder@" + "a" * 63 + ".service", "ken-actions-deploy-builder.slice"),
        ):
            with self.assertRaises(transport.TransportReject):
                transport.validate_cgroup(path, expected)

    def test_trusted_phase_admission_checks_uid_slice_live_cgroup_and_fixed_entrypoint(self):
        request_id = "a" * 64
        expanded = "/ken.slice/ken-actions.slice/ken-actions-deploy.slice/ken-actions-deploy-transaction.slice/ken-actions-deploy-transaction-1.slice/ken-beehiiv-generate-slot-1.scope"
        calls = []
        with mock.patch.object(transport.os, "geteuid", return_value=22102), \
                mock.patch.object(transport, "_current_control_group", return_value=expanded), \
                mock.patch.object(transport, "_systemctl_property", return_value="ken-actions-deploy-transaction-1.slice"), \
                mock.patch.object(transport, "_quiet_run", side_effect=lambda argv, **kwargs: calls.append(list(argv))):
            transport.run_trusted_phase("dependency", 1, request_id, [10, 11], None)
        self.assertEqual(calls[0], [
            transport.TOOLCHAIN_NODE, transport.TOOLCHAIN_PNPM, "install", "--offline", "--frozen-lockfile", "--ignore-scripts",
            "--dir", "/proc/self/fd/10", "--store-dir", "/proc/self/fd/11",
        ])
        with mock.patch.object(transport.os, "geteuid", return_value=22102), \
                mock.patch.object(transport, "_current_control_group", return_value=expanded), \
                mock.patch.object(transport, "_systemctl_property", return_value="wrong.slice"):
            with self.assertRaises(transport.TransportReject):
                transport.run_trusted_phase("generate", 1, request_id, [10, 11], None)
        with mock.patch.object(transport.os, "geteuid", return_value=22104), \
                mock.patch.object(transport, "_current_control_group", return_value=expanded), \
                mock.patch.object(transport, "_systemctl_property", return_value="ken-actions-deploy-transaction-1.slice"):
            with self.assertRaises(transport.TransportReject):
                transport.run_trusted_phase("push", 1, request_id, [10, 11], "b" * 40)

        invoked = []
        with mock.patch.object(transport, "run_trusted_phase", side_effect=lambda *args: invoked.append(args)):
            self.assertEqual(transport.main([
                "run-trusted-phase", "--role", "push", "--slot", "2", "--request-id", request_id,
                "--first-fd", "10", "--second-fd", "11", "--parent-sha", "b" * 40,
            ]), 0)
        self.assertEqual(invoked, [("push", 2, request_id, (10, 11), "b" * 40)])

        source = Path(path).read_text()
        self.assertIn("TRANSPORT_PATH, \"run-trusted-phase\"", source)
        self.assertNotIn("/usr/bin/setpriv\", f\"--reuid={identity['uid']}\", f\"--regid={identity['gid']}\", \"--clear-groups\", \"--no-new-privs\", *argv", source)

    def test_beehiiv_scopes_are_durable_and_recovery_requires_stop_and_empty_readback(self):
        lease = transport.LeaseHandle("a" * 64, (2,), "ordinary")
        seen = []
        with mock.patch.object(transport, "_stop_and_verify_unit", side_effect=lambda unit: seen.append(unit) or True):
            self.assertTrue(transport.LiveRecoveryRuntime(Path("/unused")).stop_and_reap(lease))
        self.assertIn("ken-beehiiv-generate-slot-2.scope", seen)
        self.assertIn("ken-beehiiv-push-slot-2.scope", seen)

        runtime = object.__new__(transport.LiveTrustedGenerationRuntime)
        runtime.slot = 1; runtime.active = "generate"; runtime.open_fds = [99]
        runtime.request = type("R", (), {"request_id": "a" * 64})()
        runtime.request_dir = Path("/unused")
        with mock.patch.object(transport, "_stop_and_verify_unit", return_value=False):
            with self.assertRaises(transport.TransportReject):
                runtime.abort_cleanup()
        self.assertEqual(runtime.active, "generate")
        self.assertEqual(runtime.open_fds, [99])

        self.assertEqual(transport.trusted_scope_state("c" * 64, 2, "push"), {
            "schema_version": 1, "request_id": "c" * 64, "slot": 2,
            "scopes": {
                "generate": "ken-beehiiv-generate-slot-2.scope",
                "push": "ken-beehiiv-push-slot-2.scope",
            },
            "active_role": "push",
        })

        seen = []
        def fail_generate(unit):
            seen.append(unit)
            return "generate" not in unit
        with mock.patch.object(transport, "_stop_and_verify_unit", side_effect=fail_generate):
            self.assertFalse(transport.LiveRecoveryRuntime(Path("/unused")).stop_and_reap(lease))
        self.assertIn("ken-beehiiv-generate-slot-2.scope", seen)
        self.assertIn("ken-beehiiv-push-slot-2.scope", seen)

    def test_beehiiv_contract_splits_credentials_network_cgroups_and_commit_input(self):
        contract = transport.trusted_generation_contract()
        self.assertEqual(contract["phase_order"], ["dependency", "generate", "reap", "validate", "seal", "push"])
        self.assertEqual(contract["dependency"]["credentials"], [])
        self.assertEqual(contract["dependency"]["network"], "none")
        self.assertEqual(contract["generate"]["identity"], {"name": "ken-beehiiv-generate", "uid": 22102, "gid": 22102})
        self.assertEqual(contract["generate"]["credentials"], ["BEEHIIV_API_KEY", "BEEHIIV_PUBLICATION_ID"])
        self.assertEqual(contract["generate"]["network_profile"], "beehiiv-api-fixed-target")
        self.assertEqual(contract["push"]["identity"], {"name": "ken-beehiiv-push", "uid": 22104, "gid": 22104})
        self.assertEqual(contract["push"]["credentials"], ["DEPLOY_SSH_KEY"])
        self.assertEqual(contract["push"]["network_profile"], "github-ssh-ken-website-fixed-target")
        self.assertNotEqual(contract["generate"]["request_subdirectory"], contract["push"]["request_subdirectory"])
        self.assertTrue(set(contract["generate"]["descriptors"]).isdisjoint(contract["push"]["descriptors"]))
        self.assertIn("{slot}", contract["generate"]["cgroup_scope"])
        self.assertIn("{slot}", contract["push"]["cgroup_scope"])
        self.assertNotEqual(contract["generate"]["cgroup_scope"], contract["push"]["cgroup_scope"])
        self.assertEqual(contract["generate"]["firewall_phase"], "beehiiv-api")
        self.assertEqual(contract["push"]["firewall_phase"], "github-ssh")

    def test_firewall_contract_uses_task4_ids_descriptors_and_exact_action_phases(self):
        self.assertEqual(transport.firewall_phase_plan("ken-vexa-mcp-auth-production-deploy"), (
            ("vexa-ssh", "deploy"), ("vexa-public-health", "health"),
        ))
        self.assertEqual(transport.firewall_phase_plan("ken-website-production-deploy"), (
            ("website-ssh", "deploy"), ("ken-so-public-health", "health"),
            ("getken-ai-separation", "separation"),
        ))
        with self.assertRaises(transport.TransportReject):
            transport.firewall_phase_plan("caller-selected")
        self.assertEqual(transport.SAFE_REQUEST_ID.pattern, r"^[0-9a-f]{64}$")
        self.assertEqual(transport.FRONTEND_FIREWALL_PHASES, (
            ("node-base-read", 22201), ("package-read", 22201), ("build-offline", 22201),
            ("posthog-upload", 22202), ("ghcr-write", 22003),
            ("frontend-deploy", 22203), ("frontend-public-health", 22203),
        ))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            writes = []
            commands = []
            with mock.patch.object(transport, "FIREWALL_REQUEST_ROOT", root / "firewall-requests"), \
                    mock.patch.object(transport, "_atomic_json", side_effect=lambda target, value: writes.append((target, value))), \
                    mock.patch.object(transport, "_quiet_run", side_effect=lambda argv, **kwargs: commands.append(list(argv))):
                transport._firewall(root, "a" * 64, "beehiiv-api-fixed-target", "beehiiv-api", "activate")
                with self.assertRaises(transport.TransportReject):
                    transport._firewall(root, "a" * 32, "beehiiv-api-fixed-target", "beehiiv-api", "activate")
                with self.assertRaises(transport.TransportReject):
                    transport._firewall(root, "b" * 64, "beehiiv-api-fixed-target", "github-ssh", "activate")
            descriptor = {"schema_version":1, "request_id":"a"*64, "profile":"beehiiv-api-fixed-target", "phase":"beehiiv-api"}
            self.assertEqual(writes, [
                (root / "firewall-requests" / ("a" * 64 + ".json"), descriptor),
                (root / ".firewall-phase.json", descriptor),
            ])
            self.assertEqual(commands, [[transport.FIREWALL_HELPER, "phase", "--request-id", "a"*64,
                                         "--profile", "beehiiv-api-fixed-target", "--phase", "beehiiv-api", "--state", "activate"]])

    def test_generated_diff_accepts_only_exact_regular_file_allowlist(self):
        valid = [
            {"path": "src/data/blog.beehiiv.generated.json", "type": "file", "mode": "100644", "size": 12, "sha256": "a" * 64},
            {"path": "public/images/blog/beehiiv/post-1.webp", "type": "file", "mode": "100644", "size": 42, "sha256": "b" * 64},
            {"path": "public/images/blog/beehiiv/old.webp", "type": "delete", "mode": None, "size": 0, "sha256": None},
        ]
        self.assertEqual(transport.validate_generated_diff(valid), tuple(item["path"] for item in valid))
        mutations = [
            [{**valid[0], "path": "package.json"}],
            [{**valid[0], "path": "public/images/blog/beehiiv/../../escape"}],
            [{**valid[0], "type": "symlink"}],
            [{**valid[0], "mode": "100755"}],
            [{**valid[0], "size": -1}],
            [{**valid[0], "sha256": "A" * 64}],
            [{"path": "src/data/blog.beehiiv.generated.json", "type": "delete", "mode": None, "size": 0, "sha256": None}],
            [valid[0], valid[0]],
        ]
        for mutation in mutations:
            with self.assertRaises(transport.TransportReject):
                transport.validate_generated_diff(mutation)
        self.assertEqual(transport.validate_generated_diff([]), ())

    def test_trusted_generation_orchestration_is_ordered_output_free_and_fail_closed(self):
        class Runtime:
            def __init__(self, fail_at=None):
                self.events = []; self.active = None; self.fail_at = fail_at
            def _event(self, name, payload=None):
                self.events.append((name, payload))
                if self.fail_at == name: raise transport.TransportReject("fixture_failure")
            def prepare_dependencies(self, spec):
                self.assert_inactive(); self._event("dependency", spec)
            def start_generate(self, spec):
                self.assert_inactive(); self.active = "generate"; self._event("generate", spec)
            def stop_and_reap(self, role):
                self.assertEqual(role, self.active); self._event("reap", role); self.active = None
            def generated_diff(self):
                self.assert_inactive(); self._event("diff")
                return [{"path":"src/data/blog.beehiiv.generated.json","type":"file","mode":"100644","size":1,"sha256":"a"*64}]
            def seal_commit_input(self, entries):
                self.assert_inactive(); self._event("seal", tuple(item["path"] for item in entries)); return "sealed-read-only-fd"
            def close_generate_descriptors(self):
                self.assert_inactive(); self._event("close-generate")
            def start_push(self, spec, sealed):
                self.assert_inactive(); self.assertEqual(sealed, "sealed-read-only-fd"); self.active = "push"; self._event("push", spec)
            def close_push_descriptors(self):
                self.assert_inactive(); self._event("close-push")
            def assert_inactive(self):
                if self.active is not None: raise AssertionError("phase overlap")
            def assertEqual(self, left, right):
                if left != right: raise AssertionError((left, right))
            def abort_cleanup(self):
                self._event("abort-cleanup"); self.active = None

        runtime = Runtime()
        transport.orchestrate_trusted_generation(runtime, 2)
        self.assertEqual([event[0] for event in runtime.events], [
            "dependency", "generate", "reap", "diff", "seal", "close-generate", "push", "reap", "close-push",
        ])
        generate = runtime.events[1][1]; push = runtime.events[6][1]
        self.assertEqual(generate["identity"]["uid"], 22102)
        self.assertEqual(push["identity"]["uid"], 22104)
        self.assertNotEqual(generate["cgroup_scope"].format(slot=2), push["cgroup_scope"].format(slot=2))
        self.assertTrue(set(generate["credentials"]).isdisjoint(push["credentials"]))
        runtime = Runtime(fail_at="generate")
        with self.assertRaises(transport.TransportReject):
            transport.orchestrate_trusted_generation(runtime, 1)
        self.assertEqual(runtime.events[-1][0], "abort-cleanup")

        runtime = Runtime()
        runtime.generated_diff = lambda: []
        transport.orchestrate_trusted_generation(runtime, 1)
        self.assertEqual([event[0] for event in runtime.events], ["dependency", "generate", "reap", "close-generate", "close-push"])

    def test_offline_dependency_store_is_recursively_sealed_and_reached_only_by_fd(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Path(directory) / "store"
            nested = store / "v3" / "files"
            nested.mkdir(parents=True)
            package = nested / "package.json"
            package.write_text("{}")
            for item in (store, store / "v3", nested):
                item.chmod(0o550)
            package.chmod(0o440)
            transport.validate_offline_store(store, owner_uid=os.getuid(), reader_gid=os.getgid())
            package.chmod(0o640)
            with self.assertRaises(transport.TransportReject):
                transport.validate_offline_store(store, owner_uid=os.getuid(), reader_gid=os.getgid())

    def test_generated_diff_uses_post_install_baseline_not_pristine_source(self):
        baseline = {
            "src/data/blog.beehiiv.generated.json": {"mode":"100644","size":1,"sha256":"a"*64},
            "node_modules/pkg/index.js": {"mode":"100644","size":1,"sha256":"b"*64},
        }
        generated = {
            **baseline,
            "src/data/blog.beehiiv.generated.json": {"mode":"100644","size":2,"sha256":"c"*64},
        }
        self.assertEqual(transport.generated_diff_from_snapshots(baseline, generated), [{
            "path":"src/data/blog.beehiiv.generated.json", "type":"file", "mode":"100644", "size":2, "sha256":"c"*64,
        }])
        polluted = {**generated, "package.json": {"mode":"100644","size":2,"sha256":"d"*64}}
        with self.assertRaises(transport.TransportReject):
            transport.generated_diff_from_snapshots(baseline, polluted)

    def test_action_mode_router_executes_trusted_generation_in_selected_ordinary_slot(self):
        events = []
        class Runtime:
            def prepare_dependencies(self, spec): events.append("dependency")
            def start_generate(self, spec): events.append("generate")
            def stop_and_reap(self, role): events.append("reap-" + role)
            def generated_diff(self): return [{"path":"src/data/blog.beehiiv.generated.json","type":"file","mode":"100644","size":1,"sha256":"a"*64}]
            def seal_commit_input(self, entries): events.append("seal"); return object()
            def close_generate_descriptors(self): events.append("close-generate")
            def start_push(self, spec, sealed): events.append("push")
            def close_push_descriptors(self): events.append("close-push")
            def abort_cleanup(self): events.append("abort")
        ordinary = lambda: events.append("ordinary")
        transport.execute_action_mode("trusted_generation", slot=2, ordinary=ordinary, trusted_runtime=Runtime())
        self.assertEqual(events, ["dependency", "generate", "reap-generate", "seal", "close-generate", "push", "reap-push", "close-push"])
        events.clear()
        transport.execute_action_mode("artifact", slot=1, ordinary=ordinary, trusted_runtime=None)
        self.assertEqual(events, ["ordinary"])
        for bad in ("production_build", "unknown"):
            with self.assertRaises(transport.TransportReject):
                transport.execute_action_mode(bad, slot=1, ordinary=ordinary, trusted_runtime=None)

    def test_ordinary_slot_defers_terminal_status_to_dispatcher(self):
        request_id = "5" * 64
        request = transport.TransportRequest(1, request_id, "ken-vexa-mcp-auth-production-deploy", "b" * 64, "c" * 40, ("artifact", "rendered"))
        lease = transport.LeaseHandle(request_id, (1,), "ordinary")
        scheduler = object()
        action = {"enabled": True, "input_mode": "artifact"}
        with mock.patch.object(transport.os, "geteuid", return_value=0), mock.patch.object(
            transport, "_current_control_group", return_value="/ken.slice/ken-actions.slice/ken-actions-deploy.slice/ken-actions-deploy-transaction.slice/ken-actions-deploy-transaction-1.slice/ken-actions-deploy-transaction-1.service"
        ), mock.patch.object(transport, "LeaseScheduler", return_value=scheduler), mock.patch.object(
            transport, "_lease_for_slot", return_value=lease
        ), mock.patch.object(transport, "_load_request", return_value=(Path("/request"), request)), mock.patch.object(
            transport, "_load_policy", return_value={}
        ), mock.patch.object(transport, "_action", return_value=action), mock.patch.object(
            transport, "_execute_ordinary"
        ) as execute, mock.patch.object(transport, "_status_write") as status:
            transport.run_ordinary_slot(1, Path("/state"), Path("/policy"))
        execute.assert_called_once()
        status.assert_not_called()

    def test_frontend_state_machine_never_overlaps_builder_uploader_or_deploy(self):
        state = transport.FrontendPhaseState()
        expected = ["source-ready", "dependencies-ready", "secret-build", "builder-reaped", "scan-passed", "uploader", "uploader-reaped", "registry-readback", "token-destroyed", "deploy", "deploy-reaped", "cleaned"]
        for phase in expected:
            state.advance(phase)
        self.assertTrue(state.complete)
        for bad in ("uploader", "deploy", "secret-build"):
            with self.assertRaises(transport.TransportReject):
                transport.FrontendPhaseState().advance(bad)
        state = transport.FrontendPhaseState()
        for phase in expected[:3]: state.advance(phase)
        with self.assertRaises(transport.TransportReject): state.start_role("uploader")
        state.stop_role("builder")
        state.advance("builder-reaped")
        state.advance("scan-passed")
        state.start_role("uploader")
        with self.assertRaises(transport.TransportReject): state.start_role("deploy")

    def test_frontend_phase_paths_are_disjoint_and_identity_owned_without_runner_access(self):
        request_id = "a" * 64
        expected = {
            "builder": (Path(f"/run/ken-actions-deploy-phases/{request_id}-builder"), 22201),
            "uploader": (Path(f"/run/ken-actions-deploy-phases/{request_id}-uploader"), 22202),
            "deploy": (Path(f"/run/ken-actions-deploy-phases/{request_id}-deploy"), 22203),
        }
        self.assertEqual({phase: transport.frontend_phase_directory(request_id, phase) for phase in expected}, expected)
        self.assertEqual(len({str(path) for path, _ in expected.values()}), 3)
        for bad in ("../escape", "A" * 64, "a" * 63):
            with self.assertRaises(transport.TransportReject):
                transport.frontend_phase_directory(bad, "builder")

    def test_contract_hashes_are_canonical_and_mutation_sensitive(self):
        contracts = transport.binding_contracts()
        self.assertEqual(set(contracts), {
            "ordinary_systemd_transaction_transport_sha256",
            "frontend_operation_binding_sha256",
            "frontend_phase_transport_sha256",
            "frontend_deploy_contract_sha256",
            "trusted_generation_dependency_acquisition_sha256",
            "trusted_generation_generated_paths_manifest_sha256",
            "trusted_generation_commit_input_contract_sha256",
            "trusted_generation_cgroup_contract_sha256",
            "trusted_generation_phase_transport_sha256",
        })
        for name, contract in contracts.items():
            encoded = json.dumps(contract, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
            self.assertEqual(transport.contract_sha256(contract), hashlib.sha256(encoded).hexdigest(), name)

    def _bound_frontend_action(self):
        import yaml
        root = Path(path).parent.parent
        policy = yaml.safe_load((root / "inventory/op-broker-policy.yaml").read_text())
        action = copy.deepcopy(next(row for row in policy["actions"] if row["action_id"] == "ken-frontend-production-release"))
        action["enabled"] = True
        digests = transport.binding_digests()
        action["production_build"]["phase_transport_sha256"] = digests["frontend_phase_transport_sha256"]
        action["production_build"]["deploy_contract_sha256"] = digests["frontend_deploy_contract_sha256"]
        action["executor"]["operation_binding_sha256"] = digests["frontend_operation_binding_sha256"]
        action["executor"]["systemd_transaction_transport_sha256"] = digests["ordinary_systemd_transaction_transport_sha256"]
        return action

    def test_frontend_receipt_transport_binds_exact_task6_helper_action_and_firewall(self):
        for action in ({}, {"action_id": "ken-frontend-production-release", "input_mode": "source_commit"}):
            with self.assertRaises(transport.TransportReject):
                transport.require_frontend_receipt_transport(action)
        action = self._bound_frontend_action()
        helper = transport.require_frontend_receipt_transport(action)
        self.assertEqual(helper.RECEIPT_CONTRACT_SHA256, transport.TASK6_RECEIPT_CONTRACT_SHA256)
        self.assertEqual(tuple(helper.RECEIPT_PHASES), transport.FRONTEND_RECEIPT_PHASES)
        self.assertEqual(dict(helper.RECEIPT_ACTOR_UIDS), transport.FRONTEND_RECEIPT_ACTOR_UIDS)
        self.assertEqual({key: tuple(value) for key, value in helper.RECEIPT_FIREWALL_PHASES.items()}, transport.FRONTEND_RECEIPT_FIREWALL_PHASES)
        self.assertEqual(dict(transport.FRONTEND_FIREWALL_PHASES), {
            name: row["uid"] for name, row in helper.FRONTEND_FIREWALL_PHASES.items()
        })
        drifted = copy.deepcopy(action)
        drifted["production_build"]["receipt_contract"]["contract_sha256"] = "f" * 64
        with self.assertRaises(transport.TransportReject):
            transport.require_frontend_receipt_transport(drifted)
        with mock.patch.object(transport, "TASK6_RECEIPT_HELPER_SHA256", "f" * 64), self.assertRaises(transport.TransportReject):
            transport.require_frontend_receipt_transport(action)
        with mock.patch("importlib.machinery.SourceFileLoader", side_effect=AssertionError("verified path reopened")):
            helper = transport.load_frontend_receipt_helper()
        self.assertEqual(helper.RECEIPT_CONTRACT_SHA256, transport.TASK6_RECEIPT_CONTRACT_SHA256)
        self.assertEqual(transport.TASK6_RECEIPT_SOURCE_TREE_SHA, "e8da0e42c2593ff4bb284d7bc52320cefb1ba517")
        self.assertEqual(transport.TASK6_RECEIPT_HELPER_BLOB_SHA, "ad56d39488c749a29486d2a842d713bbd838fa7d")
        self.assertEqual(len({transport.TASK6_RECEIPT_SOURCE_COMMIT_SHA, transport.TASK6_RECEIPT_SOURCE_TREE_SHA, transport.TASK6_RECEIPT_HELPER_BLOB_SHA}), 3)

    def _frontend_evidence(self, helper, phase, source_sha):
        tree = "c" * 40
        tree_manifest, variables, oci, maps = "1" * 64, "2" * 64, "3" * 64, "4" * 64
        provenance, image = "7" * 64, "sha256:" + "e" * 64
        common = {"source_sha": source_sha, "tree_sha": tree, "image_digest": image, "provenance_sha256": provenance}
        rows = {
            "source": {
                "repository_id": 1141163204, "commit_sha": source_sha, "tree_sha": tree,
                "tree_manifest_sha256": tree_manifest, **helper.SOURCE_BLOB_SHAS,
                "variables_manifest_sha256": variables,
            },
            "build": {
                "source_sha": source_sha, "tree_sha": tree, "tree_manifest_sha256": tree_manifest,
                **helper.SOURCE_BLOB_SHAS, "variables_manifest_sha256": variables,
                "oci_layout_sha256": oci, "oci_manifest_digest": image,
                "source_maps_sha256": maps, "build_log_sha256": "5" * 64,
                "cache_metadata_sha256": "6" * 64, "build_plan_sha256": helper.BUILD_PLAN_SHA256,
                "provenance_sha256": provenance, "provenance_subject_digest": image,
                "buildkit_version": "0.24.0", "buildctl_version": "0.24.0",
                "node_version": "22.20.0", "pnpm_version": "10.28.2",
                "base_image_digest": helper.BASE_IMAGE_DIGEST, "platform": "linux/amd64",
            },
            "scan": {
                "source_sha": source_sha, "tree_sha": tree, "oci_layout_sha256": oci,
                "oci_manifest_digest": image, "provenance_sha256": provenance,
                "provenance_subject_digest": image, "scan_evidence_sha256": "8" * 64,
                "leakage_encodings": ["raw", "canonical-base64", "lowercase-hex"],
            },
            "upload": {"source_maps_sha256": maps, "posthog_upload_sha256": "9" * 64},
            "registry": {
                "registry": "ghcr.io/ken-technology/ken-frontend", "image_digest": image,
                "manifest_digest": image, "platform": "linux/amd64", "source_sha": source_sha,
                "tree_sha": tree, "oci_layout_sha256": oci, "provenance_sha256": provenance,
                "provenance_subject_digest": image,
                "media_type": "application/vnd.oci.image.manifest.v1+json", "readback_verified": True,
            },
            "token-destroy": {
                **common, "token_descriptor_closed": True, "token_buffer_zeroed": True,
                "token_destroyed_monotonic_ns": 64000,
            },
            "digest": {
                **common, "digest_state_sha256": "a" * 64, "state_key_sha256": "b" * 64,
                "fsynced": True, "durable_state_published_monotonic_ns": 73000,
                "durable_state_readback_monotonic_ns": 74000,
            },
            "deploy-health": {
                **common, "deploy_receipt_sha256": "c" * 64, "health_receipt_sha256": "d" * 64,
                "deploy_completed_monotonic_ns": 80150, "health_started_monotonic_ns": 80300,
                "health_completed_monotonic_ns": 84000,
            },
            "cleanup": {
                **common, "request_state_removed": True, "source_removed": True,
                "buildkit_removed": True, "oci_removed": True, "source_maps_removed": True,
                "secret_mount_removed": True, "descriptors_closed": True,
                "firewall_inactive": True, "cgroups_empty": True,
                "cleanup_completed_monotonic_ns": 94000,
            },
        }
        return rows[phase]

    def _frontend_finished_observation(self, helper, phase, request_id):
        ordinal = helper.RECEIPT_PHASES.index(phase)
        base = (ordinal + 1) * 10000
        unit, slice_name, control_group, dedicated = helper._expected_runtime(phase, request_id)
        transitions = [{
            "phase": name, "uid": helper.FRONTEND_FIREWALL_PHASES[name]["uid"],
            "targets": list(helper.FRONTEND_FIREWALL_PHASES[name]["targets"]),
            "activate_readback_sha256": "f" * 64,
            "activated_observed_monotonic_ns": base + ((index + 1) * 100),
            "deactivated": True,
        } for index, name in enumerate(helper.RECEIPT_FIREWALL_PHASES[phase])]
        return {
            "unit": unit, "slice": slice_name, "control_group": control_group,
            "observed_actor_uid": helper.RECEIPT_ACTOR_UIDS[phase], "actor_pid": 4242,
            "boot_id": "12345678-1234-1234-1234-123456789abc", "actor_start_ticks": 100,
            "systemd_exec_start_monotonic_usec": 100,
            "systemd_exec_exit_monotonic_usec": 200 if dedicated else 0,
            "started_observed_monotonic_ns": base + 100,
            "completed_observed_monotonic_ns": base + 9000,
            "process_reaped": True, "descriptor_snapshots_sha256": "3" * 64,
            "descriptors_closed": True, "network_authority": helper._network_authority(phase),
            "firewall_transitions": transitions, "firewall_inactive_after": True,
            "cgroup_empty_after": dedicated,
        }

    def test_frontend_receipt_store_seals_verifies_and_recovers_fail_closed(self):
        helper = transport.require_frontend_receipt_transport(self._bound_frontend_action())
        request_id, source_sha = "e" * 64, "b" * 40
        current_uid, current_gid = os.geteuid(), os.getegid()
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(
            helper, "RECEIPT_OWNER_UID", current_uid
        ), mock.patch.object(helper, "RECEIPT_OWNER_GID", current_gid), mock.patch.dict(
            helper.RECEIPT_ACTOR_UIDS, {phase: current_uid for phase in helper.RECEIPT_PHASES}, clear=True
        ), mock.patch.object(helper, "_parse_start_observation", return_value={}), mock.patch.object(
            helper, "_finish_root_observation",
            side_effect=lambda records, request_id, phase: self._frontend_finished_observation(helper, phase, request_id),
        ):
            root = Path(directory)
            state = root / "state"; state.mkdir(mode=0o700)
            request = state / "requests" / request_id; request.mkdir(parents=True, mode=0o700)
            policy = root / "policy.yaml"
            policy.write_bytes((Path(path).parent.parent / "inventory/op-broker-policy.yaml").read_bytes())
            policy.chmod(0o644)
            store = transport.FrontendReceiptStore(state, request_id, source_sha, policy, helper)
            store.initialize()
            self.assertEqual(store.root, state / "frontend-receipts" / request_id)
            self.assertNotIn(request, store.root.parents)
            stdout, stderr = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                for phase in helper.RECEIPT_PHASES:
                    evidence = self._frontend_evidence(helper, phase, source_sha)
                    data = store.phase_data_path(phase)
                    data.write_bytes(helper.canonical_phase_data(request_id, source_sha, phase, evidence))
                    data.chmod(0o600)
                    for observation in store.observation_paths(phase):
                        observation.write_text("{}")
                        observation.chmod(0o600)
                    observed = (helper.RECEIPT_PHASES.index(phase) + 1) * 10000 + 5000
                    store.seal(phase, evidence, observed)
                store.verify_complete()
            self.assertEqual((stdout.getvalue(), stderr.getvalue()), ("", ""))
            self.assertEqual(store.recovery_ordinal(), 9)

            authority = store.authority_path("scan")
            original = authority.read_bytes()
            authority.write_bytes(b"{}")
            with self.assertRaises(transport.TransportReject):
                store.recovery_ordinal()
            authority.write_bytes(original); authority.chmod(0o600)
            self.assertEqual(store.recovery_ordinal(), 9)

            bad_source = self._frontend_evidence(helper, "source", source_sha)
            bad_source["tree_sha"] = source_sha
            with self.assertRaises(helper.ReleaseError):
                helper.canonical_phase_data(request_id, source_sha, "source", bad_source)

            partial = transport.FrontendReceiptStore(state, "f" * 64, source_sha, policy, helper)
            partial.initialize()
            evidence = self._frontend_evidence(helper, "source", source_sha)
            partial.phase_data_path("source").write_bytes(helper.canonical_phase_data("f" * 64, source_sha, "source", evidence))
            partial.phase_data_path("source").chmod(0o600)
            partial.observation_paths("source")[0].write_text("{}")
            partial.observation_paths("source")[0].chmod(0o600)
            partial.seal("source", evidence, 15000)
            self.assertEqual(partial.recovery_ordinal(), 1)
            partial._write_state(0)  # receipt fsync won, process died before state advance
            self.assertEqual(partial.recovery_ordinal(), 1)
            self.assertEqual(partial._read_state(), 1)
            build_evidence = self._frontend_evidence(helper, "build", source_sha)
            partial.phase_data_path("build").write_bytes(helper.canonical_phase_data("f" * 64, source_sha, "build", build_evidence))
            partial.phase_data_path("build").chmod(0o600)
            for observation in partial.observation_paths("build"):
                observation.write_text("{}"); observation.chmod(0o600)
            partial.authority_path("build").write_bytes(helper.canonical_phase_authority(
                "f" * 64, source_sha, "build", build_evidence, 25000,
            ))
            partial.authority_path("build").chmod(0o600)
            self.assertEqual(partial.recover_pending_phase("build"), (build_evidence, 25000))
            (partial.receipts / "unexpected").write_text("x")
            with self.assertRaises(transport.TransportReject):
                partial.recovery_ordinal()

    def test_production_dispatch_orchestrates_then_cleans_releases_and_succeeds(self):
        request_id = "a" * 64
        request = transport.TransportRequest(1, request_id, "ken-frontend-production-release", "b" * 64, "c" * 40, ())
        action = self._bound_frontend_action()
        lease = transport.LeaseHandle(request_id, (1, 2), "production_build")
        class Scheduler:
            def __init__(self, root): pass
            def wait_for_exclusive(self, value):
                self.assertEqual(value, request_id) if hasattr(self, "assertEqual") else None
                return lease
        events = []
        class Store:
            def __init__(self, *args): events.append("store")
        class Runtime:
            def __init__(self, *args): events.append("runtime")
        statuses = []
        with mock.patch.object(transport.os, "geteuid", return_value=0), mock.patch.object(
            transport, "_load_request", return_value=(Path("/unused"), request)), mock.patch.object(
            transport, "_load_policy", return_value={}
        ), mock.patch.object(transport, "_action", return_value=action), mock.patch.object(
            transport, "require_frontend_receipt_transport", return_value=object()
        ), mock.patch.object(transport, "LeaseScheduler", Scheduler), mock.patch.object(
            transport, "FrontendReceiptStore", Store
        ), mock.patch.object(transport, "LiveFrontendProductionRuntime", Runtime, create=True), mock.patch.object(
            transport, "orchestrate_frontend_receipts", side_effect=lambda *args: events.append("orchestrated"), create=True
        ), mock.patch.object(
            transport, "finalize_frontend_transaction", side_effect=lambda *args: events.append("finalized"), create=True
        ), mock.patch.object(
            transport, "_status_write", side_effect=lambda *args: (events.append("status"), statuses.append(args))
        ):
            transport.dispatch(request_id, Path("/state"), Path("/policy"))
        self.assertEqual(events[-3:], ["orchestrated", "finalized", "status"])
        self.assertEqual(statuses[-1][2:], ("succeeded", "transport_succeeded"))

        events.clear(); statuses.clear()
        with mock.patch.object(transport.os, "geteuid", return_value=0), mock.patch.object(
            transport, "_load_request", return_value=(Path("/unused"), request)), mock.patch.object(
            transport, "_load_policy", return_value={}
        ), mock.patch.object(transport, "_action", return_value=action), mock.patch.object(
            transport, "require_frontend_receipt_transport", return_value=object()
        ), mock.patch.object(transport, "LeaseScheduler", Scheduler), mock.patch.object(
            transport, "FrontendReceiptStore", Store
        ), mock.patch.object(transport, "LiveFrontendProductionRuntime", Runtime, create=True), mock.patch.object(
            transport, "orchestrate_frontend_receipts", side_effect=lambda *args: events.append("orchestrated"), create=True
        ), mock.patch.object(
            transport, "finalize_frontend_transaction", side_effect=transport.TransportReject("cleanup_unverified"), create=True
        ), mock.patch.object(transport, "finish_transaction", side_effect=transport.TransportReject("cleanup_unverified")), mock.patch.object(
            transport, "_status_write", side_effect=lambda *args: statuses.append(args)
        ), self.assertRaises(transport.TransportReject):
            transport.dispatch(request_id, Path("/state"), Path("/policy"))
        self.assertNotIn(("succeeded", "transport_succeeded"), [row[2:] for row in statuses])

    def test_frontend_root_orchestration_resumes_and_cleanup_commits_last(self):
        events = []
        class Store:
            def initialize_or_recover(self): events.append("recover:2"); return 2
            def recover_pending_phase(self, phase): return None
            def seal(self, phase, evidence, observed): events.append(f"seal:{phase}")
            def recovery_ordinal(self): return 8
            def verify_complete(self): events.append("verify:9")
        class Runtime:
            def execute_phase(self, phase, store): events.append(f"execute:{phase}"); return {"phase": phase}, 100
            def stop_and_reap(self, lease): events.append("reap"); return True
            def remove_request(self, lease): events.append("remove-request"); return True
            def execute_cleanup(self, store):
                events.append("execute:cleanup")
                return {"request_state_removed": True}, 200
        class Scheduler:
            def release(self, lease, *, cleanup_verified):
                self_cleanup = cleanup_verified
                events.append(f"release:{self_cleanup}")
        store = Store(); runtime = Runtime(); scheduler = Scheduler()
        lease = transport.LeaseHandle("a" * 64, (1, 2), "production_build")
        transport.orchestrate_frontend_receipts(store, runtime)
        transport.finalize_frontend_transaction(scheduler, runtime, lease, store)
        expected = []
        for phase in transport.FRONTEND_RECEIPT_PHASES[2:8]:
            expected += [f"execute:{phase}", f"seal:{phase}"]
        self.assertEqual(events, ["recover:2", *expected, "reap", "remove-request", "execute:cleanup", "seal:cleanup", "verify:9", "release:True"])
        for failed_step in ("reap", "remove"):
            events.clear()
            class FailedRuntime(Runtime):
                def stop_and_reap(self, lease): events.append("reap"); return failed_step != "reap"
                def remove_request(self, lease): events.append("remove-request"); return failed_step != "remove"
            with self.assertRaises(transport.TransportReject):
                transport.finalize_frontend_transaction(scheduler, FailedRuntime(), lease, store)
            self.assertFalse(any(item.startswith("release:") for item in events))

    def test_manifest_runtime_schema_is_exact_and_complete(self):
        import yaml
        manifest = yaml.safe_load(Path(path).parent.parent.joinpath("inventory/action-transport.lock.yaml").read_text())
        transport.validate_manifest_schema(manifest)
        mutations = []
        mutations.append({**manifest, "unreviewed": {}})
        missing = dict(manifest); missing["artifacts"] = {"coordinator": manifest["artifacts"]["coordinator"]}; mutations.append(missing)
        wrong = dict(manifest); wrong["task6_core"] = {**manifest["task6_core"], "policy_sha256": "f" * 64}; mutations.append(wrong)
        for key in ("reviewed_source_commit_sha", "reviewed_source_tree_sha", "helper_blob_sha"):
            wrong = dict(manifest)
            wrong["task6_receipts"] = {**manifest["task6_receipts"], key: "f" * 40}
            mutations.append(wrong)
        for mutation in mutations:
            with self.assertRaises(transport.TransportReject):
                transport.validate_manifest_schema(mutation)

    def test_manifest_candidate_final_binding_is_nonrecursive_and_byte_verified(self):
        import subprocess
        import yaml

        ga_root = Path(path).parent.parent
        repo_root = ga_root.parent.parent
        manifest = yaml.safe_load((ga_root / "inventory/action-transport.lock.yaml").read_text())
        manifest["transport_version"] = "2026-08-20.3"
        manifest["status"] = "reviewed-transport-bound-task6-final-awaiting-live-authorization"
        manifest["task6_final"] = {
            "status": "reviewed-final-bindings",
            "commit_sha": "81483ceaf4bbe428afe0dfe6e370003fdf740766",
            "tree_sha": "46cd45ba7f570a8cb6be54811848027eb75e4d97",
            "task7_base_commit_sha": "f672e261e4d11cf0c46b5133145676190341aab8",
            "artifacts": {
                "policy": {
                    "path": "inventory/op-broker-policy.yaml",
                    "git_blob_sha": "ff27efdb9f27fdeacd01cb68c0283a03db061af4",
                    "sha256": "954c62d37b725b9669a0178a7dfa97b971419bc8f42a020da11469b45d4f4c62",
                },
                "runtime_lock": {
                    "path": "inventory/broker-runtime.lock.yaml",
                    "git_blob_sha": "d5ee3a5aa556255b4f3958362395c172d637f15c",
                    "sha256": "8471b852e67ab3d2f53147ec1fc5e2f5ca6529d2145a307d97fbd3c5069dad90",
                },
                "broker": {
                    "path": "bin/ken-op-broker",
                    "git_blob_sha": "3125519f70f6a2802e38003d83c81033aa192960",
                    "sha256": "211f11be2df8b085cc5ebd5815fb3d8fd10209ae34010961113cad351a481ff9",
                },
                "client": {
                    "path": "bin/ken-op-exec",
                    "git_blob_sha": "90e5a39253a082598d15533f8f4d620e84468953",
                    "sha256": "2b55d1e7687929d12edec6fe220ed84274b0d2f465f562960239064c82a1922a",
                },
                "broker_unit": {
                    "path": "systemd/ken-op-broker@.service",
                    "git_blob_sha": "f3e764545d133863aabb8ea2760bf74f31e8cc1a",
                    "sha256": "dbc0f8da004054a28e9a4675cd6d10d5f17d73b2ca932b022dea632394cf7989",
                },
            },
            "receipt_helper_provenance": {
                "reviewed_source_commit_sha": "45c55b6fc0cd2752d2869c4517475c86004a1e91",
                "reviewed_source_tree_sha": "e8da0e42c2593ff4bb284d7bc52320cefb1ba517",
                "helper_path": "bin/ken-frontend-production-release",
                "helper_blob_sha": "ad56d39488c749a29486d2a842d713bbd838fa7d",
                "helper_sha256": "8a611e251c69ee0af1f66043d508695461decf271cc32b76dbe224833a17f183",
                "contract_sha256": "d5ebeb58afb5f5e24bc1b6a6e74934ee3a22ae337b103a085d2df9a5776db63c",
            },
        }
        payloads = {
            name: (ga_root / row["path"]).read_bytes()
            for name, row in manifest["task6_final"]["artifacts"].items()
        }

        transport.validate_manifest_schema(manifest)
        transport.verify_task6_final_artifacts(manifest, payloads)
        transport.verify_task6_final_repository(manifest, repo_root)

        with tempfile.TemporaryDirectory() as directory:
            fixture_root = Path(directory)
            for name, row in manifest["task6_final"]["artifacts"].items():
                target = fixture_root / "infra/github-actions" / row["path"]
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(payloads[name])
            helper_target = fixture_root / "infra/github-actions/bin/ken-frontend-production-release"
            helper_target.write_bytes((ga_root / "bin/ken-frontend-production-release").read_bytes())

            def git(*arguments):
                return subprocess.run(
                    ["git", "-C", str(fixture_root), *arguments],
                    check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                ).stdout.strip()

            git("init", "-q")
            git("config", "user.name", "Task7 Fixture")
            git("config", "user.email", "task7-fixture@example.invalid")
            git("add", "infra/github-actions")
            git("commit", "-q", "-m", "task7 stable base")
            fixture_base = git("rev-parse", "HEAD")
            helper_target.write_bytes(b"tampered receipt helper\n")
            broker_target = fixture_root / "infra/github-actions/bin/ken-op-broker"
            broker_target.write_bytes(broker_target.read_bytes() + b"\n# final binding fixture\n")
            git("add", "infra/github-actions")
            git("commit", "-q", "-m", "task6 final binding")

            tampered_helper = copy.deepcopy(manifest)
            final = tampered_helper["task6_final"]
            final["commit_sha"] = git("rev-parse", "HEAD")
            final["tree_sha"] = git("rev-parse", "HEAD^{tree}")
            final["task7_base_commit_sha"] = fixture_base
            for row in final["artifacts"].values():
                target = fixture_root / "infra/github-actions" / row["path"]
                data = target.read_bytes()
                row["git_blob_sha"] = hashlib.sha1(f"blob {len(data)}\0".encode() + data).hexdigest()
                row["sha256"] = hashlib.sha256(data).hexdigest()
            with self.assertRaises(transport.TransportReject):
                transport.verify_task6_final_repository(tampered_helper, fixture_root)

        for key in ("commit_sha", "tree_sha", "task7_base_commit_sha"):
            wrong_type = copy.deepcopy(manifest)
            wrong_type["task6_final"][key] = True
            with self.assertRaises(transport.TransportReject):
                transport.validate_manifest_schema(wrong_type)

        missing = copy.deepcopy(manifest)
        del missing["task6_final"]["tree_sha"]
        with self.assertRaises(transport.TransportReject):
            transport.validate_manifest_schema(missing)

        recursive = copy.deepcopy(manifest)
        recursive["task6_final"]["action_transport_manifest_sha256"] = "f" * 64
        with self.assertRaises(transport.TransportReject):
            transport.validate_manifest_schema(recursive)

        for key in ("enabled", "installation_authorized", "live_execution_authorized"):
            false_ready = copy.deepcopy(manifest)
            false_ready[key] = True
            with self.assertRaises(transport.TransportReject):
                transport.validate_manifest_schema(false_ready)

        wrong_path = copy.deepcopy(manifest)
        wrong_path["task6_final"]["artifacts"]["broker"]["path"] = "bin/caller-selected"
        with self.assertRaises(transport.TransportReject):
            transport.validate_manifest_schema(wrong_path)

        wrong_receipt = copy.deepcopy(manifest)
        wrong_receipt["task6_final"]["receipt_helper_provenance"]["helper_sha256"] = "0" * 64
        with self.assertRaises(transport.TransportReject):
            transport.validate_manifest_schema(wrong_receipt)

        for key in ("commit_sha", "tree_sha"):
            wrong_git = copy.deepcopy(manifest)
            wrong_git["task6_final"][key] = "0" * 40
            with self.assertRaises(transport.TransportReject):
                transport.verify_task6_final_repository(wrong_git, repo_root)

        wrong_base = copy.deepcopy(manifest)
        wrong_base["task6_final"]["task7_base_commit_sha"] = "0" * 40
        with self.assertRaises(transport.TransportReject):
            transport.verify_task6_final_repository(wrong_base, repo_root)

        wrong_blob = copy.deepcopy(manifest)
        wrong_blob["task6_final"]["artifacts"]["broker"]["git_blob_sha"] = "0" * 40
        with self.assertRaises(transport.TransportReject):
            transport.verify_task6_final_artifacts(wrong_blob, payloads)
        with self.assertRaises(transport.TransportReject):
            transport.verify_task6_final_repository(wrong_blob, repo_root)

        wrong_hash = copy.deepcopy(manifest)
        wrong_hash["task6_final"]["artifacts"]["client"]["sha256"] = "0" * 64
        with self.assertRaises(transport.TransportReject):
            transport.verify_task6_final_artifacts(wrong_hash, payloads)

        recursive_policy = payloads["policy"] + b"\naction_transport_manifest_sha256: " + b"f" * 64 + b"\n"
        recursive_payloads = dict(payloads, policy=recursive_policy)
        recursive_bytes = copy.deepcopy(manifest)
        row = recursive_bytes["task6_final"]["artifacts"]["policy"]
        row["git_blob_sha"] = hashlib.sha1(
            f"blob {len(recursive_policy)}\0".encode() + recursive_policy
        ).hexdigest()
        row["sha256"] = hashlib.sha256(recursive_policy).hexdigest()
        with self.assertRaises(transport.TransportReject):
            transport.verify_task6_final_artifacts(recursive_bytes, recursive_payloads)

        recursive_flow_policy = (
            payloads["policy"] + b"\nrecursive: {action_transport_manifest_sha256: " + b"e" * 64 + b"}\n"
        )
        recursive_flow_payloads = dict(payloads, policy=recursive_flow_policy)
        recursive_flow = copy.deepcopy(manifest)
        row = recursive_flow["task6_final"]["artifacts"]["policy"]
        row["git_blob_sha"] = hashlib.sha1(
            f"blob {len(recursive_flow_policy)}\0".encode() + recursive_flow_policy
        ).hexdigest()
        row["sha256"] = hashlib.sha256(recursive_flow_policy).hexdigest()
        with self.assertRaises(transport.TransportReject):
            transport.verify_task6_final_artifacts(recursive_flow, recursive_flow_payloads)

        with tempfile.TemporaryDirectory() as directory:
            duplicate = Path(directory) / "candidate.yaml"
            duplicate.write_text(yaml.safe_dump(manifest, sort_keys=False) + "\ntask6_final: {}\n")
            with self.assertRaises(transport.TransportReject):
                transport.strict_yaml(duplicate)


suite = unittest.defaultTestLoader.loadTestsFromTestCase(TransportTests)
result = unittest.TextTestRunner(verbosity=2).run(suite)
raise SystemExit(0 if result.wasSuccessful() else 1)
PY

echo '== syntax and forbidden authority =='
run_check 'coordinator parses and exposes only reviewed commands' \
  bash -c 'python3 -c '\''import ast, pathlib, sys; ast.parse(pathlib.Path(sys.argv[1]).read_text())'\'' "$1" && "$1" --help >/dev/null' _ "${TRANSPORT}"
run_check 'owned files contain no secret values live enablement or runner-selected authority' \
  bash -c '! rg -n -- "-----BEGIN .*PRIVATE KEY-----|ghp_[A-Za-z0-9]{20,}|github_pat_|OP_SERVICE_ACCOUNT_TOKEN=|enabled:[[:space:]]*true|installation_authorized:[[:space:]]*true|live_execution_authorized:[[:space:]]*true" "$@" && ! "$1" dispatch --help | rg -q -- "--command|--target|--uid|--gid|--slice" && ! "$1" run-ordinary-slot --help | rg -q -- "--command|--target|--uid|--gid|--slice"' _ \
    "${TRANSPORT}" "${MANIFEST}" \
    "${SYSTEMD}/ken-actions-deploy-transaction-1.service" \
    "${SYSTEMD}/ken-actions-deploy-transaction-2.service" \
    "${SYSTEMD}/ken-frontend-production-builder@.service" \
    "${SYSTEMD}/ken-frontend-source-map-uploader@.service" \
    "${SYSTEMD}/ken-frontend-deploy-executor@.service"

echo
if (( FAILED == 0 )); then
  printf 'ACTION_TRANSPORT_TESTS_OK: %d assertions passed\n' "${RAN}"
  exit 0
fi
printf 'ACTION_TRANSPORT_TESTS_FAIL: %d failed / %d assertions\n' "${FAILED}" "${RAN}"
exit 1
