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
assert manifest["transport_version"] == "2026-08-20.1"
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

import hashlib
import importlib.machinery
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

    def test_frontend_stays_unavailable_without_exact_receipt_transport(self):
        for action in ({}, {"production_build": {"phase_transport_sha256": "a" * 64, "deploy_contract_sha256": "b" * 64}}):
            with self.assertRaises(transport.TransportReject) as caught:
                transport.require_frontend_receipt_transport(action)
            self.assertEqual(caught.exception.code, "frontend_receipt_transport_unavailable")

    def test_manifest_runtime_schema_is_exact_and_complete(self):
        import yaml
        manifest = yaml.safe_load(Path(path).parent.parent.joinpath("inventory/action-transport.lock.yaml").read_text())
        transport.validate_manifest_schema(manifest)
        mutations = []
        mutations.append({**manifest, "unreviewed": {}})
        missing = dict(manifest); missing["artifacts"] = {"coordinator": manifest["artifacts"]["coordinator"]}; mutations.append(missing)
        wrong = dict(manifest); wrong["task6_core"] = {**manifest["task6_core"], "policy_sha256": "f" * 64}; mutations.append(wrong)
        for mutation in mutations:
            with self.assertRaises(transport.TransportReject):
                transport.validate_manifest_schema(mutation)


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
