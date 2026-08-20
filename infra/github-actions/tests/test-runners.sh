#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd -P)"
GA_ROOT="${ROOT}/infra/github-actions"

python3 - "${GA_ROOT}" <<'PY'
from __future__ import annotations

import re
import sys
from pathlib import Path

import yaml


class UniqueLoader(yaml.SafeLoader):
    pass


def construct_mapping(loader, node, deep=False):
    mapping = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise AssertionError(f"duplicate YAML key: {key}")
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


UniqueLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    construct_mapping,
)

root = Path(sys.argv[1])
platform_path = root / "inventory/runner-platform.yaml"
systemd = root / "systemd"
failures: list[str] = []


def check(condition, message):
    if not condition:
        failures.append(message)


def unit_values(path):
    result = {}
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", "[")) or "=" not in line:
            continue
        key, value = line.split("=", 1)
        result.setdefault(key, []).append(value)
    return result


try:
    platform = yaml.load(platform_path.read_text(), Loader=UniqueLoader)
except Exception as error:
    raise SystemExit(f"RUNNER_CONTRACT_FAIL invalid desired state: {error}")

expected_names = [f"ken-ci-standard-{index:02d}" for index in range(1, 11)] + [
    "ken-ci-heavy-01",
    "ken-ci-heavy-02",
    "ken-deploy-nonproduction-01",
    "ken-deploy-production-01",
]
enabled_ci_names = [f"ken-ci-standard-{index:02d}" for index in range(1, 9)] + [
    "ken-ci-heavy-01",
    "ken-ci-heavy-02",
]
disabled_names = {"ken-ci-standard-09", "ken-ci-standard-10"}
enabled_deploy_names = ["ken-deploy-nonproduction-01", "ken-deploy-production-01"]
expected_labels = {
    "standard": ["self-hosted", "linux", "x64", "ken-ci", "standard"],
    "heavy": ["self-hosted", "linux", "x64", "ken-ci", "heavy"],
    "nonproduction": ["self-hosted", "linux", "x64", "ken-deploy", "nonproduction"],
    "production": ["self-hosted", "linux", "x64", "ken-deploy", "production"],
}
expected_ci_slices = {
    name: name.replace("ken-ci-", "ken-ci-runner-") + ".slice"
    for name in enabled_ci_names
}
expected_slice_files = set(expected_ci_slices.values())

check(platform.get("schema_version") == 2, "runner platform schema_version must be 2")
check(platform.get("organization") == "Ken-Technology", "organization must be Ken-Technology")
check(platform.get("runner_distribution") == {
    "version": "2.336.0",
    "archive_url": "https://github.com/actions/runner/releases/download/v2.336.0/actions-runner-linux-x64-2.336.0.tar.gz",
    "sha256": "04cf0be1aff4c3ec3554466c39124ca250e3effd8873bb7e8d68535aa9505d5d",
    "release_id": 356901421,
    "asset_id": 483731096,
    "provenance_url": "https://api.github.com/repos/actions/runner/releases/356901421",
    "provenance_retrieved_at": "2026-08-19T20:52:33Z",
}, "exact pinned Actions runner distribution and provenance")
runners = platform.get("runners") or []
check([item.get("name") for item in runners] == expected_names, "exact ordered 14-identity reservation model")
check(sum(item.get("enabled") is True for item in runners) == 12, "exactly twelve identities enabled")
check([item.get("name") for item in runners if item.get("enabled") and item.get("vm") == "ken-ci"] == enabled_ci_names, "exact ten enabled CI identities")
check([item.get("name") for item in runners if item.get("enabled") and item.get("vm") == "ken-deploy"] == enabled_deploy_names, "exact two enabled deploy identities")
check({item.get("name") for item in runners if item.get("enabled") is False} == disabled_names, "09/10 are the only disabled reservations")

unique_fields = ["name", "user", "uid", "gid", "home", "runner_root", "work_root", "subuid_start", "subgid_start", "systemd_instance"]
for field in unique_fields:
    values = [item.get(field) for item in runners]
    check(None not in values and len(values) == len(set(values)), f"unique {field}")

ranges = []
for runner in runners:
    name = runner.get("name")
    check("credential_profile" not in runner and "credential_delivery" not in runner, f"{name}: runner inventory has no credential fields")
    check(runner.get("uid") == runner.get("gid"), f"{name}: UID and GID match")
    check(runner.get("subuid_start") == runner.get("subgid_start") and runner.get("subid_count") == 65536, f"{name}: exact subordinate-ID allocation")
    start = runner.get("subuid_start")
    if isinstance(start, int):
        ranges.append((start, start + 65536, name))
    base = f"/var/lib/ken-runners/{name}"
    check(runner.get("home") == f"{base}/home" and runner.get("runner_root") == f"{base}/runner" and runner.get("work_root") == f"{base}/work", f"{name}: canonical account paths")
    docker = runner.get("docker") or {}
    check(docker.get("enabled") is (runner.get("vm") == "ken-ci"), f"{name}: rootless Docker only on CI")
    if runner.get("vm") == "ken-ci":
        check(docker.get("data_root") == f"{base}/docker" and docker.get("runtime_root") == f"/run/ken-rootless-docker/{name}", f"{name}: private Docker roots")
        expected_label_key = runner.get("class")
    else:
        expected_label_key = name.removeprefix("ken-deploy-").removesuffix("-01")
    check(runner.get("labels") == expected_labels.get(expected_label_key), f"{name}: exact labels")
    if name in expected_ci_slices:
        check(runner.get("slice") == expected_ci_slices[name], f"{name}: exact concrete slice")
    elif name in disabled_names:
        check(runner.get("slice") is None, f"{name}: disabled reservation has no slice")
    else:
        check(runner.get("slice") == "ken-actions-deploy-listeners.slice", f"{name}: deploy listener aggregate slice")

for (_, end, name), (next_start, _, _) in zip(sorted(ranges), sorted(ranges)[1:]):
    check(end <= next_start, f"{name}: subordinate-ID range does not overlap")

classes = platform.get("classes") or {}
check(classes.get("standard") == {"cpu_quota": "200%", "memory_max": "8G", "memory_swap_max": 0, "tasks_max": 4096}, "standard resources are 200%/8G/0 swap")
check(classes.get("heavy") == {"cpu_quota": "400%", "memory_max": "16G", "memory_swap_max": 0, "tasks_max": 8192}, "heavy resources are 400%/16G/0 swap")
check("deploy" not in classes, "deploy resources use aggregate hierarchy, not per-runner class")

actual_slice_files = {path.name for path in systemd.glob("ken-ci-runner-*.slice")}
check(actual_slice_files == expected_slice_files, "exactly ten reviewed concrete CI slice files")
check(not list(systemd.glob("ken*runner*@*.slice")), "no instance-marked runner slice file")
check(not (systemd / "ken-runner@.slice").exists(), "invalid ken-runner@.slice removed")
check(not any("standard-09" in name or "standard-10" in name for name in actual_slice_files), "disabled reservations have no slices")
for name, filename in expected_ci_slices.items():
    path = systemd / filename
    check(path.is_file() and not path.is_symlink(), f"{name}: concrete slice exists")
    if not path.is_file():
        continue
    values = unit_values(path)
    runner_class = "standard" if "standard" in name else "heavy"
    limits = classes.get(runner_class) or {}
    check(values.get("CPUQuota") == [str(limits.get("cpu_quota"))], f"{name}: concrete CPU quota")
    check(values.get("MemoryMax") == [str(limits.get("memory_max"))], f"{name}: concrete memory max")
    check(values.get("MemorySwapMax") == [str(limits.get("memory_swap_max"))], f"{name}: concrete zero swap")
    check(values.get("TasksMax") == [str(limits.get("tasks_max"))], f"{name}: concrete tasks max")
    for accounting in ("CPUAccounting", "MemoryAccounting", "TasksAccounting"):
        check(values.get(accounting) == ["true"], f"{name}: {accounting}")

deploy_expected = {
    "ken-actions-deploy.slice": {"MemoryMax": "10G", "MemorySwapMax": "0", "CPUQuota": "350%", "TasksMax": "2048"},
    "ken-actions-deploy-listeners.slice": {"MemoryMax": "512M", "MemorySwapMax": "0", "CPUQuota": "25%", "TasksMax": "128"},
    "ken-actions-deploy-brokers.slice": {"MemoryMax": "768M", "MemorySwapMax": "0", "CPUQuota": "25%", "TasksMax": "128"},
    "ken-actions-deploy-transaction-1.slice": {"MemoryMax": "3584M", "MemorySwapMax": "0", "CPUQuota": "125%", "TasksMax": "384"},
    "ken-actions-deploy-transaction-2.slice": {"MemoryMax": "3584M", "MemorySwapMax": "0", "CPUQuota": "125%", "TasksMax": "384"},
    "ken-actions-deploy-builder.slice": {"MemoryMax": "8G", "MemorySwapMax": "0", "CPUQuota": "300%", "TasksMax": "1024"},
    "ken-actions-deploy-uploader.slice": {"MemoryMax": "512M", "MemorySwapMax": "0", "CPUQuota": "50%", "TasksMax": "128"},
    "ken-actions-deploy-executor.slice": {"MemoryMax": "1G", "MemorySwapMax": "0", "CPUQuota": "100%", "TasksMax": "256"},
}
for filename, expected in deploy_expected.items():
    path = systemd / filename
    check(path.is_file() and not path.is_symlink(), f"deploy slice exists: {filename}")
    if path.is_file():
        values = unit_values(path)
        for key, value in expected.items():
            check(values.get(key) == [value], f"{filename}: {key}={value}")
        for accounting in ("CPUAccounting", "MemoryAccounting", "TasksAccounting"):
            check(values.get(accounting) == ["true"], f"{filename}: {accounting}")
        if filename != "ken-actions-deploy.slice":
            check(filename.startswith("ken-actions-deploy-"), f"{filename}: dash-derived parent ancestry")

deploy = platform.get("deploy_resources") or {}
check(deploy.get("parent_slice") == "ken-actions-deploy.slice", "desired state names deploy parent")
check(deploy.get("ordinary_peak") == {"memory_mib": 8448, "cpu_quota": "300%"}, "two ordinary actions equal 8.25 GiB/300%")
check(deploy.get("builder_peak") == {"memory_mib": 9472, "cpu_quota": "350%"}, "exclusive builder phase equals 9.25 GiB/350%")
check(deploy.get("guest_headroom") == {"memory_gib": 2, "cpu_quota": "50%", "minimum_mem_available_gib": 1.5, "swap_allowed": False}, "deploy OS headroom contract")
check(deploy.get("ordinary_leases") == 2 and deploy.get("exclusive_action") == "ken-frontend-production-release" and deploy.get("writer_preference") is True, "two shared leases plus writer-preferring exclusive action")
expected_assignments = {
    "listeners": "ken-actions-deploy-listeners.slice",
    "brokers": "ken-actions-deploy-brokers.slice",
    "transaction_1": "ken-actions-deploy-transaction-1.slice",
    "transaction_2": "ken-actions-deploy-transaction-2.slice",
    "builder": "ken-actions-deploy-builder.slice",
    "uploader": "ken-actions-deploy-uploader.slice",
    "executor": "ken-actions-deploy-executor.slice",
}
check(deploy.get("slice_assignments") == expected_assignments, "exact deploy service slice assignments")

listener = (systemd / "ken-runner@.service").read_text()
docker_unit = (systemd / "ken-runner-docker@.service").read_text()
guest_gates = {
    "ken-actions-guest-firewall.service",
    "ken-actions-guest-runtime-verify.service",
}
for unit_name, unit_text in (("listener", listener), ("rootless Docker", docker_unit)):
    values = {}
    for raw in unit_text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", "[")) or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values.setdefault(key, []).extend(value.split())
    check(guest_gates <= set(values.get("Requires", [])), f"{unit_name} hard-requires both guest gates")
    check(guest_gates <= set(values.get("After", [])), f"{unit_name} starts after both guest gates")
for control in ("NoNewPrivileges=true", "PrivateTmp=true", "ProtectSystem=strict", "ProtectHome=read-only", "RestrictSUIDSGID=true", "LockPersonality=true", "Restart=always", "RestartSec=5"):
    check(control in listener, f"listener hardening: {control}")
check("Slice=ken-runner-%i.slice" not in listener + docker_unit, "templates do not invent instance-marked slices")
check("/var/run/docker.sock" not in listener + docker_unit, "no rootful Docker socket")
check("NoNewPrivileges=true" not in docker_unit, "rootless Docker may execute the pinned newuidmap helper")

combined = "\n".join(path.read_text(errors="replace") for path in [platform_path, systemd / "ken-runner@.service", systemd / "ken-runner-docker@.service"])
for forbidden in ("LoadCredential", "OP_SERVICE_ACCOUNT_TOKEN", "credential_profile", "credential_delivery", "1password/load-secrets-action", "docker system prune", "--replace"):
    check(forbidden not in combined, f"runner contract forbids {forbidden}")
check(not re.search(r"(?:^|[ =/])sudo(?:[ =/]|$)", combined, re.M), "runner contract has no sudo")
check(not re.search(r"(?:SupplementaryGroups|groups?).*docker", combined, re.I), "runner account has no Docker group")

if failures:
    print("\n".join(f"RUNNER_CONTRACT_FAIL {failure}" for failure in failures))
    raise SystemExit(1)
print("RUNNER_CONTRACT_OK")
PY

python3 - "${GA_ROOT}" <<'PY'
from __future__ import annotations

import copy
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import yaml

root = Path(sys.argv[1])
register = root / "scripts/register-runners.sh"
verify = root / "scripts/verify-platform.sh"
platform_path = root / "inventory/runner-platform.yaml"
platform = yaml.safe_load(platform_path.read_text())
failures = []


def call(argv, *, env=None):
    return subprocess.run(argv, text=True, capture_output=True, env={**os.environ, **(env or {})})


def check(condition, message, result=None):
    if condition:
        return
    if result is not None:
        failures.append(f"{message}: exit={result.returncode} stdout={result.stdout!r} stderr={result.stderr!r}")
    else:
        failures.append(message)


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n")


def write_artifact_authority(base):
    authority_root = base / "authority"
    authority_root.mkdir(parents=True, exist_ok=True)
    runtime_lock = authority_root / "broker-runtime.lock.yaml"
    runtime_lock.write_text("schema_version: 1\ninstallation_readiness: guest-consumable\n")
    runtime_lock.chmod(0o600)
    runtime_lock_sha256 = hashlib.sha256(runtime_lock.read_bytes()).hexdigest()
    ci_image_sha256 = "1" * 64
    deploy_image_sha256 = "2" * 64
    ci_receipt_sha256 = "3" * 64
    deploy_receipt_sha256 = "4" * 64
    manifest = {
        "schema_version": 1,
        "authority": {
            "task6_commit": "6609ab6c4f4e6ca9d2e37b75fab36a2fc337de6d",
            "broker_runtime_lock_sha256": runtime_lock_sha256,
            "op_broker_policy_sha256": "5" * 64,
        },
        "verification": {
            "result_receipts": {
                "ci": {"path": "/var/lib/ken-actions/evidence/ken-ci.receipt", "sha256": ci_receipt_sha256},
                "deploy": {"path": "/var/lib/ken-actions/evidence/ken-deploy.receipt", "sha256": deploy_receipt_sha256},
            },
        },
        "derived_images": {
            "status": "ready",
            "ci": {
                "path": "/mnt/data/libvirt/images/ken-ci.qcow2",
                "sha256": ci_image_sha256,
                "virtual_size_gib": 750,
                "receipt_sha256": ci_receipt_sha256,
            },
            "deploy": {
                "path": "/mnt/data/libvirt/images/ken-deploy.qcow2",
                "sha256": deploy_image_sha256,
                "virtual_size_gib": 80,
                "receipt_sha256": deploy_receipt_sha256,
            },
        },
        "readiness": {"state": "ready", "live_apply_allowed": True},
    }
    guest_manifest = authority_root / "guest-image-manifest.yaml"
    guest_manifest.write_text(yaml.safe_dump(manifest, sort_keys=False))
    guest_manifest.chmod(0o600)
    return {
        "task6_runtime_lock_sha256": runtime_lock_sha256,
        "guest_image_manifest_sha256": hashlib.sha256(guest_manifest.read_bytes()).hexdigest(),
        "derived_images": {"ken-ci": ci_image_sha256, "ken-deploy": deploy_image_sha256},
    }


def registration_command(base, *extra):
    return ["bash", str(register), "--org", "Ken-Technology", "--all", "--test-fake-root", str(base), *extra]


def prepare_fixture(base):
    artifact_authority = write_artifact_authority(base)
    write_json(base / "task4-evidence.json", {
        "schema_version": 1,
        "approval_phrase": "Task 4/6 approved and 1Password ready",
        "combined_approval_verified": True,
        "host": "root@167.235.8.250",
        "host_memory_available_gib": 64,
        "firewall_generation_verified": True,
        "artifact_authority": artifact_authority,
        "vms": {
            "ken-ci": {"healthy": True, "isolation_verified": True, "memory_gib": 112, "memory_health_verified": True},
            "ken-deploy": {"healthy": True, "isolation_verified": True, "memory_gib": 12, "memory_health_verified": True},
        },
    })
    (base / "task4-evidence.json").chmod(0o600)
    repositories = [
        {"name": item["name"], "id": item["repository_id"], "visibility": "private", "archived": False}
        for item in platform["groups"]["ci"]["repositories"]
    ]
    write_json(base / "github-repository-resolver.json", {
        "organization": "Ken-Technology",
        "resolved_at": platform["source_inventory"]["repository_ids_resolved_at"],
        "repositories": repositories,
    })


def counters(memory, cpu, pids):
    return {"memory.current": memory, "cpu.stat.usage_usec": cpu, "pids.current": pids}


def write_runtime_evidence(base):
    ci = {}
    for runner in platform["runners"]:
        if not runner["enabled"] or runner["vm"] != "ken-ci":
            continue
        slice_name = runner["slice"]
        ancestor = f"/{slice_name}"
        ci[runner["name"]] = {
            "listener": {
                "unit": f"ken-runner@{runner['name']}.service",
                "slice": slice_name,
                "control_group": f"{ancestor}/ken-runner@{runner['name']}.service",
                "ancestors": [slice_name],
                "before": counters(100, 1000, 2),
                "during": counters(200, 2000, 3),
            },
            "docker": {
                "unit": f"ken-runner-docker@{runner['name']}.service",
                "slice": slice_name,
                "control_group": f"{ancestor}/ken-runner-docker@{runner['name']}.service",
                "ancestors": [slice_name],
                "before": counters(200, 2000, 3),
                "during": counters(400, 4000, 5),
            },
            "combined": {
                "slice": slice_name,
                "before": counters(100, 1000, 2),
                "during": counters(500, 5000, 7),
                "limit_enforced": True,
                "sibling_counters_unchanged": True,
            },
        }
    assignments = platform["deploy_resources"]["slice_assignments"]
    units = {
        "listeners": ["ken-runner@ken-deploy-nonproduction-01.service", "ken-runner@ken-deploy-production-01.service"],
        "brokers": ["ken-op-broker@nonproduction.service", "ken-op-broker@production.service"],
        "transaction_1": ["ken-op-executor@transaction-1.service"],
        "transaction_2": ["ken-op-executor@transaction-2.service"],
        "builder": ["ken-frontend-production-builder@test.service"],
        "uploader": ["ken-frontend-source-map-uploader@test.service"],
        "executor": ["ken-frontend-deploy-executor@test.service"],
    }
    deploy_units = {}
    for role, names in units.items():
        child_slice = assignments[role]
        for unit in names:
            deploy_units[unit] = {
                "role": role,
                "slice": child_slice,
                "control_group": f"/ken-actions-deploy.slice/{child_slice}/{unit}",
                "ancestors": [child_slice, "ken-actions-deploy.slice"],
                "child_before": counters(100, 1000, 1),
                "child_during": counters(200, 2000, 2),
                "parent_before": counters(1000, 10000, 10),
                "parent_during": counters(1200, 12000, 12),
            }
    write_json(base / "runtime-evidence.json", {
        "cgroup_version": 2,
        "ci": ci,
        "deploy": {
            "units": deploy_units,
            "ordinary": {"leases_available_after": 2, "memory_mib_peak": 8448, "cpu_percent_peak": 300, "mem_available_gib_min": 1.5, "swap_bytes": 0, "oom_events": 0, "brokers_responsive": True, "independent_release": True},
            "exclusive": {"writer_preference": True, "both_leases_held": True, "queued_ordinary_side_effects": 0, "builder_memory_mib_peak": 9472, "builder_cpu_percent_peak": 350, "mem_available_gib_min": 1.5, "swap_bytes": 0, "oom_events": 0, "brokers_responsive": True, "uploader_or_executor_overlap": False, "leases_available_after": 2, "cleanup_verified": True},
        },
        "uid_output_policy_active_before_listeners": True,
        "cleanup_verified": True,
        "host_resources_healthy": True,
    })


with tempfile.TemporaryDirectory() as temporary:
    base = Path(temporary)
    prepare_fixture(base)
    env = {"KEN_RUNNER_OFFLINE_TEST": "1", "KEN_RUNNER_TEST_ARCHIVE_SHA256": platform["runner_distribution"]["sha256"]}

    dry = call(["bash", str(register), "--org", "Ken-Technology", "--all", "--dry-run"])
    check(dry.returncode == 0 and "RUNNER_PLAN_ENABLED=12" in dry.stdout and "RUNNER_PLAN_DISABLED=2" in dry.stdout and "NO_MUTATION=1" in dry.stdout, "dry-run reports exact desired state without transport", dry)

    live_refusal = call(["bash", str(register), "--org", "Ken-Technology", "--all"])
    check(live_refusal.returncode != 0 and "approval evidence" in live_refusal.stderr, "unapproved live registration remains blocked", live_refusal)

    first = call(registration_command(base), env=env)
    check(first.returncode == 0 and "CREATED_RUNNERS=12" in first.stdout and "REGISTRATION_MODE=offline-fake" in first.stdout, "offline registration creates exact 10 CI plus 2 deploy", first)
    if first.returncode != 0:
        print("\n".join(f"RUNNER_BEHAVIOR_FAIL {failure}" for failure in failures))
        raise SystemExit(1)
    second = call(registration_command(base), env=env)
    check(second.returncode == 0 and "NO_CHANGES=1" in second.stdout, "exact rerun is idempotent", second)

    disabled = [runner for runner in platform["runners"] if not runner["enabled"]]
    for runner in disabled:
        name = runner["name"]
        guest = base / "guests" / runner["vm"]
        probes = [
            base / "github/runners" / f"{name}.json",
            guest / "runners" / f"{name}.json",
            guest / "accounts" / f"{name}.json",
            guest / "subuids" / f"{name}.json",
            guest / "subgids" / f"{name}.json",
            guest / "units" / f"ken-runner@{name}.service",
            guest / "units" / f"ken-runner-docker@{name}.service",
            guest / "filesystem" / runner["work_root"].lstrip("/"),
        ]
        check(not any(path.exists() or path.is_symlink() for path in probes), f"{name}: no account/workspace/service/registration")

    enabled = [runner for runner in platform["runners"] if runner["enabled"]]
    check(len(list((base / "github/runners").glob("*.json"))) == 12, "fake GitHub has exactly twelve registrations")
    for runner in enabled:
        guest = base / "guests" / runner["vm"]
        account = json.loads((guest / "accounts" / f"{runner['name']}.json").read_text())
        check(account.get("locked") is True and account.get("groups") == [] and account.get("sudo") is False, f"{runner['name']}: locked no-group no-sudo account")
        check((guest / "subuids" / f"{runner['name']}.json").is_file() and (guest / "subgids" / f"{runner['name']}.json").is_file(), f"{runner['name']}: subordinate-ID state installed")
        listener = (guest / "units" / f"ken-runner@{runner['name']}.service").read_text()
        check(f"Slice={runner['slice']}" in listener, f"{runner['name']}: listener exact Slice assignment")
        for dependency in ("ken-actions-guest-firewall.service", "ken-actions-guest-runtime-verify.service"):
            check(f"Requires={dependency}" in listener and f"After={dependency}" in listener, f"{runner['name']}: listener hard dependency {dependency}")
        docker_unit = guest / "units" / f"ken-runner-docker@{runner['name']}.service"
        if runner["vm"] == "ken-ci":
            docker_text = docker_unit.read_text() if docker_unit.is_file() else ""
            check(docker_unit.is_file() and f"Slice={runner['slice']}" in docker_text, f"{runner['name']}: Docker shares exact concrete slice")
            for dependency in ("ken-actions-guest-firewall.service", "ken-actions-guest-runtime-verify.service"):
                check(f"Requires={dependency}" in docker_text and f"After={dependency}" in docker_text, f"{runner['name']}: Docker hard dependency {dependency}")
        else:
            check(not docker_unit.exists() and "DOCKER_HOST=" not in listener, f"{runner['name']}: deploy listener has no Docker")

    write_runtime_evidence(base)
    verified = call(["bash", str(verify), "runners", "--test-fake-root", str(base)], env={"KEN_RUNNER_OFFLINE_TEST": "1"})
    check(verified.returncode == 0 and "RUNNERS_OK=12" in verified.stdout and "CI_SLICES_OK=10" in verified.stdout and "DEPLOY_CGROUP_OK=1" in verified.stdout, "read-only verifier proves identity, slices, ancestry, counters, and pressure", verified)

    wrong_slice_root = base / "wrong-slice"
    shutil.copytree(base, wrong_slice_root)
    evidence_path = wrong_slice_root / "runtime-evidence.json"
    evidence = json.loads(evidence_path.read_text())
    evidence["ci"]["ken-ci-standard-01"]["docker"]["slice"] = "ken-ci-runner-standard-02.slice"
    write_json(evidence_path, evidence)
    wrong_slice = call(["bash", str(verify), "runners", "--test-fake-root", str(wrong_slice_root)], env={"KEN_RUNNER_OFFLINE_TEST": "1"})
    check(wrong_slice.returncode != 0 and "cgroup" in wrong_slice.stderr.lower(), "sibling-slice mutation fails closed", wrong_slice)

    wrong_parent_root = base / "wrong-parent"
    shutil.copytree(base, wrong_parent_root)
    evidence_path = wrong_parent_root / "runtime-evidence.json"
    evidence = json.loads(evidence_path.read_text())
    unit = "ken-frontend-production-builder@test.service"
    evidence["deploy"]["units"][unit]["ancestors"] = ["ken-actions-deploy-builder.slice", "system.slice"]
    write_json(evidence_path, evidence)
    wrong_parent = call(["bash", str(verify), "runners", "--test-fake-root", str(wrong_parent_root)], env={"KEN_RUNNER_OFFLINE_TEST": "1"})
    check(wrong_parent.returncode != 0 and "ancestor" in wrong_parent.stderr.lower(), "deploy wrong-parent mutation fails before routing", wrong_parent)

    stale_counter_root = base / "stale-counter"
    shutil.copytree(base, stale_counter_root)
    evidence_path = stale_counter_root / "runtime-evidence.json"
    evidence = json.loads(evidence_path.read_text())
    unit = "ken-op-executor@transaction-1.service"
    evidence["deploy"]["units"][unit]["parent_during"] = evidence["deploy"]["units"][unit]["parent_before"]
    write_json(evidence_path, evidence)
    stale_counter = call(["bash", str(verify), "runners", "--test-fake-root", str(stale_counter_root)], env={"KEN_RUNNER_OFFLINE_TEST": "1"})
    check(stale_counter.returncode != 0 and "counter" in stale_counter.stderr.lower(), "missing parent counter roll-up fails closed", stale_counter)

    disabled_root = base / "disabled-state"
    shutil.copytree(base, disabled_root)
    write_json(disabled_root / "guests/ken-ci/accounts/ken-ci-standard-09.json", {"unexpected": True})
    disabled_state = call(["bash", str(verify), "runners", "--test-fake-root", str(disabled_root)], env={"KEN_RUNNER_OFFLINE_TEST": "1"})
    check(disabled_state.returncode != 0 and "disabled runner" in disabled_state.stderr.lower(), "disabled account mutation fails closed", disabled_state)

    drift_root = base / "drift"
    shutil.copytree(base, drift_root)
    path = drift_root / "github/runners/ken-ci-standard-01.json"
    drift = json.loads(path.read_text())
    drift["labels"] = ["self-hosted"]
    write_json(path, drift)
    drift_result = call(registration_command(drift_root), env=env)
    check(drift_result.returncode != 0 and "identity drift" in drift_result.stderr.lower(), "existing local/GitHub identity drift is refused without --replace", drift_result)

with tempfile.TemporaryDirectory() as temporary:
    rollback_root = Path(temporary)
    prepare_fixture(rollback_root)
    rollback = call(registration_command(rollback_root), env={
        "KEN_RUNNER_OFFLINE_TEST": "1",
        "KEN_RUNNER_TEST_ARCHIVE_SHA256": platform["runner_distribution"]["sha256"],
        "KEN_RUNNER_TEST_FAIL_AFTER": "ken-ci-standard-01:github",
    })
    check(rollback.returncode != 0 and "ROLLBACK_STATUS=ok" in rollback.stderr and not list((rollback_root / "github/runners").glob("*.json")), "failed transaction rolls back only run-created state", rollback)

with tempfile.TemporaryDirectory() as temporary:
    missing_approval = Path(temporary)
    prepare_fixture(missing_approval)
    evidence = json.loads((missing_approval / "task4-evidence.json").read_text())
    evidence["combined_approval_verified"] = False
    write_json(missing_approval / "task4-evidence.json", evidence)
    result = call(registration_command(missing_approval), env={"KEN_RUNNER_OFFLINE_TEST": "1", "KEN_RUNNER_TEST_ARCHIVE_SHA256": platform["runner_distribution"]["sha256"]})
    check(result.returncode != 0 and "approval" in result.stderr.lower(), "combined Task 4/6 approval gate cannot be bypassed", result)

for mutation, expected_message in (
    ("missing-field", "schema"),
    ("extra-field", "schema"),
    ("malformed-digest", "malformed"),
    ("runtime-lock-digest", "runtime lock digest"),
    ("manifest-digest", "guest image manifest digest"),
    ("derived-image-digest", "derived image digest"),
    ("manifest-not-ready", "not ready"),
):
    with tempfile.TemporaryDirectory() as temporary:
        authority_root = Path(temporary)
        prepare_fixture(authority_root)
        evidence_path = authority_root / "task4-evidence.json"
        evidence = json.loads(evidence_path.read_text())
        if mutation == "missing-field":
            evidence["artifact_authority"].pop("task6_runtime_lock_sha256")
        elif mutation == "extra-field":
            evidence["unexpected"] = True
        elif mutation == "malformed-digest":
            evidence["artifact_authority"]["task6_runtime_lock_sha256"] = "ABC"
        elif mutation == "runtime-lock-digest":
            evidence["artifact_authority"]["task6_runtime_lock_sha256"] = "a" * 64
        elif mutation == "manifest-digest":
            evidence["artifact_authority"]["guest_image_manifest_sha256"] = "b" * 64
        elif mutation == "derived-image-digest":
            evidence["artifact_authority"]["derived_images"]["ken-ci"] = "c" * 64
        elif mutation == "manifest-not-ready":
            manifest_path = authority_root / "authority/guest-image-manifest.yaml"
            manifest = yaml.safe_load(manifest_path.read_text())
            manifest["readiness"] = {"state": "blocked", "live_apply_allowed": False}
            manifest["derived_images"]["status"] = "blocked"
            manifest_path.write_text(yaml.safe_dump(manifest, sort_keys=False))
            evidence["artifact_authority"]["guest_image_manifest_sha256"] = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
        write_json(evidence_path, evidence)
        evidence_path.chmod(0o600)
        result = call(registration_command(authority_root), env={"KEN_RUNNER_OFFLINE_TEST": "1", "KEN_RUNNER_TEST_ARCHIVE_SHA256": platform["runner_distribution"]["sha256"]})
        check(result.returncode != 0 and expected_message in result.stderr.lower(), f"{mutation} evidence mutation fails before registration", result)

with tempfile.TemporaryDirectory() as temporary:
    unsafe_root = Path(temporary)
    prepare_fixture(unsafe_root)
    evidence_path = unsafe_root / "task4-evidence.json"
    evidence_path.chmod(0o644)
    unsafe = call(registration_command(unsafe_root), env={"KEN_RUNNER_OFFLINE_TEST": "1", "KEN_RUNNER_TEST_ARCHIVE_SHA256": platform["runner_distribution"]["sha256"]})
    check(unsafe.returncode != 0 and "mode 0600" in unsafe.stderr.lower(), "unsafe approval evidence mode fails before registration", unsafe)
    evidence_path.unlink()
    evidence_path.symlink_to(unsafe_root / "authority/guest-image-manifest.yaml")
    symlinked = call(registration_command(unsafe_root), env={"KEN_RUNNER_OFFLINE_TEST": "1", "KEN_RUNNER_TEST_ARCHIVE_SHA256": platform["runner_distribution"]["sha256"]})
    check(symlinked.returncode != 0 and "symlink" in symlinked.stderr.lower(), "symlinked approval evidence fails before registration", symlinked)

with tempfile.TemporaryDirectory() as temporary:
    duplicate_root = Path(temporary)
    prepare_fixture(duplicate_root)
    evidence_path = duplicate_root / "task4-evidence.json"
    original = evidence_path.read_text().rstrip()
    evidence_path.write_text(original[:-1] + ',"schema_version":1}\n')
    evidence_path.chmod(0o600)
    duplicate = call(registration_command(duplicate_root), env={"KEN_RUNNER_OFFLINE_TEST": "1", "KEN_RUNNER_TEST_ARCHIVE_SHA256": platform["runner_distribution"]["sha256"]})
    check(duplicate.returncode != 0 and "duplicate json key" in duplicate.stderr.lower(), "duplicate approval evidence JSON key fails before registration", duplicate)

with tempfile.TemporaryDirectory() as temporary:
    authority_symlink_root = Path(temporary)
    prepare_fixture(authority_symlink_root)
    lock_path = authority_symlink_root / "authority/broker-runtime.lock.yaml"
    lock_copy = authority_symlink_root / "authority/broker-runtime.lock.copy"
    lock_copy.write_bytes(lock_path.read_bytes())
    lock_path.unlink()
    lock_path.symlink_to(lock_copy)
    authority_symlink = call(registration_command(authority_symlink_root), env={"KEN_RUNNER_OFFLINE_TEST": "1", "KEN_RUNNER_TEST_ARCHIVE_SHA256": platform["runner_distribution"]["sha256"]})
    check(authority_symlink.returncode != 0 and "runtime lock" in authority_symlink.stderr.lower() and "symlink" in authority_symlink.stderr.lower(), "symlinked runtime authority fails before registration", authority_symlink)

with tempfile.TemporaryDirectory() as temporary:
    bad_hash = Path(temporary)
    prepare_fixture(bad_hash)
    result = call(registration_command(bad_hash), env={"KEN_RUNNER_OFFLINE_TEST": "1", "KEN_RUNNER_TEST_ARCHIVE_SHA256": "0" * 64})
    check(result.returncode != 0 and "checksum" in result.stderr.lower(), "runner archive checksum drift fails before registration", result)

with tempfile.TemporaryDirectory() as temporary:
    mutation_root = Path(temporary)
    duplicate_platform = mutation_root / "duplicate.yaml"
    duplicate_platform.write_text(platform_path.read_text() + "\norganization: Ken-Technology\n")
    duplicate = call(["bash", str(register), "--org", "Ken-Technology", "--all", "--dry-run"], env={"KEN_RUNNER_PLATFORM_FILE": str(duplicate_platform)})
    check(duplicate.returncode != 0 and "duplicate" in duplicate.stderr.lower(), "duplicate desired-state YAML key fails closed", duplicate)

    mutated = copy.deepcopy(platform)
    mutated["runners"][0]["labels"] = ["self-hosted"]
    labels_path = mutation_root / "labels.yaml"
    labels_path.write_text(yaml.safe_dump(mutated, sort_keys=False))
    labels_result = call(["bash", str(register), "--org", "Ken-Technology", "--all", "--dry-run"], env={"KEN_RUNNER_PLATFORM_FILE": str(labels_path)})
    check(labels_result.returncode != 0 and "label" in labels_result.stderr.lower(), "label mutation fails before registration", labels_result)

    mutated = copy.deepcopy(platform)
    mutated["runners"][0]["work_root"] = "/var/lib/ken-runners/ken-ci-standard-02/work"
    path_mutation = mutation_root / "path.yaml"
    path_mutation.write_text(yaml.safe_dump(mutated, sort_keys=False))
    path_result = call(["bash", str(register), "--org", "Ken-Technology", "--all", "--dry-run"], env={"KEN_RUNNER_PLATFORM_FILE": str(path_mutation)})
    check(path_result.returncode != 0 and ("path" in path_result.stderr.lower() or "work_root" in path_result.stderr.lower()), "runner path alias mutation fails before registration", path_result)

    mutated = copy.deepcopy(platform)
    mutated["runners"][0]["slice"] = "ken-ci-runner-standard-02.slice"
    slice_path = mutation_root / "slice.yaml"
    slice_path.write_text(yaml.safe_dump(mutated, sort_keys=False))
    slice_result = call(["bash", str(register), "--org", "Ken-Technology", "--all", "--dry-run"], env={"KEN_RUNNER_PLATFORM_FILE": str(slice_path)})
    check(slice_result.returncode != 0 and "slice" in slice_result.stderr.lower(), "sibling or unlisted desired slice fails before unit generation", slice_result)

with tempfile.TemporaryDirectory() as temporary:
    cleanup_root = Path(temporary)
    runner_a = "ken-ci-standard-01"
    runner_b = "ken-ci-standard-02"
    uid = os.getuid()
    runner_base = cleanup_root / "runners"
    runtime_base = cleanup_root / "runtime"
    state_base = cleanup_root / "state"
    for base_path in (runner_base, runtime_base, state_base):
        base_path.mkdir(mode=0o700)
    for name in (runner_a, runner_b):
        for child in ("home", "runner", "work", "docker"):
            (runner_base / name / child).mkdir(mode=0o700, parents=True, exist_ok=True)
        (runtime_base / name).mkdir(mode=0o700)
        (runtime_base / name / "docker.sock").write_text("test socket")
    (runner_base / runner_a / "work/delete-me").write_text("delete")
    (runner_base / runner_b / "work/sentinel").write_text("preserve")
    docker_log = cleanup_root / "docker.log"
    fake_docker = cleanup_root / "docker"
    fake_docker.write_text("#!/usr/bin/env bash\nprintf '%s\\n' \"$*\" >>\"${KEN_CLEANUP_DOCKER_LOG:?}\"\nexit 0\n")
    fake_docker.chmod(0o700)
    cleanup_env = {
        "KEN_RUNNER_BASE": str(runner_base),
        "KEN_RUNNER_RUNTIME_BASE": str(runtime_base),
        "KEN_RUNNER_STATE_BASE": str(state_base),
        "KEN_RUNNER_DOCKER_BIN": str(fake_docker),
        "KEN_CLEANUP_DOCKER_LOG": str(docker_log),
        "KEN_RUNNER_CLEANUP_ALLOW_NON_ROOT": "1",
        "KEN_RUNNER_CLEANUP_TEST_SOCKET_FILE": "1",
    }
    cleanup = root / "systemd/ken-runner-cleanup"
    cleaned = call(["bash", str(cleanup), "cleanup", runner_a, str(uid)], env=cleanup_env)
    check(cleaned.returncode == 0 and not any((runner_base / runner_a / "work").iterdir()), "cleanup removes only the completed workspace", cleaned)
    check((runner_base / runner_b / "work/sentinel").read_text() == "preserve", "cleanup preserves another runner workspace")
    calls = docker_log.read_text()
    check(f"--host unix://{runtime_base / runner_a / 'docker.sock'}" in calls and str(runtime_base / runner_b) not in calls and "/var/run/docker.sock" not in calls and "system prune" not in calls, "cleanup uses only the exact rootless Docker socket")
    malicious = call(["bash", str(cleanup), "cleanup", "../ken-ci-standard-02", str(uid)], env=cleanup_env)
    check(malicious.returncode != 0 and "invalid runner name" in malicious.stderr.lower(), "cleanup rejects path injection", malicious)
    disabled_cleanup = call(["bash", str(cleanup), "cleanup", "ken-ci-standard-09", str(uid)], env=cleanup_env)
    check(disabled_cleanup.returncode != 0 and "invalid runner name" in disabled_cleanup.stderr.lower(), "cleanup refuses disabled reservation identity", disabled_cleanup)

with tempfile.TemporaryDirectory() as temporary:
    pressure_root = Path(temporary)
    prepare_fixture(pressure_root)
    env = {"KEN_RUNNER_OFFLINE_TEST": "1", "KEN_RUNNER_TEST_ARCHIVE_SHA256": platform["runner_distribution"]["sha256"]}
    registered = call(registration_command(pressure_root), env=env)
    if registered.returncode == 0:
        write_runtime_evidence(pressure_root)
        evidence_path = pressure_root / "runtime-evidence.json"
        evidence = json.loads(evidence_path.read_text())
        evidence["deploy"]["exclusive"]["queued_ordinary_side_effects"] = 1
        evidence["deploy"]["exclusive"]["swap_bytes"] = 4096
        write_json(evidence_path, evidence)
        pressure = call(["bash", str(verify), "runners", "--test-fake-root", str(pressure_root)], env={"KEN_RUNNER_OFFLINE_TEST": "1"})
        check(pressure.returncode != 0 and "exclusive deploy pressure" in pressure.stderr.lower(), "exclusive overlap/swap mutation fails closed", pressure)
    else:
        check(False, "pressure fixture registration succeeds", registered)

with tempfile.TemporaryDirectory() as temporary:
    live_root = Path(temporary)
    approval_path = live_root / "approval.json"
    artifact_authority = write_artifact_authority(live_root)
    write_json(approval_path, {
        "schema_version": 1,
        "approval_phrase": "Task 4/6 approved and 1Password ready",
        "combined_approval_verified": True,
        "host": "root@167.235.8.250",
        "host_memory_available_gib": 64,
        "firewall_generation_verified": True,
        "artifact_authority": artifact_authority,
        "vms": {
            "ken-ci": {"healthy": True, "isolation_verified": True, "memory_gib": 112, "memory_health_verified": True},
            "ken-deploy": {"healthy": True, "isolation_verified": True, "memory_gib": 12, "memory_health_verified": True},
        },
    })
    approval_path.chmod(0o600)
    command_log = live_root / "commands.jsonl"
    state_path = live_root / "state.json"
    repository_catalog_path = live_root / "repository-catalog.json"
    write_json(repository_catalog_path, {
        item["name"]: {
            "id": item["repository_id"],
            "name": item["name"],
            "full_name": f"Ken-Technology/{item['name']}",
            "private": True,
            "visibility": "private",
            "archived": False,
            "owner": {"login": "Ken-Technology"},
        }
        for item in platform["groups"]["ci"]["repositories"]
    })
    write_json(state_path, {"groups": {}, "repositories": {}, "runners": {}, "guests": {}})
    fake_gh = live_root / "gh"
    fake_gh.write_text(r'''#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
from urllib.parse import parse_qs, urlsplit
state_path = Path(os.environ["KEN_FAKE_LIVE_STATE"])
log_path = Path(os.environ.get("KEN_FAKE_GH_LOG", os.environ["KEN_FAKE_COMMAND_LOG"]))
args = sys.argv[1:]
with log_path.open("a") as handle: handle.write(json.dumps({"tool":"gh","args":args})+"\n")
state = json.loads(state_path.read_text())
if args[:2] == ["api", "user"]:
    print("cristian-frunze")
    raise SystemExit
method = "GET"
if "--method" in args: method = args[args.index("--method") + 1]
endpoint = next((arg for arg in args[1:] if arg.startswith(("orgs/", "repos/"))), "")
clean_endpoint = endpoint.split("?",1)[0]
query = parse_qs(urlsplit("/" + endpoint).query)
page = int(query.get("page", ["1"])[0])
if clean_endpoint.endswith("actions/runner-groups") and method == "GET":
    print(json.dumps({"runner_groups": list(state["groups"].values())}))
elif clean_endpoint.endswith("actions/runner-groups") and method == "POST":
    fields = {args[index+1].split("=",1)[0]:args[index+1].split("=",1)[1] for index,arg in enumerate(args) if arg in {"-f","-F"}}
    group = {"id": len(state["groups"])+1, "name": fields["name"], "visibility":"selected", "allows_public_repositories":False}
    state["groups"][fields["name"]] = group
    state["repositories"][fields["name"]] = []
    state_path.write_text(json.dumps(state))
    print(json.dumps(group))
elif "/repositories/" in clean_endpoint and method == "PUT":
    parts = clean_endpoint.split("/")
    group_id = int(parts[4]); repository_id = int(parts[-1])
    group = next(value for value in state["groups"].values() if value["id"] == group_id)
    state["repositories"][group["name"]] = sorted(set(state["repositories"][group["name"]] + [repository_id]))
    state_path.write_text(json.dumps(state))
elif clean_endpoint.endswith("/repositories") and method == "GET" and "runner-groups" in clean_endpoint:
    group_id = int(clean_endpoint.split("/")[4])
    group = next(value for value in state["groups"].values() if value["id"] == group_id)
    print(json.dumps({"repositories":[{"id":value} for value in state["repositories"][group["name"]]]}))
elif clean_endpoint.endswith("/runners") and method == "GET" and "runner-groups" in clean_endpoint:
    group_id = int(clean_endpoint.split("/")[4])
    group = next(value for value in state["groups"].values() if value["id"] == group_id)
    values = [value for value in state["runners"].values() if value.get("runner_group_id") == group_id]
    if os.environ.get("KEN_FAKE_GH_DUPLICATE_GROUP_AT_FINAL") == "1" and group["name"] == "Ken Private CI" and len(state["runners"]) == 12:
        values = values + [dict(values[0])]
    print(json.dumps({"total_count":len(values),"runners":values if page == 1 else []}))
elif clean_endpoint.endswith("actions/runners") and method == "GET":
    values = list(state["runners"].values())
    if os.environ.get("KEN_FAKE_GH_DISABLED_RUNNER_ON_PAGE_2") == "1":
        unrelated = [{"name":f"unrelated-runner-{index:03d}","status":"offline","busy":False,"labels":[]} for index in range(100-len(values))]
        disabled = {"name":"ken-ci-standard-09","status":"online","busy":False,"labels":["self-hosted","linux","x64","ken-ci","standard"]}
        pages = {1: values + unrelated, 2: [disabled]}
        print(json.dumps({"total_count":101,"runners":pages.get(page, [])}))
    else:
        if os.environ.get("KEN_FAKE_GH_DUPLICATE_ORG_AFTER_ADD") == "1" and values:
            values = values + [dict(values[0])]
        print(json.dumps({"total_count":len(values),"runners":values if page == 1 else []}))
elif clean_endpoint.startswith("repos/Ken-Technology/") and method == "GET":
    name = clean_endpoint.rsplit("/", 1)[-1]
    catalog = json.loads(Path(os.environ["KEN_FAKE_REPOSITORY_CATALOG"]).read_text())
    repository = catalog[name]
    if os.environ.get("KEN_FAKE_GH_STALE_REPOSITORY") == name:
        repository = {**repository, "private":False, "visibility":"public", "archived":True}
    print(json.dumps(repository))
elif clean_endpoint.endswith("registration-token") and method == "POST":
    print(json.dumps({"token":"short-lived-registration-token","expires_at":"2099-01-01T00:00:00Z"}))
elif clean_endpoint.endswith("remove-token") and method == "POST":
    print(json.dumps({"token":"short-lived-removal-token","expires_at":"2099-01-01T00:00:00Z"}))
elif "/runner-groups/" in clean_endpoint and method == "DELETE":
    group_id = int(clean_endpoint.split("/")[4])
    name = next(key for key,value in state["groups"].items() if value["id"] == group_id)
    state["groups"].pop(name); state["repositories"].pop(name, None)
    state_path.write_text(json.dumps(state))
else:
    print(f"unexpected gh call: {method} {endpoint}", file=sys.stderr); raise SystemExit(64)
''')
    fake_gh.chmod(0o700)
    fake_ssh = live_root / "ssh"
    fake_ssh.write_text(r'''#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
state_path = Path(os.environ["KEN_FAKE_LIVE_STATE"])
log_path = Path(os.environ.get("KEN_FAKE_SSH_LOG", os.environ["KEN_FAKE_COMMAND_LOG"]))
args = sys.argv[1:]
mode = args[-1]
payload = json.load(sys.stdin)
safe = {key:value for key,value in payload.items() if key not in {"registration_token","removal_token"}}
with log_path.open("a") as handle: handle.write(json.dumps({"tool":"ssh","mode":mode,"payload":safe})+"\n")
state = json.loads(state_path.read_text())
name = payload.get("name")
if mode == "probe":
    print(json.dumps(state["guests"].get(name, {"status":"absent","name":name})))
elif mode == "apply":
    if payload.get("registration_token") != "short-lived-registration-token": raise SystemExit(65)
    if name == "ken-ci-standard-01" and os.environ.get("KEN_FAKE_SSH_ECHO_REGISTRATION_TOKEN") == "1":
        print(f"remote config failure argv: --token {payload['registration_token']}", file=sys.stderr)
        raise SystemExit(69)
    fail_stage = os.environ.get("KEN_FAKE_SSH_FAIL_APPLY_STAGE")
    if name == "ken-ci-standard-01" and fail_stage in {"before-download", "before-config"}:
        state["guests"][name] = {"status":"partial","stage":fail_stage,"transaction_id":payload["transaction_id"]}
        state_path.write_text(json.dumps(state))
        raise SystemExit(67)
    record = payload["expected_probe"]
    state["guests"][name] = record
    state["runners"][name] = payload["expected_github"]
    state_path.write_text(json.dumps(state))
    print(json.dumps({"status":"created","name":name,"created_units":list(payload["units"])}))
elif mode == "rollback":
    if payload.get("removal_token") != "short-lived-removal-token": raise SystemExit(66)
    if os.environ.get("KEN_FAKE_SSH_FAIL_ROLLBACK") == "1": raise SystemExit(68)
    state["guests"].pop(name, None); state["runners"].pop(name, None)
    state_path.write_text(json.dumps(state)); print(json.dumps({"status":"rolled-back","name":name}))
elif mode == "verify":
    guest = payload["guest"]
    records = [value for value in state["guests"].values() if value["vm"] == guest]
    print(json.dumps({"guest":guest,"records":payload["expected_live_snapshot"],"disabled_accounts":[],"slice_sha256":payload["slice_sha256"]}))
else:
    raise SystemExit(64)
''')
    fake_ssh.chmod(0o700)
    fake_systemctl = live_root / "systemctl"
    fake_systemctl.write_text(r'''#!/usr/bin/env python3
import os, sys
from pathlib import Path
path = Path(os.environ["KEN_FAKE_SYSTEMCTL_LOG"])
with path.open("a") as handle: handle.write(" ".join(sys.argv[1:]) + "\n")
raise SystemExit(99)
''')
    fake_systemctl.chmod(0o700)
    live_env = {
        "KEN_RUNNER_COMMAND_TEST": "1",
        "KEN_RUNNER_RUNTIME_LOCK_FILE": str(live_root / "authority/broker-runtime.lock.yaml"),
        "KEN_RUNNER_GUEST_MANIFEST_FILE": str(live_root / "authority/guest-image-manifest.yaml"),
        "KEN_RUNNER_GH_BIN": str(fake_gh),
        "KEN_RUNNER_SSH_BIN": str(fake_ssh),
        "KEN_FAKE_LIVE_STATE": str(state_path),
        "KEN_FAKE_COMMAND_LOG": str(command_log),
        "KEN_FAKE_REPOSITORY_CATALOG": str(repository_catalog_path),
        "KEN_RUNNER_JOURNAL_DIR": str(live_root / "journals"),
    }
    approved_command = ["bash", str(register), "--org", "Ken-Technology", "--all", "--approval-evidence", str(approval_path)]

    canonical_evidence = json.loads(approval_path.read_text())
    manifest_path = live_root / "authority/guest-image-manifest.yaml"
    canonical_manifest = yaml.safe_load(manifest_path.read_text())

    def assert_pretransport_rejected(label, expected_message, mutate_evidence=None, mutate_manifest=None):
        evidence = copy.deepcopy(canonical_evidence)
        manifest = copy.deepcopy(canonical_manifest)
        if mutate_evidence is not None:
            mutate_evidence(evidence)
        if mutate_manifest is not None:
            mutate_manifest(manifest)
        manifest_path.write_text(yaml.safe_dump(manifest, sort_keys=False))
        manifest_path.chmod(0o600)
        evidence["artifact_authority"]["guest_image_manifest_sha256"] = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
        write_json(approval_path, evidence)
        approval_path.chmod(0o600)
        for command_name, command in (
            ("register", approved_command),
            ("verify", ["bash", str(verify), "runners", "--approval-evidence", str(approval_path)]),
        ):
            gh_log = live_root / f"{label}-{command_name}-gh.jsonl"
            ssh_log = live_root / f"{label}-{command_name}-ssh.jsonl"
            systemctl_log = live_root / f"{label}-{command_name}-systemctl.log"
            result = call(command, env={
                **live_env,
                "PATH": str(live_root) + os.pathsep + os.environ["PATH"],
                "KEN_FAKE_GH_LOG": str(gh_log),
                "KEN_FAKE_SSH_LOG": str(ssh_log),
                "KEN_FAKE_SYSTEMCTL_LOG": str(systemctl_log),
            })
            check(
                result.returncode != 0 and expected_message in result.stderr.lower(),
                f"{label} {command_name} rejects before transport",
                result,
            )
            check(
                not gh_log.exists() and not ssh_log.exists() and not systemctl_log.exists(),
                f"{label} {command_name} leaves fake gh/ssh/systemctl logs unchanged",
                result,
            )
        manifest_path.write_text(yaml.safe_dump(canonical_manifest, sort_keys=False))
        manifest_path.chmod(0o600)
        write_json(approval_path, canonical_evidence)
        approval_path.chmod(0o600)

    for version, name in ((True, "bool"), (1.0, "float")):
        assert_pretransport_rejected(
            f"receipt-schema-{name}",
            "evidence schema",
            mutate_evidence=lambda value, version=version: value.__setitem__("schema_version", version),
        )
        assert_pretransport_rejected(
            f"manifest-schema-{name}",
            "manifest schema",
            mutate_manifest=lambda value, version=version: value.__setitem__("schema_version", version),
        )

    assert_pretransport_rejected(
        "ci-virtual-size-float",
        "derived image contract",
        mutate_manifest=lambda value: value["derived_images"]["ci"].__setitem__("virtual_size_gib", 750.0),
    )
    assert_pretransport_rejected(
        "ci-memory-float",
        "guest memory evidence",
        mutate_evidence=lambda value: value["vms"]["ken-ci"].__setitem__("memory_gib", 112.0),
    )

    stale_repository_name = platform["groups"]["ci"]["repositories"][0]["name"]
    stale_log_start = len(command_log.read_text().splitlines()) if command_log.exists() else 0
    stale_repository = call(approved_command, env={**live_env, "KEN_FAKE_GH_STALE_REPOSITORY": stale_repository_name})
    stale_records = [json.loads(line) for line in command_log.read_text().splitlines()[stale_log_start:]]
    check(stale_repository.returncode != 0 and "fresh repository" in stale_repository.stderr.lower() and any(f"repos/Ken-Technology/{stale_repository_name}" in " ".join(record.get("args", [])) for record in stale_records if record.get("tool") == "gh") and not any("repositories/" in " ".join(record.get("args", [])) and "PUT" in record.get("args", []) for record in stale_records if record.get("tool") == "gh"), "live linking freshly resolves repository ID/privacy/archive state before any PUT", stale_repository)
    check(json.loads(state_path.read_text()) == {"groups": {}, "repositories": {}, "runners": {}, "guests": {}}, "fresh repository refusal rolls back the transaction-created group")
    write_json(state_path, {"groups": {}, "repositories": {}, "runners": {}, "guests": {}})
    duplicate_org_registration = call(approved_command, env={**live_env, "KEN_FAKE_GH_DUPLICATE_ORG_AFTER_ADD": "1"})
    check(duplicate_org_registration.returncode != 0 and "duplicate" in duplicate_org_registration.stderr.lower() and json.loads(state_path.read_text()) == {"groups": {}, "repositories": {}, "runners": {}, "guests": {}}, "registration rejects duplicate organization runner names introduced during post-add polling", duplicate_org_registration)
    write_json(state_path, {"groups": {}, "repositories": {}, "runners": {}, "guests": {}})
    duplicate_group_registration = call(approved_command, env={**live_env, "KEN_FAKE_GH_DUPLICATE_GROUP_AT_FINAL": "1"})
    check(duplicate_group_registration.returncode != 0 and "duplicate" in duplicate_group_registration.stderr.lower() and json.loads(state_path.read_text()) == {"groups": {}, "repositories": {}, "runners": {}, "guests": {}}, "registration rejects duplicate group memberships introduced during final convergence", duplicate_group_registration)
    write_json(state_path, {"groups": {}, "repositories": {}, "runners": {}, "guests": {}})
    live_log_start = len(command_log.read_text().splitlines())
    live_first = call(approved_command, env=live_env)
    check(live_first.returncode == 0 and "REGISTERED_RUNNERS=12" in live_first.stdout and "REGISTRATION_MODE=live-guarded" in live_first.stdout, "approved guarded transport converges exact live runner set", live_first)
    if live_first.returncode != 0:
        print("\n".join(f"RUNNER_BEHAVIOR_FAIL {failure}" for failure in failures))
        raise SystemExit(1)
    live_second = call(approved_command, env=live_env)
    check(live_second.returncode == 0 and "NO_CHANGES=1" in live_second.stdout, "approved guarded live rerun is exact no-op", live_second)
    log_records = [json.loads(line) for line in command_log.read_text().splitlines()[live_log_start:]]
    check(any(record.get("tool") == "gh" and "registration-token" in " ".join(record.get("args", [])) for record in log_records), "live path requests short-lived GitHub registration tokens")
    check(not any("--replace" in " ".join(record.get("args", [])) for record in log_records), "live path never uses --replace")
    check(not any("short-lived-registration-token" in json.dumps(record) for record in log_records), "live command journal never records registration token")
    deploy_apply_records = [record for record in log_records if record.get("tool") == "ssh" and record.get("mode") == "apply" and record.get("payload", {}).get("expected_probe", {}).get("vm") == "ken-deploy"]
    expected_deploy_slices = {"ken-actions-deploy.slice", "ken-actions-deploy-listeners.slice", "ken-actions-deploy-brokers.slice", "ken-actions-deploy-transaction-1.slice", "ken-actions-deploy-transaction-2.slice", "ken-actions-deploy-builder.slice", "ken-actions-deploy-uploader.slice", "ken-actions-deploy-executor.slice"}
    check(len(deploy_apply_records) == 2 and all(expected_deploy_slices <= set(record["payload"]["units"]) for record in deploy_apply_records), "guarded live install carries every reviewed deploy aggregate/child slice")
    verified_live = call(["bash", str(verify), "runners", "--approval-evidence", str(approval_path)], env=live_env)
    check(verified_live.returncode == 0 and "RUNNERS_OK=12" in verified_live.stdout and "VERIFY_MODE=live-read-only" in verified_live.stdout, "approved live verifier uses read-only gh/SSH transport", verified_live)
    duplicate_org_verify = call(["bash", str(verify), "runners", "--approval-evidence", str(approval_path)], env={**live_env, "KEN_FAKE_GH_DUPLICATE_ORG_AFTER_ADD": "1"})
    check(duplicate_org_verify.returncode != 0 and "duplicate" in duplicate_org_verify.stderr.lower(), "live verifier rejects duplicate organization runner names", duplicate_org_verify)
    duplicate_group_verify = call(["bash", str(verify), "runners", "--approval-evidence", str(approval_path)], env={**live_env, "KEN_FAKE_GH_DUPLICATE_GROUP_AT_FINAL": "1"})
    check(duplicate_group_verify.returncode != 0 and "duplicate" in duplicate_group_verify.stderr.lower(), "live verifier rejects duplicate runner-group memberships", duplicate_group_verify)
    pagination_log_start = len(command_log.read_text().splitlines())
    hidden_disabled = call(["bash", str(verify), "runners", "--approval-evidence", str(approval_path)], env={**live_env, "KEN_FAKE_GH_DISABLED_RUNNER_ON_PAGE_2": "1"})
    pagination_records = [json.loads(line) for line in command_log.read_text().splitlines()[pagination_log_start:]]
    check(hidden_disabled.returncode != 0 and "exact 10 CI + 2 deploy" in hidden_disabled.stderr and any("page=2" in " ".join(record.get("args", [])) for record in pagination_records if record.get("tool") == "gh"), "live verifier paginates and rejects a disabled runner on page two", hidden_disabled)

    write_json(state_path, {"groups": {}, "repositories": {}, "runners": {}, "guests": {}})
    failed_live = call(approved_command, env={**live_env, "KEN_RUNNER_TEST_FAIL_AFTER_LIVE": "ken-ci-standard-01"})
    failed_state = json.loads(state_path.read_text())
    check(failed_live.returncode != 0 and failed_state == {"groups": {}, "repositories": {}, "runners": {}, "guests": {}}, "live failure rolls back only transaction-created runner and groups", failed_live)
    rollback_log = [json.loads(line) for line in command_log.read_text().splitlines()]
    check(any(record.get("tool") == "gh" and "remove-token" in " ".join(record.get("args", [])) for record in rollback_log) and any(record.get("tool") == "ssh" and record.get("mode") == "rollback" for record in rollback_log), "live rollback uses a short-lived removal token and exact remote rollback")
    journal_text = "\n".join(path.read_text() for path in (live_root / "journals").glob("*.jsonl"))
    check("short-lived-registration-token" not in journal_text and "short-lived-removal-token" not in journal_text, "transaction journals contain no runner token")

    register_text = register.read_text()
    check('config.is_symlink() or (config.exists() and not config.is_file())' in register_text and 'elif config.is_file()' in register_text, "remote rollback skips an absent config.sh and refuses an unsafe one")
    check('subprocess.run(command, check=True' not in register_text and 'stdout=subprocess.DEVNULL' in register_text and 'stderr=subprocess.DEVNULL' in register_text, "remote config failure cannot serialize token-bearing argv or child output")
    write_json(state_path, {"groups": {}, "repositories": {}, "runners": {}, "guests": {}})
    token_failure = call(approved_command, env={**live_env, "KEN_FAKE_SSH_ECHO_REGISTRATION_TOKEN": "1"})
    token_failure_output = token_failure.stdout + token_failure.stderr
    check(token_failure.returncode != 0 and "short-lived-registration-token" not in token_failure_output, "SSH failure propagation redacts a registration token echoed by the remote process", token_failure)
    for failure_stage in ("before-download", "before-config"):
        write_json(state_path, {"groups": {}, "repositories": {}, "runners": {}, "guests": {}})
        partial_failure = call(approved_command, env={**live_env, "KEN_FAKE_SSH_FAIL_APPLY_STAGE": failure_stage})
        partial_state = json.loads(state_path.read_text())
        check(partial_failure.returncode != 0 and partial_state == {"groups": {}, "repositories": {}, "runners": {}, "guests": {}}, f"failure {failure_stage} fully rolls back pre-registration guest state", partial_failure)

    write_json(state_path, {"groups": {}, "repositories": {}, "runners": {}, "guests": {}})
    incomplete_rollback = call(approved_command, env={
        **live_env,
        "KEN_FAKE_SSH_FAIL_APPLY_STAGE": "before-download",
        "KEN_FAKE_SSH_FAIL_ROLLBACK": "1",
    })
    incomplete_state = json.loads(state_path.read_text())
    check(incomplete_rollback.returncode != 0 and "rollback incomplete" in incomplete_rollback.stderr.lower() and incomplete_state["guests"], "rollback failure is aggregated, reported, and leaves ownership evidence for recovery", incomplete_rollback)

    no_approval_log = live_root / "no-approval.jsonl"
    no_approval_env = {**live_env, "KEN_FAKE_COMMAND_LOG": str(no_approval_log)}
    unapproved = call(["bash", str(register), "--org", "Ken-Technology", "--all", "--approval-evidence", str(live_root / "missing.json")], env=no_approval_env)
    check(unapproved.returncode != 0 and "approval" in unapproved.stderr.lower() and not no_approval_log.exists(), "missing live approval refuses before gh or SSH", unapproved)

    mismatched_approval = json.loads(approval_path.read_text())
    mismatched_approval["artifact_authority"]["derived_images"]["ken-deploy"] = "f" * 64
    write_json(approval_path, mismatched_approval)
    approval_path.chmod(0o600)
    digest_log = live_root / "digest-mismatch.jsonl"
    digest_refusal = call(approved_command, env={**live_env, "KEN_FAKE_COMMAND_LOG": str(digest_log)})
    check(digest_refusal.returncode != 0 and "derived image digest" in digest_refusal.stderr.lower() and not digest_log.exists(), "digest mismatch refuses before gh or SSH", digest_refusal)
    digest_verify_log = live_root / "digest-mismatch-verify.jsonl"
    digest_verify_refusal = call(["bash", str(verify), "runners", "--approval-evidence", str(approval_path)], env={**live_env, "KEN_FAKE_COMMAND_LOG": str(digest_verify_log)})
    check(digest_verify_refusal.returncode != 0 and "derived image digest" in digest_verify_refusal.stderr.lower() and not digest_verify_log.exists(), "read-only verifier digest mismatch refuses before gh or SSH", digest_verify_refusal)

if failures:
    print("\n".join(f"RUNNER_BEHAVIOR_FAIL {failure}" for failure in failures))
    raise SystemExit(1)
print("RUNNER_BEHAVIOR_OK")
PY

bash -n \
  "${GA_ROOT}/scripts/register-runners.sh" \
  "${GA_ROOT}/scripts/verify-platform.sh" \
  "${GA_ROOT}/systemd/ken-runner-cleanup"

printf 'RUNNER_TESTS_OK\n'
