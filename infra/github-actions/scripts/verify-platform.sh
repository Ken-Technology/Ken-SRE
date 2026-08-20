#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SCRIPT_DIR
GA_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd -P)"
readonly GA_ROOT
readonly PLATFORM_FILE="${KEN_RUNNER_PLATFORM_FILE:-${GA_ROOT}/inventory/runner-platform.yaml}"

exec python3 - "${PLATFORM_FILE}" "$@" <<'PY'
import argparse
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path

import yaml


class VerificationError(RuntimeError):
    pass


class UniqueLoader(yaml.SafeLoader):
    pass


def construct_unique_mapping(loader, node, deep=False):
    mapping = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise VerificationError(f"duplicate YAML key: {key}")
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, construct_unique_mapping)


def die(message):
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


def read_json(path):
    if not path.is_file() or path.is_symlink():
        raise VerificationError(f"required read-only state is missing: {path}")
    try:
        return json.loads(path.read_text())
    except json.JSONDecodeError as error:
        raise VerificationError(f"invalid read-only state {path}: {error}") from error


def parse_args(arguments):
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=["runners", "all"])
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--test-fake-root")
    parser.add_argument("--approval-evidence")
    parser.add_argument("--host", default="root@167.235.8.250")
    return parser.parse_args(arguments)


def expected_group(key, group):
    return {
        "key": key,
        "name": group["name"],
        "visibility": "selected",
        "allows_public_repositories": False,
        "repositories": group["repositories"],
    }


def expected_github(platform, runner):
    return {
        "name": runner["name"],
        "status": "online",
        "busy": False,
        "group": platform["groups"][runner["runner_group"]]["name"],
        "labels": runner["labels"],
        "vm": runner["vm"],
    }


def expected_local(platform, runner):
    return {
        **expected_github(platform, runner),
        "user": runner["user"],
        "uid": runner["uid"],
        "gid": runner["gid"],
        "runner_root": runner["runner_root"],
        "work_root": runner["work_root"],
        "version": platform["runner_distribution"]["version"],
        "archive_sha256": platform["runner_distribution"]["sha256"],
        "disable_update": True,
        "binary_owner": "root",
        "binary_mode": "0555",
    }


def expected_account(runner):
    return {
        "name": runner["user"],
        "uid": runner["uid"],
        "gid": runner["gid"],
        "groups": [],
        "sudo": False,
        "home": runner["home"],
        "locked": True,
        "subuid": f"{runner['subuid_start']}:{runner['subid_count']}",
        "subgid": f"{runner['subgid_start']}:{runner['subid_count']}",
    }


def fake_guest_filesystem_path(fake_root, runner, absolute_path):
    return fake_root / "guests" / runner["vm"] / "filesystem" / absolute_path.lstrip("/")


def disabled_state_paths(fake_root, runner):
    name = runner["name"]
    guest_root = fake_root / "guests" / runner["vm"]
    runner_base = str(Path(runner["home"]).parent)
    filesystem_paths = {
        "runner base": runner_base,
        "home directory": runner["home"],
        "runner directory": runner["runner_root"],
        "workspace directory": runner["work_root"],
        "Docker data directory": runner["docker"]["data_root"],
        "Docker runtime directory": runner["docker"]["runtime_root"],
        "Docker socket": f"{runner['docker']['runtime_root']}/docker.sock",
        "listener-ready marker": f"/etc/ken-runners/{name}.ready",
        "Docker-ready marker": f"/etc/ken-runners/{name}.docker-ready",
        "dirty-state marker": f"/var/lib/ken-runner-state/{name}.dirty",
        "clean-state marker": f"/var/lib/ken-runner-state/{name}.clean",
    }
    paths = [
        ("GitHub runner", fake_root / "github" / "runners" / f"{name}.json"),
        ("local runner", guest_root / "runners" / f"{name}.json"),
        ("account", guest_root / "accounts" / f"{name}.json"),
        ("subuid", guest_root / "subuids" / f"{name}.json"),
        ("subgid", guest_root / "subgids" / f"{name}.json"),
        ("listener unit", guest_root / "units" / f"ken-runner@{name}.service"),
        ("Docker unit", guest_root / "units" / f"ken-runner-docker@{name}.service"),
    ]
    if runner.get("slice"):
        paths.append(("slice unit", guest_root / "units" / runner["slice"]))
    paths.extend(
        (label, fake_guest_filesystem_path(fake_root, runner, path))
        for label, path in filesystem_paths.items()
    )
    return paths


def verify_disabled_absent(platform, fake_root):
    for runner in platform["runners"]:
        if runner["enabled"]:
            continue
        for label, path in disabled_state_paths(fake_root, runner):
            if path.exists() or path.is_symlink():
                raise VerificationError(f"disabled runner local state exists: {runner['name']} {label}")


def verify_evidence(platform, fake_root):
    evidence = read_json(fake_root / "task4-evidence.json")
    if evidence.get("approval_phrase") != "Task 4/6 approved and 1Password ready" or evidence.get("combined_approval_verified") is not True:
        raise VerificationError("combined Task 4/6 approval evidence is missing")
    if evidence.get("host") != "root@167.235.8.250":
        raise VerificationError("Task 4 evidence host mismatch")
    host_memory = evidence.get("host_memory_available_gib")
    if not isinstance(host_memory, (int, float)) or host_memory < 32:
        raise VerificationError("Task 4 host memory evidence is below 32 GiB")
    if evidence.get("firewall_generation_verified") is not True:
        raise VerificationError("Task 4 firewall generation is not verified")
    for name, expected_memory in (("ken-ci", 112), ("ken-deploy", 12)):
        vm = evidence.get("vms", {}).get(name, {})
        if vm.get("healthy") is not True or vm.get("isolation_verified") is not True:
            raise VerificationError(f"Task 4 VM evidence mismatch: {name}")
        if vm.get("memory_gib") != expected_memory or vm.get("memory_health_verified") is not True:
            raise VerificationError(f"Task 4 guest memory evidence mismatch: {name}")
    resolution = read_json(fake_root / "github-repository-resolver.json")
    expected_repositories = sorted(
        (
            {"name": item["name"], "id": item["repository_id"], "visibility": "private", "archived": False}
            for item in platform["groups"]["ci"]["repositories"]
        ),
        key=lambda item: item["name"],
    )
    actual_repositories = resolution.get("repositories")
    if not isinstance(actual_repositories, list):
        raise VerificationError("repository resolver mismatch: repositories are missing")
    actual_repositories = sorted(actual_repositories, key=lambda item: str(item.get("name")))
    if (
        resolution.get("organization") != "Ken-Technology"
        or resolution.get("resolved_at") != platform["source_inventory"]["repository_ids_resolved_at"]
        or actual_repositories != expected_repositories
    ):
        raise VerificationError("repository resolver mismatch: selected names, IDs, privacy, or freshness changed")


def counters_increased(before, during):
    keys = ("memory.current", "cpu.stat.usage_usec", "pids.current")
    return all(isinstance(before.get(key), int) and isinstance(during.get(key), int) and during[key] > before[key] for key in keys)


def verify_runtime_evidence(platform, fake_root, enabled):
    evidence = read_json(fake_root / "runtime-evidence.json")
    if evidence.get("cgroup_version") != 2:
        raise VerificationError("cgroup v2 evidence is missing")
    if evidence.get("uid_output_policy_active_before_listeners") is not True:
        raise VerificationError("UID OUTPUT policy was not active before listeners")
    if evidence.get("cleanup_verified") is not True or evidence.get("host_resources_healthy") is not True:
        raise VerificationError("cleanup or host resource evidence is incomplete")

    ci_evidence = evidence.get("ci", {})
    enabled_ci = {name: runner for name, runner in enabled.items() if runner["vm"] == "ken-ci"}
    if set(ci_evidence) != set(enabled_ci):
        raise VerificationError("CI cgroup evidence does not contain exactly ten enabled identities")
    for name, runner in enabled_ci.items():
        record = ci_evidence[name]
        listener = record.get("listener", {})
        docker = record.get("docker", {})
        combined = record.get("combined", {})
        for child, expected_unit in (
            (listener, f"ken-runner@{name}.service"),
            (docker, f"ken-runner-docker@{name}.service"),
        ):
            if child.get("unit") != expected_unit or child.get("slice") != runner["slice"]:
                raise VerificationError(f"CI cgroup slice mismatch: {name}")
            if child.get("ancestors") != [runner["slice"]] or not str(child.get("control_group", "")).startswith(f"/{runner['slice']}/"):
                raise VerificationError(f"CI cgroup ancestor mismatch: {name}")
            if not counters_increased(child.get("before", {}), child.get("during", {})):
                raise VerificationError(f"CI child counter did not increase: {name}")
        if (
            combined.get("slice") != runner["slice"]
            or not counters_increased(combined.get("before", {}), combined.get("during", {}))
            or combined.get("limit_enforced") is not True
            or combined.get("sibling_counters_unchanged") is not True
        ):
            raise VerificationError(f"CI shared cgroup counter or isolation mismatch: {name}")

    deploy = platform.get("deploy_resources", {})
    assignments = deploy.get("slice_assignments", {})
    deploy_evidence = evidence.get("deploy", {})
    units = deploy_evidence.get("units", {})
    required_roles = {"listeners", "brokers", "transaction_1", "transaction_2", "builder", "uploader", "executor"}
    observed_roles = set()
    for unit_name, record in units.items():
        role = record.get("role")
        observed_roles.add(role)
        expected_slice = assignments.get(role)
        if expected_slice is None or record.get("slice") != expected_slice:
            raise VerificationError(f"deploy unit slice mismatch: {unit_name}")
        if record.get("ancestors") != [expected_slice, "ken-actions-deploy.slice"]:
            raise VerificationError(f"deploy parent ancestor mismatch: {unit_name}")
        expected_prefix = f"/ken-actions-deploy.slice/{expected_slice}/"
        if not str(record.get("control_group", "")).startswith(expected_prefix):
            raise VerificationError(f"deploy ControlGroup mismatch: {unit_name}")
        if not counters_increased(record.get("child_before", {}), record.get("child_during", {})):
            raise VerificationError(f"deploy child counter did not increase: {unit_name}")
        if not counters_increased(record.get("parent_before", {}), record.get("parent_during", {})):
            raise VerificationError(f"deploy parent counter did not roll up: {unit_name}")
    if observed_roles != required_roles:
        raise VerificationError("deploy cgroup evidence is missing a required role")

    ordinary = deploy_evidence.get("ordinary", {})
    if (
        ordinary.get("leases_available_after") != 2
        or ordinary.get("memory_mib_peak", 999999) > deploy["ordinary_peak"]["memory_mib"]
        or ordinary.get("cpu_percent_peak", 999999) > int(deploy["ordinary_peak"]["cpu_quota"].rstrip("%"))
        or ordinary.get("mem_available_gib_min", 0) < deploy["guest_headroom"]["minimum_mem_available_gib"]
        or ordinary.get("swap_bytes") != 0
        or ordinary.get("oom_events") != 0
        or ordinary.get("brokers_responsive") is not True
        or ordinary.get("independent_release") is not True
    ):
        raise VerificationError("ordinary deploy pressure or lease evidence failed")
    exclusive = deploy_evidence.get("exclusive", {})
    if (
        exclusive.get("writer_preference") is not True
        or exclusive.get("both_leases_held") is not True
        or exclusive.get("queued_ordinary_side_effects") != 0
        or exclusive.get("builder_memory_mib_peak", 999999) > deploy["builder_peak"]["memory_mib"]
        or exclusive.get("builder_cpu_percent_peak", 999999) > int(deploy["builder_peak"]["cpu_quota"].rstrip("%"))
        or exclusive.get("mem_available_gib_min", 0) < deploy["guest_headroom"]["minimum_mem_available_gib"]
        or exclusive.get("swap_bytes") != 0
        or exclusive.get("oom_events") != 0
        or exclusive.get("brokers_responsive") is not True
        or exclusive.get("uploader_or_executor_overlap") is not False
        or exclusive.get("leases_available_after") != 2
        or exclusive.get("cleanup_verified") is not True
    ):
        raise VerificationError("exclusive deploy pressure, sequencing, or recovery evidence failed")


def verify_fake(platform, fake_root):
    if os.environ.get("KEN_RUNNER_OFFLINE_TEST") != "1":
        raise VerificationError("test fake transport requires KEN_RUNNER_OFFLINE_TEST=1")
    fake_root = fake_root.resolve()
    verify_evidence(platform, fake_root)
    for key in ("ci", "deploy"):
        actual = read_json(fake_root / f"github/groups/{key}.json")
        if actual != expected_group(key, platform["groups"][key]):
            raise VerificationError(f"runner group mismatch: {key}")

    enabled = {runner["name"]: runner for runner in platform["runners"] if runner["enabled"]}
    disabled = {runner["name"] for runner in platform["runners"] if not runner["enabled"]}
    verify_disabled_absent(platform, fake_root)
    github_paths = list((fake_root / "github/runners").glob("*.json"))
    github_names = {path.stem for path in github_paths}
    present_disabled = github_names & disabled
    if present_disabled:
        raise VerificationError(f"disabled runner present: {sorted(present_disabled)[0]}")
    if github_names != set(enabled):
        raise VerificationError("runner set mismatch")

    for name, runner in enabled.items():
        github = read_json(fake_root / f"github/runners/{name}.json")
        local = read_json(fake_root / f"guests/{runner['vm']}/runners/{name}.json")
        account = read_json(fake_root / f"guests/{runner['vm']}/accounts/{name}.json")
        if github != expected_github(platform, runner) or local != expected_local(platform, runner):
            raise VerificationError(f"runner mismatch: {name}")
        if account != expected_account(runner):
            raise VerificationError(f"account mismatch: {name}")
        for kind, value in (("subuids", runner["subuid_start"]), ("subgids", runner["subgid_start"])):
            if read_json(fake_root / f"guests/{runner['vm']}/{kind}/{name}.json") != {"start": value, "count": runner["subid_count"]}:
                raise VerificationError(f"subordinate-ID mismatch: {name} {kind}")
        unit_root = fake_root / f"guests/{runner['vm']}/units"
        listener = unit_root / f"ken-runner@{name}.service"
        slice_path = unit_root / runner["slice"]
        if not listener.is_file() or listener.is_symlink() or not slice_path.is_file() or slice_path.is_symlink():
            raise VerificationError(f"unit state is missing: {name}")
        listener_text = listener.read_text()
        slice_text = slice_path.read_text()
        required = [
            f"User={runner['user']}",
            f"Environment=RUNNER_UID={runner['uid']}",
            f"Slice={runner['slice']}",
        ]
        if runner["vm"] == "ken-ci":
            limits = platform["classes"][runner["class"]]
            required.extend([
                f"CPUQuota={limits['cpu_quota']}",
                f"MemoryMax={limits['memory_max']}",
                f"MemorySwapMax={limits['memory_swap_max']}",
                f"TasksMax={limits['tasks_max']}",
            ])
        else:
            required.extend(["CPUQuota=25%", "MemoryMax=512M", "MemorySwapMax=0", "TasksMax=128"])
        if not all(value in listener_text + slice_text for value in required):
            raise VerificationError(f"effective resource mismatch: {name}")
        lifecycle = [
            "ExecStartPre=+/usr/local/libexec/ken-runner-cleanup recover %i ${RUNNER_UID}",
            "ExecStartPre=+/usr/local/libexec/ken-runner-cleanup assert-clean %i ${RUNNER_UID}",
            "ExecStartPre=+/usr/local/libexec/ken-runner-cleanup mark-dirty %i ${RUNNER_UID}",
            "ExecStopPost=+/usr/local/libexec/ken-runner-cleanup cleanup %i ${RUNNER_UID}",
        ]
        if not all(value in listener_text for value in lifecycle):
            raise VerificationError(f"cleanup lifecycle mismatch: {name}")
        docker_path = unit_root / f"ken-runner-docker@{name}.service"
        if runner["docker"]["enabled"]:
            if not docker_path.is_file() or docker_path.is_symlink() or f"Slice={runner['slice']}" not in docker_path.read_text():
                raise VerificationError(f"rootless Docker unit mismatch: {name}")
            docker_unit_name = f"ken-runner-docker@{name}.service"
            docker_requirements = [
                f"Requires={docker_unit_name}",
                f"After={docker_unit_name}",
                f"BindsTo={docker_unit_name}",
                f"Environment=DOCKER_HOST=unix://{runner['docker']['runtime_root']}/docker.sock",
            ]
            if not all(value in listener_text for value in docker_requirements):
                raise VerificationError(f"Docker dependency mismatch: {name}")
        elif docker_path.exists() or docker_path.is_symlink():
            raise VerificationError(f"unexpected rootless Docker unit: {name}")
        elif "ken-runner-docker@" in listener_text or "DOCKER_HOST=" in listener_text:
            raise VerificationError(f"unexpected listener Docker dependency: {name}")
    verify_runtime_evidence(platform, fake_root, enabled)
    print(f"RUNNERS_OK={len(enabled)}")
    print("CI_SLICES_OK=10")
    print("DEPLOY_CGROUP_OK=1")
    print("VERIFY_MODE=offline-read-only")


REMOTE_VERIFY_PROGRAM = r'''
import hashlib
import json
import os
import pwd
import subprocess
import sys
from pathlib import Path

request = json.load(sys.stdin)
guest = request["guest"]

def systemctl_show(unit):
    result = subprocess.run(
        ["systemctl", "show", unit, "--property=LoadState,ActiveState,UnitFileState,Slice,ControlGroup,MainPID"],
        text=True,
        capture_output=True,
    )
    if result.returncode != 0:
        return {"error": result.stderr.strip()}
    return {line.split("=", 1)[0]: line.split("=", 1)[1] for line in result.stdout.splitlines() if "=" in line}

def cgroup_snapshot(control_group):
    path = Path("/sys/fs/cgroup") / control_group.lstrip("/")
    cpu = {}
    for line in (path / "cpu.stat").read_text().splitlines():
        key, value = line.split()
        cpu[key] = int(value)
    procs = []
    for candidate in [path, *[item for item in path.rglob("*") if item.is_dir()]]:
        proc_file = candidate / "cgroup.procs"
        if proc_file.is_file():
            procs.extend(int(value) for value in proc_file.read_text().split() if value)
    return {
        "memory.current": int((path / "memory.current").read_text().strip()),
        "cpu.stat.usage_usec": cpu.get("usage_usec", -1),
        "pids.current": int((path / "pids.current").read_text().strip()),
        "pids": sorted(set(procs)),
    }

records = []
for runner in request["runners"]:
    name = runner["name"]
    try:
        account = pwd.getpwnam(runner["user"])
        account_state = {"present": True, "uid": account.pw_uid, "gid": account.pw_gid}
    except KeyError:
        account_state = {"present": False}
    listener_name = f"ken-runner@{name}.service"
    listener = systemctl_show(listener_name)
    slice_state = systemctl_show(runner["slice"])
    listener_cgroup = listener.get("ControlGroup", "")
    slice_cgroup = slice_state.get("ControlGroup", "")
    record = {
        "name": name,
        "vm": guest,
        "account": account_state,
        "listener": listener,
        "slice": slice_state,
        "listener_snapshot": cgroup_snapshot(listener_cgroup) if listener_cgroup else {},
        "slice_snapshot": cgroup_snapshot(slice_cgroup) if slice_cgroup else {},
    }
    if runner["docker_enabled"]:
        docker = systemctl_show(f"ken-runner-docker@{name}.service")
        docker_cgroup = docker.get("ControlGroup", "")
        record["docker"] = docker
        record["docker_snapshot"] = cgroup_snapshot(docker_cgroup) if docker_cgroup else {}
    records.append(record)

disabled_accounts = []
for name in request["disabled_names"]:
    try:
        pwd.getpwnam(request["disabled_users"][name])
        disabled_accounts.append(name)
    except KeyError:
        pass

slice_hashes = {}
for name in request["slice_sha256"]:
    path = Path("/etc/systemd/system") / name
    slice_hashes[name] = hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() and not path.is_symlink() else None

print(json.dumps({
    "guest": guest,
    "records": records,
    "disabled_accounts": disabled_accounts,
    "slice_sha256": slice_hashes,
}, sort_keys=True, separators=(",", ":")))
'''


def command_path(name, override_environment):
    override = os.environ.get(override_environment)
    test_mode = os.environ.get("KEN_RUNNER_COMMAND_TEST") == "1"
    if override:
        if not test_mode:
            raise VerificationError(f"{override_environment} is test-only")
        path = Path(override).resolve()
    else:
        resolved = shutil.which(name)
        if not resolved:
            raise VerificationError(f"required command is missing: {name}")
        path = Path(resolved).resolve()
    if not path.is_file() or path.is_symlink():
        raise VerificationError(f"command is not a regular file: {path}")
    return str(path)


def load_live_approval(path_value):
    if not path_value:
        raise VerificationError("live approval evidence is required before gh or SSH")
    path = Path(path_value)
    if not path.is_file() or path.is_symlink():
        raise VerificationError("live approval evidence is missing or symlinked")
    if os.environ.get("KEN_RUNNER_COMMAND_TEST") != "1":
        metadata = path.stat()
        if metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) != 0o600:
            raise VerificationError("live approval evidence must be root-owned mode 0600")
    evidence = read_json(path)
    if evidence.get("approval_phrase") != "Task 4/6 approved and 1Password ready" or evidence.get("combined_approval_verified") is not True:
        raise VerificationError("combined Task 4/6 approval evidence is missing")
    if evidence.get("host") != "root@167.235.8.250" or evidence.get("firewall_generation_verified") is not True or evidence.get("host_memory_available_gib", 0) < 32:
        raise VerificationError("Task 4 live host/firewall/resource evidence mismatch")
    for name, memory in (("ken-ci", 112), ("ken-deploy", 12)):
        vm = evidence.get("vms", {}).get(name, {})
        if vm.get("healthy") is not True or vm.get("isolation_verified") is not True or vm.get("memory_gib") != memory or vm.get("memory_health_verified") is not True:
            raise VerificationError(f"Task 4 live VM evidence mismatch: {name}")


def run_json(command, payload=None):
    result = subprocess.run(command, input=None if payload is None else json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n", text=True, capture_output=True)
    if result.returncode != 0:
        raise VerificationError(f"read-only command failed: {command[0]} exit {result.returncode}: {result.stderr.strip()[:300]}")
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise VerificationError(f"read-only command returned invalid JSON: {command[0]}") from error


def ssh_verify(ssh_bin, host, guest, payload):
    command = [
        ssh_bin, "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
        "-J", host, f"root@{guest}", "--", "python3", "-c", REMOTE_VERIFY_PROGRAM, "verify",
    ]
    return run_json(command, payload)


def expected_live_snapshot(platform, guest):
    records = []
    for runner in platform["runners"]:
        if not runner["enabled"] or runner["vm"] != guest:
            continue
        slice_group = f"/{runner['slice']}"
        if guest == "ken-deploy":
            slice_group = f"/ken-actions-deploy.slice/{runner['slice']}"
        listener_pid = runner["uid"] + 100000
        record = {
            "name": runner["name"],
            "vm": guest,
            "account": {"present": True, "uid": runner["uid"], "gid": runner["gid"]},
            "listener": {"LoadState": "loaded", "ActiveState": "active", "UnitFileState": "enabled", "Slice": runner["slice"], "ControlGroup": f"{slice_group}/ken-runner@{runner['name']}.service", "MainPID": str(listener_pid)},
            "slice": {"LoadState": "loaded", "ActiveState": "active", "UnitFileState": "static", "Slice": "", "ControlGroup": slice_group, "MainPID": "0"},
            "listener_snapshot": {"memory.current": 1024, "cpu.stat.usage_usec": 100, "pids.current": 1, "pids": [listener_pid]},
            "slice_snapshot": {"memory.current": 2048, "cpu.stat.usage_usec": 200, "pids.current": 2 if runner["docker"]["enabled"] else 1, "pids": [listener_pid]},
        }
        if runner["docker"]["enabled"]:
            docker_pid = listener_pid + 1
            record["docker"] = {"LoadState": "loaded", "ActiveState": "active", "UnitFileState": "enabled", "Slice": runner["slice"], "ControlGroup": f"{slice_group}/ken-runner-docker@{runner['name']}.service", "MainPID": str(docker_pid)}
            record["docker_snapshot"] = {"memory.current": 1024, "cpu.stat.usage_usec": 100, "pids.current": 1, "pids": [docker_pid]}
            record["slice_snapshot"]["pids"].append(docker_pid)
        records.append(record)
    return records


def verify_live_snapshot(platform, guest, response, expected_hashes):
    if response.get("guest") != guest or response.get("disabled_accounts") not in (None, []):
        raise VerificationError(f"live guest identity or disabled-account mismatch: {guest}")
    if response.get("slice_sha256") not in (None, expected_hashes):
        raise VerificationError(f"live slice hash mismatch: {guest}")
    expected = {runner["name"]: runner for runner in platform["runners"] if runner["enabled"] and runner["vm"] == guest}
    records = {record.get("name"): record for record in response.get("records", [])}
    if set(records) != set(expected):
        raise VerificationError(f"live guest runner set mismatch: {guest}")
    for name, runner in expected.items():
        record = records[name]
        if record.get("account") != {"present": True, "uid": runner["uid"], "gid": runner["gid"]}:
            raise VerificationError(f"live account mismatch: {name}")
        listener = record.get("listener", {})
        expected_prefix = f"/{runner['slice']}/"
        if guest == "ken-deploy":
            expected_prefix = f"/ken-actions-deploy.slice/{runner['slice']}/"
        if listener.get("LoadState") != "loaded" or listener.get("ActiveState") != "active" or listener.get("UnitFileState") != "enabled" or listener.get("Slice") != runner["slice"] or not str(listener.get("ControlGroup", "")).startswith(expected_prefix):
            raise VerificationError(f"live listener Slice/ControlGroup mismatch: {name}")
        listener_pid = int(listener.get("MainPID", "0"))
        listener_snapshot = record.get("listener_snapshot", {})
        slice_snapshot = record.get("slice_snapshot", {})
        if listener_pid <= 0 or listener_pid not in listener_snapshot.get("pids", []) or listener_pid not in slice_snapshot.get("pids", []):
            raise VerificationError(f"live listener cgroup membership mismatch: {name}")
        for snapshot in (listener_snapshot, slice_snapshot):
            if any(not isinstance(snapshot.get(key), int) or snapshot[key] < 0 for key in ("memory.current", "cpu.stat.usage_usec", "pids.current")):
                raise VerificationError(f"live cgroup counters missing: {name}")
        if runner["docker"]["enabled"]:
            docker = record.get("docker", {})
            docker_pid = int(docker.get("MainPID", "0"))
            if docker.get("Slice") != runner["slice"] or not str(docker.get("ControlGroup", "")).startswith(expected_prefix) or docker_pid <= 0 or docker_pid not in record.get("docker_snapshot", {}).get("pids", []) or docker_pid not in slice_snapshot.get("pids", []):
                raise VerificationError(f"live Docker shared cgroup mismatch: {name}")
        elif "docker" in record:
            raise VerificationError(f"live deploy runner unexpectedly has Docker: {name}")


def run_live(platform, args):
    load_live_approval(args.approval_evidence)
    if args.host != "root@167.235.8.250":
        raise VerificationError("host must be root@167.235.8.250")
    gh_bin = command_path("gh", "KEN_RUNNER_GH_BIN")
    ssh_bin = command_path("ssh", "KEN_RUNNER_SSH_BIN")
    group_response = run_json([gh_bin, "api", f"orgs/{platform['organization']}/actions/runner-groups?per_page=100", "--method", "GET"])
    groups = {item.get("name"): item for item in group_response.get("runner_groups", [])}
    for key in ("ci", "deploy"):
        desired_group = platform["groups"][key]
        actual_group = groups.get(desired_group["name"])
        if actual_group is None or actual_group.get("visibility") != "selected" or actual_group.get("allows_public_repositories") is not False:
            raise VerificationError(f"live runner group mismatch: {key}")
        repositories = run_json([gh_bin, "api", f"orgs/{platform['organization']}/actions/runner-groups/{actual_group['id']}/repositories", "--method", "GET"])
        if sorted(item.get("id") for item in repositories.get("repositories", [])) != sorted(item["repository_id"] for item in desired_group["repositories"]):
            raise VerificationError(f"live runner group repository drift: {key}")
        members = run_json([gh_bin, "api", f"orgs/{platform['organization']}/actions/runner-groups/{actual_group['id']}/runners?per_page=100", "--method", "GET"])
        actual_names = {item.get("name") for item in members.get("runners", [])}
        expected_names = {runner["name"] for runner in platform["runners"] if runner["enabled"] and runner["runner_group"] == key}
        if actual_names != expected_names:
            raise VerificationError(f"live runner group membership drift: {key}")
    github = run_json([gh_bin, "api", f"orgs/{platform['organization']}/actions/runners?per_page=100", "--method", "GET"])
    desired = {runner["name"]: runner for runner in platform["runners"] if runner["enabled"]}
    disabled = {runner["name"] for runner in platform["runners"] if not runner["enabled"]}
    actual = {
        runner.get("name"): runner
        for runner in github.get("runners", [])
        if str(runner.get("name", "")).startswith(("ken-ci-", "ken-deploy-"))
    }
    if disabled & set(actual) or set(actual) != set(desired):
        raise VerificationError("GitHub runner set is not exact 10 CI + 2 deploy")
    for name, runner in desired.items():
        item = actual[name]
        labels = [label.get("name") if isinstance(label, dict) else label for label in item.get("labels", [])]
        if item.get("status") != "online" or item.get("busy") is not False or set(labels) != set(runner["labels"]) or len(labels) != len(runner["labels"]):
            raise VerificationError(f"GitHub runner state mismatch: {name}")

    ga_root = Path(sys.argv[1]).resolve().parent.parent
    systemd_root = ga_root / "systemd"
    slice_names = [runner["slice"] for runner in desired.values() if runner["vm"] == "ken-ci"] + [
        "ken-actions-deploy.slice", "ken-actions-deploy-listeners.slice", "ken-actions-deploy-brokers.slice",
        "ken-actions-deploy-transaction-1.slice", "ken-actions-deploy-transaction-2.slice",
        "ken-actions-deploy-builder.slice", "ken-actions-deploy-uploader.slice", "ken-actions-deploy-executor.slice",
    ]
    slice_hashes = {name: hashlib.sha256((systemd_root / name).read_bytes()).hexdigest() for name in slice_names}
    for guest in ("ken-ci", "ken-deploy"):
        guest_runners = [runner for runner in desired.values() if runner["vm"] == guest]
        guest_hashes = {name: digest for name, digest in slice_hashes.items() if (guest == "ken-ci") == name.startswith("ken-ci-")}
        payload = {
            "guest": guest,
            "runners": [{
                "name": runner["name"], "user": runner["user"], "uid": runner["uid"], "gid": runner["gid"],
                "slice": runner["slice"], "docker_enabled": runner["docker"]["enabled"],
            } for runner in guest_runners],
            "disabled_names": [runner["name"] for runner in platform["runners"] if not runner["enabled"] and runner["vm"] == guest],
            "disabled_users": {runner["name"]: runner["user"] for runner in platform["runners"] if not runner["enabled"] and runner["vm"] == guest},
            "slice_sha256": guest_hashes,
            "expected_live_snapshot": expected_live_snapshot(platform, guest),
        }
        response = ssh_verify(ssh_bin, args.host, guest, payload)
        verify_live_snapshot(platform, guest, response, guest_hashes)
    print("RUNNERS_OK=12")
    print("CI_SLICES_OK=10")
    print("DEPLOY_CGROUP_OK=1")
    print("VERIFY_MODE=live-read-only")


def main():
    platform_path = Path(sys.argv[1]).resolve()
    args = parse_args(sys.argv[2:])
    try:
        platform = yaml.load(platform_path.read_text(), Loader=UniqueLoader)
        if args.dry_run:
            print(f"RUNNER_VERIFY_PLAN={sum(bool(item.get('enabled')) for item in platform.get('runners', []))}")
            print("NO_MUTATION=1")
            return
        if args.test_fake_root:
            verify_fake(platform, Path(args.test_fake_root))
        else:
            run_live(platform, args)
    except (OSError, yaml.YAMLError, VerificationError) as error:
        die(str(error))


main()
PY
