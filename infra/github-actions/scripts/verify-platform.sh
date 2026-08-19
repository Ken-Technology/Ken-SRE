#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SCRIPT_DIR
GA_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd -P)"
readonly GA_ROOT
readonly PLATFORM_FILE="${KEN_RUNNER_PLATFORM_FILE:-${GA_ROOT}/inventory/runner-platform.yaml}"

exec python3 - "${PLATFORM_FILE}" "$@" <<'PY'
import argparse
import json
import os
import sys
from pathlib import Path

import yaml


class VerificationError(RuntimeError):
    pass


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
    parser.add_argument("mode", choices=["runners"])
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--test-fake-root")
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
        "credential_profile": "none",
        "credential_delivery": "broker-only-pending-task-6",
    }


def expected_account(runner):
    return {
        "name": runner["user"],
        "uid": runner["uid"],
        "gid": runner["gid"],
        "groups": [],
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
        ("slice unit", guest_root / "units" / runner["slice"]),
    ]
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
        unit_root = fake_root / f"guests/{runner['vm']}/units"
        listener = unit_root / f"ken-runner@{name}.service"
        slice_path = unit_root / runner["slice"]
        if not listener.is_file() or listener.is_symlink() or not slice_path.is_file() or slice_path.is_symlink():
            raise VerificationError(f"unit state is missing: {name}")
        listener_text = listener.read_text()
        slice_text = slice_path.read_text()
        limits = platform["classes"][runner["class"]]
        required = [
            f"User={runner['user']}",
            f"Environment=RUNNER_UID={runner['uid']}",
            f"Slice={runner['slice']}",
            f"CPUQuota={limits['cpu_quota']}",
            f"MemoryMax={limits['memory_max']}",
            f"MemorySwapMax={limits['memory_swap_max']}",
            f"TasksMax={limits['tasks_max']}",
        ]
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
    print(f"RUNNERS_OK={len(enabled)}")
    print("VERIFY_MODE=offline-read-only")


def main():
    platform_path = Path(sys.argv[1]).resolve()
    args = parse_args(sys.argv[2:])
    try:
        platform = yaml.safe_load(platform_path.read_text())
        if args.dry_run:
            print(f"RUNNER_VERIFY_PLAN={sum(bool(item.get('enabled')) for item in platform.get('runners', []))}")
            print("NO_MUTATION=1")
            return
        if not args.test_fake_root:
            raise VerificationError("live verification is blocked until Task 4 evidence is reviewed; offline Task 5 has no live transport")
        verify_fake(platform, Path(args.test_fake_root))
    except (OSError, yaml.YAMLError, VerificationError) as error:
        die(str(error))


main()
PY
