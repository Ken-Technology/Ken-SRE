#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SCRIPT_DIR
GA_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd -P)"
readonly GA_ROOT
readonly PLATFORM_FILE="${KEN_RUNNER_PLATFORM_FILE:-${GA_ROOT}/inventory/runner-platform.yaml}"

exec python3 - "${PLATFORM_FILE}" "${GA_ROOT}" "$@" <<'PY'
import argparse
import json
import os
import re
import sys
from pathlib import Path

import yaml


class ContractError(RuntimeError):
    pass


def die(message):
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


def canonical_json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"


def read_json(path):
    try:
        return json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as error:
        raise ContractError(f"cannot read exact state {path}: {error}") from error


class Transaction:
    def __init__(self, fake_root):
        self.fake_root = fake_root
        self.created_files = []
        self.created_dirs = []
        transaction_root = fake_root / ".transactions"
        transaction_root.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.journal = transaction_root / f"register-{os.getpid()}.jsonl"
        self.journal.write_text("")

    def ensure_dir(self, path):
        missing = []
        current = path
        while not current.exists() and current != self.fake_root.parent:
            missing.append(current)
            current = current.parent
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.created_dirs.extend(missing)

    def create(self, path, content, mode=0o600):
        if path.exists() or path.is_symlink():
            raise ContractError(f"refusing to overwrite existing state: {path}")
        self.ensure_dir(path.parent)
        path.write_text(content)
        path.chmod(mode)
        self.created_files.append(path)
        with self.journal.open("a") as handle:
            handle.write(canonical_json({"created": str(path.relative_to(self.fake_root))}))

    def finish(self):
        self.journal.unlink(missing_ok=True)
        try:
            self.journal.parent.rmdir()
        except OSError:
            pass

    def rollback(self):
        ok = True
        for path in reversed(self.created_files):
            try:
                path.unlink(missing_ok=True)
            except OSError:
                ok = False
        for path in sorted(set(self.created_dirs), key=lambda value: len(value.parts), reverse=True):
            try:
                path.rmdir()
            except OSError:
                pass
        self.finish()
        return ok


def load_contract(platform_path, ga_root):
    try:
        platform = yaml.safe_load(platform_path.read_text())
        observed = yaml.safe_load((ga_root / "inventory/repositories.yaml").read_text())
    except (OSError, yaml.YAMLError) as error:
        raise ContractError(f"cannot load runner inventory: {error}") from error
    if platform.get("schema_version") != 1 or platform.get("organization") != "Ken-Technology":
        raise ContractError("runner platform schema or organization is invalid")
    if platform.get("source_inventory", {}).get("generated_at") != observed.get("generated_at"):
        raise ContractError("runner platform does not match the fresh repository inventory")
    observed_private = {
        item["name"]
        for item in observed.get("repositories", [])
        if item.get("visibility") == "private" and not item.get("archived")
    }
    for key in ("ci", "deploy"):
        group = platform.get("groups", {}).get(key, {})
        repositories = group.get("repositories", [])
        names = [item.get("name") for item in repositories]
        ids = [item.get("repository_id") for item in repositories]
        if group.get("visibility") != "selected" or group.get("allows_public_repositories") is not False:
            raise ContractError(f"{key} runner group is not selected/private-only")
        if len(names) != 15 or len(set(names)) != 15 or not set(names) <= observed_private:
            raise ContractError(f"{key} runner group repository contract is stale or non-private")
        if any(not isinstance(value, int) or value <= 0 for value in ids) or len(set(ids)) != 15:
            raise ContractError(f"{key} runner group repository IDs are invalid")
    runners = platform.get("runners", [])
    if len(runners) != 14 or sum(bool(item.get("enabled")) for item in runners) != 12:
        raise ContractError("runner identity count is not 14 reserved / 12 enabled")
    for runner in runners:
        if runner.get("credential_profile") != "none" or runner.get("credential_delivery") != "broker-only-pending-task-6":
            raise ContractError(f"runner credential boundary changed: {runner.get('name')}")
    return platform


def parse_args(arguments):
    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument("--org", required=True)
    parser.add_argument("--all", action="store_true", dest="all_runners")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--host", default="root@167.235.8.250")
    parser.add_argument("--ci-guest", default="ken-ci")
    parser.add_argument("--deploy-guest", default="ken-deploy")
    parser.add_argument("--test-fake-root")
    return parser.parse_args(arguments)


def validate_target(args):
    if args.org != "Ken-Technology":
        raise ContractError("organization must be Ken-Technology")
    if not args.all_runners:
        raise ContractError("only the reviewed --all runner set is accepted")
    if args.host != "root@167.235.8.250":
        raise ContractError("host must be root@167.235.8.250")
    if args.ci_guest != "ken-ci" or args.deploy_guest != "ken-deploy":
        raise ContractError("guest targets must be ken-ci and ken-deploy")


def verify_task4_evidence(fake_root):
    path = fake_root / "task4-evidence.json"
    if not path.is_file() or path.is_symlink():
        raise ContractError("Task 4 evidence is missing")
    evidence = read_json(path)
    if evidence.get("host") != "root@167.235.8.250":
        raise ContractError("Task 4 evidence host mismatch")
    host_memory = evidence.get("host_memory_available_gib")
    if not isinstance(host_memory, (int, float)) or host_memory < 32:
        raise ContractError("Task 4 host memory evidence is below 32 GiB")
    vms = evidence.get("vms", {})
    if not all(vms.get(name, {}).get("healthy") is True for name in ("ken-ci", "ken-deploy")):
        raise ContractError("Task 4 guest health evidence is incomplete")
    if evidence.get("firewall_generation_verified") is not True or not all(vms.get(name, {}).get("isolation_verified") is True for name in ("ken-ci", "ken-deploy")):
        raise ContractError("Task 4 isolation evidence is incomplete")
    for name, expected_memory in (("ken-ci", 112), ("ken-deploy", 12)):
        if vms.get(name, {}).get("memory_gib") != expected_memory or vms.get(name, {}).get("memory_health_verified") is not True:
            raise ContractError(f"Task 4 guest memory evidence is incomplete: {name}")


def verify_repository_resolution(platform, fake_root):
    resolution = read_json(fake_root / "github-repository-resolver.json")
    expected_repositories = sorted(
        (
            {
                "name": item["name"],
                "id": item["repository_id"],
                "visibility": "private",
                "archived": False,
            }
            for item in platform["groups"]["ci"]["repositories"]
        ),
        key=lambda item: item["name"],
    )
    actual_repositories = resolution.get("repositories")
    if not isinstance(actual_repositories, list):
        raise ContractError("repository resolver mismatch: repositories are missing")
    actual_repositories = sorted(actual_repositories, key=lambda item: str(item.get("name")))
    if (
        resolution.get("organization") != "Ken-Technology"
        or resolution.get("resolved_at") != platform["source_inventory"]["repository_ids_resolved_at"]
        or actual_repositories != expected_repositories
    ):
        raise ContractError("repository resolver mismatch: selected names, IDs, privacy, or freshness changed")


def group_state(key, group):
    return {
        "key": key,
        "name": group["name"],
        "visibility": "selected",
        "allows_public_repositories": False,
        "repositories": group["repositories"],
    }


def account_state(runner):
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


def github_runner_state(platform, runner):
    return {
        "name": runner["name"],
        "status": "online",
        "busy": False,
        "group": platform["groups"][runner["runner_group"]]["name"],
        "labels": runner["labels"],
        "vm": runner["vm"],
    }


def local_runner_state(platform, runner):
    return {
        **github_runner_state(platform, runner),
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


def replace_limit(text, key, value):
    pattern = rf"(?m)^{re.escape(key)}=.*$"
    replacement = f"{key}={value}"
    if not re.search(pattern, text):
        raise ContractError(f"slice template is missing {key}")
    return re.sub(pattern, replacement, text)


def rendered_units(ga_root, platform, runner):
    listener = (ga_root / "systemd/ken-runner@.service").read_text()
    docker = (ga_root / "systemd/ken-runner-docker@.service").read_text()
    slice_text = (ga_root / "systemd/ken-runner@.slice").read_text()
    limits = platform["classes"][runner["class"]]
    slice_text = replace_limit(slice_text, "CPUQuota", limits["cpu_quota"])
    slice_text = replace_limit(slice_text, "MemoryMax", limits["memory_max"])
    slice_text = replace_limit(slice_text, "MemorySwapMax", limits["memory_swap_max"])
    slice_text = replace_limit(slice_text, "TasksMax", limits["tasks_max"])
    unit_override = ""
    docker_environment = ""
    if runner["docker"]["enabled"]:
        docker_unit_name = f"ken-runner-docker@{runner['name']}.service"
        unit_override = (
            "\n[Unit]\n"
            f"Requires={docker_unit_name}\n"
            f"After={docker_unit_name}\n"
            f"BindsTo={docker_unit_name}\n"
        )
        docker_environment = f"Environment=DOCKER_HOST=unix://{runner['docker']['runtime_root']}/docker.sock\n"
    override = (
        unit_override
        + "\n[Service]\n"
        f"User={runner['user']}\n"
        f"Group={runner['user']}\n"
        f"Environment=RUNNER_UID={runner['uid']}\n"
        f"{docker_environment}"
        f"Slice={runner['slice']}\n"
        f"ReadWritePaths={runner['home']}\n"
        f"ReadWritePaths={runner['work_root']}\n"
    )
    result = {
        f"ken-runner@{runner['name']}.service": listener + override,
        runner["slice"]: slice_text,
    }
    if runner["docker"]["enabled"]:
        docker_override = (
            "\n[Service]\n"
            f"User={runner['user']}\n"
            f"Group={runner['user']}\n"
            f"Slice={runner['slice']}\n"
            f"ReadWritePaths={runner['docker']['data_root']}\n"
            f"ReadWritePaths={runner['docker']['runtime_root']}\n"
        )
        result[f"ken-runner-docker@{runner['name']}.service"] = docker + docker_override
    return result


def existing_exact(path, expected):
    return path.is_file() and not path.is_symlink() and read_json(path) == expected


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
                raise ContractError(f"disabled runner local state exists: {runner['name']} {label}")


def maybe_fail(point):
    if os.environ.get("KEN_RUNNER_TEST_FAIL_AFTER") == point:
        raise ContractError(f"injected failure after {point}")


def register_fake(platform, ga_root, fake_root):
    if os.environ.get("KEN_RUNNER_OFFLINE_TEST") != "1":
        raise ContractError("test fake transport requires KEN_RUNNER_OFFLINE_TEST=1")
    fake_root = fake_root.resolve()
    verify_task4_evidence(fake_root)
    verify_repository_resolution(platform, fake_root)
    digest = os.environ.get("KEN_RUNNER_TEST_ARCHIVE_SHA256", "")
    if digest != platform["runner_distribution"]["sha256"]:
        raise ContractError("runner archive checksum mismatch")
    verify_disabled_absent(platform, fake_root)
    transaction = Transaction(fake_root)
    created_runners = 0
    changed = False
    try:
        for key in ("ci", "deploy"):
            expected = group_state(key, platform["groups"][key])
            path = fake_root / f"github/groups/{key}.json"
            if path.exists() or path.is_symlink():
                if not existing_exact(path, expected):
                    raise ContractError(f"runner group mismatch: {key}")
            else:
                transaction.create(path, canonical_json(expected))
                changed = True
            maybe_fail(f"group:{key}")

        for runner in platform["runners"]:
            github_path = fake_root / f"github/runners/{runner['name']}.json"
            guest_path = fake_root / f"guests/{runner['vm']}/runners/{runner['name']}.json"
            if not runner["enabled"]:
                continue
            expected_github = github_runner_state(platform, runner)
            expected_local = local_runner_state(platform, runner)
            exists_github = github_path.exists() or github_path.is_symlink()
            exists_local = guest_path.exists() or guest_path.is_symlink()
            if exists_github or exists_local:
                if not (exists_github and exists_local and existing_exact(github_path, expected_github) and existing_exact(guest_path, expected_local)):
                    raise ContractError(f"local/GitHub runner identity drift: {runner['name']}")
                account_path = fake_root / f"guests/{runner['vm']}/accounts/{runner['name']}.json"
                if not existing_exact(account_path, account_state(runner)):
                    raise ContractError(f"local/GitHub runner identity drift: {runner['name']} account")
                for unit_name, unit_content in rendered_units(ga_root, platform, runner).items():
                    unit_path = fake_root / f"guests/{runner['vm']}/units/{unit_name}"
                    if not unit_path.is_file() or unit_path.is_symlink() or unit_path.read_text() != unit_content:
                        raise ContractError(f"local/GitHub runner identity drift: {runner['name']} unit")
                continue

            registration_token = "offline-test-short-lived-token"
            if not registration_token:
                raise ContractError("short-lived registration token retrieval failed")
            account_path = fake_root / f"guests/{runner['vm']}/accounts/{runner['name']}.json"
            transaction.create(account_path, canonical_json(account_state(runner)))
            for unit_name, unit_content in rendered_units(ga_root, platform, runner).items():
                transaction.create(fake_root / f"guests/{runner['vm']}/units/{unit_name}", unit_content, 0o644)
            transaction.create(guest_path, canonical_json(expected_local))
            maybe_fail(f"{runner['name']}:local")
            transaction.create(github_path, canonical_json(expected_github))
            maybe_fail(f"{runner['name']}:github")
            created_runners += 1
            changed = True
            registration_token = ""
        transaction.finish()
    except Exception:
        rollback_ok = transaction.rollback()
        print(f"ROLLBACK_STATUS={'ok' if rollback_ok else 'failed'}", file=sys.stderr)
        raise
    if changed:
        print(f"CREATED_RUNNERS={created_runners}")
    else:
        print("NO_CHANGES=1")
    print("REGISTRATION_MODE=offline-fake")


def main():
    platform_path = Path(sys.argv[1]).resolve()
    ga_root = Path(sys.argv[2]).resolve()
    args = parse_args(sys.argv[3:])
    try:
        validate_target(args)
        platform = load_contract(platform_path, ga_root)
        enabled = [runner for runner in platform["runners"] if runner["enabled"]]
        if args.dry_run:
            print(f"RUNNER_PLAN_ENABLED={len(enabled)}")
            print("RUNNER_PLAN_DISABLED=2")
            print("NO_MUTATION=1")
            return
        if not args.test_fake_root:
            raise ContractError("live registration is blocked until Task 4 evidence is reviewed; offline Task 5 has no live transport")
        register_fake(platform, ga_root, Path(args.test_fake_root))
    except ContractError as error:
        die(str(error))


main()
PY
