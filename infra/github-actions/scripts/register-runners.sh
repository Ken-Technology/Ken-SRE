#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SCRIPT_DIR
GA_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd -P)"
readonly GA_ROOT
readonly PLATFORM_FILE="${KEN_RUNNER_PLATFORM_FILE:-${GA_ROOT}/inventory/runner-platform.yaml}"

exec python3 - "${PLATFORM_FILE}" "${GA_ROOT}" "$@" <<'PY'
import argparse
import hashlib
import grp
import json
import math
import os
import re
import shlex
import stat
import subprocess
import sys
import time
import uuid
from pathlib import Path

import yaml


class ContractError(RuntimeError):
    pass


class UniqueLoader(yaml.SafeLoader):
    pass


def construct_unique_mapping(loader, node, deep=False):
    mapping = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise ContractError(f"duplicate YAML key: {key}")
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, construct_unique_mapping)


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


def read_strict_json(path, label, *, require_root=False):
    def reject_duplicate(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ContractError(f"{label} contains duplicate JSON key: {key}")
            result[key] = value
        return result

    def reject_constant(value):
        raise ContractError(f"{label} contains invalid numeric constant: {value}")

    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError as error:
        if path.is_symlink():
            raise ContractError(f"{label} is symlinked") from error
        raise ContractError(f"{label} is missing or unsafe") from error
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode):
            raise ContractError(f"{label} is not a regular file")
        if stat.S_IMODE(metadata.st_mode) != 0o600:
            raise ContractError(f"{label} must be mode 0600")
        if require_root and metadata.st_uid != 0:
            raise ContractError(f"{label} must be root-owned mode 0600")
        with os.fdopen(fd, "r", encoding="utf-8") as handle:
            fd = -1
            value = json.load(handle, object_pairs_hook=reject_duplicate, parse_constant=reject_constant)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ContractError(f"{label} is malformed: {error}") from error
    finally:
        if fd >= 0:
            os.close(fd)
    if not isinstance(value, dict):
        raise ContractError(f"{label} schema must be an object")
    return value


def authority_paths(ga_root, *, fake_root=None):
    if fake_root is not None:
        return (
            fake_root / "authority/broker-runtime.lock.yaml",
            fake_root / "authority/guest-image-manifest.yaml",
        )
    lock_override = os.environ.get("KEN_RUNNER_RUNTIME_LOCK_FILE")
    manifest_override = os.environ.get("KEN_RUNNER_GUEST_MANIFEST_FILE")
    if lock_override or manifest_override:
        if os.environ.get("KEN_RUNNER_COMMAND_TEST") != "1" or not (lock_override and manifest_override):
            raise ContractError("runtime authority path overrides are test-only and must be complete")
        return Path(lock_override), Path(manifest_override)
    return (
        ga_root / "inventory/broker-runtime.lock.yaml",
        ga_root / "inventory/guest-image-manifest.yaml",
    )


def read_authority_file(path, label):
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError as error:
        detail = "symlinked" if path.is_symlink() else "missing or unsafe"
        raise ContractError(f"{label} is {detail}") from error
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode):
            raise ContractError(f"{label} is not a regular file")
        if metadata.st_uid not in {0, os.getuid()} or stat.S_IMODE(metadata.st_mode) & 0o022:
            raise ContractError(f"{label} has unsafe ownership or mode")
        with os.fdopen(fd, "rb") as handle:
            fd = -1
            return handle.read()
    finally:
        if fd >= 0:
            os.close(fd)


def require_exact_keys(value, expected, label):
    if not isinstance(value, dict) or set(value) != set(expected):
        raise ContractError(f"{label} schema mismatch")


def require_sha256(value, label):
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise ContractError(f"{label} is malformed")
    return value


def validate_artifact_authority(evidence, ga_root, *, fake_root=None):
    lock_path, manifest_path = authority_paths(ga_root, fake_root=fake_root)
    lock_bytes = read_authority_file(lock_path, "Task 6 runtime lock")
    manifest_bytes = read_authority_file(manifest_path, "Task 4 guest image manifest")
    try:
        manifest = yaml.load(manifest_bytes, Loader=UniqueLoader)
    except yaml.YAMLError as error:
        raise ContractError(f"Task 4 guest image manifest is malformed: {error}") from error
    if not isinstance(manifest, dict) or manifest.get("schema_version") != 1:
        raise ContractError("Task 4 guest image manifest schema mismatch")

    authority = manifest.get("authority")
    if not isinstance(authority, dict):
        raise ContractError("Task 4 guest image manifest authority schema mismatch")
    task6_commit = authority.get("task6_commit")
    if not isinstance(task6_commit, str) or re.fullmatch(r"[0-9a-f]{40}", task6_commit) is None:
        raise ContractError("Task 4 guest image manifest Task 6 commit is malformed")
    lock_sha256 = hashlib.sha256(lock_bytes).hexdigest()
    if authority.get("broker_runtime_lock_sha256") != lock_sha256:
        raise ContractError("Task 4 manifest runtime lock digest mismatch")
    require_sha256(authority.get("op_broker_policy_sha256"), "Task 4 manifest broker policy digest")

    readiness = manifest.get("readiness")
    if not isinstance(readiness, dict) or readiness.get("state") != "ready" or readiness.get("live_apply_allowed") is not True:
        raise ContractError("Task 4 guest image manifest is not ready for live apply")
    derived = manifest.get("derived_images")
    require_exact_keys(derived, {"status", "ci", "deploy"}, "Task 4 derived images")
    if derived.get("status") != "ready":
        raise ContractError("Task 4 derived images are not ready")
    verification = manifest.get("verification")
    if not isinstance(verification, dict):
        raise ContractError("Task 4 verification schema mismatch")
    receipts = verification.get("result_receipts")
    require_exact_keys(receipts, {"ci", "deploy"}, "Task 4 result receipts")

    derived_sha256 = {}
    for key, guest, expected_path, expected_size in (
        ("ci", "ken-ci", "/mnt/data/libvirt/images/ken-ci.qcow2", 750),
        ("deploy", "ken-deploy", "/mnt/data/libvirt/images/ken-deploy.qcow2", 80),
    ):
        image = derived.get(key)
        receipt = receipts.get(key)
        require_exact_keys(image, {"path", "sha256", "virtual_size_gib", "receipt_sha256"}, f"Task 4 {guest} derived image")
        require_exact_keys(receipt, {"path", "sha256"}, f"Task 4 {guest} result receipt")
        if image.get("path") != expected_path or image.get("virtual_size_gib") != expected_size:
            raise ContractError(f"Task 4 {guest} derived image contract mismatch")
        derived_sha256[guest] = require_sha256(image.get("sha256"), f"Task 4 {guest} derived image digest")
        receipt_sha256 = require_sha256(receipt.get("sha256"), f"Task 4 {guest} result receipt digest")
        if image.get("receipt_sha256") != receipt_sha256 or not isinstance(receipt.get("path"), str) or not receipt.get("path").startswith("/"):
            raise ContractError(f"Task 4 {guest} result receipt mismatch")

    artifact = evidence.get("artifact_authority")
    require_exact_keys(
        artifact,
        {"task6_runtime_lock_sha256", "guest_image_manifest_sha256", "derived_images"},
        "Task 4 artifact authority",
    )
    require_exact_keys(artifact.get("derived_images"), {"ken-ci", "ken-deploy"}, "Task 4 evidence derived images")
    if require_sha256(artifact.get("task6_runtime_lock_sha256"), "Task 4 evidence runtime lock digest") != lock_sha256:
        raise ContractError("Task 4 evidence runtime lock digest mismatch")
    manifest_sha256 = hashlib.sha256(manifest_bytes).hexdigest()
    if require_sha256(artifact.get("guest_image_manifest_sha256"), "Task 4 evidence guest image manifest digest") != manifest_sha256:
        raise ContractError("Task 4 evidence guest image manifest digest mismatch")
    for guest, expected_digest in derived_sha256.items():
        if require_sha256(artifact["derived_images"].get(guest), f"Task 4 evidence {guest} derived image digest") != expected_digest:
            raise ContractError(f"Task 4 evidence derived image digest mismatch: {guest}")


def validate_task4_evidence(evidence, ga_root, *, fake_root=None):
    require_exact_keys(
        evidence,
        {
            "schema_version",
            "approval_phrase",
            "combined_approval_verified",
            "host",
            "host_memory_available_gib",
            "firewall_generation_verified",
            "artifact_authority",
            "vms",
        },
        "Task 4 evidence",
    )
    if evidence.get("schema_version") != 1:
        raise ContractError("Task 4 evidence schema mismatch")
    if evidence.get("approval_phrase") != "Task 4/6 approved and 1Password ready" or evidence.get("combined_approval_verified") is not True:
        raise ContractError("combined Task 4/6 approval evidence is missing")
    if evidence.get("host") != "root@167.235.8.250":
        raise ContractError("Task 4 evidence host mismatch")
    host_memory = evidence.get("host_memory_available_gib")
    if isinstance(host_memory, bool) or not isinstance(host_memory, (int, float)) or not math.isfinite(host_memory) or host_memory < 32:
        raise ContractError("Task 4 host memory evidence is below 32 GiB")
    if evidence.get("firewall_generation_verified") is not True:
        raise ContractError("Task 4 isolation evidence is incomplete")
    vms = evidence.get("vms")
    require_exact_keys(vms, {"ken-ci", "ken-deploy"}, "Task 4 VM evidence")
    for name, expected_memory in (("ken-ci", 112), ("ken-deploy", 12)):
        vm = vms.get(name)
        require_exact_keys(vm, {"healthy", "isolation_verified", "memory_gib", "memory_health_verified"}, f"Task 4 VM evidence {name}")
        if vm.get("healthy") is not True or vm.get("isolation_verified") is not True:
            raise ContractError(f"Task 4 VM evidence mismatch: {name}")
        if vm.get("memory_gib") != expected_memory or vm.get("memory_health_verified") is not True:
            raise ContractError(f"Task 4 guest memory evidence is incomplete: {name}")
    validate_artifact_authority(evidence, ga_root, fake_root=fake_root)
    return evidence


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
        platform = yaml.load(platform_path.read_text(), Loader=UniqueLoader)
        observed = yaml.load((ga_root / "inventory/repositories.yaml").read_text(), Loader=UniqueLoader)
    except (OSError, yaml.YAMLError) as error:
        raise ContractError(f"cannot load runner inventory: {error}") from error
    if platform.get("schema_version") != 2 or platform.get("organization") != "Ken-Technology":
        raise ContractError("runner platform schema or organization is invalid")
    if platform.get("runner_distribution") != {
        "version": "2.336.0",
        "archive_url": "https://github.com/actions/runner/releases/download/v2.336.0/actions-runner-linux-x64-2.336.0.tar.gz",
        "sha256": "04cf0be1aff4c3ec3554466c39124ca250e3effd8873bb7e8d68535aa9505d5d",
        "release_id": 356901421,
        "asset_id": 483731096,
        "provenance_url": "https://api.github.com/repos/actions/runner/releases/356901421",
        "provenance_retrieved_at": "2026-08-19T20:52:33Z",
    }:
        raise ContractError("runner distribution pin or provenance changed")
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
    expected_enabled_ci = [f"ken-ci-standard-{index:02d}" for index in range(1, 9)] + ["ken-ci-heavy-01", "ken-ci-heavy-02"]
    expected_enabled_deploy = ["ken-deploy-nonproduction-01", "ken-deploy-production-01"]
    enabled_ci = [item.get("name") for item in runners if item.get("enabled") and item.get("vm") == "ken-ci"]
    enabled_deploy = [item.get("name") for item in runners if item.get("enabled") and item.get("vm") == "ken-deploy"]
    disabled = {item.get("name") for item in runners if item.get("enabled") is False}
    if enabled_ci != expected_enabled_ci or enabled_deploy != expected_enabled_deploy or disabled != {"ken-ci-standard-09", "ken-ci-standard-10"}:
        raise ContractError("runner identity enablement does not match exact 10 CI + 2 deploy model")
    unique_fields = ("name", "user", "uid", "gid", "home", "runner_root", "work_root", "subuid_start", "subgid_start", "systemd_instance")
    for field in unique_fields:
        values = [item.get(field) for item in runners]
        if None in values or len(values) != len(set(values)):
            raise ContractError(f"runner desired state has duplicate or missing {field}")
    ranges = []
    exact_labels = {
        "standard": ["self-hosted", "linux", "x64", "ken-ci", "standard"],
        "heavy": ["self-hosted", "linux", "x64", "ken-ci", "heavy"],
        "nonproduction": ["self-hosted", "linux", "x64", "ken-deploy", "nonproduction"],
        "production": ["self-hosted", "linux", "x64", "ken-deploy", "production"],
    }
    for runner in runners:
        name = runner.get("name")
        if "credential_profile" in runner or "credential_delivery" in runner:
            raise ContractError(f"runner inventory contains credential delivery fields: {name}")
        if runner.get("uid") != runner.get("gid") or runner.get("subuid_start") != runner.get("subgid_start") or runner.get("subid_count") != 65536:
            raise ContractError(f"runner account or subordinate-ID contract changed: {name}")
        base = f"/var/lib/ken-runners/{name}"
        expected_paths = {
            "home": f"{base}/home",
            "runner_root": f"{base}/runner",
            "work_root": f"{base}/work",
        }
        if any(runner.get(key) != value for key, value in expected_paths.items()):
            raise ContractError(f"runner canonical path contract changed: {name}")
        ranges.append((runner["subuid_start"], runner["subuid_start"] + runner["subid_count"], name))
        expected_slice = None
        if runner.get("enabled") and runner.get("vm") == "ken-ci":
            expected_slice = name.replace("ken-ci-", "ken-ci-runner-") + ".slice"
        elif runner.get("enabled") and runner.get("vm") == "ken-deploy":
            expected_slice = "ken-actions-deploy-listeners.slice"
        if runner.get("slice") != expected_slice:
            raise ContractError(f"runner slice contract changed: {name}")
        if runner.get("labels") != exact_labels.get(runner.get("class")):
            raise ContractError(f"runner label contract changed: {name}")
        expected_group = "ci" if runner.get("vm") == "ken-ci" else "deploy"
        if runner.get("runner_group") != expected_group:
            raise ContractError(f"runner group/VM contract changed: {name}")
        docker = runner.get("docker", {})
        if docker.get("enabled") is not (runner.get("vm") == "ken-ci"):
            raise ContractError(f"runner Docker contract changed: {name}")
        if docker.get("data_root") != f"{base}/docker" or docker.get("runtime_root") != f"/run/ken-rootless-docker/{name}":
            raise ContractError(f"runner Docker path contract changed: {name}")
    for (_, end, name), (next_start, _, _) in zip(sorted(ranges), sorted(ranges)[1:]):
        if end > next_start:
            raise ContractError(f"runner subordinate-ID range overlaps after {name}")
    if platform.get("classes") != {
        "standard": {"cpu_quota": "200%", "memory_max": "8G", "memory_swap_max": 0, "tasks_max": 4096},
        "heavy": {"cpu_quota": "400%", "memory_max": "16G", "memory_swap_max": 0, "tasks_max": 8192},
    }:
        raise ContractError("CI resource classes changed")
    deploy = platform.get("deploy_resources", {})
    if (
        deploy.get("parent_slice") != "ken-actions-deploy.slice"
        or deploy.get("ordinary_leases") != 2
        or deploy.get("exclusive_action") != "ken-frontend-production-release"
        or deploy.get("writer_preference") is not True
    ):
        raise ContractError("deploy aggregate or lease contract changed")
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
    parser.add_argument("--approval-evidence")
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


def verify_task4_evidence(fake_root, ga_root):
    path = fake_root / "task4-evidence.json"
    evidence = read_strict_json(path, "Task 4 evidence")
    validate_task4_evidence(evidence, ga_root, fake_root=fake_root)


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
        "sudo": False,
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
    }


def rendered_units(ga_root, platform, runner):
    listener = (ga_root / "systemd/ken-runner@.service").read_text()
    docker = (ga_root / "systemd/ken-runner-docker@.service").read_text()
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
    }
    if runner["vm"] == "ken-ci":
        slice_path = ga_root / "systemd" / runner["slice"]
        if not slice_path.is_file() or slice_path.is_symlink():
            raise ContractError(f"reviewed concrete slice is missing: {runner['slice']}")
        result[runner["slice"]] = slice_path.read_text()
    else:
        for filename in (
            "ken-actions-deploy.slice",
            "ken-actions-deploy-listeners.slice",
            "ken-actions-deploy-brokers.slice",
            "ken-actions-deploy-transaction-1.slice",
            "ken-actions-deploy-transaction-2.slice",
            "ken-actions-deploy-builder.slice",
            "ken-actions-deploy-uploader.slice",
            "ken-actions-deploy-executor.slice",
        ):
            path = ga_root / "systemd" / filename
            if not path.is_file() or path.is_symlink():
                raise ContractError(f"reviewed deploy slice is missing: {filename}")
            result[filename] = path.read_text()
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


def rendered_helpers(ga_root):
    path = ga_root / "systemd/ken-runner-cleanup"
    if not path.is_file() or path.is_symlink():
        raise ContractError("reviewed runner cleanup helper is missing")
    return {"/usr/local/libexec/ken-runner-cleanup": path.read_text()}


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
                raise ContractError(f"disabled runner local state exists: {runner['name']} {label}")


def maybe_fail(point):
    if os.environ.get("KEN_RUNNER_TEST_FAIL_AFTER") == point:
        raise ContractError(f"injected failure after {point}")


def register_fake(platform, ga_root, fake_root):
    if os.environ.get("KEN_RUNNER_OFFLINE_TEST") != "1":
        raise ContractError("test fake transport requires KEN_RUNNER_OFFLINE_TEST=1")
    fake_root = fake_root.resolve()
    verify_task4_evidence(fake_root, ga_root)
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

        deploy_unit_root = fake_root / "guests/ken-deploy/units"
        for filename in (
            "ken-actions-deploy.slice",
            "ken-actions-deploy-listeners.slice",
            "ken-actions-deploy-brokers.slice",
            "ken-actions-deploy-transaction-1.slice",
            "ken-actions-deploy-transaction-2.slice",
            "ken-actions-deploy-builder.slice",
            "ken-actions-deploy-uploader.slice",
            "ken-actions-deploy-executor.slice",
        ):
            source = ga_root / "systemd" / filename
            target = deploy_unit_root / filename
            if target.exists() or target.is_symlink():
                if not target.is_file() or target.is_symlink() or target.read_text() != source.read_text():
                    raise ContractError(f"deploy slice identity drift: {filename}")
            else:
                transaction.create(target, source.read_text(), 0o644)
                changed = True

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
                for kind, value in (("subuids", runner["subuid_start"]), ("subgids", runner["subgid_start"])):
                    subid_path = fake_root / f"guests/{runner['vm']}/{kind}/{runner['name']}.json"
                    if not existing_exact(subid_path, {"start": value, "count": runner["subid_count"]}):
                        raise ContractError(f"local/GitHub runner identity drift: {runner['name']} {kind}")
                for unit_name, unit_content in rendered_units(ga_root, platform, runner).items():
                    unit_path = fake_root / f"guests/{runner['vm']}/units/{unit_name}"
                    if not unit_path.is_file() or unit_path.is_symlink() or unit_path.read_text() != unit_content:
                        raise ContractError(f"local/GitHub runner identity drift: {runner['name']} unit")
                for helper_name, helper_content in rendered_helpers(ga_root).items():
                    helper_path = fake_root / f"guests/{runner['vm']}/filesystem/{helper_name.lstrip('/')}"
                    if not helper_path.is_file() or helper_path.is_symlink() or helper_path.read_text() != helper_content:
                        raise ContractError(f"local/GitHub runner identity drift: {runner['name']} helper")
                continue

            registration_token = "offline-test-short-lived-token"
            if not registration_token:
                raise ContractError("short-lived registration token retrieval failed")
            account_path = fake_root / f"guests/{runner['vm']}/accounts/{runner['name']}.json"
            transaction.create(account_path, canonical_json(account_state(runner)))
            transaction.create(fake_root / f"guests/{runner['vm']}/subuids/{runner['name']}.json", canonical_json({"start": runner["subuid_start"], "count": runner["subid_count"]}))
            transaction.create(fake_root / f"guests/{runner['vm']}/subgids/{runner['name']}.json", canonical_json({"start": runner["subgid_start"], "count": runner["subid_count"]}))
            filesystem_roots = [runner["home"], runner["runner_root"], runner["work_root"]]
            if runner["docker"]["enabled"]:
                filesystem_roots.append(runner["docker"]["data_root"])
            for absolute_path in filesystem_roots:
                transaction.ensure_dir(fake_guest_filesystem_path(fake_root, runner, absolute_path))
            if runner["docker"]["enabled"]:
                transaction.ensure_dir(fake_guest_filesystem_path(fake_root, runner, runner["docker"]["runtime_root"]))
            for unit_name, unit_content in rendered_units(ga_root, platform, runner).items():
                unit_path = fake_root / f"guests/{runner['vm']}/units/{unit_name}"
                if unit_path.exists() or unit_path.is_symlink():
                    if not unit_path.is_file() or unit_path.is_symlink() or unit_path.read_text() != unit_content:
                        raise ContractError(f"unit identity drift: {runner['name']} {unit_name}")
                else:
                    transaction.create(unit_path, unit_content, 0o644)
            for helper_name, helper_content in rendered_helpers(ga_root).items():
                helper_path = fake_root / f"guests/{runner['vm']}/filesystem/{helper_name.lstrip('/')}"
                if helper_path.exists() or helper_path.is_symlink():
                    if not helper_path.is_file() or helper_path.is_symlink() or helper_path.read_text() != helper_content:
                        raise ContractError(f"helper identity drift: {runner['name']} {helper_name}")
                else:
                    transaction.create(helper_path, helper_content, 0o755)
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


REMOTE_RUNNER_PROGRAM = r'''
import hashlib
import grp
import json
import os
import pwd
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
from pathlib import Path

mode = sys.argv[1]
request = json.load(sys.stdin)
name = request.get("name", "")
if not re.fullmatch(r"ken-(?:ci-standard-0[1-8]|ci-heavy-0[12]|deploy-(?:nonproduction|production)-01)", name):
    raise SystemExit("invalid runner identity")
marker = Path("/etc/ken-runners") / f"{name}.desired.json"

def atomic_write(path, content, file_mode=0o600):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + f".tmp.{os.getpid()}")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, file_mode)
    try:
        with os.fdopen(fd, "w") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        try: temporary.unlink()
        except FileNotFoundError: pass

def subid_contract(database, user, start, count, require_own):
    if database.is_symlink() or not database.is_file():
        return False
    own = []
    target_end = start + count
    for line in database.read_text().splitlines():
        parts = line.split(":")
        if len(parts) != 3:
            return False
        entry_user, raw_start, raw_count = parts
        try:
            entry_start, entry_count = int(raw_start), int(raw_count)
        except ValueError:
            return False
        if entry_start < 0 or entry_count <= 0:
            return False
        if entry_user == user:
            own.append(line)
        elif max(start, entry_start) < min(target_end, entry_start + entry_count):
            return False
    expected_line = f"{user}:{start}:{count}"
    return own == ([expected_line] if require_own else [])

def subid_user_present(database, user):
    return database.is_file() and not database.is_symlink() and any(line.startswith(user + ":") for line in database.read_text().splitlines())

def probe():
    expected = request["expected_probe"]
    material = [Path(expected["home"]).parent, Path(expected["home"]), Path(expected["runner_root"]), Path(expected["work_root"]), marker]
    if expected["docker_enabled"]:
        material.extend((Path(expected["docker_data_root"]), Path(expected["docker_runtime_root"])))
    material.append(Path("/etc/ken-runners") / f"{name}.ready")
    if expected["docker_enabled"]:
        material.append(Path("/etc/ken-runners") / f"{name}.docker-ready")
    for unit_name in expected["unit_sha256"]:
        if name in unit_name or (expected["vm"] == "ken-ci" and unit_name.startswith("ken-ci-runner-")):
            material.append(Path("/etc/systemd/system") / unit_name)
    present = [path.exists() or path.is_symlink() for path in material]
    present.extend(subid_user_present(database, expected["user"]) for database in (Path("/etc/subuid"), Path("/etc/subgid")))
    try:
        account = pwd.getpwnam(expected["user"])
        present.append(True)
    except KeyError:
        account = None
        present.append(False)
    if not any(present):
        return {"status": "absent", "name": name}
    if not all(present) or marker.is_symlink() or not marker.is_file():
        return {"status": "drift", "name": name, "reason": "partial-local-state"}
    try:
        marker_record = json.loads(marker.read_text())
    except Exception:
        return {"status": "drift", "name": name, "reason": "invalid-marker"}
    supplementary = sorted(group.gr_name for group in grp.getgrall() if expected["user"] in group.gr_mem)
    if marker_record.get("phase") != "exact" or marker_record.get("desired") != expected or not isinstance(marker_record.get("created_by_transaction"), str) or account.pw_uid != expected["uid"] or account.pw_gid != expected["gid"] or account.pw_dir != expected["home"] or account.pw_shell != "/usr/sbin/nologin" or supplementary:
        return {"status": "drift", "name": name, "reason": "desired-state-mismatch"}
    for database, start in ((Path("/etc/subuid"), expected["subuid_start"]), (Path("/etc/subgid"), expected["subgid_start"])):
        if not subid_contract(database, expected["user"], start, expected["subid_count"], True):
            return {"status": "drift", "name": name, "reason": "subordinate-id-mismatch"}
    for unit_name, digest in expected["unit_sha256"].items():
        path = Path("/etc/systemd/system") / unit_name
        if path.is_symlink() or not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            return {"status": "drift", "name": name, "reason": f"unit-mismatch:{unit_name}"}
    for helper_name, digest in expected["helper_sha256"].items():
        path = Path(helper_name)
        if path.is_symlink() or not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != digest or path.stat().st_uid != 0 or path.stat().st_gid != 0 or (path.stat().st_mode & 0o777) != 0o755:
            return {"status": "drift", "name": name, "reason": f"helper-mismatch:{helper_name}"}
    listener = f"ken-runner@{name}.service"
    enabled = subprocess.run(["systemctl", "is-enabled", "--quiet", listener]).returncode == 0
    active = subprocess.run(["systemctl", "is-active", "--quiet", listener]).returncode == 0
    if not enabled or not active:
        return {"status": "drift", "name": name, "reason": "listener-not-enabled-active"}
    if expected["docker_enabled"]:
        docker = f"ken-runner-docker@{name}.service"
        if subprocess.run(["systemctl", "is-enabled", "--quiet", docker]).returncode or subprocess.run(["systemctl", "is-active", "--quiet", docker]).returncode:
            return {"status": "drift", "name": name, "reason": "docker-not-enabled-active"}
    return {**expected, "created_by_transaction": marker_record["created_by_transaction"]}

if mode == "probe":
    print(json.dumps(probe(), sort_keys=True, separators=(",", ":")))
    raise SystemExit

if mode == "apply":
    if probe().get("status") != "absent":
        raise SystemExit("refusing non-absent runner state")
    expected = request["expected_probe"]
    token = request.pop("registration_token", "")
    if not token or "\n" in token or "\x00" in token:
        raise SystemExit("invalid registration token")
    user = expected["user"]
    uid = expected["uid"]
    gid = expected["gid"]
    for lookup, value, label in ((pwd.getpwuid, uid, "UID"), (grp.getgrgid, gid, "GID")):
        try:
            lookup(value)
        except KeyError:
            pass
        else:
            raise SystemExit(f"refusing occupied {label}")
    try:
        grp.getgrnam(user)
    except KeyError:
        pass
    else:
        raise SystemExit("refusing existing group name")
    for database, start in ((Path("/etc/subuid"), expected["subuid_start"]), (Path("/etc/subgid"), expected["subgid_start"])):
        if not subid_contract(database, user, start, expected["subid_count"], False):
            raise SystemExit(f"refusing subordinate-ID drift: {database.name}")
    if {key: hashlib.sha256(value.encode()).hexdigest() for key, value in request.get("units", {}).items()} != expected["unit_sha256"]:
        raise SystemExit("runner unit payload contract mismatch")
    for unit_name, content in request["units"].items():
        unit_path = Path("/etc/systemd/system") / unit_name
        if unit_path.exists() or unit_path.is_symlink():
            if unit_path.is_symlink() or not unit_path.is_file() or unit_path.read_text() != content:
                raise SystemExit(f"refusing unit drift: {unit_name}")
    helpers = request.get("helpers", {})
    if set(helpers) != {"/usr/local/libexec/ken-runner-cleanup"} or {key: hashlib.sha256(value.encode()).hexdigest() for key, value in helpers.items()} != expected["helper_sha256"]:
        raise SystemExit("runner helper contract mismatch")
    for helper_name, content in helpers.items():
        helper_path = Path(helper_name)
        if helper_path.exists() or helper_path.is_symlink():
            if helper_path.is_symlink() or not helper_path.is_file() or helper_path.read_text() != content:
                raise SystemExit(f"refusing helper drift: {helper_name}")
    transaction = {"desired": expected, "created_by_transaction": request["transaction_id"], "phase": "installing", "created_units": [], "created_helpers": [], "created_group": False, "created_user": False}
    atomic_write(marker, json.dumps(transaction, sort_keys=True, separators=(",", ":")) + "\n", 0o600)
    subprocess.run(["groupadd", "--gid", str(gid), user], check=True)
    transaction["created_group"] = True
    atomic_write(marker, json.dumps(transaction, sort_keys=True, separators=(",", ":")) + "\n", 0o600)
    subprocess.run(["useradd", "--uid", str(uid), "--gid", str(gid), "--home-dir", expected["home"], "--shell", "/usr/sbin/nologin", "--no-create-home", user], check=True)
    transaction["created_user"] = True
    atomic_write(marker, json.dumps(transaction, sort_keys=True, separators=(",", ":")) + "\n", 0o600)
    subprocess.run(["usermod", "--lock", user], check=True)
    for database, start in ((Path("/etc/subuid"), expected["subuid_start"]), (Path("/etc/subgid"), expected["subgid_start"])):
        lines = [line for line in database.read_text().splitlines() if not line.startswith(user + ":")]
        lines.append(f"{user}:{start}:{expected['subid_count']}")
        atomic_write(database, "\n".join(lines) + "\n", 0o644)
    runner_base = Path(expected["home"]).parent
    shared_base = runner_base.parent
    if runner_base != Path("/var/lib/ken-runners") / name or shared_base != Path("/var/lib/ken-runners"):
        raise SystemExit("runner filesystem base mismatch")
    if shared_base.is_symlink() or (shared_base.exists() and not shared_base.is_dir()):
        raise SystemExit("runner shared base is unsafe")
    shared_base.mkdir(mode=0o755, parents=True, exist_ok=True)
    runner_base.mkdir(mode=0o700, exist_ok=False)
    os.chown(runner_base, uid, gid)
    filesystem_keys = ["home", "runner_root", "work_root"]
    if expected["docker_enabled"]:
        filesystem_keys.append("docker_data_root")
    for key in filesystem_keys:
        path = Path(expected[key])
        path.mkdir(mode=0o700, exist_ok=False)
        os.chown(path, uid, gid)
    if expected["docker_enabled"]:
        runtime = Path(expected["docker_runtime_root"])
        runtime.mkdir(mode=0o700, parents=True, exist_ok=False)
        os.chown(runtime, uid, gid)
    archive = request["runner_distribution"]
    with tempfile.NamedTemporaryFile(prefix="ken-runner-", suffix=".tar.gz", delete=False) as handle:
        archive_path = Path(handle.name)
        with urllib.request.urlopen(archive["archive_url"], timeout=120) as response:
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk: break
                handle.write(chunk)
    try:
        if hashlib.sha256(archive_path.read_bytes()).hexdigest() != archive["sha256"]:
            raise SystemExit("runner archive checksum mismatch")
        with tarfile.open(archive_path, "r:gz") as bundle:
            bundle.extractall(expected["runner_root"], filter="data")
    finally:
        archive_path.unlink(missing_ok=True)
    for unit_name, content in request["units"].items():
        unit_path = Path("/etc/systemd/system") / unit_name
        if unit_path.exists() or unit_path.is_symlink():
            if unit_path.is_symlink() or not unit_path.is_file() or unit_path.read_text() != content:
                raise SystemExit(f"refusing unit drift: {unit_name}")
        else:
            atomic_write(unit_path, content, 0o644)
            transaction["created_units"].append(unit_name)
            atomic_write(marker, json.dumps(transaction, sort_keys=True, separators=(",", ":")) + "\n", 0o600)
    for helper_name, content in helpers.items():
        helper_path = Path(helper_name)
        if helper_path.exists() or helper_path.is_symlink():
            if helper_path.is_symlink() or not helper_path.is_file() or helper_path.read_text() != content:
                raise SystemExit(f"refusing helper drift: {helper_name}")
        else:
            atomic_write(helper_path, content, 0o755)
            transaction["created_helpers"].append(helper_name)
            atomic_write(marker, json.dumps(transaction, sort_keys=True, separators=(",", ":")) + "\n", 0o600)
    config = Path(expected["runner_root"]) / "config.sh"
    command = [
        "runuser", "-u", user, "--", str(config), "--unattended",
        "--url", request["organization_url"], "--token", token,
        "--name", name, "--runnergroup", expected["runner_group"],
        "--labels", ",".join(expected["labels"]), "--work", expected["work_root"],
        "--disableupdate",
    ]
    try:
        config_result = subprocess.run(
            command,
            check=False,
            env={"PATH": "/usr/bin:/bin", "HOME": expected["home"]},
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except OSError as error:
        token = ""
        raise SystemExit(f"runner configuration execution failed: {type(error).__name__}")
    token = ""
    if config_result.returncode != 0:
        raise SystemExit(f"runner configuration failed: exit {config_result.returncode}")
    runner_root = Path(expected["runner_root"])
    for path in runner_root.rglob("*"):
        if path.is_symlink():
            os.chown(path, 0, 0, follow_symlinks=False)
        elif path.is_file():
            os.chown(path, 0, 0)
            path.chmod(path.stat().st_mode & ~0o222)
        elif path.is_dir():
            os.chown(path, 0, 0)
            path.chmod(0o555)
    for state_name in (".runner", ".credentials", ".credentials_rsaparams"):
        state_path = runner_root / state_name
        if state_path.is_file() and not state_path.is_symlink():
            os.chown(state_path, uid, gid)
            state_path.chmod(0o600)
    for writable_name in ("_diag", "_tool"):
        writable = runner_root / writable_name
        writable.mkdir(mode=0o700, exist_ok=True)
        os.chown(writable, uid, gid)
    os.chown(runner_root, 0, 0)
    runner_root.chmod(0o755)
    Path("/var/lib/ken-runner-state").mkdir(mode=0o700, parents=True, exist_ok=True)
    ready = Path("/etc/ken-runners") / f"{name}.ready"
    atomic_write(ready, "ready\n", 0o600)
    if expected["docker_enabled"]:
        atomic_write(Path("/etc/ken-runners") / f"{name}.docker-ready", "ready\n", 0o600)
    transaction["phase"] = "exact"
    atomic_write(marker, json.dumps(transaction, sort_keys=True, separators=(",", ":")) + "\n", 0o600)
    subprocess.run(["systemctl", "daemon-reload"], check=True)
    units = [f"ken-runner@{name}.service"]
    if expected["docker_enabled"]: units.insert(0, f"ken-runner-docker@{name}.service")
    subprocess.run(["systemctl", "enable", "--now", *units], check=True)
    print(json.dumps({"status": "created", "name": name, "created_units": transaction["created_units"]}))
    raise SystemExit

if mode == "rollback":
    expected = request["expected_probe"]
    user = expected["user"]
    if not marker.is_file() or marker.is_symlink():
        raise SystemExit("rollback ownership marker is missing")
    marker_record = json.loads(marker.read_text())
    if marker_record.get("desired") != expected or marker_record.get("created_by_transaction") != request.get("transaction_id"):
        raise SystemExit("rollback ownership mismatch")
    token = request.pop("removal_token", "")
    rollback_failures = []

    def cleanup_command(label, argv, env=None, suppress_output=False):
        try:
            result = subprocess.run(
                argv,
                check=False,
                env=env,
                stdout=subprocess.DEVNULL if suppress_output else None,
                stderr=subprocess.DEVNULL if suppress_output else None,
            )
        except OSError as error:
            rollback_failures.append(f"{label}:exec-{type(error).__name__}")
            return
        if result.returncode != 0:
            rollback_failures.append(f"{label}:exit-{result.returncode}")

    units = [f"ken-runner@{name}.service"]
    if expected["docker_enabled"]: units.append(f"ken-runner-docker@{name}.service")
    cleanup_command("disable-units", ["systemctl", "disable", "--now", *units])
    config = Path(expected["runner_root"]) / "config.sh"
    if config.is_symlink() or (config.exists() and not config.is_file()):
        rollback_failures.append("remove-registration:unsafe-config")
    elif config.is_file():
        cleanup_command(
            "remove-registration",
            ["runuser", "-u", user, "--", str(config), "remove", "--unattended", "--token", token],
            {"PATH": "/usr/bin:/bin", "HOME": expected["home"]},
            True,
        )
    token = ""
    for unit_name in marker_record.get("created_units", []):
        path = Path("/etc/systemd/system") / unit_name
        expected_digest = expected["unit_sha256"].get(unit_name)
        if path.is_symlink() or (path.exists() and not path.is_file()):
            rollback_failures.append(f"remove-unit:{unit_name}:unsafe")
        elif path.is_file():
            if expected_digest is None or hashlib.sha256(path.read_bytes()).hexdigest() != expected_digest:
                rollback_failures.append(f"remove-unit:{unit_name}:drift")
            else:
                try: path.unlink()
                except OSError as error: rollback_failures.append(f"remove-unit:{unit_name}:{type(error).__name__}")
    for helper_name in marker_record.get("created_helpers", []):
        if helper_name != "/usr/local/libexec/ken-runner-cleanup":
            rollback_failures.append("remove-helper:unsafe-name")
            continue
        path = Path(helper_name)
        expected_digest = expected.get("helper_sha256", {}).get(helper_name)
        if path.is_symlink() or (path.exists() and not path.is_file()):
            rollback_failures.append("remove-helper:unsafe")
        elif path.is_file():
            if expected_digest is None or hashlib.sha256(path.read_bytes()).hexdigest() != expected_digest:
                rollback_failures.append("remove-helper:drift")
            else:
                try: path.unlink()
                except OSError as error: rollback_failures.append(f"remove-helper:{type(error).__name__}")
    for suffix in (".ready", ".docker-ready"):
        (Path("/etc/ken-runners") / f"{name}{suffix}").unlink(missing_ok=True)
    base = Path(expected["home"]).parent
    if base == Path("/var/lib/ken-runners") / name and base.is_dir() and not base.is_symlink():
        try: shutil.rmtree(base)
        except OSError as error: rollback_failures.append(f"remove-runner-tree:{type(error).__name__}")
    elif base.exists() or base.is_symlink():
        rollback_failures.append("remove-runner-tree:unsafe")
    runtime = Path(expected["docker_runtime_root"])
    if runtime == Path("/run/ken-rootless-docker") / name and runtime.is_dir() and not runtime.is_symlink():
        try: shutil.rmtree(runtime)
        except OSError as error: rollback_failures.append(f"remove-runtime-tree:{type(error).__name__}")
    elif runtime.exists() or runtime.is_symlink():
        rollback_failures.append("remove-runtime-tree:unsafe")
    if marker_record.get("created_user") is True:
        cleanup_command("remove-user", ["userdel", user])
        for database in (Path("/etc/subuid"), Path("/etc/subgid")):
            if database.is_file() and not database.is_symlink():
                lines = [line for line in database.read_text().splitlines() if not line.startswith(user + ":")]
                atomic_write(database, "\n".join(lines) + ("\n" if lines else ""), 0o644)
            else:
                rollback_failures.append(f"rewrite-{database.name}:unsafe")
    if marker_record.get("created_group") is True:
        cleanup_command("remove-group", ["groupdel", user])
    for suffix in (".dirty", ".clean"):
        (Path("/var/lib/ken-runner-state") / f"{name}{suffix}").unlink(missing_ok=True)
    cleanup_command("daemon-reload", ["systemctl", "daemon-reload"])
    if rollback_failures:
        marker_record["phase"] = "rollback-incomplete"
        marker_record["rollback_failures"] = rollback_failures
        atomic_write(marker, json.dumps(marker_record, sort_keys=True, separators=(",", ":")) + "\n", 0o600)
        raise SystemExit("rollback incomplete: " + ",".join(rollback_failures))
    marker.unlink(missing_ok=True)
    print(json.dumps({"status": "rolled-back", "name": name}))
    raise SystemExit

raise SystemExit("invalid remote mode")
'''


def command_path(name, override_environment):
    override = os.environ.get(override_environment)
    test_mode = os.environ.get("KEN_RUNNER_COMMAND_TEST") == "1"
    if override:
        if not test_mode:
            raise ContractError(f"{override_environment} is test-only")
        path = Path(override).resolve()
    else:
        import shutil
        resolved = shutil.which(name)
        if not resolved:
            raise ContractError(f"required command is missing: {name}")
        path = Path(resolved).resolve()
    if not path.is_file() or path.is_symlink():
        raise ContractError(f"command is not a regular file: {path}")
    return str(path)


def load_live_approval(path_value, ga_root):
    if not path_value:
        raise ContractError("live approval evidence is required before gh or SSH")
    path = Path(path_value)
    evidence = read_strict_json(
        path,
        "live approval evidence",
        require_root=os.environ.get("KEN_RUNNER_COMMAND_TEST") != "1",
    )
    return validate_task4_evidence(evidence, ga_root)


def run_command_json(command, *, input_value=None):
    result = subprocess.run(
        command,
        input=None if input_value is None else canonical_json(input_value),
        text=True,
        capture_output=True,
    )
    if result.returncode != 0:
        detail = "" if input_value is not None else f": {result.stderr.strip()[:300]}"
        raise ContractError(f"command failed without accepted state: {command[0]} exit {result.returncode}{detail}")
    try:
        return json.loads(result.stdout) if result.stdout.strip() else {}
    except json.JSONDecodeError as error:
        raise ContractError(f"command returned invalid JSON: {command[0]}") from error


def gh_api(gh_bin, endpoint, method="GET", fields=None):
    command = [gh_bin, "api", endpoint, "--method", method]
    for key, value in (fields or {}).items():
        command.extend(["-F", f"{key}={str(value).lower() if isinstance(value, bool) else value}"])
    return run_command_json(command)


def gh_paginated(gh_bin, endpoint, collection):
    collected = []
    expected_total = None
    separator = "&" if "?" in endpoint else "?"
    for page in range(1, 101):
        response = gh_api(gh_bin, f"{endpoint}{separator}per_page=100&page={page}")
        items = response.get(collection)
        if not isinstance(items, list) or len(items) > 100:
            raise ContractError(f"GitHub pagination returned invalid {collection} page")
        page_total = response.get("total_count")
        if page_total is not None:
            if not isinstance(page_total, int) or page_total < 0 or (expected_total is not None and page_total != expected_total):
                raise ContractError(f"GitHub pagination returned inconsistent {collection} total")
            expected_total = page_total
        collected.extend(items)
        if expected_total is not None:
            if len(collected) == expected_total:
                return collected
            if len(collected) > expected_total or len(items) < 100:
                raise ContractError(f"GitHub pagination returned incomplete {collection} inventory")
        elif len(items) < 100:
            return collected
    raise ContractError(f"GitHub pagination exceeded the reviewed limit for {collection}")


def resolve_repository_for_link(gh_bin, organization, desired):
    name = desired["name"]
    actual = gh_api(gh_bin, f"repos/{organization}/{name}")
    if (
        actual.get("id") != desired["repository_id"]
        or actual.get("name") != name
        or actual.get("full_name") != f"{organization}/{name}"
        or actual.get("private") is not True
        or actual.get("visibility") != "private"
        or actual.get("archived") is not False
        or actual.get("owner", {}).get("login") != organization
    ):
        raise ContractError(f"fresh repository ID/privacy/archive resolution failed: {name}")
    return actual["id"]


def ssh_runner(ssh_bin, host, guest, mode, payload):
    command = [
        ssh_bin,
        "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=yes",
        "-J", host,
        f"root@{guest}",
        "--", "python3", "-c", REMOTE_RUNNER_PROGRAM, mode,
    ]
    return run_command_json(command, input_value=payload)


def unit_sha256(units):
    return {name: hashlib.sha256(content.encode()).hexdigest() for name, content in units.items()}


def expected_live_probe(ga_root, platform, runner):
    units = rendered_units(ga_root, platform, runner)
    helpers = rendered_helpers(ga_root)
    return {
        "status": "exact",
        "name": runner["name"],
        "vm": runner["vm"],
        "user": runner["user"],
        "uid": runner["uid"],
        "gid": runner["gid"],
        "home": runner["home"],
        "runner_root": runner["runner_root"],
        "work_root": runner["work_root"],
        "docker_enabled": runner["docker"]["enabled"],
        "docker_data_root": runner["docker"]["data_root"],
        "docker_runtime_root": runner["docker"]["runtime_root"],
        "subuid_start": runner["subuid_start"],
        "subgid_start": runner["subgid_start"],
        "subid_count": runner["subid_count"],
        "slice": runner["slice"],
        "runner_group": platform["groups"][runner["runner_group"]]["name"],
        "labels": runner["labels"],
        "version": platform["runner_distribution"]["version"],
        "archive_sha256": platform["runner_distribution"]["sha256"],
        "unit_sha256": unit_sha256(units),
        "helper_sha256": unit_sha256(helpers),
    }


class LiveJournal:
    def __init__(self):
        base = Path(os.environ.get("KEN_RUNNER_JOURNAL_DIR", f"/var/tmp/ken-runner-registration-{os.getuid()}"))
        base.mkdir(mode=0o700, parents=True, exist_ok=True)
        if base.is_symlink() or stat.S_IMODE(base.stat().st_mode) & 0o077:
            raise ContractError("live registration journal directory is not private")
        self.transaction_id = str(uuid.uuid4())
        self.path = base / f"{self.transaction_id}.jsonl"
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
        self.handle = os.fdopen(fd, "w")

    def record(self, event, **fields):
        self.handle.write(canonical_json({"event": event, **fields}))
        self.handle.flush()
        os.fsync(self.handle.fileno())

    def finish(self):
        self.handle.close()


def runner_labels_from_api(item):
    labels = item.get("labels", [])
    return [label.get("name") if isinstance(label, dict) else label for label in labels]


def unique_runner_names(items, context):
    names = [item.get("name") for item in items]
    if None in names or len(names) != len(set(names)):
        raise ContractError(f"{context} contains duplicate or missing runner names")
    return names


def run_live(platform, ga_root, args):
    load_live_approval(args.approval_evidence, ga_root)
    gh_bin = command_path("gh", "KEN_RUNNER_GH_BIN")
    ssh_bin = command_path("ssh", "KEN_RUNNER_SSH_BIN")
    identity = subprocess.run([gh_bin, "api", "user", "--jq", ".login"], text=True, capture_output=True)
    if identity.returncode != 0 or identity.stdout.strip() != "cristian-frunze":
        raise ContractError("GitHub controller identity must be cristian-frunze")
    journal = LiveJournal()
    created_groups = []
    created_runners = []
    try:
        groups_by_name = {item.get("name"): item for item in gh_paginated(gh_bin, f"orgs/{args.org}/actions/runner-groups", "runner_groups")}
        group_ids = {}
        for key in ("ci", "deploy"):
            desired = platform["groups"][key]
            actual = groups_by_name.get(desired["name"])
            if actual is None:
                actual = gh_api(gh_bin, f"orgs/{args.org}/actions/runner-groups", "POST", {
                    "name": desired["name"],
                    "visibility": "selected",
                    "allows_public_repositories": False,
                })
                created_groups.append(actual["id"])
                journal.record("group-created", key=key, group_id=actual["id"])
                for repository in desired["repositories"]:
                    repository_id = resolve_repository_for_link(gh_bin, args.org, repository)
                    gh_api(gh_bin, f"orgs/{args.org}/actions/runner-groups/{actual['id']}/repositories/{repository_id}", "PUT")
            elif actual.get("visibility") != "selected" or actual.get("allows_public_repositories") is not False:
                raise ContractError(f"runner group identity drift: {key}")
            repositories = gh_paginated(gh_bin, f"orgs/{args.org}/actions/runner-groups/{actual['id']}/repositories", "repositories")
            actual_ids = sorted(item.get("id") for item in repositories)
            expected_ids = sorted(item["repository_id"] for item in desired["repositories"])
            if actual_ids != expected_ids:
                raise ContractError(f"runner group repository drift: {key}")
            group_ids[key] = actual["id"]

        github_runners = gh_paginated(gh_bin, f"orgs/{args.org}/actions/runners", "runners")
        unique_runner_names(github_runners, "GitHub runner inventory")
        github_by_name = {item["name"]: item for item in github_runners}
        expected_group_members = {
            key: {runner["name"] for runner in platform["runners"] if runner["enabled"] and runner["runner_group"] == key}
            for key in ("ci", "deploy")
        }
        actual_group_members = {}
        for key in ("ci", "deploy"):
            response = gh_paginated(gh_bin, f"orgs/{args.org}/actions/runner-groups/{group_ids[key]}/runners", "runners")
            names = unique_runner_names(response, f"runner group membership: {key}")
            if not set(names) <= expected_group_members[key]:
                raise ContractError(f"runner group membership drift: {key}")
            actual_group_members[key] = set(names)
        disabled = {runner["name"] for runner in platform["runners"] if not runner["enabled"]}
        if disabled & set(github_by_name):
            raise ContractError(f"disabled runner is registered: {sorted(disabled & set(github_by_name))[0]}")

        changed = False
        for runner in platform["runners"]:
            if not runner["enabled"]:
                continue
            expected_probe = expected_live_probe(ga_root, platform, runner)
            probe_payload = {"name": runner["name"], "expected_probe": expected_probe}
            local = ssh_runner(ssh_bin, args.host, runner["vm"], "probe", probe_payload)
            github = github_by_name.get(runner["name"])
            if local.get("status") == "exact" and github is not None:
                if (
                    github.get("status") != "online"
                    or github.get("busy") is not False
                    or set(runner_labels_from_api(github)) != set(runner["labels"])
                    or len(runner_labels_from_api(github)) != len(runner["labels"])
                    or runner["name"] not in actual_group_members[runner["runner_group"]]
                ):
                    raise ContractError(f"local/GitHub runner identity drift: {runner['name']}")
                continue
            if local.get("status") != "absent" or github is not None:
                raise ContractError(f"local/GitHub runner identity drift: {runner['name']}")
            token_response = gh_api(gh_bin, f"orgs/{args.org}/actions/runners/registration-token", "POST")
            token = token_response.get("token")
            if not isinstance(token, str) or not token:
                raise ContractError("short-lived registration token retrieval failed")
            units = rendered_units(ga_root, platform, runner)
            helpers = rendered_helpers(ga_root)
            expected_github = {
                "name": runner["name"],
                "status": "online",
                "busy": False,
                "runner_group_id": group_ids[runner["runner_group"]],
                "labels": runner["labels"],
            }
            apply_payload = {
                **probe_payload,
                "registration_token": token,
                "expected_github": expected_github,
                "units": units,
                "helpers": helpers,
                "runner_distribution": platform["runner_distribution"],
                "organization_url": f"https://github.com/{args.org}",
                "transaction_id": journal.transaction_id,
            }
            created_runners.append((runner, expected_probe))
            result = ssh_runner(ssh_bin, args.host, runner["vm"], "apply", apply_payload)
            token = ""
            if result.get("status") != "created" or result.get("name") != runner["name"] or not isinstance(result.get("created_units"), list):
                raise ContractError(f"runner install did not return exact success: {runner['name']}")
            registered = None
            for attempt in range(12):
                refreshed = gh_paginated(gh_bin, f"orgs/{args.org}/actions/runners", "runners")
                unique_runner_names(refreshed, "GitHub runner polling inventory")
                registered = next((item for item in refreshed if item["name"] == runner["name"]), None)
                if registered is not None and registered.get("status") == "online" and registered.get("busy") is False:
                    break
                if os.environ.get("KEN_RUNNER_COMMAND_TEST") != "1":
                    time.sleep(5)
            if registered is None or registered.get("status") != "online" or registered.get("busy") is not False or set(runner_labels_from_api(registered)) != set(runner["labels"]) or len(runner_labels_from_api(registered)) != len(runner["labels"]):
                raise ContractError(f"GitHub runner did not reach exact online state: {runner['name']}")
            group_runners = gh_paginated(gh_bin, f"orgs/{args.org}/actions/runner-groups/{group_ids[runner['runner_group']]}/runners", "runners")
            group_names = unique_runner_names(group_runners, f"runner group polling inventory: {runner['runner_group']}")
            if runner["name"] not in set(group_names):
                raise ContractError(f"GitHub runner did not join exact runner group: {runner['name']}")
            journal.record("runner-created", name=runner["name"], vm=runner["vm"])
            changed = True
            if os.environ.get("KEN_RUNNER_TEST_FAIL_AFTER_LIVE") == runner["name"]:
                raise ContractError(f"injected live failure after {runner['name']}")
        for key in ("ci", "deploy"):
            response = gh_paginated(gh_bin, f"orgs/{args.org}/actions/runner-groups/{group_ids[key]}/runners", "runners")
            names = unique_runner_names(response, f"final runner group inventory: {key}")
            if set(names) != expected_group_members[key]:
                raise ContractError(f"runner group membership did not converge exactly: {key}")
        journal.record("complete", created=len(created_runners))
        journal.finish()
        if changed:
            print(f"REGISTERED_RUNNERS={len(created_runners)}")
        else:
            print("NO_CHANGES=1")
        print("REGISTRATION_MODE=live-guarded")
    except Exception as original_error:
        rollback_failures = []
        for runner, expected_probe in reversed(created_runners):
            try:
                token_response = gh_api(gh_bin, f"orgs/{args.org}/actions/runners/remove-token", "POST")
                rollback_payload = {
                    "name": runner["name"],
                    "expected_probe": expected_probe,
                    "transaction_id": journal.transaction_id,
                    "removal_token": token_response.get("token", ""),
                }
                ssh_runner(ssh_bin, args.host, runner["vm"], "rollback", rollback_payload)
            except Exception as rollback_error:
                journal.record("rollback-failed", name=runner["name"], reason=type(rollback_error).__name__)
                rollback_failures.append(f"runner:{runner['name']}")
        for group_id in reversed(created_groups):
            try:
                gh_api(gh_bin, f"orgs/{args.org}/actions/runner-groups/{group_id}", "DELETE")
            except Exception as rollback_error:
                journal.record("group-rollback-failed", group_id=group_id, reason=type(rollback_error).__name__)
                rollback_failures.append(f"group:{group_id}")
        journal.record("failed", rollback_attempted=True, rollback_complete=not rollback_failures)
        journal.finish()
        if rollback_failures:
            raise ContractError(
                f"{original_error}; rollback incomplete: {','.join(rollback_failures)}"
            ) from original_error
        raise


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
        if args.test_fake_root:
            register_fake(platform, ga_root, Path(args.test_fake_root))
        else:
            run_live(platform, ga_root, args)
    except ContractError as error:
        die(str(error))


main()
PY
