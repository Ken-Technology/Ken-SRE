#!/usr/bin/env python3
"""Populate canonical vaults from protected authorities without value-bearing evidence.

This is a deliberately small orchestration layer around the existing
``consolidate-1password.py`` readers and writer.  It resolves a complete batch
before the first target write, and it never places a credential in an argv,
report, or log record.
"""

from __future__ import annotations

import argparse
import base64
import importlib.util
import json
import os
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Mapping, Sequence

import yaml


_MIGRATION_PATH = Path(__file__).resolve().with_name("consolidate-1password.py")
_SPEC = importlib.util.spec_from_file_location("consolidate_onepassword", _MIGRATION_PATH)
if _SPEC is None or _SPEC.loader is None:  # pragma: no cover - installation error
    raise RuntimeError("existing migration module could not be loaded")
_MIGRATION = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_MIGRATION)

MigrationError = _MIGRATION.MigrationError
MappingSourceAdapter = _MIGRATION.MappingSourceAdapter
OpSourceAdapter = _MIGRATION.OpSourceAdapter
DeployedSourceAdapter = _MIGRATION.DeployedSourceAdapter
EvidenceSourceAdapter = _MIGRATION.EvidenceSourceAdapter
SourceOrchestrationAdapter = _MIGRATION.SourceOrchestrationAdapter
TARGET_VAULTS = frozenset(_MIGRATION.APPROVED_VAULTS)
KNOWN_STATUSES = frozenset(
    {"verified-readable", "verified-reconstructable", "existing-direct-reference"}
)
ITEM_DISPOSITIONS = frozenset({"canonical-item", "dedicated-item"})
GENERATION_ACTIONS = frozenset({"generate-random-additive", "generate-ssh-additive"})
FIELD_TYPES = frozenset({"CONCEALED", "STRING"})
APPROVED_PERSONAL_ACCOUNT_UUID = "PHLSEQ2HNVAALEWHKWGKZOAGSY"
APPROVED_PERSONAL_VAULT_NAME = "Employee"
APPROVED_PERSONAL_VAULT_ID = "crnj3w2djpvppe452icvu6fblm"
APPROVED_WRITER_ITEMS = {
    "Ken CI Runtime": {
        "id": "j34dtkat667tgzeopkanjwbdau",
        "title": "Service Account Auth Token: ken-ci-runtime",
    },
    "Ken Deploy Nonproduction": {
        "id": "h5lsxmq25qrgk4x22wf4k57z24",
        "title": "Service Account Auth Token: ken-deploy-nonproduction",
    },
    "Ken Deploy Production": {
        "id": "5ncmp2wtb44nmvdwmlo5coirq4",
        "title": "Service Account Auth Token: ken-deploy-production",
    },
}
APPROVED_TARGET_VAULT_IDS = {
    "Ken CI Runtime": "istjrwyeqryhpv7rytbm34pfea",
    "Ken Deploy Nonproduction": "wmb7rpm5xvl4ez4kur3s5l3hxe",
    "Ken Deploy Production": "q7zdmdggp2ng7hvxozhzt4uupm",
}
GENERATION_PROFILES = frozenset(
    {
        "opaque-token",
        "ken-agents-internal-key",
        "mcp-smoke-token",
        "oauth2-cookie-secret",
        "next-server-actions-key",
        "ssh-ed25519",
        "openssl-rsa-private-key",
    }
)


class StaticWriterTokenSource:
    """Test-only protected boundary; production uses PersonalWriterTokenSource."""

    def __init__(self, tokens: Mapping[str, str]):
        self._tokens = dict(tokens)

    def load(self) -> dict[str, str]:
        _validate_writer_tokens(self._tokens)
        return dict(self._tokens)


class PersonalWriterTokenSource:
    """Read exactly three writer tokens from an explicitly personal vault.

    ``personal_token`` authenticates only the personal source boundary.  It is
    never passed to a target write; the returned writer tokens are retained in
    memory and supplied only through the existing CLI environment boundary.
    """

    def __init__(
        self,
        *,
        op_bin: Path,
        personal_token: str | None = None,
        personal_account: bool = False,
        personal_vault: str = APPROVED_PERSONAL_VAULT_NAME,
        token_items: Mapping[str, str] | None = None,
        extra_env: Mapping[str, str] | None = None,
    ):
        if personal_vault != APPROVED_PERSONAL_VAULT_NAME:
            raise MigrationError("personal source vault must be distinct from target vaults")
        if personal_token is not None and (
            not isinstance(personal_token, str) or not personal_token or "\n" in personal_token
        ):
            raise MigrationError("personal source token is invalid")
        if (personal_token is None) != personal_account:
            raise MigrationError("choose exactly one personal desktop session or token boundary")
        self.op_bin = Path(op_bin)
        self.personal_token = personal_token
        self.personal_account = personal_account
        self.personal_vault = personal_vault
        expected_items = {vault: details["id"] for vault, details in APPROVED_WRITER_ITEMS.items()}
        if token_items is not None and dict(token_items) != expected_items:
            raise MigrationError("personal writer source requires exactly three reviewed item IDs")
        self.token_items = expected_items
        self.extra_env = extra_env
        if set(self.token_items) != TARGET_VAULTS:
            raise MigrationError("personal writer source requires exactly three target vault items")
        for item_id in self.token_items.values():
            if not isinstance(item_id, str) or not item_id or any(c in item_id for c in "\r\n\x00"):
                raise MigrationError("personal writer token item ID is invalid")

    def load(self) -> dict[str, str]:
        tokens: dict[str, str] = {}
        def run_json(argv: Sequence[str]) -> Any:
            command = _personal_account_argv(argv)
            if self.personal_account:
                return _run_personal_session_json(
                    op_bin=self.op_bin, argv=command, extra_env=self.extra_env
                )
            return _MIGRATION.run_op_json(
                op_bin=self.op_bin,
                argv=command,
                token=self.personal_token,
                extra_env=self.extra_env,
            )

        try:
            identity = run_json(["whoami", "--format=json"])
        except MigrationError:
            identity = run_json(
                ["account", "get", "--format=json"]
            )
            _validate_personal_account_record(identity)
        else:
            _validate_personal_identity(identity)
        vault = run_json(["vault", "get", APPROVED_PERSONAL_VAULT_NAME, "--format=json"])
        personal_vault_id = _validate_personal_vault(vault)
        for vault in sorted(TARGET_VAULTS):
            item_id = self.token_items[vault]
            argv = ["item", "get", item_id, "--vault", personal_vault_id, "--format=json"]
            argv = _personal_account_argv(argv)
            if self.personal_account:
                response = _run_personal_session_json(
                    op_bin=self.op_bin, argv=argv, extra_env=self.extra_env
                )
            else:
                response = _MIGRATION.run_op_json(
                    op_bin=self.op_bin,
                    argv=argv,
                    token=self.personal_token,
                    extra_env=self.extra_env,
                )
            _validate_personal_token_item(response, vault, item_id, personal_vault_id)
            token = _extract_personal_token(response)
            if token == self.personal_token:
                raise MigrationError("personal source and writer token must be distinct")
            tokens[vault] = token
        _validate_writer_tokens(tokens)
        return tokens


def _run_personal_session_json(
    *, op_bin: Path, argv: Sequence[str], extra_env: Mapping[str, str] | None = None
) -> Any:
    """Read through the user's authenticated desktop session, never a SA env token."""
    if not op_bin.is_file() or op_bin.is_symlink() or not os.access(op_bin, os.X_OK):
        raise MigrationError("1Password executable is unsafe")
    if any(not isinstance(argument, str) or "\n" in argument for argument in argv):
        raise MigrationError("1Password argument is invalid")
    environment = _personal_session_environment(extra_env)
    try:
        completed = subprocess.run(
            [str(op_bin), *argv],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            check=False,
            env=environment,
        )
    except OSError as exc:
        raise MigrationError("personal session command failed") from exc
    if completed.returncode != 0:
        raise MigrationError("personal session command failed")
    try:
        return _MIGRATION.strict_json_loads(completed.stdout.decode("utf-8"))
    except (UnicodeDecodeError, MigrationError) as exc:
        raise MigrationError("personal session response is invalid") from exc


def _extract_personal_token(response: Any) -> str:
    if not isinstance(response, Mapping) or not isinstance(response.get("fields"), list):
        raise MigrationError("personal token item response is invalid")
    candidates = []
    for field in response["fields"]:
        if not isinstance(field, Mapping) or not isinstance(field.get("value"), str):
            continue
        label = str(field.get("label", "")).casefold()
        if label in {"credential", "token", "password", "service_account_token"}:
            candidates.append(field["value"])
    if len(candidates) != 1 or not candidates[0] or "\n" in candidates[0]:
        raise MigrationError("personal token item must contain one credential field")
    return candidates[0]


def _personal_account_argv(argv: Sequence[str]) -> list[str]:
    return [*argv, "--account", APPROVED_PERSONAL_ACCOUNT_UUID]


_PERSONAL_ENV_KEYS = frozenset({"HOME", "PATH", "LANG", "LC_ALL", "TMPDIR"})
_PERSONAL_EXTRA_ENV_KEYS = frozenset({"LOG", "FAKE_OP_LOG", "OP_BIOMETRIC_UNLOCK_ENABLED"})


def _personal_session_environment(extra_env: Mapping[str, str] | None = None) -> dict[str, str]:
    """Build the narrowly-scoped environment needed by desktop ``op`` integration."""
    environment = {
        "HOME": os.environ.get("HOME") or "/nonexistent",
        "PATH": os.environ.get("PATH") or "/usr/bin:/bin",
        "LANG": os.environ.get("LANG") or "C.UTF-8",
        "LC_ALL": os.environ.get("LC_ALL") or "C.UTF-8",
        "TMPDIR": os.environ.get("TMPDIR") or "/tmp",
    }
    if set(environment) != _PERSONAL_ENV_KEYS:
        raise MigrationError("personal session environment is invalid")
    for key, value in (extra_env or {}).items():
        if (
            not isinstance(key, str)
            or not isinstance(value, str)
            or key not in _PERSONAL_EXTRA_ENV_KEYS
            or key.startswith("OP_SESSION")
            or key.startswith("OP_CONNECT")
            or key in {"OP_" + "SERVICE_ACCOUNT_TOKEN", "OP_ACCOUNT"}
        ):
            raise MigrationError("personal session environment is invalid")
        environment[key] = value
    return environment


def _validate_personal_identity(response: Any) -> None:
    if not isinstance(response, Mapping) or response.get("account_uuid") != APPROVED_PERSONAL_ACCOUNT_UUID:
        raise MigrationError("personal account identity is not the reviewed account")
    if not isinstance(response.get("user_uuid"), str) or not response["user_uuid"]:
        raise MigrationError("personal account identity is invalid")
    if str(response.get("user_type", "")).upper() not in {"PERSON", "USER"}:
        raise MigrationError("personal account identity is invalid")


def _validate_personal_account_record(response: Any) -> None:
    if not isinstance(response, Mapping) or response.get("id") != APPROVED_PERSONAL_ACCOUNT_UUID:
        raise MigrationError("personal account identity is not the reviewed account")
    if str(response.get("type", "")).upper() != "TEAM":
        raise MigrationError("personal account identity is invalid")
    if str(response.get("state", "")).upper() != "ACTIVE":
        raise MigrationError("personal account identity is invalid")


def _validate_personal_vault(response: Any) -> str:
    if not isinstance(response, Mapping) or response.get("name") != APPROVED_PERSONAL_VAULT_NAME:
        raise MigrationError("personal source vault is not the reviewed vault")
    if response.get("id") != APPROVED_PERSONAL_VAULT_ID:
        raise MigrationError("personal source vault is not the reviewed vault")
    return APPROVED_PERSONAL_VAULT_ID


def _validate_personal_token_item(response: Any, vault: str, item_id: str, vault_id: str) -> None:
    expected = APPROVED_WRITER_ITEMS[vault]
    if not isinstance(response, Mapping) or response.get("id") != item_id:
        raise MigrationError("personal token item ID mismatch")
    if response.get("title") != expected["title"]:
        raise MigrationError("personal token item title mismatch")
    if response.get("vault", {}).get("id") != vault_id:
        raise MigrationError("personal token item vault mismatch")
    if response.get("vault", {}).get("name") != APPROVED_PERSONAL_VAULT_NAME:
        raise MigrationError("personal token item vault mismatch")
    fields = response.get("fields")
    if not isinstance(fields, list):
        raise MigrationError("personal token item response is invalid")
    credential_fields = [
        field
        for field in fields
        if isinstance(field, Mapping)
        and str(field.get("label", "")).casefold()
        in {"credential", "token", "password", "service_account_token"}
    ]
    if len(credential_fields) != 1 or credential_fields[0].get("type") != "CONCEALED":
        raise MigrationError("personal token item must contain one credential field with type concealed")


def _validate_writer_tokens(tokens: Mapping[str, str]) -> None:
    if set(tokens) != TARGET_VAULTS:
        raise MigrationError("writer token map must cover exactly three target vaults")
    values = list(tokens.values())
    if any(not isinstance(token, str) or not token or "\n" in token for token in values):
        raise MigrationError("writer token is invalid")
    if len(set(values)) != len(values):
        raise MigrationError("writer service accounts must be distinct")


def _validate_writer_scopes(
    *, op_bin: Path, writer_tokens: Mapping[str, str], extra_env: Mapping[str, str] | None = None
) -> None:
    """Prove each temporary writer can see exactly its one target vault."""
    for vault in sorted(TARGET_VAULTS):
        token = writer_tokens[vault]
        identity = _MIGRATION.run_op_json(
            op_bin=op_bin,
            argv=["whoami", "--format=json"],
            token=token,
            extra_env=extra_env,
        )
        vaults = _MIGRATION.run_op_json(
            op_bin=op_bin,
            argv=["vault", "list", "--format=json"],
            token=token,
            extra_env=extra_env,
        )
        if not isinstance(identity, Mapping) or not isinstance(vaults, list):
            raise MigrationError("writer scope response is invalid")
        _MIGRATION.validate_service_account_scope(identity, vaults, vault)
        if vaults[0].get("id") != APPROVED_TARGET_VAULT_IDS[vault]:
            raise MigrationError("writer target vault ID is not the reviewed vault")


def _registry_document(*, registry_path: Path | None, registry: Mapping[str, Any] | None) -> Mapping[str, Any]:
    if (registry_path is None) == (registry is None):
        raise MigrationError("provide exactly one canonical registry")
    if registry_path is not None:
        return _MIGRATION._registry_document(registry_path=registry_path, registry=None)
    return _MIGRATION.load_registry_from_document(registry)


def _metadata_entry(entry: Mapping[str, Any], *, status: str, reason: str | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {
        "coordinate": str(entry.get("coordinate", "")),
        "vault": entry.get("canonical_vault"),
        "item": entry.get("canonical_item"),
        "field": entry.get("canonical_field"),
        "status": status,
    }
    if reason:
        result["reason"] = reason
    return result


def _source_token_set(source_adapter: Any) -> set[str]:
    result: set[str] = set()
    for candidate in (
        source_adapter,
        getattr(source_adapter, "op_adapter", None),
        getattr(source_adapter, "ssh_adapter", None),
        getattr(source_adapter, "evidence_adapter", None),
    ):
        token = getattr(candidate, "source_token", None)
        if isinstance(token, str):
            result.add(token)
    return result


def _selected_entries(
    document: Mapping[str, Any], *, known_only: bool
) -> tuple[list[Mapping[str, Any]], list[dict[str, Any]]]:
    entries = document.get("entries")
    if not isinstance(entries, list):
        raise MigrationError("canonical registry entries are invalid")
    selected: list[Mapping[str, Any]] = []
    blocked: list[dict[str, Any]] = []
    for entry in entries:
        if not isinstance(entry, Mapping) or entry.get("disposition") not in ITEM_DISPOSITIONS:
            continue
        status = entry.get("verification_status")
        if status in KNOWN_STATUSES:
            selected.append(entry)
        elif status == "unresolved":
            blocked.append(_metadata_entry(entry, status="unresolved", reason="source authority unresolved"))
        elif status not in {"planned-variable", "planned-secretless", "bootstrap-to-replace"}:
            blocked.append(_metadata_entry(entry, status="blocked", reason="verification status not eligible"))
    if blocked and not known_only:
        raise MigrationError("unresolved canonical registry entries require --known-only")
    return selected, blocked


def _resolve_targets(
    entries: Sequence[Mapping[str, Any]], source_adapter: Any
) -> dict[tuple[str, str], list[dict[str, Any]]]:
    if getattr(source_adapter, "protected", False) is not True:
        raise MigrationError("source resolution requires a protected adapter")
    by_field: dict[tuple[str, str, str], list[Mapping[str, Any]]] = {}
    item_vaults: dict[str, str] = {}
    for entry in entries:
        source = entry.get("source_authority")
        vault, item, field = _MIGRATION._validate_target_entry(entry, source_adapter)
        prior = item_vaults.setdefault(item, vault)
        if prior != vault:
            raise MigrationError("canonical item is reused across vaults")
        by_field.setdefault((vault, item, field), []).append(entry)

    values: dict[str, str] = {}
    for authority in sorted({str(entry["source_authority"]) for entry in entries}):
        values[authority] = _MIGRATION._resolve_source(source_adapter, authority)

    grouped: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for (vault, item, field), matches in sorted(by_field.items()):
        types = {str(match.get("field_type", "")).upper() for match in matches}
        if len(types) != 1 or next(iter(types)) not in FIELD_TYPES:
            raise MigrationError("duplicate target field has conflicting field types")
        source_values = {values[str(match["source_authority"])] for match in matches}
        if len(source_values) != 1:
            raise MigrationError("conflicting values for duplicate target field")
        representative = min(matches, key=lambda row: str(row.get("coordinate", "")))
        grouped.setdefault((vault, item), []).append(
            {
                "label": field,
                "type": next(iter(types)),
                "value": values[str(representative["source_authority"])],
                "coordinate": str(representative["coordinate"]),
            }
        )
    return grouped


def _report_item(vault: str, item: str, status: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "vault": vault,
        "vault_id": status["vault_id"],
        "item": item,
        "item_id": status["item_id"],
        "status": status["status"],
        "fields": [
            {"label": label, "type": field_type, "status": "verified"}
            for label, field_type in sorted(status["fields"].items())
        ],
    }


def _validate_value_free_document(document: Mapping[str, Any]) -> None:
    forbidden = ("value", "plaintext", "secret_value", "digest", "hash", "prefix", "length", "bytes")
    def walk(value: Any, path: str = "document") -> None:
        if isinstance(value, Mapping):
            for key, child in value.items():
                key_text = str(key).casefold()
                if any(fragment in key_text for fragment in forbidden):
                    raise MigrationError(f"value-bearing ledger key: {path}.{key}")
                walk(child, f"{path}.{key}")
        elif isinstance(value, list):
            for index, child in enumerate(value):
                walk(child, f"{path}[{index}]")
    walk(document)


def _validate_ledger_shape(document: Mapping[str, Any]) -> None:
    """Keep the persisted ledger to the deliberately small metadata schema."""
    if set(document) != {"status", "ready", "counts", "items", "blocked"}:
        raise MigrationError("ledger schema mismatch")
    if document["status"] not in {"complete", "blocked", "in-progress"} or not isinstance(document["ready"], bool):
        raise MigrationError("ledger status is invalid")
    counts = document["counts"]
    if not isinstance(counts, Mapping) or set(counts) != {"selected", "populated", "blocked"}:
        raise MigrationError("ledger counts are invalid")
    if any(not isinstance(counts[key], int) or isinstance(counts[key], bool) or counts[key] < 0 for key in counts):
        raise MigrationError("ledger counts are invalid")
    if document["status"] == "complete" and document["ready"] is not True:
        raise MigrationError("complete ledger must be ready")
    if document["status"] in {"blocked", "in-progress"} and document["ready"] is not False:
        raise MigrationError("non-complete ledger cannot claim readiness")
    if not isinstance(document["items"], list) or not isinstance(document["blocked"], list):
        raise MigrationError("ledger collections are invalid")
    for item in document["items"]:
        if not isinstance(item, Mapping) or set(item) != {"vault", "vault_id", "item", "item_id", "status", "fields"}:
            raise MigrationError("ledger item metadata is invalid")
        if any(not isinstance(item[key], str) or not item[key] for key in ("vault", "vault_id", "item", "item_id", "status")):
            raise MigrationError("ledger item metadata is invalid")
        fields = item["fields"]
        if not isinstance(fields, list) or not fields:
            raise MigrationError("ledger item fields are invalid")
        for field in fields:
            if not isinstance(field, Mapping) or set(field) != {"label", "type", "status"}:
                raise MigrationError("ledger field metadata is invalid")
            if not isinstance(field["label"], str) or not field["label"]:
                raise MigrationError("ledger field label is invalid")
            if field["type"] not in FIELD_TYPES or not isinstance(field["status"], str) or not field["status"]:
                raise MigrationError("ledger field metadata is invalid")
    for blocked in document["blocked"]:
        if not isinstance(blocked, Mapping):
            raise MigrationError("ledger blocked metadata is invalid")
        allowed = {"coordinate", "vault", "item", "field", "status", "reason"}
        if not set(blocked) <= allowed or "coordinate" not in blocked or "status" not in blocked:
            raise MigrationError("ledger blocked metadata is invalid")
        for key, value in blocked.items():
            if not isinstance(value, str) or not value:
                raise MigrationError("ledger blocked metadata is invalid")


def write_value_free_ledger(path: Path, document: Mapping[str, Any]) -> bool:
    if not isinstance(document, Mapping):
        raise MigrationError("ledger must be an object")
    _validate_ledger_shape(document)
    _validate_value_free_document(document)
    parent = path.parent
    # System temporary paths such as macOS /tmp may themselves be symlinks;
    # reject a symlink at the ledger file, while allowing the trusted parent.
    if path.is_symlink() or not parent.is_dir():
        raise MigrationError("ledger path is unsafe")
    payload = yaml.safe_dump(dict(document), sort_keys=False).encode("utf-8")
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=parent)
    try:
        os.fchmod(fd, stat.S_IRUSR | stat.S_IWUSR)
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory_fd = os.open(parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except Exception:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise
    return bool(document.get("ready"))


def _ledger_document(
    *, status: str, selected: int, items: Sequence[Mapping[str, Any]], blocked: Sequence[Mapping[str, Any]]
) -> dict[str, Any]:
    return {
        "status": status,
        "ready": status == "complete",
        "counts": {"selected": selected, "populated": len(items), "blocked": len(blocked)},
        "items": list(items),
        "blocked": list(blocked),
    }


def _write_failure_ledger(
    path: Path, *, selected: int, items: Sequence[Mapping[str, Any]], blocked: Sequence[Mapping[str, Any]]
) -> None:
    try:
        write_value_free_ledger(
            path,
            _ledger_document(status="blocked", selected=selected, items=items, blocked=blocked),
        )
    except (MigrationError, OSError):
        # Preserve the original failure; the caller must not mistake this for readiness.
        pass


def _write_registration_artifact(
    path: Path, entries: Sequence[Mapping[str, str]], *, status: str = "ready"
) -> None:
    if path.is_symlink() or path.parent.is_symlink() or not path.parent.is_dir():
        raise MigrationError("registration artifact path is unsafe")
    if status not in {"pending", "ready"}:
        raise MigrationError("registration artifact status is invalid")
    if path.exists():
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise MigrationError("registration artifact target is unsafe")
    document = {"schema_version": 1, "status": status, "entries": list(entries)}
    _validate_value_free_document(document)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(fd, stat.S_IRUSR | stat.S_IWUSR)
        payload = (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
        offset = 0
        while offset < len(payload):
            written = os.write(fd, payload[offset:])
            if written <= 0:
                raise MigrationError("registration artifact short write")
            offset += written
        os.fsync(fd)
        os.close(fd)
        fd = -1
        os.replace(temporary, path)
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except Exception:
        if fd >= 0:
            os.close(fd)
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def populate_canonical_vaults(
    *,
    registry_path: Path | None = None,
    registry: Mapping[str, Any] | None = None,
    source_adapter: Any,
    writer_source: Any,
    op_bin: Path,
    ledger_path: Path,
    known_only: bool = False,
    extra_env: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    document = _registry_document(registry_path=registry_path, registry=registry)
    items: list[dict[str, Any]] = []
    selected: list[Mapping[str, Any]] = []
    blocked: list[dict[str, Any]] = []
    # Invalidate any prior ready ledger before source resolution or a target write.
    write_value_free_ledger(ledger_path, _ledger_document(status="in-progress", selected=0, items=[], blocked=[]))
    try:
        selected, blocked = _selected_entries(document, known_only=known_only)
        write_value_free_ledger(
            ledger_path,
            _ledger_document(status="in-progress", selected=len(selected), items=[], blocked=blocked),
        )
        writer_tokens = writer_source.load()
        _validate_writer_tokens(writer_tokens)
        _validate_writer_scopes(op_bin=op_bin, writer_tokens=writer_tokens, extra_env=extra_env)
        if _source_token_set(source_adapter) & set(writer_tokens.values()):
            raise MigrationError("source and target writer tokens must be distinct")
        grouped = _resolve_targets(selected, source_adapter) if selected else {}
    except MigrationError:
        failure = blocked or [{"coordinate": "registry|selection", "status": "blocked", "reason": "population preflight failed"}]
        _write_failure_ledger(ledger_path, selected=len(selected), items=items, blocked=failure)
        raise
    try:
        for (vault, item), fields in sorted(grouped.items()):
            concealed = {field["label"]: field["value"] for field in fields if field["type"] == "CONCEALED"}
            text = {field["label"]: field["value"] for field in fields if field["type"] == "STRING"}
            status = _MIGRATION.populate_item(
                op_bin=op_bin,
                target_token=writer_tokens[vault],
                expected_vault=vault,
                coordinate=f"{vault}|{item}",
                title=item,
                concealed_fields=concealed,
                text_fields=text,
                extra_env=extra_env,
            )
            items.append(_report_item(vault, item, status))
            write_value_free_ledger(
                ledger_path,
                _ledger_document(status="in-progress", selected=len(selected), items=items, blocked=blocked),
            )
    except (MigrationError, OSError):
        _write_failure_ledger(ledger_path, selected=len(selected), items=items, blocked=blocked or [{"coordinate": "registry|write", "status": "blocked", "reason": "item population failed"}])
        raise
    result = _ledger_document(
        status="complete" if not blocked else "blocked", selected=len(selected), items=items, blocked=blocked
    )
    write_value_free_ledger(ledger_path, result)
    return result


def _load_yaml(path: Path) -> Any:
    if path.is_symlink() or not path.is_file():
        raise MigrationError("planning file is unsafe")
    try:
        with path.open("r", encoding="utf-8") as stream:
            return yaml.safe_load(stream)
    except (OSError, yaml.YAMLError) as exc:
        raise MigrationError("planning file is invalid") from exc


def _allowlist(path: Path) -> set[str]:
    document = _load_yaml(path)
    if isinstance(document, list):
        coordinates = document
    elif isinstance(document, Mapping):
        coordinates = document.get("coordinates", document.get("approved_coordinates", []))
        profiles = document.get("profiles", document.get("approved_profiles", []))
        if profiles:
            raise MigrationError("generation profile wildcards are not allowed")
    else:
        raise MigrationError("generation allowlist is invalid")
    if not isinstance(coordinates, list):
        raise MigrationError("generation allowlist lists are invalid")
    if any(not isinstance(value, str) or not value for value in coordinates):
        raise MigrationError("generation allowlist entry is invalid")
    return set(coordinates)


def _source_adapter_from_cli(args: argparse.Namespace) -> Any:
    source_token = None
    source_token_file = getattr(args, "source_token_file", None)
    source_session = bool(getattr(args, "source_session", False))
    if source_token_file is not None and source_session:
        raise MigrationError("source token file and source session are mutually exclusive")
    if source_token_file is not None:
        source_token = _read_protected_token(source_token_file)
    op_adapter = None
    if source_token is not None or source_session:
        op_adapter = OpSourceAdapter(
            op_bin=args.source_op_bin,
            source_token=source_token,
            source_session=source_session,
        )
    ssh_adapter = None
    if source_token is not None or args.source_ssh_bin is not None or args.source_ssh_key is not None:
        ssh_adapter = DeployedSourceAdapter(
            ssh_bin=args.source_ssh_bin or Path("/usr/bin/ssh"),
            source_token=source_token,
            ssh_user=args.source_ssh_user,
            ssh_key=args.source_ssh_key,
        )
    evidence_adapter = None
    if args.evidence_root is not None:
        evidence_adapter = EvidenceSourceAdapter(args.evidence_root)
    if op_adapter is None and ssh_adapter is None and evidence_adapter is None:
        raise MigrationError("a protected source reader is required")
    return SourceOrchestrationAdapter(
        op_adapter=op_adapter,
        ssh_adapter=ssh_adapter,
        evidence_adapter=evidence_adapter,
    )


def _row_profiles(row: Mapping[str, Any]) -> set[str]:
    values = {
        row.get("generation_profile"),
        row.get("credential_group_id"),
        row.get("grouping_key"),
        _generation_profile(row),
    }
    target = row.get("target_canonical")
    if isinstance(target, Mapping):
        values.add(target.get("item"))
        values.add(f"{target.get('vault')}|{target.get('item')}|{target.get('field')}")
    return {value for value in values if isinstance(value, str) and value}


def _generation_profile(row: Mapping[str, Any]) -> str:
    explicit = row.get("generation_profile")
    if explicit is not None:
        if explicit not in GENERATION_PROFILES:
            raise MigrationError("generation profile is not approved")
        return explicit
    target = row.get("target_canonical")
    field = target.get("field") if isinstance(target, Mapping) else None
    action = row.get("action")
    if action == "generate-ssh-additive":
        return "ssh-ed25519"
    if field in {"OAUTH2_PROXY_COOKIE_SECRET", "OAUTH2_PROXY_COOKIE_SECRET_LANGGRAPH"}:
        return "oauth2-cookie-secret"
    if field == "NEXT_SERVER_ACTIONS_ENCRYPTION_KEY":
        return "next-server-actions-key"
    if field == "REDIRECT_RELEASE_SIGNING_PRIVATE_KEY":
        return "openssl-rsa-private-key"
    if field == "KEN_AGENTS_INTERNAL_KEY":
        return "ken-agents-internal-key"
    if field == "MCP_SMOKE_TOKEN":
        return "mcp-smoke-token"
    return "opaque-token"


def _generate_secret(row: Mapping[str, Any]) -> tuple[str, str | None]:
    profile = _generation_profile(row)
    if profile == "ssh-ed25519":
        return _ed25519_keypair()
    if profile == "openssl-rsa-private-key":
        return _openssl_private_key(), None
    if profile == "oauth2-cookie-secret":
        return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii").rstrip("="), None
    if profile == "next-server-actions-key":
        return base64.b64encode(secrets.token_bytes(32)).decode("ascii"), None
    if profile == "ken-agents-internal-key":
        return secrets.token_hex(32), None
    if profile in {"mcp-smoke-token", "opaque-token"}:
        return secrets.token_urlsafe(32), None
    raise MigrationError("generation profile is not approved")


def _tool_path(name: str) -> Path:
    candidates = [Path(f"/usr/bin/{name}"), Path(f"/opt/homebrew/bin/{name}")]
    resolved = shutil.which(name)
    if resolved:
        candidates.append(Path(resolved))
    for candidate in candidates:
        if candidate.is_file() and not candidate.is_symlink() and os.access(candidate, os.X_OK):
            return candidate
    raise MigrationError(f"required crypto tool is unavailable: {name}")


def _ed25519_keypair() -> tuple[str, str]:
    """Generate an OpenSSH key using the maintained system implementation."""
    ssh_keygen = _tool_path("ssh-keygen")
    with tempfile.TemporaryDirectory(prefix="ken-key-", dir=os.environ.get("TMPDIR", "/tmp")) as temp:
        root = Path(temp)
        os.chmod(root, 0o700)
        private_path = root / "id_ed25519"
        completed = subprocess.run(
            [str(ssh_keygen), "-q", "-t", "ed25519", "-N", "", "-C", "ken-generated", "-f", str(private_path)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=30,
        )
        if completed.returncode != 0:
            raise MigrationError("SSH key generation failed")
        try:
            private = private_path.read_text(encoding="utf-8")
            public = private_path.with_name("id_ed25519.pub").read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            raise MigrationError("SSH key generation output is invalid") from exc
        openssh_marker = "-----BEGIN OPENSSH " + "PRIVATE KEY-----"
        if not private.startswith(openssh_marker) or not public.startswith("ssh-ed25519 "):
            raise MigrationError("SSH key generation output is invalid")
        public_parts = public.strip().split()
        if len(public_parts) < 2:
            raise MigrationError("SSH public-key output is invalid")
        return private, public


def _openssl_private_key() -> str:
    """Generate a PKCS#8 PEM key for the redirector's openssl dgst consumer."""
    openssl = _tool_path("openssl")
    completed = subprocess.run(
        [str(openssl), "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:3072"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
        timeout=60,
    )
    if completed.returncode != 0:
        raise MigrationError("OpenSSL private-key generation failed")
    try:
        value = completed.stdout.decode("ascii")
    except UnicodeDecodeError as exc:
        raise MigrationError("OpenSSL private-key output is invalid") from exc
    pem_marker = "-----BEGIN " + "PRIVATE KEY-----"
    if not value.startswith(pem_marker):
        raise MigrationError("OpenSSL private-key output is invalid")
    return value


def _build_generation_groups(
    selected: Sequence[Mapping[str, Any]],
) -> tuple[dict[tuple[str, str], dict[str, tuple[str, str, str, str | None]]], dict[tuple[str, str], list[dict[str, str]]]]:
    grouped: dict[tuple[str, str], dict[str, tuple[str, str, str, str | None]]] = {}
    registrations_by_item: dict[tuple[str, str], list[dict[str, str]]] = {}
    for row in selected:
        target = row.get("target_canonical")
        if not isinstance(target, Mapping):
            raise MigrationError("generation target is invalid")
        vault, item, field = target.get("vault"), target.get("item"), target.get("field")
        if vault not in TARGET_VAULTS or not all(isinstance(value, str) and value for value in (item, field)):
            raise MigrationError("generation target is invalid")
        action = row["action"]
        profile = _generation_profile(row)
        target_fields = grouped.setdefault((vault, item), {})
        prior = target_fields.get(field)
        if prior is None:
            value, public = _generate_secret(row)
            target_fields[field] = (action, profile, value, public)
            if public is not None:
                registrations_by_item.setdefault((vault, item), []).append(
                    {"coordinate": row["coordinate"], "public_key": public.rstrip("\n")}
                )
        elif prior[0] != action or prior[1] != profile:
            raise MigrationError("generation target has conflicting actions")
    return grouped, registrations_by_item


def generate_canonical_vaults(
    *,
    plan_path: Path,
    allowlist_path: Path,
    writer_source: Any,
    op_bin: Path,
    ledger_path: Path,
    registration_artifact: Path | None = None,
    extra_env: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    plan = _load_yaml(plan_path)
    rows = plan.get("rows") if isinstance(plan, Mapping) else None
    if not isinstance(rows, list):
        raise MigrationError("generation plan rows are invalid")
    write_value_free_ledger(
        ledger_path, _ledger_document(status="in-progress", selected=0, items=[], blocked=[])
    )
    allowed_coordinates = _allowlist(allowlist_path)
    generation_rows = [
        row for row in rows if isinstance(row, Mapping) and row.get("action") in GENERATION_ACTIONS
    ]
    approved_coordinates = {
        row["coordinate"]
        for row in generation_rows
        if isinstance(row.get("coordinate"), str) and row["coordinate"]
    }
    if not allowed_coordinates <= approved_coordinates:
        raise MigrationError("generation allowlist contains an unapproved coordinate")
    selected: list[Mapping[str, Any]] = []
    blocked: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, Mapping) or row.get("action") not in GENERATION_ACTIONS:
            continue
        coordinate = row.get("coordinate")
        if not isinstance(coordinate, str) or not coordinate:
            raise MigrationError("generation coordinate is invalid")
        if coordinate in allowed_coordinates:
            selected.append(row)
        else:
            blocked.append({"coordinate": coordinate, "status": "not-allowlisted"})
    try:
        writer_tokens = writer_source.load()
        _validate_writer_tokens(writer_tokens)
        _validate_writer_scopes(op_bin=op_bin, writer_tokens=writer_tokens, extra_env=extra_env)
    except MigrationError:
        _write_failure_ledger(ledger_path, selected=len(selected), items=[], blocked=blocked or [{"coordinate": "generation|preflight", "status": "blocked", "reason": "generation preflight failed"}])
        raise
    try:
        grouped, registrations_by_item = _build_generation_groups(selected)
    except MigrationError:
        _write_failure_ledger(ledger_path, selected=len(selected), items=[], blocked=blocked or [{"coordinate": "generation|plan", "status": "blocked", "reason": "generation plan invalid"}])
        raise
    if registrations_by_item:
        if registration_artifact is None:
            raise MigrationError("SSH generation requires a protected registration artifact")
    items: list[dict[str, Any]] = []
    published_registrations: list[dict[str, str]] = []
    try:
        for (vault, item), fields in sorted(grouped.items()):
            status = _MIGRATION.populate_item(
                op_bin=op_bin,
                target_token=writer_tokens[vault],
                expected_vault=vault,
                coordinate=f"{vault}|{item}",
                title=item,
                concealed_fields={field: value[2] for field, value in fields.items()},
                text_fields={},
                extra_env=extra_env,
            )
            items.append(_report_item(vault, item, status))
            published_registrations.extend(registrations_by_item.get((vault, item), []))
            if published_registrations:
                _write_registration_artifact(registration_artifact, published_registrations, status="pending")
            write_value_free_ledger(
                ledger_path,
                _ledger_document(status="in-progress", selected=len(selected), items=items, blocked=blocked),
            )
    except (MigrationError, OSError):
        _write_failure_ledger(ledger_path, selected=len(selected), items=items, blocked=blocked or [{"coordinate": "generation|write", "status": "blocked", "reason": "generated item population failed"}])
        raise
    if published_registrations:
        _write_registration_artifact(registration_artifact, published_registrations, status="ready")
    result = _ledger_document(
        status="complete" if not blocked else "blocked", selected=len(selected), items=items, blocked=blocked
    )
    write_value_free_ledger(ledger_path, result)
    return result


def _read_protected_token(path: Path) -> str:
    info = path.lstat()
    if (
        not stat.S_ISREG(info.st_mode)
        or path.is_symlink()
        or info.st_nlink != 1
        or stat.S_IMODE(info.st_mode) != 0o600
    ):
        raise MigrationError("token file must be a regular mode-0600 file")
    token = path.read_text(encoding="utf-8")
    if token.endswith("\n"):
        token = token[:-1]
    if not token:
        raise MigrationError("token file is empty")
    return token


def _cli() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="mode", required=True)
    populate = sub.add_parser("populate")
    populate.add_argument("--registry", type=Path, required=True)
    populate.add_argument("--ledger", type=Path, required=True)
    populate.add_argument("--op-bin", type=Path, default=Path("/usr/local/bin/op"))
    populate.add_argument("--personal-op-bin", type=Path, default=Path("/usr/local/bin/op"))
    populate.add_argument("--personal-token-file", type=Path)
    populate.add_argument("--writer-token-items", type=Path, required=True)
    populate.add_argument("--personal-account", action="store_true")
    populate.add_argument("--personal-vault", default="Employee")
    populate.add_argument("--source-token-file", type=Path)
    populate.add_argument(
        "--source-session",
        action="store_true",
        help="read source authorities through the authenticated local 1Password desktop session",
    )
    populate.add_argument("--source-op-bin", type=Path, default=Path("/usr/local/bin/op"))
    populate.add_argument("--source-ssh-bin", type=Path)
    populate.add_argument("--source-ssh-key", type=Path)
    populate.add_argument("--source-ssh-user")
    populate.add_argument("--evidence-root", type=Path)
    populate.add_argument("--known-only", action="store_true")
    generate = sub.add_parser("generate")
    generate.add_argument("--plan", type=Path, required=True)
    generate.add_argument("--allowlist", type=Path, required=True)
    generate.add_argument("--ledger", type=Path, required=True)
    generate.add_argument("--op-bin", type=Path, default=Path("/usr/local/bin/op"))
    generate.add_argument("--personal-op-bin", type=Path, default=Path("/usr/local/bin/op"))
    generate.add_argument("--personal-token-file", type=Path)
    generate.add_argument("--writer-token-items", type=Path, required=True)
    generate.add_argument("--personal-account", action="store_true")
    generate.add_argument("--personal-vault", default="Employee")
    generate.add_argument("--registration-artifact", type=Path)
    return parser


def _load_token_items(path: Path) -> Mapping[str, str]:
    document = _load_yaml(path)
    if not isinstance(document, Mapping):
        raise MigrationError("writer token item map is invalid")
    return document


def main(argv: Sequence[str] | None = None) -> int:
    try:
        args = _cli().parse_args(argv)
        personal = PersonalWriterTokenSource(
            op_bin=args.personal_op_bin,
            personal_token=(
                _read_protected_token(args.personal_token_file)
                if args.personal_token_file is not None
                else None
            ),
            personal_account=args.personal_account,
            personal_vault=args.personal_vault,
            token_items=_load_token_items(args.writer_token_items),
        )
        if args.mode == "populate":
            result = populate_canonical_vaults(
                registry_path=args.registry,
                source_adapter=_source_adapter_from_cli(args),
                writer_source=personal,
                op_bin=args.op_bin,
                ledger_path=args.ledger,
                known_only=args.known_only,
            )
        else:
            result = generate_canonical_vaults(
                plan_path=args.plan,
                allowlist_path=args.allowlist,
                writer_source=personal,
                op_bin=args.op_bin,
                ledger_path=args.ledger,
                registration_artifact=args.registration_artifact,
            )
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 0 if result["ready"] else 2
    except (MigrationError, OSError, ValueError, yaml.YAMLError) as exc:
        print(f"canonical vault population refused: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
