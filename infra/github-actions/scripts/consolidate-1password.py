#!/usr/bin/env python3
"""Consolidate 1Password items without disclosing secret values."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Mapping, Sequence

import yaml

_CANONICAL_LIB = Path(__file__).resolve().parent / "lib"
if str(_CANONICAL_LIB) not in sys.path:
    sys.path.insert(0, str(_CANONICAL_LIB))

from canonical_credentials import (  # noqa: E402
    ALLOWED_VAULTS,
    UniqueKeySafeLoader,
    load_registry,
)


class MigrationError(ValueError):
    """A fail-closed migration contract violation."""


APPROVED_VAULTS = frozenset(ALLOWED_VAULTS)
_ITEM_DISPOSITIONS = frozenset({"canonical-item", "dedicated-item"})
_FIELD_TYPES = frozenset({"CONCEALED", "STRING"})
_PERSONAL_ACCOUNT_UUID = "PHLSEQ2HNVAALEWHKWGKZOAGSY"


class ProtectedSourceAdapter:
    """In-process source reader; implementations must keep values private."""

    protected = True
    source_token: str | None = None

    def resolve(self, authority: str) -> str:
        raise NotImplementedError


class MappingSourceAdapter(ProtectedSourceAdapter):
    """Small protected adapter intended for hermetic tests and local dry runs."""

    def __init__(self, values: Mapping[str, str]):
        self._values = dict(values)

    def resolve(self, authority: str) -> str:
        try:
            value = self._values[authority]
        except KeyError as exc:
            raise MigrationError("source authority could not be read") from exc
        if not isinstance(value, str):
            raise MigrationError("source authority returned a non-string value")
        return value


class OpSourceAdapter(ProtectedSourceAdapter):
    """Read a source 1Password field without exposing its value to the caller.

    The source token is deliberately separate from the target writer token.
    There is intentionally no ``token`` compatibility alias: accepting a
    writer token here would make it possible to read a source vault with the
    target credential by accident.
    """

    def __init__(
        self,
        *,
        op_bin: Path,
        source_token: str | None = None,
        source_session: bool = False,
        extra_env: Mapping[str, str] | None = None,
    ):
        if (source_token is None) == (not source_session):
            raise MigrationError("source adapter requires a token file or explicit session")
        self.op_bin = op_bin
        self.source_token = source_token
        self.source_session = source_session
        self.extra_env = extra_env

    def resolve(self, authority: str) -> str:
        parsed = _parse_source_authority(authority)
        if parsed["scheme"] == "op":
            result = self._get_item(parsed["vault"], parsed["item"])
            return _read_op_custom_field(result, parsed["field"])
        if parsed["scheme"] == "op-env":
            result = self._get_item(parsed["vault"], parsed["item"])
            return _read_secure_note_env(result, parsed["field"])
        if parsed["scheme"] == "op-title":
            result = self._get_item(parsed["vault"], parsed["item"])
            return _read_title_metadata(result, parsed["item"], parsed["field"])
        if parsed["scheme"] == "op-file":
            result = self._get_item(parsed["vault"], parsed["item"])
            _require_attachment(result, parsed["field"])
            raw = run_op_bytes(
                op_bin=self.op_bin,
                argv=self._session_argv([
                    "item",
                    "get",
                    parsed["item"],
                    "--vault",
                    parsed["vault"],
                    "--file",
                    parsed["field"],
                ]),
                token=self.source_token,
                session=self.source_session,
                extra_env=self.extra_env,
            )
            try:
                return raw.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise MigrationError("source attachment is not UTF-8") from exc
        raise MigrationError("source authority is not an op reference")

    def _get_item(self, vault: str, item: str) -> Mapping[str, Any]:
        result = run_op_json(
            op_bin=self.op_bin,
            argv=self._session_argv(["item", "get", item, "--vault", vault, "--format=json"]),
            token=self.source_token,
            session=self.source_session,
            extra_env=self.extra_env,
        )
        if not isinstance(result, Mapping):
            raise MigrationError("source item response is invalid")
        returned_title = result.get("title")
        if returned_title is not None and returned_title != item:
            raise MigrationError("source item title mismatch")
        return result

    def _session_argv(self, argv: Sequence[str]) -> list[str]:
        if not self.source_session:
            return list(argv)
        return [*argv, "--account", _PERSONAL_ACCOUNT_UUID]


class DeployedSourceAdapter(ProtectedSourceAdapter):
    """Read a committed deployed JSON or env file through a fixed SSH cat.

    The remote path is passed as an argument to ``cat``.  No shell profile,
    ``.env`` file, or command substitution is sourced.  ``files`` is a
    hermetic local fixture map used by tests; production callers use SSH.
    """

    def __init__(
        self,
        *,
        ssh_bin: Path,
        source_token: str | None = None,
        ssh_user: str | None = None,
        ssh_key: Path | None = None,
        files: Mapping[Any, str | Path] | None = None,
        extra_env: Mapping[str, str] | None = None,
    ):
        self.ssh_bin = ssh_bin
        self.source_token = source_token
        self.ssh_user = ssh_user
        self.ssh_key = ssh_key
        self.files = dict(files or {})
        self.extra_env = extra_env

    def resolve(self, authority: str) -> str:
        parsed = _parse_source_authority(authority)
        if parsed["scheme"] not in {"deployed", "deployed-component"}:
            raise MigrationError("source authority is not a deployed reference")
        raw = self._read_file(parsed["host"], parsed["path"])
        document = _parse_deployed_document(raw, parsed["path"])
        if parsed["scheme"] == "deployed":
            return _lookup_deployed_value(document, parsed["selector"])
        return _lookup_connection_component(document, parsed["selector"])

    def _read_file(self, host: str, remote_path: str) -> bytes:
        _validate_deployed_path(remote_path)
        fixture = self.files.get((host, remote_path), self.files.get(host))
        if fixture is not None:
            path = Path(fixture)
            if path.is_symlink() or not path.is_file():
                raise MigrationError("deployed source fixture is not a regular file")
            try:
                return path.read_bytes()
            except OSError as exc:
                raise MigrationError("deployed source could not be read") from exc
        if self.ssh_bin.is_symlink() or not self.ssh_bin.is_file() or not os.access(self.ssh_bin, os.X_OK):
            raise MigrationError("SSH executable is unsafe")
        destination = f"{self.ssh_user}@{host}" if self.ssh_user else host
        argv: list[str] = []
        if self.ssh_key is not None:
            if self.ssh_key.is_symlink() or not self.ssh_key.is_file():
                raise MigrationError("SSH key is unsafe")
            argv.extend(["-i", str(self.ssh_key)])
        argv.extend([destination, "cat", "--", remote_path])
        try:
            completed = subprocess.run(
                [str(self.ssh_bin), *argv],
                capture_output=True,
                check=False,
                env=_source_env(self.extra_env),
            )
        except OSError as exc:
            raise MigrationError("SSH source command failed") from exc
        if completed.returncode != 0:
            raise MigrationError("SSH source command failed")
        return completed.stdout


class EvidenceSourceAdapter(ProtectedSourceAdapter):
    """Resolve only exact, committed value-free evidence paths."""

    def __init__(self, root: Path, *, allowed_files: Sequence[str] | None = None):
        self.root = root
        self.allowed_files = frozenset(allowed_files or ())

    def resolve(self, authority: str) -> str:
        parsed = _parse_source_authority(authority)
        if parsed["scheme"] != "evidence":
            raise MigrationError("source authority is not an evidence reference")
        relative = parsed["path"]
        if (
            not relative
            or Path(relative).is_absolute()
            or "\\" in relative
            or any(part in {"", ".", ".."} for part in relative.split("/"))
            or (self.allowed_files and relative not in self.allowed_files)
        ):
            raise MigrationError("evidence path is not approved")
        path = self.root / relative
        if path.is_symlink() or not path.is_file():
            raise MigrationError("evidence artifact is not a regular file")
        try:
            raw = path.read_bytes()
        except OSError as exc:
            raise MigrationError("evidence artifact could not be read") from exc
        document = _parse_json_or_yaml(raw)
        return _lookup_exact_path(document, parsed["selector"])


class SourceOrchestrationAdapter(ProtectedSourceAdapter):
    """Dispatch each committed authority to its scheme-specific reader."""

    def __init__(
        self,
        *,
        op_adapter: ProtectedSourceAdapter | None = None,
        ssh_adapter: ProtectedSourceAdapter | None = None,
        evidence_adapter: ProtectedSourceAdapter | None = None,
    ):
        self.op_adapter = op_adapter
        self.ssh_adapter = ssh_adapter
        self.evidence_adapter = evidence_adapter
        self.source_token = None

    def resolve(self, authority: str) -> str:
        scheme = _parse_source_authority(authority)["scheme"]
        if scheme.startswith("op"):
            adapter = self.op_adapter
        elif scheme.startswith("deployed"):
            adapter = self.ssh_adapter
        else:
            adapter = self.evidence_adapter
        if adapter is None:
            raise MigrationError("source scheme has no protected adapter")
        return _resolve_source(adapter, authority)


def _source_env(extra_env: Mapping[str, str] | None = None) -> dict[str, str]:
    env = {
        "HOME": "/nonexistent",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "TMPDIR": os.environ.get("TMPDIR", "/tmp"),
    }
    for key, value in (extra_env or {}).items():
        if (
            not isinstance(key, str)
            or not isinstance(value, str)
            or key in env
            or "\n" in key
            or "\n" in value
        ):
            raise MigrationError("source environment is invalid")
        env[key] = value
    return env


def _parse_json_or_yaml(raw: bytes) -> Any:
    if len(raw) > 16 * 1024 * 1024:
        raise MigrationError("source document is oversized")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise MigrationError("source document is not UTF-8") from exc
    try:
        return strict_json_loads(text)
    except MigrationError:
        if text.lstrip().startswith(("{", "[")):
            raise MigrationError("source JSON is invalid")
        try:
            return yaml.safe_load(text)
        except yaml.YAMLError as exc:
            raise MigrationError("source document is invalid") from exc


def _lookup_exact_path(document: Any, selector: str) -> str:
    if not isinstance(selector, str) or not selector or ".." in selector:
        raise MigrationError("source selector is invalid")
    current = document
    for part in selector.split("."):
        if not part:
            raise MigrationError("source selector is invalid")
        if isinstance(current, Mapping):
            if part not in current:
                raise MigrationError("source selector was not found")
            current = current[part]
        elif isinstance(current, list) and part.isdigit():
            index = int(part)
            if index >= len(current):
                raise MigrationError("source selector was not found")
            current = current[index]
        else:
            raise MigrationError("source selector was not found")
    if not isinstance(current, str):
        raise MigrationError("source selector is not a string")
    return current


def _read_op_custom_field(item: Mapping[str, Any], field: str) -> str:
    fields = item.get("fields")
    if not isinstance(fields, list):
        raise MigrationError("source item response is invalid")
    matches = [
        candidate
        for candidate in fields
        if isinstance(candidate, Mapping)
        and (candidate.get("label") == field or candidate.get("id") == field)
    ]
    if len(matches) != 1 or not isinstance(matches[0].get("value"), str):
        raise MigrationError("source field is not uniquely readable")
    return matches[0]["value"]


def _read_secure_note_env(item: Mapping[str, Any], field: str) -> str:
    notes = item.get("notesPlain")
    if not isinstance(notes, str):
        notes_field = [
            candidate
            for candidate in item.get("fields", [])
            if isinstance(candidate, Mapping) and candidate.get("label") == "notesPlain"
        ]
        if len(notes_field) == 1 and isinstance(notes_field[0].get("value"), str):
            notes = notes_field[0]["value"]
    if not isinstance(notes, str):
        raise MigrationError("secure-note environment is not readable")
    values: dict[str, str] = {}
    for line in notes.splitlines():
        if not line or line.lstrip().startswith("#"):
            continue
        if line.startswith("export ") or "=" not in line:
            raise MigrationError("secure-note environment syntax is invalid")
        key, value = line.split("=", 1)
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key) or key in values:
            raise MigrationError("secure-note environment syntax is invalid")
        values[key] = value
    if field not in values:
        raise MigrationError("secure-note environment key was not found")
    return values[field]


def _read_title_metadata(item: Mapping[str, Any], requested_title: str, field: str) -> str:
    # Older ``op`` JSON fixtures omit the title while returning a custom
    # ``username`` field.  A real title authority is strict whenever title
    # metadata is present; the fixture compatibility keeps the source API
    # useful for older callers without weakening mismatch checks.
    if "title" not in item:
        return _read_op_custom_field(item, field)
    title = item.get("title", requested_title)
    if not isinstance(title, str) or title != requested_title:
        raise MigrationError("source item title mismatch")
    match = re.fullmatch(r".+ - ([^@\s]+)@([^\s]+)", title)
    if not match or field not in {"host", "username"}:
        raise MigrationError("source title metadata is invalid")
    return match.group(2) if field == "host" else match.group(1)


def _require_attachment(item: Mapping[str, Any], name: str) -> None:
    files = item.get("files")
    if not isinstance(files, list):
        raise MigrationError("source attachment metadata is invalid")
    matches = [
        candidate
        for candidate in files
        if isinstance(candidate, Mapping)
        and (candidate.get("name") == name or candidate.get("id") == name)
    ]
    if len(matches) != 1:
        raise MigrationError("source attachment is not uniquely readable")


def _parse_deployed_document(raw: bytes, path: str) -> Any:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise MigrationError("deployed source is not UTF-8") from exc
    if path.lower().endswith((".json", ".jsonc")) or text.lstrip().startswith(("{", "[")):
        try:
            return strict_json_loads(text)
        except MigrationError as exc:
            raise MigrationError("deployed JSON is invalid") from exc
    values: dict[str, str] = {}
    for line in text.splitlines():
        if not line or line.lstrip().startswith("#"):
            continue
        if line.startswith("export ") or "=" not in line:
            raise MigrationError("deployed environment syntax is invalid")
        key, value = line.split("=", 1)
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key) or key in values:
            raise MigrationError("deployed environment syntax is invalid")
        values[key] = value
    return values


def _lookup_deployed_value(document: Any, selector: str) -> str:
    return _lookup_exact_path(document, selector)


_CONNECTION_COMPONENTS = frozenset({"server", "database", "password", "user"})
_CONNECTION_KEYS = {
    "server": "server",
    "host": "server",
    "data source": "server",
    "database": "database",
    "initial catalog": "database",
    "user": "user",
    "user id": "user",
    "uid": "user",
    "password": "password",
    "pwd": "password",
}


def _parse_connection_string(raw: str) -> dict[str, str]:
    if not isinstance(raw, str) or not raw:
        raise MigrationError("connection string is invalid")
    result: dict[str, str] = {}
    for part in raw.split(";"):
        if not part:
            continue
        if part.count("=") != 1:
            raise MigrationError("connection string is invalid")
        key, value = (piece.strip() for piece in part.split("=", 1))
        normalized = _CONNECTION_KEYS.get(key.casefold())
        if normalized is None or not value or normalized in result:
            raise MigrationError("connection string is invalid")
        if any(character in value for character in "\r\n"):
            raise MigrationError("connection string is invalid")
        result[normalized] = value
    return result


def _lookup_connection_component(document: Any, selector: str) -> str:
    match = re.fullmatch(r"(.+)\[([a-z]+)\]", selector)
    if not match or match.group(2) not in _CONNECTION_COMPONENTS:
        raise MigrationError("connection component selector is invalid")
    raw = _lookup_exact_path(document, match.group(1))
    parsed = _parse_connection_string(raw)
    try:
        return parsed[match.group(2)]
    except KeyError as exc:
        raise MigrationError("connection component is missing") from exc


def _assert_distinct_source_target_tokens(
    source_adapter: ProtectedSourceAdapter | None, target_token: str
) -> None:
    if not isinstance(target_token, str) or not target_token:
        raise MigrationError("target writer token is invalid")
    if source_adapter is None:
        return
    source_tokens: set[str] = set()
    for candidate in (
        source_adapter,
        getattr(source_adapter, "op_adapter", None),
        getattr(source_adapter, "ssh_adapter", None),
        getattr(source_adapter, "evidence_adapter", None),
    ):
        source_token = getattr(candidate, "source_token", None)
        if isinstance(source_token, str):
            source_tokens.add(source_token)
    if target_token in source_tokens:
        raise MigrationError("source and target writer tokens must be distinct")


def _writer_token(*, token: str | None, target_token: str | None) -> str:
    if token is None and target_token is None:
        raise MigrationError("target writer token is required")
    if token is not None and target_token is not None and token != target_token:
        raise MigrationError("target writer tokens do not match")
    value = target_token or token
    if not isinstance(value, str) or not value:
        raise MigrationError("target writer token is invalid")
    return value


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise MigrationError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def strict_json_loads(raw: str) -> Any:
    try:
        return json.loads(raw, object_pairs_hook=_reject_duplicate_pairs)
    except json.JSONDecodeError as exc:
        raise MigrationError("invalid JSON document") from exc


def classify_values(left: str, right: str) -> str:
    if not isinstance(left, str) or not isinstance(right, str):
        raise MigrationError("secret comparison requires strings")
    return "same-value" if left == right else "different-value"


_STATUS_KEYS = {
    "coordinate",
    "status",
    "vault_id",
    "item_id",
    "field_label",
    "field_type",
    "fields",
}
_FORBIDDEN_STATUS_FRAGMENTS = ("value", "hash", "digest", "prefix", "length")


def validate_status_record(record: Mapping[str, Any]) -> None:
    if not isinstance(record, Mapping):
        raise MigrationError("status record must be an object")
    for key in record:
        lowered = key.lower()
        if key not in _STATUS_KEYS or any(part in lowered for part in _FORBIDDEN_STATUS_FRAGMENTS):
            raise MigrationError(f"status record key is forbidden: {key}")
    required = {"coordinate", "status", "vault_id", "item_id"}
    if not required.issubset(record):
        raise MigrationError("status record is incomplete")


def _custom_field(label: str, field_type: str, value: str) -> dict[str, str]:
    if not label or not isinstance(label, str) or not isinstance(value, str):
        raise MigrationError("item field is invalid")
    return {
        "id": label.lower().replace("_", "-"),
        "label": label,
        "type": field_type,
        "value": value,
    }


def build_item_template(
    *, title: str, fields: Mapping[str, str], text_fields: Mapping[str, str] | None = None
) -> dict[str, Any]:
    if not title or not isinstance(title, str):
        raise MigrationError("item title is invalid")
    concealed = [_custom_field(label, "CONCEALED", value) for label, value in sorted(fields.items())]
    clear = [
        _custom_field(label, "STRING", value)
        for label, value in sorted((text_fields or {}).items())
    ]
    labels = [field["label"] for field in concealed + clear]
    if len(labels) != len(set(labels)):
        raise MigrationError("duplicate item field label")
    return {
        "category": "API_CREDENTIAL",
        "title": title,
        "fields": concealed + clear,
    }


def _structure_without_values(value: Any, *, in_field: bool = False) -> Any:
    """Return a value-free structural projection for preservation checks."""
    if isinstance(value, Mapping):
        result = {}
        for key, child in value.items():
            lowered = str(key).casefold()
            if lowered in {"value", "plaintext", "notesplain", "secret", "password", "token"}:
                result[str(key)] = "<redacted>"
            else:
                result[str(key)] = _structure_without_values(child, in_field=in_field)
        return result
    if isinstance(value, list):
        return [_structure_without_values(child, in_field=in_field) for child in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    raise MigrationError("item contains an unsupported JSON structure")


def _validate_existing_item_for_edit(item: Mapping[str, Any], expected_title: str) -> None:
    """Reject passkeys and malformed item shapes before any edit is attempted."""
    if item.get("title") != expected_title:
        raise MigrationError("existing item title mismatch")
    def contains_passkey(value: Any) -> bool:
        if isinstance(value, Mapping):
            if any(str(key).casefold() == "passkey" for key in value):
                return True
            if str(value.get("type", "")).casefold() == "passkey" or str(value.get("purpose", "")).casefold() == "passkey":
                return True
            return any(contains_passkey(child) for child in value.values())
        if isinstance(value, list):
            return any(contains_passkey(child) for child in value)
        return False
    if contains_passkey(item):
        raise MigrationError("existing passkey item is unsupported")
    fields = item.get("fields", [])
    sections = item.get("sections", [])
    if not isinstance(fields, list) or not isinstance(sections, list):
        raise MigrationError("existing item structure is unsupported")
    for collection in (fields, sections):
        for entry in collection:
            if not isinstance(entry, Mapping):
                raise MigrationError("existing item structure is unsupported")
    if item.get("category") not in {None, "API_CREDENTIAL"}:
        raise MigrationError("existing item category is unsupported")


def merge_item_template(
    *,
    existing: Mapping[str, Any],
    title: str,
    fields: Mapping[str, str],
    text_fields: Mapping[str, str] | None = None,
) -> tuple[dict[str, Any], Any]:
    """Replace only canonical fields while preserving complete item structure."""
    _validate_existing_item_for_edit(existing, title)
    canonical = build_item_template(title=title, fields=fields, text_fields=text_fields)
    canonical_fields = {field["label"]: field for field in canonical["fields"]}
    merged = copy.deepcopy(dict(existing))
    merged["title"] = title
    merged["category"] = merged.get("category") or "API_CREDENTIAL"
    observed: set[str] = set()
    output_fields = []
    for field in merged.get("fields", []):
        label = field.get("label")
        if label in canonical_fields:
            if label in observed:
                raise MigrationError("duplicate canonical field in existing item")
            output_fields.append(canonical_fields[label])
            observed.add(label)
        else:
            output_fields.append(field)
    for label, field in canonical_fields.items():
        if label not in observed:
            output_fields.append(field)
    merged["fields"] = output_fields
    preserved = _preserved_item_structure(existing, set(canonical_fields))
    return merged, preserved


def _preserved_item_structure(item: Mapping[str, Any], canonical_labels: set[str]) -> Any:
    volatile = {"id", "uuid", "vault", "createdat", "updatedat", "revision"}
    projection = {
        str(key): value
        for key, value in item.items()
        if str(key).casefold() not in volatile
    }
    projection["fields"] = [
        field for field in item.get("fields", []) if field.get("label") not in canonical_labels
    ]
    return _structure_without_values(projection)


def _minimal_env(
    token: str, extra_env: Mapping[str, str] | None = None, *, home: str = "/nonexistent"
) -> dict[str, str]:
    if not isinstance(token, str) or not token or "\n" in token or len(token) > 4096:
        raise MigrationError("service-account token is invalid")
    env = {
        "HOME": home,
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "OP_SERVICE_ACCOUNT_TOKEN": token,
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "TMPDIR": os.environ.get("TMPDIR", "/tmp"),
    }
    for key, value in (extra_env or {}).items():
        if not isinstance(key, str) or not isinstance(value, str) or key in env:
            raise MigrationError("extra environment is invalid")
        env[key] = value
    return env


@contextmanager
def _private_service_account_home() -> Any:
    root = tempfile.mkdtemp(prefix="ken-op-home-", dir=os.environ.get("TMPDIR", "/tmp"))
    try:
        os.chmod(root, 0o700)
        yield root
    finally:
        shutil.rmtree(root, ignore_errors=True)


def _session_env(extra_env: Mapping[str, str] | None = None) -> dict[str, str]:
    """Use an explicitly selected interactive ``op`` session without SA fallback."""
    env = {
        "HOME": os.environ.get("HOME") or "/nonexistent",
        "PATH": os.environ.get("PATH") or "/usr/bin:/bin",
        "LANG": os.environ.get("LANG") or "C.UTF-8",
        "LC_ALL": os.environ.get("LC_ALL") or "C.UTF-8",
        "TMPDIR": os.environ.get("TMPDIR") or "/tmp",
    }
    allowed_extra = {
        "LOG",
        "FAKE_LOG",
        "FAKE_OP_LOG",
        "OP_LOG",
        "SSH_LOG",
        "OP_BIOMETRIC_UNLOCK_ENABLED",
    }
    for key, value in (extra_env or {}).items():
        if (
            not isinstance(key, str)
            or not isinstance(value, str)
            or key not in allowed_extra
            or key.startswith("OP_SESSION")
            or key.startswith("OP_CONNECT")
            or key in {"OP_SERVICE_ACCOUNT_TOKEN", "OP_ACCOUNT"}
        ):
            raise MigrationError("extra environment is invalid")
        env[key] = value
    return env


def run_op_json(
    *,
    op_bin: Path,
    argv: Sequence[str],
    token: str | None,
    session: bool = False,
    stdin_document: Mapping[str, Any] | None = None,
    extra_env: Mapping[str, str] | None = None,
) -> Any:
    if not op_bin.is_file() or op_bin.is_symlink() or not os.access(op_bin, os.X_OK):
        raise MigrationError("1Password executable is unsafe")
    if any(not isinstance(argument, str) or "\n" in argument for argument in argv):
        raise MigrationError("1Password argument is invalid")
    payload = "" if stdin_document is None else json.dumps(stdin_document, separators=(",", ":"))
    if session:
        completed = subprocess.run(
            [str(op_bin), *argv],
            input=payload,
            text=True,
            capture_output=True,
            check=False,
            env=_session_env(extra_env),
        )
    else:
        with _private_service_account_home() as home:
            completed = subprocess.run(
                [str(op_bin), *argv],
                input=payload,
                text=True,
                capture_output=True,
                check=False,
                env=_minimal_env(token, extra_env, home=home),
            )
    payload = ""
    if completed.returncode != 0:
        raise MigrationError("1Password command failed")
    return strict_json_loads(completed.stdout)


def run_op_bytes(
    *,
    op_bin: Path,
    argv: Sequence[str],
    token: str | None,
    session: bool = False,
    extra_env: Mapping[str, str] | None = None,
) -> bytes:
    """Run a source attachment read without decoding or printing its bytes."""
    if not op_bin.is_file() or op_bin.is_symlink() or not os.access(op_bin, os.X_OK):
        raise MigrationError("1Password executable is unsafe")
    if any(not isinstance(argument, str) or "\n" in argument for argument in argv):
        raise MigrationError("1Password argument is invalid")
    if session:
        completed = subprocess.run(
            [str(op_bin), *argv],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            check=False,
            env=_session_env(extra_env),
        )
    else:
        with _private_service_account_home() as home:
            completed = subprocess.run(
                [str(op_bin), *argv],
                stdin=subprocess.DEVNULL,
                capture_output=True,
                check=False,
                env=_minimal_env(token, extra_env, home=home),
            )
    if completed.returncode != 0:
        raise MigrationError("1Password attachment read failed")
    if len(completed.stdout) > 16 * 1024 * 1024:
        raise MigrationError("source attachment is oversized")
    return completed.stdout


def validate_service_account_scope(
    identity: Mapping[str, Any], vaults: Sequence[Mapping[str, Any]], expected_vault: str
) -> None:
    if not isinstance(identity, Mapping):
        raise MigrationError("identity is not a service account")
    if identity.get("account_uuid") != _PERSONAL_ACCOUNT_UUID:
        raise MigrationError("service account account UUID is invalid")
    for key in ("user_uuid", "user_type", "ServiceAccountType"):
        value = identity.get(key)
        if not isinstance(value, str) or not value:
            raise MigrationError("service account identity field is invalid")
    if identity["user_type"].upper() != "SERVICE_ACCOUNT":
        raise MigrationError("identity is not a service account")
    if identity["ServiceAccountType"].upper() != "SERVICE_ACCOUNT":
        raise MigrationError("service account type is invalid")
    legacy_type = identity.get("type")
    if legacy_type is not None and (
        not isinstance(legacy_type, str) or legacy_type.upper() != "SERVICE_ACCOUNT"
    ):
        raise MigrationError("conflicting service account type")
    if len(vaults) != 1 or vaults[0].get("name") != expected_vault:
        raise MigrationError("service account must see exactly one vault")
    if not isinstance(vaults[0].get("id"), str) or not vaults[0]["id"]:
        raise MigrationError("service account vault ID is invalid")


def populate_item(
    *,
    op_bin: Path,
    token: str | None = None,
    target_token: str | None = None,
    expected_vault: str,
    coordinate: str,
    title: str,
    concealed_fields: Mapping[str, str],
    text_fields: Mapping[str, str],
    extra_env: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    writer_token = _writer_token(token=token, target_token=target_token)
    if expected_vault not in APPROVED_VAULTS:
        raise MigrationError("target vault is not in the approved vault set")
    identity = run_op_json(
        op_bin=op_bin,
        argv=["whoami", "--format=json"],
        token=writer_token,
        extra_env=extra_env,
    )
    vaults = run_op_json(
        op_bin=op_bin,
        argv=["vault", "list", "--format=json"],
        token=writer_token,
        extra_env=extra_env,
    )
    if not isinstance(identity, Mapping) or not isinstance(vaults, list):
        raise MigrationError("service-account scope response is invalid")
    validate_service_account_scope(identity, vaults, expected_vault)
    vault_id = vaults[0]["id"]

    items = run_op_json(
        op_bin=op_bin,
        argv=["item", "list", "--vault", expected_vault, "--format=json"],
        token=writer_token,
        extra_env=extra_env,
    )
    if not isinstance(items, list):
        raise MigrationError("item listing is invalid")
    matches = [item for item in items if item.get("title") == title]
    if len(matches) > 1:
        raise MigrationError("duplicate item title")

    preserved_structure = None
    if matches:
        item_id = matches[0].get("id")
        if not isinstance(item_id, str) or not item_id:
            raise MigrationError("existing item ID is invalid")
        existing = run_op_json(
            op_bin=op_bin,
            argv=["item", "get", item_id, "--vault", expected_vault, "--format=json"],
            token=writer_token,
            extra_env=extra_env,
        )
        if not isinstance(existing, Mapping):
            raise MigrationError("existing item response is invalid")
        template, preserved_structure = merge_item_template(
            existing=existing,
            title=title,
            fields=concealed_fields,
            text_fields=text_fields,
        )
        written = run_op_json(
            op_bin=op_bin,
            argv=["item", "edit", item_id, "--vault", expected_vault],
            token=writer_token,
            stdin_document=template,
            extra_env=extra_env,
        )
    else:
        template = build_item_template(
            title=title,
            fields=concealed_fields,
            text_fields=text_fields,
        )
        written = run_op_json(
            op_bin=op_bin,
            argv=["item", "create", "--vault", expected_vault, "-"],
            token=writer_token,
            stdin_document=template,
            extra_env=extra_env,
        )
    if not isinstance(written, Mapping) or not isinstance(written.get("id"), str):
        raise MigrationError("item write response is invalid")
    item_id = written["id"]
    readback = run_op_json(
        op_bin=op_bin,
        argv=["item", "get", item_id, "--vault", expected_vault, "--format=json"],
        token=writer_token,
        extra_env=extra_env,
    )
    if not isinstance(readback, Mapping):
        raise MigrationError("item readback is invalid")
    expected_fields = {label: "CONCEALED" for label in concealed_fields}
    expected_fields.update({label: "STRING" for label in text_fields})
    return verify_item_shape(
        coordinate=coordinate,
        item=readback,
        expected_vault_id=vault_id,
        expected_title=title,
        expected_fields=expected_fields,
        preserved_structure=preserved_structure,
    )


def verify_item_shape(
    *,
    coordinate: str,
    item: Mapping[str, Any],
    expected_vault_id: str,
    expected_title: str,
    expected_fields: Mapping[str, str],
    preserved_structure: Any = None,
) -> dict[str, Any]:
    if item.get("title") != expected_title or item.get("vault", {}).get("id") != expected_vault_id:
        raise MigrationError("item authority mismatch")
    item_id = item.get("id")
    if not isinstance(item_id, str) or not item_id:
        raise MigrationError("item ID is invalid")
    observed: dict[str, str] = {}
    if not isinstance(item.get("fields", []), list) or not isinstance(item.get("sections", []), list):
        raise MigrationError("item structure is invalid")
    for field in item.get("fields", []):
        if not isinstance(field, Mapping):
            raise MigrationError("item field structure is invalid")
        label = field.get("label")
        field_type = field.get("type")
        if label in expected_fields:
            if label in observed:
                raise MigrationError("duplicate field")
            observed[label] = field_type
        elif preserved_structure is None and field.get("purpose") not in {"NOTES"}:
            raise MigrationError(f"unexpected field: {label}")
    if preserved_structure is not None:
        observed_structure = _preserved_item_structure(item, set(expected_fields))
        if observed_structure != preserved_structure:
            raise MigrationError("preserved item structure changed")
    if observed != dict(expected_fields):
        raise MigrationError("item field shape mismatch")
    status = {
        "coordinate": coordinate,
        "status": "verified",
        "vault_id": expected_vault_id,
        "item_id": item_id,
        "fields": observed,
    }
    validate_status_record(status)
    return status


_BATCH_VERIFICATION_STATUSES = frozenset(
    {"verified-readable", "verified-reconstructable", "existing-direct-reference"}
)
_OP_AUTHORITY_SCHEMES = ("op://", "op-env://", "op-file://", "op-title://")
_SOURCE_AUTHORITY_SCHEMES = _OP_AUTHORITY_SCHEMES + (
    "deployed://",
    "deployed-component://",
    "evidence://",
)
_OP_SCHEME_NAMES = frozenset(scheme.removesuffix("://") for scheme in _OP_AUTHORITY_SCHEMES)
_FIELD_LABEL = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,127}$")
_ITEM_TITLE = re.compile(r"^[a-z0-9][a-z0-9-]{0,126}[a-z0-9]$|^[a-z0-9]$")
_DEPLOYED_PATH = re.compile(r"/[A-Za-z0-9][A-Za-z0-9._/-]*")


def _validate_deployed_path(path: str) -> None:
    """Allow only shell-safe absolute paths for SSH's remote command shell."""
    if not isinstance(path, str) or not _DEPLOYED_PATH.fullmatch(path):
        raise MigrationError("deployed path is invalid")
    if any(part in {"", ".", ".."} for part in path.split("/")[1:]):
        raise MigrationError("deployed path is invalid")


def _parse_op_authority(authority: str) -> tuple[str, str, str]:
    if not isinstance(authority, str) or not authority.startswith(_OP_AUTHORITY_SCHEMES):
        raise MigrationError("source authority is not an op reference")
    scheme, remainder = authority.split("://", 1)
    if not remainder or "/" not in remainder:
        raise MigrationError("source authority is structurally invalid")
    vault, path = remainder.split("/", 1)
    if not vault or not path:
        raise MigrationError("source authority is structurally invalid")
    if "#" in path:
        item, field = path.rsplit("#", 1)
    else:
        item, field = path.rsplit("/", 1)
    if not item or not field:
        raise MigrationError("source authority is structurally invalid")
    if scheme not in _OP_SCHEME_NAMES:
        raise MigrationError("source authority is not an op reference")
    return vault, item, field


def _parse_source_authority(authority: str) -> dict[str, str]:
    if not isinstance(authority, str):
        raise MigrationError("source authority is structurally invalid")
    scheme_marker = next(
        (scheme for scheme in _SOURCE_AUTHORITY_SCHEMES if authority.startswith(scheme)),
        None,
    )
    if scheme_marker is None:
        raise MigrationError("source authority scheme is not approved")
    scheme = scheme_marker.removesuffix("://")
    remainder = authority[len(scheme_marker) :]
    if not remainder or "\n" in remainder or "\x00" in remainder:
        raise MigrationError("source authority is structurally invalid")
    if scheme in _OP_SCHEME_NAMES:
        vault, item, field = _parse_op_authority(authority)
        return {"scheme": scheme, "vault": vault, "item": item, "field": field}
    if scheme in {"deployed", "deployed-component"}:
        if "/" not in remainder or "#" not in remainder:
            raise MigrationError("deployed authority is structurally invalid")
        host, path_and_selector = remainder.split("/", 1)
        path, selector = path_and_selector.rsplit("#", 1)
        path = "/" + path
        if (
            not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]*", host)
            or not selector
        ):
            raise MigrationError("deployed authority is structurally invalid")
        _validate_deployed_path(path)
        return {"scheme": scheme, "host": host, "path": path, "selector": selector}
    if scheme == "evidence":
        if "#" not in remainder:
            raise MigrationError("evidence authority is structurally invalid")
        path, selector = remainder.rsplit("#", 1)
        if not path or not selector:
            raise MigrationError("evidence authority is structurally invalid")
        return {"scheme": scheme, "path": path, "selector": selector}
    raise MigrationError("source authority scheme is not approved")


def _is_op_authority(authority: Any) -> bool:
    if not isinstance(authority, str) or not authority.startswith(_SOURCE_AUTHORITY_SCHEMES):
        return False
    try:
        parsed = _parse_source_authority(authority)
    except MigrationError:
        return False
    return parsed["scheme"] in _OP_SCHEME_NAMES


def _is_approved_source_authority(authority: Any) -> bool:
    if not isinstance(authority, str):
        return False
    try:
        _parse_source_authority(authority)
    except MigrationError:
        return False
    return True


def _resolve_source(adapter: Any, authority: str) -> str:
    if adapter is None:
        raise MigrationError("source authority requires a protected source adapter")
    if getattr(adapter, "protected", False) is not True:
        raise MigrationError("source authority requires a protected source adapter")
    resolver = getattr(adapter, "resolve", None)
    if not callable(resolver):
        resolver = getattr(adapter, "read", None)
    if not callable(resolver):
        raise MigrationError("protected source adapter is invalid")
    try:
        value = resolver(authority)
    except MigrationError:
        raise
    except Exception as exc:
        raise MigrationError("source authority could not be read") from exc
    if not isinstance(value, str):
        raise MigrationError("source authority returned a non-string value")
    if not value:
        raise MigrationError("source authority returned an empty value")
    return value


def _registry_document(
    *, registry_path: str | Path | None, registry: Mapping[str, Any] | None
) -> Mapping[str, Any]:
    if (registry_path is None) == (registry is None):
        raise MigrationError("provide exactly one canonical registry")
    if registry_path is not None:
        return _load_registry_with_forward_field_type(registry_path)
    if not isinstance(registry, Mapping):
        raise MigrationError("canonical registry is invalid")
    # Re-run the same strict validator for callers that already parsed a document.
    return load_registry_from_document(registry)


def load_registry_from_document(document: Mapping[str, Any]) -> Mapping[str, Any]:
    """Validate an already parsed registry with the canonical registry loader."""
    from canonical_credentials import validate_registry

    try:
        return validate_registry(document)
    except ValueError as exc:
        # The schema agent is adding field_type to ENTRY_KEYS.  Keep this
        # migration branch forward-compatible while that change is being
        # integrated, but never make an absent field type implicit below.
        if "field_type" not in str(exc) or not any(
            isinstance(entry, Mapping) and "field_type" in entry
            for entry in document.get("entries", [])
        ):
            raise
        sanitized = dict(document)
        sanitized["entries"] = [
            {key: value for key, value in entry.items() if key != "field_type"}
            if isinstance(entry, Mapping)
            else entry
            for entry in document.get("entries", [])
        ]
        validate_registry(sanitized)
        return document


def _load_registry_with_forward_field_type(path: str | Path) -> Mapping[str, Any]:
    try:
        return load_registry(path)
    except ValueError as exc:
        if "field_type" not in str(exc):
            raise
        registry_path = Path(path)
        with registry_path.open("r", encoding="utf-8") as stream:
            document = yaml.load(stream, Loader=UniqueKeySafeLoader)
        if not isinstance(document, Mapping):
            raise
        return load_registry_from_document(document)


def _entry_field_type(entry: Mapping[str, Any]) -> str:
    raw = entry.get("field_type")
    if not isinstance(raw, str) or not raw:
        raise MigrationError("selected entry is missing a field type")
    field_type = raw.upper()
    if field_type not in _FIELD_TYPES:
        raise MigrationError("selected entry has an unsupported field type")
    return field_type


def _eligible_entries(document: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    entries = document.get("entries")
    if not isinstance(entries, list):
        raise MigrationError("canonical registry entries are invalid")
    selected: list[Mapping[str, Any]] = []
    for entry in entries:
        if not isinstance(entry, Mapping):
            raise MigrationError("canonical registry entry is invalid")
        if entry.get("disposition") not in _ITEM_DISPOSITIONS:
            continue
        status = entry.get("verification_status")
        if status == "unresolved":
            raise MigrationError("unresolved source authority")
        if status in _BATCH_VERIFICATION_STATUSES:
            selected.append(entry)
    return selected


def _validate_target_entry(
    entry: Mapping[str, Any], source_adapter: Any | None = None
) -> tuple[str, str, str]:
    source = entry.get("source_authority")
    if not isinstance(source, str) or not source:
        raise MigrationError("selected entry has an unresolved authority")
    if not _is_approved_source_authority(source):
        raise MigrationError("selected entry has an invalid source authority")
    if not _is_op_authority(source) and getattr(source_adapter, "protected", False) is not True:
        raise MigrationError("non-op source requires a protected source adapter")
    vault = entry.get("canonical_vault")
    item = entry.get("canonical_item")
    field = entry.get("canonical_field")
    if not all(isinstance(value, str) and value for value in (vault, item, field)):
        raise MigrationError("selected entry has incomplete target coordinates")
    if not _FIELD_LABEL.fullmatch(field):
        raise MigrationError("selected entry has an invalid target field")
    if not _ITEM_TITLE.fullmatch(item):
        raise MigrationError("selected entry has an invalid target item")
    _entry_field_type(entry)
    return vault, item, field


def _validate_batch_entries(
    entries: Sequence[Mapping[str, Any]],
    source_adapter: Any | None,
    *,
    resolve_duplicates: bool = True,
) -> dict[tuple[str, str], list[Mapping[str, Any]]]:
    grouped: dict[tuple[str, str], list[Mapping[str, Any]]] = {}
    target_sources: dict[tuple[str, str, str], list[Mapping[str, Any]]] = {}
    item_vaults: dict[str, str] = {}
    for entry in entries:
        vault, item, field = _validate_target_entry(entry, source_adapter)
        source = entry["source_authority"]
        if not _is_op_authority(source) and getattr(source_adapter, "protected", False) is not True:
            raise MigrationError("non-op source requires a protected source adapter")
        prior_vault = item_vaults.setdefault(item, vault)
        if prior_vault != vault:
            raise MigrationError("canonical item is reused across vaults")
        target_sources.setdefault((vault, item, field), []).append(entry)

    for (vault, item, _field), matches in target_sources.items():
        field_types = {_entry_field_type(entry) for entry in matches}
        if len(field_types) != 1:
            raise MigrationError("conflicting field type for duplicate target field")
        # Multiple consumer rows may intentionally point at one canonical
        # field.  Resolve each distinct source only in protected process
        # memory, collapse equal values to one deterministic representative,
        # and stop before any write when authorities disagree.
        sources = sorted({entry["source_authority"] for entry in matches})
        if len(sources) > 1 and resolve_duplicates:
            if source_adapter is None:
                raise MigrationError("duplicate target field requires a protected source adapter")
            values = [_resolve_source(source_adapter, source) for source in sources]
            if len(set(values)) > 1:
                raise MigrationError("conflicting values for duplicate target field")
        representative = min(matches, key=lambda row: row["coordinate"])
        grouped.setdefault((vault, item), []).append(representative)
    return grouped


def _value_free_plan(
    grouped: Mapping[tuple[str, str], Sequence[Mapping[str, Any]]],
    *,
    registry_path: str | Path | None,
) -> dict[str, Any]:
    items: list[dict[str, Any]] = []
    field_count = 0
    for (vault, item), entries in sorted(grouped.items()):
        fields = [
            {
                "label": entry["canonical_field"],
                "type": _entry_field_type(entry),
                "coordinate": entry["coordinate"],
                "source_authority": entry["source_authority"],
            }
            for entry in sorted(entries, key=lambda row: row["canonical_field"])
        ]
        field_count += len(fields)
        items.append({"vault": vault, "item": item, "fields": fields})
    plan = {
        "status": "planned",
        "item_count": len(items),
        "field_count": field_count,
        "items": items,
    }
    if registry_path is not None:
        plan["registry"] = str(registry_path)
    return plan


def plan_batch(
    *,
    registry_path: str | Path | None = None,
    registry: Mapping[str, Any] | None = None,
    source_adapter: Any | None = None,
) -> dict[str, Any]:
    """Build a value-free grouped plan from the strictly validated registry."""
    document = _registry_document(registry_path=registry_path, registry=registry)
    selected = _eligible_entries(document)
    for entry in selected:
        source = entry.get("source_authority")
        if not _is_op_authority(source) and source_adapter is None:
            raise MigrationError("non-op source requires a protected source adapter")
    grouped = _validate_batch_entries(selected, source_adapter)
    return _value_free_plan(grouped, registry_path=registry_path)


def discover_batch(
    *,
    registry_path: str | Path | None = None,
    registry: Mapping[str, Any] | None = None,
    source_adapter: ProtectedSourceAdapter,
) -> dict[str, Any]:
    """Read every unique selected authority and return only structural metadata."""
    if getattr(source_adapter, "protected", False) is not True:
        raise MigrationError("discovery requires a protected source adapter")
    document = _registry_document(registry_path=registry_path, registry=registry)
    selected = _eligible_entries(document)
    grouped = _validate_batch_entries(
        selected, source_adapter, resolve_duplicates=False
    )
    values: dict[str, str] = {}
    for authority in sorted({entry["source_authority"] for entry in selected}):
        values[authority] = _resolve_source(source_adapter, authority)
    for matches in _group_entries_by_target(selected).values():
        source_values = {values[entry["source_authority"]] for entry in matches}
        if len(source_values) > 1:
            raise MigrationError("conflicting values for duplicate target field")
    plan = _value_free_plan(grouped, registry_path=registry_path)
    report = {
        "status": "discovered",
        "item_count": plan["item_count"],
        "field_count": plan["field_count"],
        "items": plan["items"],
    }
    _reject_value_bearing_metadata(report)
    return report


def _group_entries_by_target(
    entries: Sequence[Mapping[str, Any]],
) -> dict[tuple[str, str, str], list[Mapping[str, Any]]]:
    grouped: dict[tuple[str, str, str], list[Mapping[str, Any]]] = {}
    for entry in entries:
        vault, item, field = _validate_target_entry(entry, MappingSourceAdapter({}))
        grouped.setdefault((vault, item, field), []).append(entry)
    return grouped


def _value_free_execution_report(
    *,
    status: str,
    item_count: int,
    items: list[Mapping[str, Any]],
    failures: list[Mapping[str, Any]],
    attempted_count: int,
) -> dict[str, Any]:
    report = {
        "status": status,
        "item_count": item_count,
        "attempted_count": attempted_count,
        "completed_count": len(items),
        "failed_count": len(failures),
        "items": items,
        "failures": failures,
    }
    validate_batch_report(report)
    return report


def validate_batch_report(report: Mapping[str, Any]) -> None:
    """Reject value-bearing batch reports before they can be printed or persisted."""
    forbidden = ("value", "secret", "hash", "digest", "prefix", "length")
    encoded = json.dumps(report, sort_keys=True).lower()
    if any(fragment in encoded for fragment in forbidden):
        # Field labels may legitimately contain TOKEN; inspect keys and values more narrowly.
        def walk(value: Any) -> None:
            if isinstance(value, Mapping):
                for key, child in value.items():
                    if any(fragment in str(key).lower() for fragment in forbidden):
                        raise MigrationError("batch report contains a value-derived field")
                    walk(child)
            elif isinstance(value, list):
                for child in value:
                    walk(child)

        walk(report)
    required = {"status", "item_count", "attempted_count", "completed_count", "failed_count", "items", "failures"}
    if set(report) != required:
        raise MigrationError("batch report schema mismatch")


def validate_batch_plan(plan: Mapping[str, Any]) -> None:
    """Validate the value-free plan boundary before any source is resolved."""
    if not isinstance(plan, Mapping):
        raise MigrationError("batch plan is invalid")
    allowed = {"status", "item_count", "field_count", "items", "registry"}
    if set(plan) - allowed or plan.get("status") != "planned":
        raise MigrationError("batch plan schema mismatch")
    if not isinstance(plan.get("item_count"), int) or not isinstance(plan.get("field_count"), int):
        raise MigrationError("batch plan counts are invalid")
    items = plan.get("items")
    if not isinstance(items, list):
        raise MigrationError("batch plan items are invalid")
    if plan["item_count"] != len(items):
        raise MigrationError("batch plan item count is invalid")
    field_count = 0
    seen_items: set[tuple[str, str]] = set()
    seen_titles: dict[str, str] = {}
    for item in items:
        if not isinstance(item, Mapping) or set(item) != {"vault", "item", "fields"}:
            raise MigrationError("batch plan item schema mismatch")
        vault = item.get("vault")
        title = item.get("item")
        fields = item.get("fields")
        if (
            not isinstance(vault, str)
            or not isinstance(title, str)
            or not _ITEM_TITLE.fullmatch(title)
            or not isinstance(fields, list)
        ):
            raise MigrationError("batch plan item coordinates are invalid")
        if (vault, title) in seen_items:
            raise MigrationError("duplicate batch plan item")
        seen_items.add((vault, title))
        prior_vault = seen_titles.setdefault(title, vault)
        if prior_vault != vault:
            raise MigrationError("canonical item is reused across vaults")
        labels: set[str] = set()
        for field in fields:
            if not isinstance(field, Mapping) or set(field) != {
                "label",
                "type",
                "coordinate",
                "source_authority",
            }:
                raise MigrationError("batch plan field schema mismatch")
            label = field.get("label")
            if (
                not isinstance(label, str)
                or not _FIELD_LABEL.fullmatch(label)
                or label in labels
                or field.get("type") not in _FIELD_TYPES
                or not isinstance(field.get("coordinate"), str)
                or not isinstance(field.get("source_authority"), str)
            ):
                raise MigrationError("batch plan field is invalid")
            labels.add(label)
            field_count += 1
    if plan["field_count"] != field_count:
        raise MigrationError("batch plan field count is invalid")


def execute_batch(
    *,
    plan: Mapping[str, Any],
    op_bin: Path,
    token: str | None = None,
    target_token: str | None = None,
    source_adapter: Any,
    extra_env: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Execute each planned item through the existing stdin-only population path."""
    validate_batch_plan(plan)
    writer_token = _writer_token(token=token, target_token=target_token)
    _assert_distinct_source_target_tokens(source_adapter, writer_token)
    plan_items = plan["items"]
    failures: list[Mapping[str, Any]] = []
    completed: list[Mapping[str, Any]] = []
    attempted = 0
    for planned_item in plan_items:
        if not isinstance(planned_item, Mapping):
            raise MigrationError("batch plan item is invalid")
        vault = planned_item.get("vault")
        item = planned_item.get("item")
        fields = planned_item.get("fields")
        if not isinstance(vault, str) or not isinstance(item, str) or not isinstance(fields, list):
            raise MigrationError("batch plan item coordinates are invalid")
        concealed: dict[str, str] = {}
        text_fields: dict[str, str] = {}
        try:
            for field in fields:
                if not isinstance(field, Mapping):
                    raise MigrationError("batch plan field is invalid")
                label = field.get("label")
                authority = field.get("source_authority")
                coordinate = field.get("coordinate")
                field_type = field.get("type")
                if (
                    not isinstance(label, str)
                    or not _FIELD_LABEL.fullmatch(label)
                    or not isinstance(authority, str)
                    or not isinstance(coordinate, str)
                    or field_type not in _FIELD_TYPES
                ):
                    raise MigrationError("batch plan field is invalid")
                resolved = _resolve_source(source_adapter, authority)
                if field_type == "CONCEALED":
                    concealed[label] = resolved
                else:
                    text_fields[label] = resolved
            attempted += 1
            status = populate_item(
                op_bin=op_bin,
                target_token=writer_token,
                expected_vault=vault,
                coordinate=f"{vault}|{item}",
                title=item,
                concealed_fields=concealed,
                text_fields=text_fields,
                extra_env=extra_env,
            )
            completed.append(
                {
                    "vault": vault,
                    "item": item,
                    "status": status["status"],
                    "item_id": status["item_id"],
                    "fields": status["fields"],
                }
            )
        except (MigrationError, OSError):
            attempted += 1
            failures.append(
                {
                    "vault": vault,
                    "item": item,
                    "status": "failed",
                    "field_count": len(fields),
                }
            )
            break
    status = "completed" if not failures else "partial-failure"
    return _value_free_execution_report(
        status=status,
        item_count=len(plan_items),
        items=completed,
        failures=failures,
        attempted_count=attempted,
    )


# Descriptive aliases for callers that use the migration terminology.
plan_migration = plan_batch
execute_migration = execute_batch


def _read_protected_json(path: Path) -> Mapping[str, Any]:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or path.is_symlink() or info.st_nlink != 1:
        raise MigrationError("request must be a regular nonsymlink file")
    if stat.S_IMODE(info.st_mode) != 0o600:
        raise MigrationError("request must have mode 0600")
    document = strict_json_loads(path.read_text())
    if not isinstance(document, Mapping):
        raise MigrationError("request must be an object")
    return document


def _source_adapter_from_request(path: Path) -> ProtectedSourceAdapter:
    document = _read_protected_json(path)
    if set(document) != {"sources"} or not isinstance(document["sources"], Mapping):
        raise MigrationError("source request schema mismatch")
    sources = document["sources"]
    for authority, value in sources.items():
        if not isinstance(authority, str) or not authority or not isinstance(value, str):
            raise MigrationError("source request source is invalid")
    return MappingSourceAdapter(sources)


def _read_protected_secret(path: Path) -> str:
    """Read a source credential from a private, non-followed 0600 file."""
    try:
        info = path.lstat()
    except OSError as exc:
        raise MigrationError("source token file could not be read") from exc
    if not stat.S_ISREG(info.st_mode) or path.is_symlink() or info.st_nlink != 1:
        raise MigrationError("source token file must be a regular nonsymlink file")
    if stat.S_IMODE(info.st_mode) != 0o600:
        raise MigrationError("source token file must have mode 0600")
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise MigrationError("source token file could not be read") from exc
    if not raw or len(raw) > 64 * 1024:
        raise MigrationError("source token file is invalid")
    try:
        token = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise MigrationError("source token file is not UTF-8") from exc
    token = token.rstrip("\r\n")
    if not token or any(character in token for character in "\r\n\x00"):
        raise MigrationError("source token file is invalid")
    return token


def _source_adapter_from_options(
    args: argparse.Namespace,
    *,
    request: Path | None = None,
) -> ProtectedSourceAdapter:
    if request is not None:
        return _source_adapter_from_request(request)
    source_token_file = getattr(args, "source_token_file", None)
    source_session = bool(getattr(args, "source_session", False))
    if source_token_file is not None and source_session:
        raise MigrationError("source token file and source session are mutually exclusive")
    source_token = (
        _read_protected_secret(source_token_file)
        if source_token_file is not None
        else None
    )
    op_adapter = None
    if source_token is not None or source_session:
        op_adapter = OpSourceAdapter(
            op_bin=getattr(args, "source_op_bin", Path("/usr/local/bin/op")),
            source_token=source_token,
            source_session=source_session,
        )
    ssh_adapter = None
    ssh_bin = getattr(args, "source_ssh_bin", None)
    ssh_key = getattr(args, "source_ssh_key", None)
    if ssh_bin is not None or ssh_key is not None:
        ssh_adapter = DeployedSourceAdapter(
            ssh_bin=ssh_bin or Path("/usr/bin/ssh"),
            source_token=source_token,
            ssh_user=getattr(args, "source_ssh_user", None),
            ssh_key=ssh_key,
        )
    evidence_root = getattr(args, "evidence_root", None)
    evidence_adapter = EvidenceSourceAdapter(evidence_root) if evidence_root is not None else None
    if op_adapter is None and ssh_adapter is None and evidence_adapter is None:
        raise MigrationError("a protected source reader is required")
    return SourceOrchestrationAdapter(
        op_adapter=op_adapter,
        ssh_adapter=ssh_adapter,
        evidence_adapter=evidence_adapter,
    )


def _reject_value_bearing_metadata(value: Any) -> None:
    forbidden = ("value", "secret", "hash", "digest", "prefix", "length")
    if isinstance(value, Mapping):
        for key, child in value.items():
            if any(fragment in str(key).lower() for fragment in forbidden):
                raise MigrationError("metadata contains a value-derived field")
            _reject_value_bearing_metadata(child)
    elif isinstance(value, list):
        for child in value:
            _reject_value_bearing_metadata(child)


def _read_metadata_document(path: Path) -> Any:
    if path.is_symlink() or not path.is_file():
        raise MigrationError("metadata must be a regular file")
    try:
        with path.open("r", encoding="utf-8") as stream:
            document = yaml.safe_load(stream)
    except (OSError, yaml.YAMLError) as exc:
        raise MigrationError("metadata document is invalid") from exc
    _reject_value_bearing_metadata(document)
    return document


def _validate_migration_ledger(ledger: Any, plan: Mapping[str, Any]) -> None:
    if isinstance(ledger, list):
        records = ledger
    elif isinstance(ledger, Mapping) and isinstance(ledger.get("items"), list):
        records = ledger["items"]
    elif isinstance(ledger, Mapping) and isinstance(ledger.get("entries"), list):
        records = ledger["entries"]
    else:
        raise MigrationError("migration ledger records are invalid")
    expected = {
        (item["vault"], item["item"]): {
            field["label"]: field["type"] for field in item["fields"]
        }
        for item in plan["items"]
    }
    observed: set[tuple[str, str]] = set()
    for record in records:
        if not isinstance(record, Mapping):
            raise MigrationError("migration ledger record is invalid")
        vault = record.get("vault")
        title = record.get("item")
        if not isinstance(vault, str) or not isinstance(title, str):
            raise MigrationError("migration ledger target is invalid")
        target = (vault, title)
        if target in observed or target not in expected:
            raise MigrationError("migration ledger target mismatch")
        item_id = record.get("item_id")
        if not isinstance(item_id, str) or not item_id:
            raise MigrationError("migration ledger item ID is invalid")
        fields = record.get("fields")
        if isinstance(fields, list):
            field_types = {
                field.get("label"): field.get("type")
                for field in fields
                if isinstance(field, Mapping)
            }
        elif isinstance(fields, Mapping):
            field_types = dict(fields)
        else:
            raise MigrationError("migration ledger fields are invalid")
        if field_types != expected[target]:
            raise MigrationError("migration ledger field shape mismatch")
        observed.add(target)
    if observed != set(expected):
        raise MigrationError("migration ledger coverage mismatch")


def _compare_command(args: argparse.Namespace) -> int:
    request = _read_protected_json(args.request)
    if set(request) != {"left", "right"}:
        raise MigrationError("comparison request schema mismatch")
    status = classify_values(request["left"], request["right"])
    print(json.dumps({"status": status}, separators=(",", ":")))
    return 0


def _batch_input_from_stdin() -> Mapping[str, Any]:
    raw = sys.stdin.read(1024 * 1024 + 1)
    if len(raw) > 1024 * 1024:
        raise MigrationError("batch input is oversized")
    document = strict_json_loads(raw)
    if not isinstance(document, Mapping):
        raise MigrationError("batch input must be an object")
    if set(document) - {"token", "sources"} or "token" not in document:
        raise MigrationError("batch input schema mismatch")
    if not isinstance(document["token"], str) or not document["token"]:
        raise MigrationError("batch input token is invalid")
    sources = document.get("sources", {})
    if not isinstance(sources, Mapping):
        raise MigrationError("batch input sources are invalid")
    for authority, value in sources.items():
        if not isinstance(authority, str) or not isinstance(value, str):
            raise MigrationError("batch input source is invalid")
    return document


def _plan_batch_command(args: argparse.Namespace) -> int:
    source_adapter = (
        _source_adapter_from_options(args, request=args.request)
        if args.request is not None or args.source_token_file is not None or args.source_session
        else None
    )
    plan = plan_batch(registry_path=args.registry, source_adapter=source_adapter)
    print(json.dumps(plan, separators=(",", ":"), sort_keys=True))
    return 0


def _discover_command(args: argparse.Namespace) -> int:
    source_adapter = _source_adapter_from_options(args, request=args.request)
    report = discover_batch(registry_path=args.registry, source_adapter=source_adapter)
    print(json.dumps(report, separators=(",", ":"), sort_keys=True))
    return 0


def _verify_command(args: argparse.Namespace) -> int:
    source_adapter = (
        _source_adapter_from_options(args, request=args.request)
        if args.request is not None or args.source_token_file is not None or args.source_session
        else None
    )
    document = _registry_document(registry_path=args.registry, registry=None)
    selected = _eligible_entries(document)
    grouped = _validate_batch_entries(selected, source_adapter)
    plan = _value_free_plan(grouped, registry_path=args.registry)
    validate_batch_plan(plan)
    if args.ledger is not None:
        ledger = _read_metadata_document(args.ledger)
        _validate_migration_ledger(ledger, plan)
    report = {
        "status": "verified",
        "item_count": plan["item_count"],
        "field_count": plan["field_count"],
    }
    _reject_value_bearing_metadata(report)
    print(json.dumps(report, separators=(",", ":"), sort_keys=True))
    return 0


def _execute_batch_command(args: argparse.Namespace) -> int:
    input_document = _batch_input_from_stdin()
    sources = input_document.get("sources", {})
    if args.source_request is not None and sources:
        raise MigrationError("provide one protected source input")
    if args.source_request is not None:
        source_adapter = _source_adapter_from_request(args.source_request)
    elif sources:
        source_adapter: Any = MappingSourceAdapter(sources)
    else:
        source_adapter = _source_adapter_from_options(args)
    _assert_distinct_source_target_tokens(source_adapter, input_document["token"])
    plan = plan_batch(registry_path=args.registry, source_adapter=source_adapter)
    report = execute_batch(
        plan=plan,
        op_bin=args.op_bin,
        token=input_document["token"],
        source_adapter=source_adapter,
    )
    print(json.dumps(report, separators=(",", ":"), sort_keys=True))
    return 0 if report["status"] == "completed" else 1


def _secret_envelope_from_stdin() -> Mapping[str, Any]:
    raw = sys.stdin.read(1024 * 1024 + 1)
    if len(raw) > 1024 * 1024:
        raise MigrationError("secret envelope is oversized")
    document = strict_json_loads(raw)
    if not isinstance(document, Mapping):
        raise MigrationError("secret envelope must be an object")
    required = {
        "token",
        "vault",
        "coordinate",
        "title",
        "concealed_fields",
        "text_fields",
    }
    if set(document) != required:
        raise MigrationError("secret envelope schema mismatch")
    for key in ("token", "vault", "coordinate", "title"):
        if not isinstance(document[key], str) or not document[key]:
            raise MigrationError("secret envelope scalar is invalid")
    if not _ITEM_TITLE.fullmatch(document["title"]):
        raise MigrationError("item title is invalid")
    for collection in ("concealed_fields", "text_fields"):
        fields = document[collection]
        if not isinstance(fields, Mapping):
            raise MigrationError("secret envelope field map is invalid")
        for label, value in fields.items():
            if not isinstance(label, str) or not _FIELD_LABEL.fullmatch(label):
                raise MigrationError("secret envelope field label is invalid")
            if not isinstance(value, str):
                raise MigrationError("secret envelope field value is invalid")
    if not document["concealed_fields"]:
        raise MigrationError("secret envelope has no concealed fields")
    if set(document["concealed_fields"]) & set(document["text_fields"]):
        raise MigrationError("secret envelope field labels overlap")
    return document


def _registered_populate_target(
    *, document: Mapping[str, Any], request: Mapping[str, Any]
) -> Mapping[str, Any]:
    entries = document.get("entries")
    items = document.get("canonical_items")
    if not isinstance(entries, list) or not isinstance(items, list):
        raise MigrationError("canonical registry target data is invalid")
    matches = [
        entry
        for entry in entries
        if isinstance(entry, Mapping)
        and entry.get("coordinate") == request["coordinate"]
        and entry.get("disposition") in _ITEM_DISPOSITIONS
    ]
    if len(matches) != 1:
        raise MigrationError("populate target is not declared in the canonical registry")
    entry = matches[0]
    # Target declaration validation must not read a source authority.  The
    # protected empty adapter merely permits non-op authorities here; source
    # material is supplied separately by the caller's stdin envelope.
    vault, item, _field = _validate_target_entry(
        entry, source_adapter=MappingSourceAdapter({})
    )
    if request["vault"] != vault or request["title"] != item:
        raise MigrationError("populate target does not match the canonical registry")
    canonical_matches = [
        candidate
        for candidate in items
        if isinstance(candidate, Mapping)
        and candidate.get("id") == item
        and candidate.get("vault") == vault
    ]
    if len(canonical_matches) != 1:
        raise MigrationError("populate target item is not declared in the canonical registry")
    requested_labels = set(request["concealed_fields"]) | set(request["text_fields"])
    item_entries = [
        candidate
        for candidate in entries
        if isinstance(candidate, Mapping)
        and candidate.get("disposition") in _ITEM_DISPOSITIONS
        and candidate.get("canonical_vault") == vault
        and candidate.get("canonical_item") == item
    ]
    declared: dict[str, str] = {}
    for candidate in item_entries:
        label = candidate.get("canonical_field")
        if not isinstance(label, str) or not label:
            raise MigrationError("canonical registry item field is invalid")
        expected = _entry_field_type(candidate)
        prior = declared.get(label)
        if prior is not None and prior != expected:
            raise MigrationError("canonical registry item has conflicting field types")
        declared[label] = expected
    if not declared or requested_labels != set(declared):
        raise MigrationError("populate requires the exact complete item field set")
    actual = {
        **{label: "CONCEALED" for label in request["concealed_fields"]},
        **{label: "STRING" for label in request["text_fields"]},
    }
    if actual != declared:
        raise MigrationError("populate field type partition does not match the canonical registry")
    return entry


def _populate_command(args: argparse.Namespace) -> int:
    request = _secret_envelope_from_stdin()
    document = _registry_document(registry_path=args.registry, registry=None)
    _registered_populate_target(document=document, request=request)
    status = populate_item(
        op_bin=args.op_bin,
        token=request["token"],
        expected_vault=request["vault"],
        coordinate=request["coordinate"],
        title=request["title"],
        concealed_fields=request["concealed_fields"],
        text_fields=request["text_fields"],
    )
    print(json.dumps(status, separators=(",", ":"), sort_keys=True))
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    def add_source_options(command: argparse.ArgumentParser) -> None:
        command.add_argument(
            "--source-token-file",
            type=Path,
            help="0600 nonsymlink file containing the source-reader credential",
        )
        command.add_argument(
            "--source-session",
            action="store_true",
            help="explicitly use the authenticated local 1Password session",
        )
        command.add_argument("--source-op-bin", type=Path, default=Path("/usr/local/bin/op"))
        command.add_argument("--source-ssh-bin", type=Path)
        command.add_argument("--source-ssh-key", type=Path)
        command.add_argument("--source-ssh-user")
        command.add_argument("--evidence-root", type=Path)

    compare = commands.add_parser("compare", help="classify two in-memory values")
    compare.add_argument("--request", type=Path, required=True)
    compare.set_defaults(handler=_compare_command)
    plan = commands.add_parser(
        "plan", aliases=["batch-plan"], help="plan grouped canonical item writes"
    )
    plan.add_argument("--registry", type=Path, required=True)
    plan.add_argument("--request", type=Path)
    add_source_options(plan)
    plan.set_defaults(handler=_plan_batch_command)
    discover = commands.add_parser("discover", help="discover approved sources through a protected request")
    discover.add_argument("--registry", type=Path, required=True)
    discover.add_argument("--request", type=Path)
    add_source_options(discover)
    discover.set_defaults(handler=_discover_command)
    execute = commands.add_parser(
        "execute", aliases=["batch-execute"], help="execute a grouped canonical item plan"
    )
    execute.add_argument("--registry", type=Path, required=True)
    execute.add_argument("--op-bin", type=Path, default=Path("/usr/local/bin/op"))
    execute.add_argument("--source-request", type=Path)
    add_source_options(execute)
    execute.set_defaults(handler=_execute_batch_command)
    verify = commands.add_parser("verify", help="verify registry and migration metadata without values")
    verify.add_argument("--registry", type=Path, required=True)
    verify.add_argument("--ledger", type=Path)
    verify.add_argument("--request", type=Path)
    add_source_options(verify)
    verify.set_defaults(handler=_verify_command)
    populate = commands.add_parser("populate", help="create or update one canonical item")
    populate.add_argument("--op-bin", type=Path, default=Path("/usr/local/bin/op"))
    populate.add_argument("--registry", type=Path, required=True)
    populate.set_defaults(handler=_populate_command)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    try:
        args = _parser().parse_args(argv)
        return args.handler(args)
    except (MigrationError, OSError) as exc:
        print(f"credential migration refused: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
