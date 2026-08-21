#!/usr/bin/env python3
"""Consolidate 1Password items without disclosing secret values."""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence

_CANONICAL_LIB = Path(__file__).resolve().parent / "lib"
if str(_CANONICAL_LIB) not in sys.path:
    sys.path.insert(0, str(_CANONICAL_LIB))

from canonical_credentials import load_registry  # noqa: E402


class MigrationError(ValueError):
    """A fail-closed migration contract violation."""


class ProtectedSourceAdapter:
    """In-process source reader; implementations must keep values private."""

    protected = True

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
    """Read a source 1Password field without exposing its value to the caller."""

    def __init__(
        self,
        *,
        op_bin: Path,
        token: str,
        extra_env: Mapping[str, str] | None = None,
    ):
        self.op_bin = op_bin
        self.token = token
        self.extra_env = extra_env

    def resolve(self, authority: str) -> str:
        vault, item, field = _parse_op_authority(authority)
        result = run_op_json(
            op_bin=self.op_bin,
            argv=["item", "get", item, "--vault", vault, "--format=json"],
            token=self.token,
            extra_env=self.extra_env,
        )
        if not isinstance(result, Mapping) or not isinstance(result.get("fields"), list):
            raise MigrationError("source item response is invalid")
        matches = [
            candidate
            for candidate in result["fields"]
            if candidate.get("label") == field or candidate.get("id") == field
        ]
        if len(matches) != 1 or not isinstance(matches[0].get("value"), str):
            raise MigrationError("source field is not uniquely readable")
        return matches[0]["value"]


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


def _minimal_env(token: str, extra_env: Mapping[str, str] | None = None) -> dict[str, str]:
    if not isinstance(token, str) or not token or "\n" in token or len(token) > 4096:
        raise MigrationError("service-account token is invalid")
    env = {
        "HOME": "/nonexistent",
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


def run_op_json(
    *,
    op_bin: Path,
    argv: Sequence[str],
    token: str,
    stdin_document: Mapping[str, Any] | None = None,
    extra_env: Mapping[str, str] | None = None,
) -> Any:
    if not op_bin.is_file() or op_bin.is_symlink() or not os.access(op_bin, os.X_OK):
        raise MigrationError("1Password executable is unsafe")
    if any(not isinstance(argument, str) or "\n" in argument for argument in argv):
        raise MigrationError("1Password argument is invalid")
    payload = "" if stdin_document is None else json.dumps(stdin_document, separators=(",", ":"))
    completed = subprocess.run(
        [str(op_bin), *argv],
        input=payload,
        text=True,
        capture_output=True,
        check=False,
        env=_minimal_env(token, extra_env),
    )
    payload = ""
    if completed.returncode != 0:
        raise MigrationError("1Password command failed")
    return strict_json_loads(completed.stdout)


def validate_service_account_scope(
    identity: Mapping[str, Any], vaults: Sequence[Mapping[str, Any]], expected_vault: str
) -> None:
    if str(identity.get("type", "")).upper() != "SERVICE_ACCOUNT":
        raise MigrationError("identity is not a service account")
    if len(vaults) != 1 or vaults[0].get("name") != expected_vault:
        raise MigrationError("service account must see exactly one vault")
    if not isinstance(vaults[0].get("id"), str) or not vaults[0]["id"]:
        raise MigrationError("service account vault ID is invalid")


def populate_item(
    *,
    op_bin: Path,
    token: str,
    expected_vault: str,
    coordinate: str,
    title: str,
    concealed_fields: Mapping[str, str],
    text_fields: Mapping[str, str],
    extra_env: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    identity = run_op_json(
        op_bin=op_bin,
        argv=["whoami", "--format=json"],
        token=token,
        extra_env=extra_env,
    )
    vaults = run_op_json(
        op_bin=op_bin,
        argv=["vault", "list", "--format=json"],
        token=token,
        extra_env=extra_env,
    )
    if not isinstance(identity, Mapping) or not isinstance(vaults, list):
        raise MigrationError("service-account scope response is invalid")
    validate_service_account_scope(identity, vaults, expected_vault)
    vault_id = vaults[0]["id"]

    items = run_op_json(
        op_bin=op_bin,
        argv=["item", "list", "--vault", expected_vault, "--format=json"],
        token=token,
        extra_env=extra_env,
    )
    if not isinstance(items, list):
        raise MigrationError("item listing is invalid")
    matches = [item for item in items if item.get("title") == title]
    if len(matches) > 1:
        raise MigrationError("duplicate item title")

    template = build_item_template(
        title=title,
        fields=concealed_fields,
        text_fields=text_fields,
    )
    if matches:
        item_id = matches[0].get("id")
        if not isinstance(item_id, str) or not item_id:
            raise MigrationError("existing item ID is invalid")
        written = run_op_json(
            op_bin=op_bin,
            argv=["item", "edit", item_id, "--vault", expected_vault],
            token=token,
            stdin_document=template,
            extra_env=extra_env,
        )
    else:
        written = run_op_json(
            op_bin=op_bin,
            argv=["item", "create", "--vault", expected_vault, "-"],
            token=token,
            stdin_document=template,
            extra_env=extra_env,
        )
    if not isinstance(written, Mapping) or not isinstance(written.get("id"), str):
        raise MigrationError("item write response is invalid")
    item_id = written["id"]
    readback = run_op_json(
        op_bin=op_bin,
        argv=["item", "get", item_id, "--vault", expected_vault, "--format=json"],
        token=token,
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
    )


def verify_item_shape(
    *,
    coordinate: str,
    item: Mapping[str, Any],
    expected_vault_id: str,
    expected_title: str,
    expected_fields: Mapping[str, str],
) -> dict[str, Any]:
    if item.get("title") != expected_title or item.get("vault", {}).get("id") != expected_vault_id:
        raise MigrationError("item authority mismatch")
    item_id = item.get("id")
    if not isinstance(item_id, str) or not item_id:
        raise MigrationError("item ID is invalid")
    observed: dict[str, str] = {}
    for field in item.get("fields", []):
        label = field.get("label")
        field_type = field.get("type")
        if label in expected_fields:
            if label in observed:
                raise MigrationError("duplicate field")
            observed[label] = field_type
        elif field.get("purpose") not in {"NOTES"}:
            raise MigrationError(f"unexpected field: {label}")
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
_FIELD_LABEL = re.compile(r"^[A-Z][A-Z0-9_]{0,127}$")
_ITEM_TITLE = re.compile(r"^[a-z0-9][a-z0-9-]{0,126}[a-z0-9]$|^[a-z0-9]$")


def _parse_op_authority(authority: str) -> tuple[str, str, str]:
    if not isinstance(authority, str) or not authority.startswith(_OP_AUTHORITY_SCHEMES):
        raise MigrationError("source authority is not an op reference")
    _, remainder = authority.split("://", 1)
    if "#" in remainder:
        path, field = remainder.rsplit("#", 1)
    else:
        path, field = remainder.rsplit("/", 1)
    parts = path.split("/", 1)
    if len(parts) != 2 or not all(parts) or not field:
        raise MigrationError("source authority is structurally invalid")
    if any(character.isspace() for character in authority):
        raise MigrationError("source authority is structurally invalid")
    return parts[0], parts[1], field


def _is_op_authority(authority: Any) -> bool:
    if not isinstance(authority, str) or not authority.startswith(_OP_AUTHORITY_SCHEMES):
        return False
    try:
        _parse_op_authority(authority)
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
    return value


def _registry_document(
    *, registry_path: str | Path | None, registry: Mapping[str, Any] | None
) -> Mapping[str, Any]:
    if (registry_path is None) == (registry is None):
        raise MigrationError("provide exactly one canonical registry")
    if registry_path is not None:
        return load_registry(registry_path)
    if not isinstance(registry, Mapping):
        raise MigrationError("canonical registry is invalid")
    # Re-run the same strict validator for callers that already parsed a document.
    return load_registry_from_document(registry)


def load_registry_from_document(document: Mapping[str, Any]) -> Mapping[str, Any]:
    """Validate an already parsed registry with the canonical registry loader."""
    from canonical_credentials import validate_registry

    return validate_registry(document)


def _eligible_entries(document: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    entries = document.get("entries")
    if not isinstance(entries, list):
        raise MigrationError("canonical registry entries are invalid")
    selected: list[Mapping[str, Any]] = []
    for entry in entries:
        if not isinstance(entry, Mapping):
            raise MigrationError("canonical registry entry is invalid")
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
    return vault, item, field


def _validate_batch_entries(
    entries: Sequence[Mapping[str, Any]], source_adapter: Any | None
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
        grouped.setdefault((vault, item), []).append(entry)

    for _target, matches in target_sources.items():
        if len(matches) < 2:
            continue
        sources = {entry["source_authority"] for entry in matches}
        if len(sources) > 1:
            if source_adapter is not None:
                values = [_resolve_source(source_adapter, source) for source in sorted(sources)]
                if len(set(values)) > 1:
                    raise MigrationError("conflicting values for duplicate target field")
            raise MigrationError("duplicate target field with different sources")
        raise MigrationError("duplicate target field")
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
                "type": "CONCEALED",
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
                or field.get("type") != "CONCEALED"
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
    token: str,
    source_adapter: Any,
    extra_env: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Execute each planned item through the existing stdin-only population path."""
    validate_batch_plan(plan)
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
        try:
            for field in fields:
                if not isinstance(field, Mapping):
                    raise MigrationError("batch plan field is invalid")
                label = field.get("label")
                authority = field.get("source_authority")
                coordinate = field.get("coordinate")
                if (
                    not isinstance(label, str)
                    or not _FIELD_LABEL.fullmatch(label)
                    or not isinstance(authority, str)
                    or not isinstance(coordinate, str)
                ):
                    raise MigrationError("batch plan field is invalid")
                concealed[label] = _resolve_source(source_adapter, authority)
            attempted += 1
            status = populate_item(
                op_bin=op_bin,
                token=token,
                expected_vault=vault,
                coordinate=f"{vault}|{item}",
                title=item,
                concealed_fields=concealed,
                text_fields={},
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
    plan = plan_batch(registry_path=args.registry)
    print(json.dumps(plan, separators=(",", ":"), sort_keys=True))
    return 0


def _execute_batch_command(args: argparse.Namespace) -> int:
    input_document = _batch_input_from_stdin()
    sources = input_document.get("sources", {})
    if sources:
        source_adapter: Any = MappingSourceAdapter(sources)
    else:
        source_adapter = OpSourceAdapter(
            op_bin=args.op_bin,
            token=input_document["token"],
        )
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


def _populate_command(args: argparse.Namespace) -> int:
    request = _secret_envelope_from_stdin()
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
    compare = commands.add_parser("compare", help="classify two in-memory values")
    compare.add_argument("--request", type=Path, required=True)
    compare.set_defaults(handler=_compare_command)
    plan = commands.add_parser(
        "plan", aliases=["batch-plan"], help="plan grouped canonical item writes"
    )
    plan.add_argument("--registry", type=Path, required=True)
    plan.set_defaults(handler=_plan_batch_command)
    execute = commands.add_parser(
        "execute", aliases=["batch-execute"], help="execute a grouped canonical item plan"
    )
    execute.add_argument("--registry", type=Path, required=True)
    execute.add_argument("--op-bin", type=Path, default=Path("/usr/local/bin/op"))
    execute.set_defaults(handler=_execute_batch_command)
    populate = commands.add_parser("populate", help="create or update one canonical item")
    populate.add_argument("--op-bin", type=Path, default=Path("/usr/local/bin/op"))
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
