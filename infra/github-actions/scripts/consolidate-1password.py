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


class MigrationError(ValueError):
    """A fail-closed migration contract violation."""


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


_FIELD_LABEL = re.compile(r"^[A-Z][A-Z0-9_]{0,127}$")
_ITEM_TITLE = re.compile(r"^[a-z0-9][a-z0-9-]{0,126}[a-z0-9]$|^[a-z0-9]$")


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
