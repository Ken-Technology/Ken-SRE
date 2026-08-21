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
import hashlib
import importlib.util
import json
import os
import secrets
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
GENERATION_PROFILES = frozenset(
    {
        "opaque-token",
        "ken-agents-internal-key",
        "mcp-smoke-token",
        "oauth2-cookie-secret",
        "next-server-actions-key",
        "ed25519-private-key",
        "ssh-ed25519",
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
        personal_vault: str = "Employee",
        token_items: Mapping[str, str],
        extra_env: Mapping[str, str] | None = None,
    ):
        if not isinstance(personal_vault, str) or not personal_vault or personal_vault in TARGET_VAULTS:
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
        self.token_items = dict(token_items)
        self.extra_env = extra_env
        if set(self.token_items) != TARGET_VAULTS:
            raise MigrationError("personal writer source requires exactly three target vault items")
        for item_id in self.token_items.values():
            if not isinstance(item_id, str) or not item_id or any(c in item_id for c in "\r\n\x00"):
                raise MigrationError("personal writer token item ID is invalid")

    def load(self) -> dict[str, str]:
        tokens: dict[str, str] = {}
        for vault in sorted(TARGET_VAULTS):
            item_id = self.token_items[vault]
            argv = ["item", "get", item_id, "--vault", self.personal_vault, "--format=json"]
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
            if isinstance(response, Mapping) and response.get("id") not in {None, item_id}:
                raise MigrationError("personal token item ID mismatch")
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
    environment = dict(os.environ)
    service_account_env = "OP_" + "SERVICE_ACCOUNT_TOKEN"
    environment.pop(service_account_env, None)
    for key, value in (extra_env or {}).items():
        if not isinstance(key, str) or not isinstance(value, str) or key == service_account_env:
            raise MigrationError("personal session environment is invalid")
        environment[key] = value
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
    if document["status"] not in {"complete", "blocked"} or not isinstance(document["ready"], bool):
        raise MigrationError("ledger status is invalid")
    counts = document["counts"]
    if not isinstance(counts, Mapping) or set(counts) != {"selected", "populated", "blocked"}:
        raise MigrationError("ledger counts are invalid")
    if any(not isinstance(counts[key], int) or isinstance(counts[key], bool) or counts[key] < 0 for key in counts):
        raise MigrationError("ledger counts are invalid")
    if document["status"] == "complete" and document["ready"] is not True:
        raise MigrationError("complete ledger must be ready")
    if document["status"] == "blocked" and document["ready"] is not False:
        raise MigrationError("blocked ledger cannot claim readiness")
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
    if path.is_symlink() or not parent.is_dir() or parent.is_symlink():
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


def _write_registration_artifact(path: Path, entries: Sequence[Mapping[str, str]]) -> None:
    if path.is_symlink() or path.parent.is_symlink() or not path.parent.is_dir():
        raise MigrationError("registration artifact path is unsafe")
    document = {"schema_version": 1, "entries": list(entries)}
    _validate_value_free_document(document)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(fd, stat.S_IRUSR | stat.S_IWUSR)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(document, stream, sort_keys=True, separators=(",", ":"))
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except Exception:
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
    selected, blocked = _selected_entries(document, known_only=known_only)
    writer_tokens = writer_source.load()
    _validate_writer_tokens(writer_tokens)
    _validate_writer_scopes(op_bin=op_bin, writer_tokens=writer_tokens, extra_env=extra_env)
    if _source_token_set(source_adapter) & set(writer_tokens.values()):
        raise MigrationError("source and target writer tokens must be distinct")
    grouped = _resolve_targets(selected, source_adapter) if selected else {}
    items: list[dict[str, Any]] = []
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
    ready = not blocked
    result = {
        "status": "complete" if ready else "blocked",
        "ready": ready,
        "counts": {"selected": len(selected), "populated": len(items), "blocked": len(blocked)},
        "items": items,
        "blocked": blocked,
    }
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


def _allowlist(path: Path) -> tuple[set[str], set[str]]:
    document = _load_yaml(path)
    if isinstance(document, list):
        return {str(value) for value in document}, set()
    if not isinstance(document, Mapping):
        raise MigrationError("generation allowlist is invalid")
    coordinates = document.get("coordinates", document.get("approved_coordinates", []))
    profiles = document.get("profiles", document.get("approved_profiles", []))
    if not isinstance(coordinates, list) or not isinstance(profiles, list):
        raise MigrationError("generation allowlist lists are invalid")
    if any(not isinstance(value, str) or not value for value in [*coordinates, *profiles]):
        raise MigrationError("generation allowlist entry is invalid")
    return set(coordinates), set(profiles)


def _source_adapter_from_cli(args: argparse.Namespace) -> Any:
    source_token = None
    source_token_file = getattr(args, "source_token_file", None)
    if source_token_file is not None:
        source_token = _read_protected_token(source_token_file)
    op_adapter = None
    if source_token is not None:
        op_adapter = OpSourceAdapter(
            op_bin=args.source_op_bin,
            source_token=source_token,
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
        return "ed25519-private-key"
    if field == "KEN_AGENTS_INTERNAL_KEY":
        return "ken-agents-internal-key"
    if field == "MCP_SMOKE_TOKEN":
        return "mcp-smoke-token"
    return "opaque-token"


def _generate_secret(row: Mapping[str, Any]) -> tuple[str, str | None]:
    profile = _generation_profile(row)
    if profile in {"ssh-ed25519", "ed25519-private-key"}:
        return _ed25519_keypair()
    if profile == "oauth2-cookie-secret":
        return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii").rstrip("="), None
    if profile == "next-server-actions-key":
        return base64.b64encode(secrets.token_bytes(32)).decode("ascii"), None
    if profile == "ken-agents-internal-key":
        return secrets.token_hex(32), None
    if profile in {"mcp-smoke-token", "opaque-token"}:
        return secrets.token_urlsafe(32), None
    raise MigrationError("generation profile is not approved")


def _ed25519_keypair() -> tuple[str, str]:
    # RFC 8032 scalar multiplication, keeping all key material in memory.
    q = 2**255 - 19
    d = (-121665 * pow(121666, q - 2, q)) % q
    seed = secrets.token_bytes(32)
    digest = hashlib.sha512(seed).digest()
    scalar = int.from_bytes(digest[:32], "little")
    scalar &= (1 << 254) - 8
    scalar |= 1 << 254
    by = 4 * pow(5, q - 2, q) % q
    bx = pow((by * by - 1) * pow(d * by * by + 1, q - 2, q), (q + 3) // 8, q)
    if (bx * bx - (by * by - 1) * pow(d * by * by + 1, q - 2, q)) % q:
        bx = (bx * pow(2, (q - 1) // 4, q)) % q
    if bx & 1:
        bx = q - bx
    point = (0, 1, 1, 0)
    base = (bx, by, 1, (bx * by) % q)
    def add(p, r):
        x1, y1, z1, t1 = p
        x2, y2, z2, t2 = r
        a = (y1 - x1) * (y2 - x2) % q
        b = (y1 + x1) * (y2 + x2) % q
        c = 2 * d * t1 * t2 % q
        dd = 2 * z1 * z2 % q
        e, f, g, h = (b - a) % q, (dd - c) % q, (dd + c) % q, (b + a) % q
        return (e * f % q, g * h % q, f * g % q, e * h % q)
    n = scalar
    while n:
        if n & 1:
            point = add(point, base)
        base = add(base, base)
        n >>= 1
    x, y, z, _ = point
    zi = pow(z, q - 2, q)
    x, y = x * zi % q, y * zi % q
    public = y.to_bytes(32, "little")
    public = bytearray(public)
    public[31] |= (x & 1) << 7
    public_bytes = bytes(public)
    def blob(value: bytes) -> bytes:
        return len(value).to_bytes(4, "big") + value
    public_blob = blob(b"ssh-ed25519") + blob(public_bytes)
    check = secrets.randbits(32).to_bytes(4, "big")
    private_block = check + check + blob(b"ssh-ed25519") + blob(public_bytes) + blob(seed + public_bytes) + blob(b"")
    pad = (8 - len(private_block) % 8) % 8 or 8
    private_block += bytes(range(1, pad + 1))
    raw = b"openssh-key-v1\0" + blob(b"none") + blob(b"none") + blob(b"") + (1).to_bytes(4, "big") + blob(public_blob) + blob(private_block)
    private = "-----BEGIN " + "OPENSSH PRIVATE KEY-----\n" + "\n".join(
        base64.b64encode(raw).decode("ascii")[offset : offset + 70] for offset in range(0, len(base64.b64encode(raw)), 70)
    ) + "\n-----END OPENSSH PRIVATE KEY-----\n"
    public_text = "ssh-ed25519 " + base64.b64encode(public_blob).decode("ascii") + " ken-generated\n"
    return private, public_text


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
    allowed_coordinates, allowed_profiles = _allowlist(allowlist_path)
    generation_rows = [
        row for row in rows if isinstance(row, Mapping) and row.get("action") in GENERATION_ACTIONS
    ]
    approved_coordinates = {
        row["coordinate"]
        for row in generation_rows
        if isinstance(row.get("coordinate"), str) and row["coordinate"]
    }
    approved_profiles = set().union(*(_row_profiles(row) for row in generation_rows)) if generation_rows else set()
    if not allowed_coordinates <= approved_coordinates:
        raise MigrationError("generation allowlist contains an unapproved coordinate")
    if not allowed_profiles <= approved_profiles:
        raise MigrationError("generation allowlist contains an unapproved profile")
    selected: list[Mapping[str, Any]] = []
    blocked: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, Mapping) or row.get("action") not in GENERATION_ACTIONS:
            continue
        coordinate = row.get("coordinate")
        if not isinstance(coordinate, str) or not coordinate:
            raise MigrationError("generation coordinate is invalid")
        if coordinate in allowed_coordinates or _row_profiles(row) & allowed_profiles:
            selected.append(row)
        else:
            blocked.append({"coordinate": coordinate, "status": "not-allowlisted"})
    writer_tokens = writer_source.load()
    _validate_writer_tokens(writer_tokens)
    _validate_writer_scopes(op_bin=op_bin, writer_tokens=writer_tokens, extra_env=extra_env)
    grouped: dict[tuple[str, str], dict[str, tuple[str, str, str, str | None]]] = {}
    registrations: list[dict[str, str]] = []
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
                registrations.append({"coordinate": row["coordinate"], "public_key": public.rstrip("\n")})
        elif prior[0] != action or prior[1] != profile:
            raise MigrationError("generation target has conflicting actions")
    if registrations:
        if registration_artifact is None:
            raise MigrationError("SSH generation requires a protected registration artifact")
        _write_registration_artifact(registration_artifact, registrations)
    items: list[dict[str, Any]] = []
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
    result = {
        "status": "complete" if not blocked else "blocked",
        "ready": not blocked,
        "counts": {"selected": len(selected), "populated": len(items), "blocked": len(blocked)},
        "items": items,
        "blocked": blocked,
    }
    write_value_free_ledger(ledger_path, result)
    return result


def _read_protected_token(path: Path) -> str:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or path.is_symlink() or stat.S_IMODE(info.st_mode) != 0o600:
        raise MigrationError("token file must be a regular mode-0600 file")
    token = path.read_text(encoding="utf-8")
    if token.endswith("\n"):
        token = token[:-1]
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
