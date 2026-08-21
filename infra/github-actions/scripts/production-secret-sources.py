#!/usr/bin/env python3
"""Resolve the approved production secret authorities in protected memory.

The source map is deliberately value-free.  It describes authority ownership;
this module reads the authority only when a mapped coordinate is selected and
returns the resulting value to the existing in-process migration writer.
"""

from __future__ import annotations

import base64
import copy
import importlib.util
import os
import re
import stat
import subprocess
from pathlib import Path
from typing import Any, Callable, Mapping
from urllib.parse import quote, unquote, urlsplit

import yaml


_MIGRATION_PATH = Path(__file__).resolve().with_name("consolidate-1password.py")
_SPEC = importlib.util.spec_from_file_location("consolidate_onepassword", _MIGRATION_PATH)
if _SPEC is None or _SPEC.loader is None:  # pragma: no cover
    raise RuntimeError("migration module could not be loaded")
_MIGRATION = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_MIGRATION)
MigrationError = _MIGRATION.MigrationError

SOURCE_PREFIX = "ken-production://"
MAPPED_GROUPS_KEY = "mapped_groups"
_COORDINATE_RE = re.compile(r"^[^|\r\n]+\|[^|\r\n]+\|[^|\r\n]+$")
_LOCATOR_RE = re.compile(r"^(?:[^>]+->\s*)?([A-Za-z0-9_.:-]+):(/[^\r\n]+)$")
_ENV_KEY_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def authority_for_coordinate(coordinate: str) -> str:
    if not isinstance(coordinate, str) or not _COORDINATE_RE.fullmatch(coordinate):
        raise ValueError("coordinate is invalid")
    repository, field, environment = coordinate.split("|", 2)
    return SOURCE_PREFIX + "/".join(
        quote(part, safe="") for part in (repository, field, environment)
    )


def coordinate_from_authority(authority: str) -> str:
    if not isinstance(authority, str) or not authority.startswith(SOURCE_PREFIX):
        raise ValueError("production authority is invalid")
    parts = authority[len(SOURCE_PREFIX) :].split("/")
    if len(parts) != 3 or any(not part for part in parts):
        raise ValueError("production authority is invalid")
    coordinate = "|".join(unquote(part) for part in parts)
    if authority_for_coordinate(coordinate) != authority:
        raise ValueError("production authority is not canonical")
    return coordinate


def _safe_source_map(path: Path) -> Mapping[str, Any]:
    try:
        info = path.lstat()
    except OSError as exc:
        raise ValueError("source map could not be read") from exc
    if not stat.S_ISREG(info.st_mode) or path.is_symlink() or stat.S_IMODE(info.st_mode) != 0o600:
        raise ValueError("source map must be a regular mode-0600 file")
    try:
        with path.open("r", encoding="utf-8") as stream:
            document = yaml.safe_load(stream)
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise ValueError("source map is invalid") from exc
    if not isinstance(document, Mapping):
        raise ValueError("source map is invalid")
    return document


class ProductionSourceMap:
    """Validated, value-free authority metadata for one population run."""

    def __init__(self, document: Mapping[str, Any]):
        self.document = copy.deepcopy(dict(document))
        groups = document.get(MAPPED_GROUPS_KEY)
        if not isinstance(groups, list):
            raise ValueError("source map mapped groups are invalid")
        coordinates: dict[str, Mapping[str, Any]] = {}
        for group in groups:
            if not isinstance(group, Mapping) or group.get("status") != "mapped":
                raise ValueError("source map must contain mapped groups only")
            rows = group.get("coordinates")
            authority = group.get("authority")
            if not isinstance(rows, list) or not rows or not isinstance(authority, Mapping):
                raise ValueError("source map mapped group is invalid")
            kind = authority.get("kind")
            if not isinstance(kind, str) or not kind:
                raise ValueError("source map authority kind is invalid")
            for coordinate in rows:
                if not isinstance(coordinate, str) or not _COORDINATE_RE.fullmatch(coordinate):
                    raise ValueError("source map coordinate is invalid")
                if coordinate in coordinates:
                    raise ValueError("source map coordinate is duplicated")
                if coordinate.split("|", 2)[2] != "Ken Deploy Production":
                    raise ValueError("source map environment is not production")
                coordinates[coordinate] = group
        if len(coordinates) != 18:
            raise ValueError("source map must contain exactly 18 mapped coordinates")
        if document.get("schema_version") != 1:
            raise ValueError("source map schema version is invalid")
        policy = document.get("policy")
        if not isinstance(policy, Mapping) or policy.get("value_free") is not True:
            raise ValueError("source map value-free policy is invalid")
        self.coordinates = frozenset(coordinates)
        self._groups = coordinates

    @classmethod
    def load(cls, path: Path) -> "ProductionSourceMap":
        return cls(_safe_source_map(path))

    def group_for(self, coordinate: str) -> Mapping[str, Any]:
        try:
            return self._groups[coordinate]
        except KeyError as exc:
            raise ValueError("coordinate is not mapped") from exc


def _parse_locator(locator: Any) -> tuple[str, str]:
    if not isinstance(locator, str):
        raise MigrationError("source locator is invalid")
    match = _LOCATOR_RE.fullmatch(locator)
    if not match:
        raise MigrationError("source locator is invalid")
    return match.group(1), match.group(2)


def _parse_env(raw: bytes) -> dict[str, str]:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise MigrationError("source environment is not UTF-8") from exc
    values: dict[str, str] = {}
    for line in text.splitlines():
        if not line or line.lstrip().startswith("#"):
            continue
        if line.startswith("export ") or "=" not in line:
            raise MigrationError("source environment syntax is invalid")
        key, value = line.split("=", 1)
        if not _ENV_KEY_RE.fullmatch(key) or key in values:
            raise MigrationError("source environment syntax is invalid")
        values[key] = value
    return values


def _connection_uri_component(raw: str, component: str) -> str:
    if not isinstance(raw, str) or not raw or any(c in raw for c in "\r\n"):
        raise MigrationError("connection URI is invalid")
    try:
        parsed = urlsplit(raw)
    except ValueError as exc:
        raise MigrationError("connection URI is invalid") from exc
    if parsed.scheme not in {"postgres", "postgresql", "mysql", "mariadb"} or not parsed.hostname:
        raise MigrationError("connection URI is invalid")
    if component == "database":
        value = parsed.path[1:]
    elif component == "user":
        value = parsed.username
    elif component == "password":
        value = parsed.password
    else:
        raise MigrationError("connection URI component is invalid")
    if not isinstance(value, str) or not value:
        raise MigrationError("connection URI component is missing")
    return unquote(value)


def _default_fingerprint(raw: bytes) -> str:
    """Derive the consumer's SHA-256 certificate fingerprint in memory."""
    openssl = Path("/usr/bin/openssl")
    if openssl.is_symlink() or not openssl.is_file() or not os.access(openssl, os.X_OK):
        raise MigrationError("openssl executable is unsafe")
    completed = subprocess.run(
        [str(openssl), "x509", "-fingerprint", "-sha256", "-noout"],
        input=raw,
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        raise MigrationError("certificate fingerprint derivation failed")
    match = re.search(rb"Fingerprint=([0-9A-Fa-f:]+)", completed.stdout)
    if match is None:
        raise MigrationError("certificate fingerprint derivation failed")
    return match.group(1).decode("ascii").replace(":", "").upper()


class ProductionSourceAdapter:
    """Resolve only coordinates declared as mapped in ``ProductionSourceMap``."""

    protected = True
    source_token = None

    def __init__(
        self,
        source_map: ProductionSourceMap,
        *,
        read_file: Callable[[str, str], bytes],
        read_item: Callable[[str, str], Mapping[str, Any]],
        fingerprint: Callable[[bytes], str] = _default_fingerprint,
    ):
        self.source_map = source_map
        self._read_file = read_file
        self._read_item = read_item
        self._fingerprint = fingerprint

    def resolve(self, authority: str) -> str:
        coordinate = coordinate_from_authority(authority)
        group = self.source_map.group_for(coordinate)
        value = self._resolve_group(coordinate, group)
        if not isinstance(value, str) or not value:
            raise MigrationError("production authority returned an empty value")
        return value

    def _resolve_group(self, coordinate: str, group: Mapping[str, Any]) -> str:
        authority = group["authority"]
        kind = authority["kind"]
        if kind == "server_endpoint_metadata":
            component = str(authority.get("component", ""))
            match = re.search(r"\bport\s+(\d+)\b", component)
            if match is None:
                raise MigrationError("endpoint metadata component is ambiguous")
            return match.group(1)
        if kind == "active_frontend_deployment_metadata":
            components = authority.get("components")
            if not isinstance(components, Mapping):
                raise MigrationError("deployment metadata components are invalid")
            field = coordinate.split("|", 2)[1]
            mapping = {"DEPLOY_HOST": "host", "DEPLOY_PATH": "path", "DEPLOY_USER": "user"}
            value = components.get(mapping.get(field, ""))
            if not isinstance(value, str) or not value:
                raise MigrationError("deployment metadata component is ambiguous")
            return value
        if kind == "onepassword_secure_note_component":
            item = authority.get("item")
            vault = authority.get("vault")
            if not isinstance(vault, str) or not isinstance(item, str):
                raise MigrationError("1Password source authority is invalid")
            response = self._read_item(vault, item)
            notes = response.get("notesPlain") if isinstance(response, Mapping) else None
            if not isinstance(notes, str) and isinstance(response, Mapping):
                note_fields = [
                    field
                    for field in response.get("fields", [])
                    if isinstance(field, Mapping) and field.get("label") == "notesPlain"
                ]
                if len(note_fields) == 1:
                    notes = note_fields[0].get("value")
            if not isinstance(notes, str):
                raise MigrationError("secure note source is invalid")
            env = _parse_env(notes.encode("utf-8"))
            raw = env.get("DATABASE_URI")
            if raw is None:
                raise MigrationError("secure note database URI is missing")
            field = coordinate.split("|", 2)[1]
            component = {"POSTGRES_DB": "database", "POSTGRES_PASSWORD": "password", "POSTGRES_USER": "user"}.get(field)
            if component is None:
                raise MigrationError("secure note component is ambiguous")
            return _connection_uri_component(raw, component)
        locator = authority.get("locator")
        host, path = _parse_locator(locator)
        if kind == "server_file_component":
            field = coordinate.split("|", 2)[1]
            raw = _parse_env(self._read_file(host, path))
            if field == "KEN_AGENTS_PLATFORM_DB_PASSWORD":
                uri = raw.get("DATABASE_URL")
                if uri is None:
                    raise MigrationError("DATABASE_URL source is missing")
                return _connection_uri_component(uri, "password")
            variable = authority.get("component")
            if not isinstance(variable, str) or variable not in raw:
                raise MigrationError("source environment component is ambiguous")
            return raw[variable]
        if kind in {"server_certificate_pair", "server_certificate", "server_certificate_bundle", "server_redirect_sync_bundle"}:
            components = authority.get("components")
            component_name = None
            if isinstance(components, Mapping):
                field = coordinate.split("|", 2)[1]
                aliases = {
                    "CLOUDFLARE_REDIRECT_INGRESS_CERT_BASE64": "certificate",
                    "CLOUDFLARE_REDIRECT_INGRESS_KEY_BASE64": "private_key",
                    "REDIRECT_SYNC_CLIENT_CA_BASE64": "client_ca",
                    "REDIRECT_SYNC_SERVER_CERT_BASE64": "server_certificate",
                    "REDIRECT_SYNC_SERVER_KEY_BASE64": "server_private_key",
                    "REDIRECT_SYNC_SOURCE_ALLOWLIST_BASE64": "source_allowlist",
                }
                component_name = aliases.get(field)
                if component_name is None and len(components) == 1:
                    component_name = next(iter(components))
                if component_name is not None:
                    path = str(components.get(component_name, ""))
                    if not path.startswith("/"):
                        path = str(Path(_parse_locator(locator)[1]) / path)
            raw = self._read_file(host, path)
            return base64.b64encode(raw).decode("ascii")
        if kind == "server_certificate_derivation":
            return self._fingerprint(self._read_file(host, path)).replace(":", "").upper()
        raise MigrationError("production source authority kind is unsupported")


def apply_registry_sources(registry: Mapping[str, Any], source_map: ProductionSourceMap) -> dict[str, Any]:
    updated = copy.deepcopy(dict(registry))
    entries = updated.get("entries")
    if not isinstance(entries, list):
        raise ValueError("canonical registry entries are invalid")
    found: set[str] = set()
    for entry in entries:
        coordinate = entry.get("coordinate") if isinstance(entry, Mapping) else None
        if coordinate not in source_map.coordinates:
            continue
        if entry.get("verification_status") != "unresolved" or entry.get("source_authority") is not None:
            raise ValueError("mapped registry row is not unresolved")
        if entry.get("canonical_vault") != "Ken Deploy Production":
            raise ValueError("mapped registry row has the wrong vault")
        entry["source_authority"] = authority_for_coordinate(coordinate)
        entry["verification_status"] = "verified-readable"
        found.add(coordinate)
    if found != set(source_map.coordinates):
        raise ValueError("source map and registry coordinates do not match")
    return updated


def population_registry(registry: Mapping[str, Any], source_map: ProductionSourceMap) -> dict[str, Any]:
    """Return a validated registry containing only the eighteen mapped rows."""
    mapped = set(source_map.coordinates)
    result = copy.deepcopy(dict(registry))
    result["entries"] = [entry for entry in result.get("entries", []) if entry.get("coordinate") in mapped]
    item_ids = {entry["canonical_id"] for entry in result["entries"]}
    result["canonical_items"] = [item for item in result.get("canonical_items", []) if item.get("id") in item_ids]
    return result


def source_evidence(source_map: ProductionSourceMap) -> dict[str, Any]:
    rows = []
    for coordinate in sorted(source_map.coordinates):
        authority = source_map.group_for(coordinate)["authority"]
        row = {
            "coordinate": coordinate,
            "source_authority": authority_for_coordinate(coordinate),
            "kind": authority["kind"],
            "locator": authority.get("locator"),
        }
        rows.append({key: value for key, value in row.items() if value is not None})
    return {
        "schema_version": 1,
        "status": "mapped",
        "value_disclosure": "none",
        "comparison_boundary": "single-process-memory-only",
        "mapped_count": len(rows),
        "rows": rows,
    }
