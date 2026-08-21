#!/usr/bin/env python3
"""Strict, value-free validation for the canonical credential registry.

The registry is intentionally metadata-only.  It records where a credential
will live and how a consumer should migrate, never the credential itself or
evidence derived from its value.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Mapping

import yaml

ALLOWED_VAULTS = frozenset(
    {
        "Ken CI Runtime",
        "Ken Deploy Nonproduction",
        "Ken Deploy Production",
    }
)
DISPOSITIONS = frozenset(
    {
        "canonical-item",
        "dedicated-item",
        "github-variable",
        "github-token",
        "oidc",
        "retired",
    }
)
VERIFICATION_STATUSES = frozenset(
    {
        "verified-readable",
        "verified-reconstructable",
        "existing-direct-reference",
        "planned-variable",
        "planned-secretless",
        "bootstrap-to-replace",
        "unresolved",
    }
)
ENVIRONMENTS = frozenset({"ci", "nonproduction", "production", "none"})

TOP_LEVEL_KEYS = frozenset(
    {"schema_version", "organization", "allowed_vaults", "canonical_items", "entries"}
)
ITEM_KEYS = frozenset({"id", "vault", "aliases"})
ENTRY_KEYS = frozenset(
    {
        "coordinate",
        "canonical_id",
        "aliases",
        "disposition",
        "verification_status",
        "source_authority",
        "canonical_vault",
        "canonical_item",
        "canonical_field",
        "environment",
        "consumer_repositories",
    }
)

# A registry may describe labels and references, but not anything calculated
# from a secret.  Matching is case-insensitive and recursive so a future
# nested section cannot accidentally become a covert value store.
FORBIDDEN_VALUE_DERIVED_KEYS = frozenset(
    {
        "value",
        "secret",
        "secret_value",
        "plaintext",
        "digest",
        "hash",
        "sha",
        "sha1",
        "sha256",
        "checksum",
        "prefix",
        "length",
        "bytes",
    }
)


class UniqueKeySafeLoader(yaml.SafeLoader):
    """PyYAML loader that refuses duplicate keys at every mapping depth."""


def _construct_unique_mapping(
    loader: UniqueKeySafeLoader, node: yaml.MappingNode, deep: bool = False
) -> dict[Any, Any]:
    loader.flatten_mapping(node)
    mapping: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in mapping
        except TypeError as exc:
            raise ValueError("unhashable YAML mapping key") from exc
        if duplicate:
            raise ValueError(f"duplicate YAML mapping key: {key}")
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


UniqueKeySafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


def _is_bool(value: Any) -> bool:
    return isinstance(value, bool)


def _require_string(value: Any, path: str, *, allow_none: bool = False) -> None:
    if allow_none and value is None:
        return
    if not isinstance(value, str) or not value:
        raise ValueError(f"{path} must be a non-empty string")


def _require_string_list(value: Any, path: str) -> None:
    if not isinstance(value, list):
        raise ValueError(f"{path} must be a list")
    for index, item in enumerate(value):
        _require_string(item, f"{path}[{index}]")


def _walk_forbidden_keys(value: Any, path: str = "document") -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            if not isinstance(key, str):
                raise ValueError(f"{path} contains a non-string key")
            normalized = re.sub(r"(?<!^)(?=[A-Z])", "_", key).casefold()
            normalized = normalized.replace("-", "_")
            derived_suffixes = (
                "_digest",
                "_hash",
                "_sha",
                "_sha1",
                "_sha256",
                "_checksum",
                "_prefix",
                "_length",
                "_bytes",
            )
            if (
                normalized in FORBIDDEN_VALUE_DERIVED_KEYS
                or normalized.endswith(derived_suffixes)
                or normalized.startswith(("value_", "secret_", "plaintext_"))
            ):
                raise ValueError(f"forbidden value-derived key: {path}.{key}")
            _walk_forbidden_keys(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _walk_forbidden_keys(child, f"{path}[{index}]")


def _require_exact_keys(
    value: Mapping[str, Any], allowed: frozenset[str], path: str
) -> None:
    unknown = set(value) - allowed
    if unknown:
        names = ", ".join(sorted(str(key) for key in unknown))
        raise ValueError(f"unknown key(s) at {path}: {names}")


def _environment_for_vault(vault: str | None) -> str:
    return {
        "Ken CI Runtime": "ci",
        "Ken Deploy Nonproduction": "nonproduction",
        "Ken Deploy Production": "production",
        None: "none",
    }.get(vault, "invalid")


def _validate_item(
    item: Any, index: int, seen_ids: set[str], seen_aliases: set[str]
) -> None:
    path = f"canonical_items[{index}]"
    if not isinstance(item, dict):
        raise ValueError(f"{path} must be a mapping")
    _require_exact_keys(item, ITEM_KEYS, path)
    if set(item) != ITEM_KEYS:
        raise ValueError(f"{path} must contain exactly: {', '.join(sorted(ITEM_KEYS))}")
    _require_string(item["id"], f"{path}.id")
    if item["id"] in seen_ids:
        raise ValueError(f"duplicate canonical item id: {item['id']}")
    seen_ids.add(item["id"])
    _require_string(item["vault"], f"{path}.vault")
    if item["vault"] not in ALLOWED_VAULTS:
        raise ValueError(f"unsupported vault at {path}.vault: {item['vault']}")
    _require_string_list(item["aliases"], f"{path}.aliases")
    if len(set(item["aliases"])) != len(item["aliases"]):
        raise ValueError(f"duplicate alias in {path}.aliases")
    for alias in item["aliases"]:
        if alias in seen_aliases:
            raise ValueError(f"duplicate alias: {alias}")
        seen_aliases.add(alias)


def _validate_entry(
    entry: Any,
    index: int,
    item_by_id: Mapping[str, Mapping[str, Any]],
    seen_coordinates: set[str],
    seen_aliases: set[str],
) -> None:
    path = f"entries[{index}]"
    if not isinstance(entry, dict):
        raise ValueError(f"{path} must be a mapping")
    _require_exact_keys(entry, ENTRY_KEYS, path)
    if set(entry) != ENTRY_KEYS:
        raise ValueError(
            f"{path} must contain exactly: {', '.join(sorted(ENTRY_KEYS))}"
        )

    _require_string(entry["coordinate"], f"{path}.coordinate")
    coordinate = entry["coordinate"]
    if coordinate in seen_coordinates:
        raise ValueError(f"duplicate coordinate: {coordinate}")
    seen_coordinates.add(coordinate)

    canonical_id = entry["canonical_id"]
    _require_string(canonical_id, f"{path}.canonical_id", allow_none=True)
    aliases = entry["aliases"]
    _require_string_list(aliases, f"{path}.aliases")
    if len(set(aliases)) != len(aliases):
        raise ValueError(f"duplicate alias in {path}.aliases")
    disposition = entry["disposition"]
    _require_string(disposition, f"{path}.disposition")
    if disposition not in DISPOSITIONS:
        raise ValueError(
            f"unsupported disposition at {path}.disposition: {disposition}"
        )
    status = entry["verification_status"]
    _require_string(status, f"{path}.verification_status")
    if status not in VERIFICATION_STATUSES:
        raise ValueError(
            f"unsupported verification_status at {path}.verification_status: {status}"
        )
    source_authority = entry["source_authority"]
    _require_string(source_authority, f"{path}.source_authority", allow_none=True)
    canonical_vault = entry["canonical_vault"]
    _require_string(canonical_vault, f"{path}.canonical_vault", allow_none=True)
    if canonical_vault is not None and canonical_vault not in ALLOWED_VAULTS:
        raise ValueError(
            f"unsupported vault at {path}.canonical_vault: {canonical_vault}"
        )
    canonical_item = entry["canonical_item"]
    _require_string(canonical_item, f"{path}.canonical_item", allow_none=True)
    canonical_field = entry["canonical_field"]
    _require_string(canonical_field, f"{path}.canonical_field", allow_none=True)
    environment = entry["environment"]
    _require_string(environment, f"{path}.environment")
    if environment not in ENVIRONMENTS:
        raise ValueError(
            f"unsupported environment at {path}.environment: {environment}"
        )
    if environment != _environment_for_vault(canonical_vault):
        raise ValueError(f"environment does not match canonical_vault at {path}")
    _require_string_list(
        entry["consumer_repositories"], f"{path}.consumer_repositories"
    )

    item = item_by_id.get(canonical_id) if canonical_id is not None else None
    if canonical_id is not None and item is None:
        raise ValueError(
            f"{path}.canonical_id does not name a canonical item: {canonical_id}"
        )
    if item is not None:
        if canonical_vault != item["vault"] or canonical_item != item["id"]:
            raise ValueError(f"canonical item coordinate mismatch at {path}")
    for alias in aliases:
        if alias in seen_aliases:
            raise ValueError(f"duplicate alias: {alias}")
        seen_aliases.add(alias)

    if disposition in {"canonical-item", "dedicated-item"}:
        if (
            canonical_id is None
            or canonical_vault is None
            or canonical_item is None
            or canonical_field is None
        ):
            raise ValueError(
                f"item disposition requires canonical coordinates at {path}"
            )
    else:
        if (
            canonical_id is not None
            or canonical_vault is not None
            or canonical_item is not None
            or canonical_field is not None
        ):
            raise ValueError(
                f"non-item disposition cannot have canonical item coordinates at {path}"
            )
    if (
        disposition in {"github-variable", "github-token", "oidc", "retired"}
        and environment != "none"
    ):
        raise ValueError(f"{disposition} entries must use environment none at {path}")
    if status == "unresolved" and source_authority is not None:
        raise ValueError(f"unresolved entry must not claim an authority at {path}")


def validate_registry(
    document: Any, handoff: Mapping[str, Any] | None = None
) -> dict[str, Any]:
    """Validate a parsed registry and optionally its complete handoff coverage."""
    _walk_forbidden_keys(document)
    if not isinstance(document, dict):
        raise ValueError("registry document must be a mapping")
    _require_exact_keys(document, TOP_LEVEL_KEYS, "document")
    if set(document) != TOP_LEVEL_KEYS:
        raise ValueError(
            f"document must contain exactly: {', '.join(sorted(TOP_LEVEL_KEYS))}"
        )
    if (
        _is_bool(document["schema_version"])
        or not isinstance(document["schema_version"], int)
        or document["schema_version"] != 1
    ):
        raise ValueError("schema_version must be integer 1")
    _require_string(document["organization"], "organization")
    if document["organization"] != "Ken-Technology":
        raise ValueError("organization must be Ken-Technology")
    _require_string_list(document["allowed_vaults"], "allowed_vaults")
    if len(set(document["allowed_vaults"])) != len(document["allowed_vaults"]):
        raise ValueError("allowed_vaults must not contain duplicates")
    if set(document["allowed_vaults"]) != set(ALLOWED_VAULTS):
        raise ValueError("allowed_vaults must exactly match the approved vault set")
    if not isinstance(document["canonical_items"], list):
        raise ValueError("canonical_items must be a list")
    if not isinstance(document["entries"], list):
        raise ValueError("entries must be a list")

    item_by_id: dict[str, Mapping[str, Any]] = {}
    seen_ids: set[str] = set()
    seen_aliases: set[str] = set()
    for index, item in enumerate(document["canonical_items"]):
        _validate_item(item, index, seen_ids, seen_aliases)
        item_by_id[item["id"]] = item

    seen_coordinates: set[str] = set()
    for index, entry in enumerate(document["entries"]):
        _validate_entry(entry, index, item_by_id, seen_coordinates, seen_aliases)
    if handoff is not None:
        validate_complete_coverage(document, handoff)
    return document


def canonical_coordinate(row: Mapping[str, Any]) -> str:
    """Return the handoff's stable coordinate without consulting any value."""
    coordinate = row.get("coordinate")
    if isinstance(coordinate, str) and coordinate:
        return coordinate
    if row.get("reference_class") != "github-secret":
        raise ValueError("row without coordinate must be a github-secret row")
    repository = row.get("repository")
    field = row.get("github_secret_name")
    if not isinstance(repository, str) or not repository:
        raise ValueError("github row missing repository")
    if not isinstance(field, str) or not field:
        raise ValueError("github row missing github_secret_name")
    target_vault = row.get("target_vault")
    if target_vault is None:
        target_vault = "no-1password-target"
    if not isinstance(target_vault, str) or not target_vault:
        raise ValueError("github row has invalid target_vault")
    return f"{repository}|{field}|{target_vault}"


def validate_complete_coverage(
    registry: Mapping[str, Any], handoff: Mapping[str, Any]
) -> None:
    """Require an exact one-to-one coordinate match with the 308-row handoff."""
    rows = handoff.get("rows") if isinstance(handoff, Mapping) else None
    if not isinstance(rows, list):
        raise ValueError("handoff.rows must be a list")
    expected = [canonical_coordinate(row) for row in rows]
    actual = [entry.get("coordinate") for entry in registry.get("entries", [])]
    declared_count = (
        handoff.get("counts", {}).get("rows") if isinstance(handoff, Mapping) else None
    )
    if declared_count == 308 and len(expected) != 308:
        raise ValueError(f"handoff must contain exactly 308 rows, got {len(expected)}")
    if len(actual) != len(set(actual)):
        raise ValueError("registry contains duplicate coordinates")
    expected_set = set(expected)
    actual_set = set(actual)
    missing = sorted(expected_set - actual_set)
    extra = sorted(actual_set - expected_set)
    if missing or extra or len(expected_set) != len(expected):
        details = []
        if missing:
            details.append(f"missing={missing[:3]}")
        if extra:
            details.append(f"extra={extra[:3]}")
        if len(expected_set) != len(expected):
            details.append("handoff contains duplicate coordinates")
        raise ValueError("registry coordinate coverage mismatch: " + "; ".join(details))


def load_registry(
    path: str | Path, handoff: Mapping[str, Any] | None = None
) -> dict[str, Any]:
    """Load and strictly validate a registry YAML file."""
    registry_path = Path(path)
    with registry_path.open("r", encoding="utf-8") as stream:
        document = yaml.load(stream, Loader=UniqueKeySafeLoader)
    return validate_registry(document, handoff=handoff)


def minimal_document() -> dict[str, Any]:
    """Small valid document used by contract tests and downstream callers."""
    return {
        "schema_version": 1,
        "organization": "Ken-Technology",
        "allowed_vaults": sorted(ALLOWED_VAULTS),
        "canonical_items": [
            {"id": "test-item", "vault": "Ken Deploy Production", "aliases": []}
        ],
        "entries": [
            {
                "coordinate": "test|TOKEN|Ken Deploy Production",
                "canonical_id": "test-item",
                "aliases": ["TEST_TOKEN"],
                "disposition": "dedicated-item",
                "verification_status": "verified-readable",
                "source_authority": "op://source/item/field",
                "canonical_vault": "Ken Deploy Production",
                "canonical_item": "test-item",
                "canonical_field": "TEST_TOKEN",
                "environment": "production",
                "consumer_repositories": ["test"],
            }
        ],
    }
