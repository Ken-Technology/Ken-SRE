#!/usr/bin/env python3
"""Strict, value-free validation for the canonical credential registry.

The registry is intentionally metadata-only.  It records where a credential
will live and how a consumer should migrate, never the credential itself or
evidence derived from its value.
"""

from __future__ import annotations

import hashlib
import os
import re
import stat
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
FIELD_TYPES = frozenset({"CONCEALED", "STRING"})
RULE_STATUSES = frozenset(
    {
        "same",
        "same-identity",
        "same-value-scope-unproven",
        "different",
        "different-value",
        "resolved-readable",
        "scope-unproven",
        "retire-or-secretless",
        "unresolved",
    }
)
RULE_ENVIRONMENT_SCOPES = frozenset({"matching", "different", "unproven", "unresolved"})
RULE_REASONS = frozenset(
    {
        "different-value",
        "environment-conflict",
        "scope-unproven",
        "account-unproven",
        "environment-split",
        "scope-conflict",
        "unresolved-authority",
        "retire-or-secretless",
    }
)
REVIEWED_EVIDENCE_SHA256 = (
    "51113962b9cb1705f66ff51700afacf9f65da37753e215b3e0d4606d9211c5c0"
)
REPOSITORY_ROOT = Path(__file__).resolve().parents[4]

TOP_LEVEL_KEYS = frozenset(
    {"schema_version", "organization", "allowed_vaults", "canonical_items", "entries"}
)
ITEM_KEYS = frozenset({"id", "vault", "aliases"})
ENTRY_KEYS = frozenset(
    {
        "coordinate",
        "field_type",
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
ENTRY_REQUIRED_KEYS = ENTRY_KEYS - {"field_type"}
RULES_TOP_LEVEL_KEYS = frozenset(
    {
        "schema_version",
        "organization",
        "reviewed_evidence",
        "reviewed_groups",
        "approved_same_identity",
        "preserve_separately",
    }
)
RULE_EVIDENCE_KEYS = frozenset(
    {
        "id",
        "artifact",
        "sha256",
        "value_disclosure",
        "comparison_boundary",
        "row_count",
    }
)
REVIEWED_EVIDENCE_ARTIFACTS = {
    "baseline-authority-resolution": {
        "artifact": "infra/github-actions/inventory/evidence/ken-secret-authority-resolution.yaml",
        "sha256": REVIEWED_EVIDENCE_SHA256,
    },
    "production-credential-comparison": {
        "artifact": "infra/github-actions/inventory/evidence/ken-production-credential-comparison.yaml",
        "sha256": "4b2f27dbd8de06c2b8c725a8dd68d5e2b4cc9b77acce1494735bd34a0b1afe96",
        "row_count": 57,
    },
    "unresolved-authority-resolution": {
        "artifact": "infra/github-actions/inventory/evidence/ken-unresolved-authority-resolution.yaml",
        "sha256": "317b3ed71f1128d80b9b890059d5e7b0a4c0e6400779709c2ec178b31a77d250",
        "row_count": 124,
    },
}
REVIEWED_GROUP_KEYS = frozenset(
    {"id", "status", "source_coordinates", "environment_scope", "evidence_class"}
)
APPROVED_GROUP_KEYS = frozenset(
    {
        "id",
        "source_coordinates",
        "handoff_coordinates",
        "environment_scope",
        "target",
        "evidence_group",
    }
)
PRESERVED_GROUP_KEYS = frozenset(
    {
        "id",
        "source_coordinates",
        "handoff_coordinates",
        "status",
        "reason",
        "evidence_group",
    }
)
RULE_TARGET_KEYS = frozenset(
    {"disposition", "environment", "vault", "item", "field"}
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
    *,
    require_field_type: bool = False,
) -> None:
    path = f"entries[{index}]"
    if not isinstance(entry, dict):
        raise ValueError(f"{path} must be a mapping")
    _require_exact_keys(entry, ENTRY_KEYS, path)
    if set(entry) not in {ENTRY_KEYS, ENTRY_REQUIRED_KEYS}:
        raise ValueError(
            f"{path} must contain exactly: {', '.join(sorted(ENTRY_KEYS))}"
        )

    _require_string(entry["coordinate"], f"{path}.coordinate")
    coordinate = entry["coordinate"]
    if coordinate in seen_coordinates:
        raise ValueError(f"duplicate coordinate: {coordinate}")
    seen_coordinates.add(coordinate)

    field_type = entry.get("field_type")
    if field_type is not None:
        _require_string(field_type, f"{path}.field_type")
        if field_type not in FIELD_TYPES:
            raise ValueError(f"unsupported field_type at {path}.field_type")

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
        if require_field_type and field_type not in FIELD_TYPES:
            raise ValueError(f"item disposition requires field_type at {path}")
    elif disposition == "github-variable":
        if (
            canonical_id is not None
            or canonical_vault is not None
            or canonical_item is not None
        ):
            raise ValueError(
                f"github-variable cannot have canonical item coordinates at {path}"
            )
        if canonical_field is not None:
            _require_string(canonical_field, f"{path}.canonical_field")
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
        _validate_entry(
            entry,
            index,
            item_by_id,
            seen_coordinates,
            seen_aliases,
            require_field_type=handoff is not None,
        )
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
    if len(expected) != 308:
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

    handoff_types = {
        canonical_coordinate(row): row.get("field_type")
        for row in rows
    }
    registry_entries = {
        entry.get("coordinate"): entry
        for entry in registry.get("entries", [])
        if isinstance(entry, Mapping)
    }
    for coordinate, expected_type in handoff_types.items():
        if expected_type is None:
            continue
        normalized_type = str(expected_type).upper()
        if normalized_type not in FIELD_TYPES:
            raise ValueError(f"unsupported handoff field_type at {coordinate}")
        actual_type = registry_entries[coordinate].get("field_type")
        if actual_type != normalized_type:
            raise ValueError(
                f"registry field_type mismatch at {coordinate}: "
                f"expected {normalized_type}, got {actual_type}"
            )


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
                "field_type": "CONCEALED",
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


def _walk_rule_forbidden_keys(value: Any, path: str = "document") -> None:
    """Reject value-bearing or value-derived rule metadata.

    The reviewed artifact digest is the one intentional exception: it identifies
    the reviewed evidence file and is not derived from a credential value.
    """
    if isinstance(value, Mapping):
        for key, child in value.items():
            if not isinstance(key, str):
                raise ValueError(f"{path} contains a non-string key")
            normalized = re.sub(r"(?<!^)(?=[A-Z])", "_", key).casefold()
            normalized = normalized.replace("-", "_")
            allowed_evidence_digest = (
                (path == "document.reviewed_evidence" or path.startswith("document.reviewed_evidence["))
                and normalized == "sha256"
            )
            allowed_evidence_disclosure = (
                (path == "document.reviewed_evidence" or path.startswith("document.reviewed_evidence["))
                and normalized == "value_disclosure"
            )
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
            if not (allowed_evidence_digest or allowed_evidence_disclosure) and (
                normalized in FORBIDDEN_VALUE_DERIVED_KEYS
                or normalized.endswith(derived_suffixes)
                or normalized.startswith(("value_", "secret_", "plaintext_"))
            ):
                raise ValueError(f"forbidden value-derived key: {path}.{key}")
            _walk_rule_forbidden_keys(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _walk_rule_forbidden_keys(child, f"{path}[{index}]")


_ARTIFACT_FORBIDDEN_KEYS = frozenset(
    {
        "api_key",
        "bytes",
        "checksum",
        "digest",
        "hash",
        "length",
        "prefix",
        "secret",
        "secret_value",
        "sha",
        "sha1",
        "sha256",
        "plaintext",
        "credential_value",
        "token_value",
        "private_key",
        "password",
    }
)


def _resolve_reviewed_artifact_path(
    artifact: str | Path, *, base_dir: str | Path | None
) -> Path:
    """Resolve an evidence path while keeping it inside the approved root."""
    raw = Path(artifact)
    if base_dir is not None and raw.is_absolute():
        raise ValueError("reviewed evidence artifact must be repo-relative")
    if not raw.is_absolute() and any(part in {"", ".", ".."} for part in raw.parts):
        raise ValueError("reviewed evidence artifact path traversal is not allowed")

    root = Path(base_dir).resolve() if base_dir is not None else REPOSITORY_ROOT
    candidate = raw if raw.is_absolute() else root / raw
    resolved = candidate.resolve(strict=False)
    if not raw.is_absolute():
        try:
            resolved.relative_to(root)
        except ValueError as exc:
            raise ValueError("reviewed evidence artifact escapes repository root") from exc

        current = root
        for part in raw.parts:
            current /= part
            try:
                if stat.S_ISLNK(current.lstat().st_mode):
                    raise ValueError("reviewed evidence artifact path contains a symlink")
            except FileNotFoundError:
                break
    return candidate


def artifact_sha256(path: str | Path) -> str:
    """Return a reviewed artifact digest without exposing its contents."""
    try:
        return hashlib.sha256(Path(path).read_bytes()).hexdigest()
    except OSError as exc:
        raise ValueError("reviewed evidence artifact could not be read") from exc


def _validate_value_free_artifact(document: Any, path: str) -> None:
    if not isinstance(document, Mapping):
        raise ValueError(f"reviewed evidence artifact is not a mapping: {path}")
    if "value_disclosure" in document and document["value_disclosure"] != "none":
        raise ValueError(f"reviewed evidence artifact discloses values: {path}")

    def walk(value: Any, location: str) -> None:
        if isinstance(value, Mapping):
            for key, child in value.items():
                normalized = key.casefold().replace("-", "_") if isinstance(key, str) else ""
                allowed_artifact_digest = location == "artifact" and normalized == "sha256"
                if (
                    isinstance(key, str)
                    and not allowed_artifact_digest
                    and (
                        normalized in _ARTIFACT_FORBIDDEN_KEYS
                        or normalized.endswith(("_hash", "_digest", "_sha", "_sha1", "_sha256", "_checksum", "_prefix", "_length", "_bytes"))
                    )
                ):
                    raise ValueError(
                        f"reviewed evidence artifact contains value-derived metadata: {location}.{key}"
                    )
                walk(child, f"{location}.{key}")
        elif isinstance(value, list):
            for index, child in enumerate(value):
                walk(child, f"{location}[{index}]")

    walk(document, "artifact")


def validate_reviewed_evidence_artifacts(
    document: Mapping[str, Any], *, base_dir: str | Path | None = None
) -> None:
    """Hash and structurally validate each approved evidence artifact."""
    for item in document["reviewed_evidence"]:
        artifact = _resolve_reviewed_artifact_path(item["artifact"], base_dir=base_dir)
        try:
            info = artifact.lstat()
        except OSError as exc:
            raise ValueError(f"reviewed evidence artifact is missing: {artifact}") from exc
        if not stat.S_ISREG(info.st_mode) or artifact.is_symlink() or info.st_nlink != 1:
            raise ValueError(f"reviewed evidence artifact is not a regular file: {artifact}")
        try:
            with artifact.open("rb") as stream:
                before = os.fstat(stream.fileno())
                raw = stream.read()
                after = os.fstat(stream.fileno())
        except OSError as exc:
            raise ValueError(f"reviewed evidence artifact could not be read: {item['id']}") from exc
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        ):
            raise ValueError(f"reviewed evidence artifact changed while being read: {item['id']}")
        if hashlib.sha256(raw).hexdigest() != item["sha256"]:
            raise ValueError(f"reviewed evidence artifact sha256 mismatch: {item['id']}")
        try:
            artifact_document = yaml.load(raw.decode("utf-8"), Loader=UniqueKeySafeLoader)
        except (UnicodeError, yaml.YAMLError) as exc:
            raise ValueError(f"reviewed evidence artifact is invalid: {item['id']}") from exc
        _validate_value_free_artifact(artifact_document, str(artifact))
        rows = artifact_document.get("rows") if isinstance(artifact_document, Mapping) else None
        if rows is not None and not isinstance(rows, list):
            raise ValueError(f"reviewed evidence artifact rows are invalid: {item['id']}")
        actual_row_count = len(rows) if isinstance(rows, list) else 1
        if actual_row_count != item["row_count"]:
            raise ValueError(f"reviewed evidence artifact row count mismatch: {item['id']}")


def _validate_rule_target(target: Any, path: str) -> None:
    if not isinstance(target, dict):
        raise ValueError(f"{path} must be a mapping")
    _require_exact_keys(target, RULE_TARGET_KEYS, path)
    if set(target) != RULE_TARGET_KEYS:
        raise ValueError(f"{path} must contain exactly: {', '.join(sorted(RULE_TARGET_KEYS))}")
    _require_string(target["disposition"], f"{path}.disposition")
    if target["disposition"] not in {"canonical-item", "dedicated-item", "github-variable"}:
        raise ValueError(f"unsupported consolidation target disposition at {path}")
    _require_string(target["environment"], f"{path}.environment")
    if target["environment"] not in ENVIRONMENTS:
        raise ValueError(f"unsupported consolidation target environment at {path}")
    for key in ("vault", "item", "field"):
        _require_string(target[key], f"{path}.{key}", allow_none=True)
    if target["disposition"] == "github-variable":
        if target["environment"] != "none" or target["vault"] is not None or target["item"] is not None:
            raise ValueError(f"github-variable target must be unscoped at {path}")
        if target["field"] is None:
            raise ValueError(f"github-variable target requires a field at {path}")
    else:
        if target["vault"] not in ALLOWED_VAULTS or target["item"] is None or target["field"] is None:
            raise ValueError(f"item target requires vault, item, and field at {path}")
        if target["environment"] != _environment_for_vault(target["vault"]):
            raise ValueError(f"target environment does not match vault at {path}")


def _validate_rule_group_common(
    group: Any,
    index: int,
    keys: frozenset[str],
    path_prefix: str,
) -> None:
    path = f"{path_prefix}[{index}]"
    if not isinstance(group, dict):
        raise ValueError(f"{path} must be a mapping")
    _require_exact_keys(group, keys, path)
    if set(group) != keys:
        raise ValueError(f"{path} must contain exactly: {', '.join(sorted(keys))}")
    _require_string(group["id"], f"{path}.id")
    _require_string_list(group["source_coordinates"], f"{path}.source_coordinates")
    if not group["source_coordinates"]:
        raise ValueError(f"{path}.source_coordinates must not be empty")
    if "handoff_coordinates" in group:
        _require_string_list(group["handoff_coordinates"], f"{path}.handoff_coordinates")
    _require_string(group["evidence_group"], f"{path}.evidence_group")


def validate_consolidation_rules(document: Any) -> dict[str, Any]:
    """Validate the reviewed, value-free same-identity consolidation rules."""
    _walk_rule_forbidden_keys(document)
    if not isinstance(document, dict):
        raise ValueError("consolidation rules document must be a mapping")
    _require_exact_keys(document, RULES_TOP_LEVEL_KEYS, "document")
    if set(document) != RULES_TOP_LEVEL_KEYS:
        raise ValueError(
            "document must contain exactly: "
            + ", ".join(sorted(RULES_TOP_LEVEL_KEYS))
        )
    if _is_bool(document["schema_version"]) or document["schema_version"] != 1:
        raise ValueError("consolidation rules schema_version must be integer 1")
    if not isinstance(document["schema_version"], int):
        raise ValueError("consolidation rules schema_version must be integer 1")
    _require_string(document["organization"], "organization")
    if document["organization"] != "Ken-Technology":
        raise ValueError("consolidation rules organization must be Ken-Technology")

    evidence = document["reviewed_evidence"]
    if not isinstance(evidence, list) or not evidence:
        raise ValueError("reviewed_evidence must be a non-empty list")
    evidence_ids: set[str] = set()
    for index, item in enumerate(evidence):
        path = f"reviewed_evidence[{index}]"
        if not isinstance(item, dict):
            raise ValueError(f"{path} must be a mapping")
        _require_exact_keys(item, RULE_EVIDENCE_KEYS, path)
        if set(item) != RULE_EVIDENCE_KEYS:
            raise ValueError(f"{path} has an incomplete schema")
        _require_string(item["id"], f"{path}.id")
        if item["id"] in evidence_ids:
            raise ValueError(f"duplicate reviewed evidence id: {item['id']}")
        evidence_ids.add(item["id"])
        _require_string(item["artifact"], f"{path}.artifact")
        _require_string(item["sha256"], f"{path}.sha256")
        if item["value_disclosure"] != "none":
            raise ValueError("reviewed evidence must declare value_disclosure: none")
        _require_string(item["comparison_boundary"], f"{path}.comparison_boundary")
        if (
            _is_bool(item["row_count"])
            or not isinstance(item["row_count"], int)
            or item["row_count"] <= 0
        ):
            raise ValueError(f"{path}.row_count must be a positive integer")
        expected = REVIEWED_EVIDENCE_ARTIFACTS.get(item["id"])
        if expected is None:
            raise ValueError(f"unapproved reviewed evidence id: {item['id']}")
        if item["artifact"] != expected["artifact"] or item["sha256"] != expected["sha256"]:
            raise ValueError(f"reviewed evidence does not match approved artifact: {item['id']}")
        expected_count = expected.get("row_count")
        if expected_count is not None and item["row_count"] != expected_count:
            raise ValueError(f"reviewed evidence row_count does not match approved artifact: {item['id']}")

    for key in ("reviewed_groups", "approved_same_identity", "preserve_separately"):
        if not isinstance(document[key], list):
            raise ValueError(f"{key} must be a list")

    reviewed_ids: set[str] = set()
    for index, group in enumerate(document["reviewed_groups"]):
        path = f"reviewed_groups[{index}]"
        if not isinstance(group, dict):
            raise ValueError(f"{path} must be a mapping")
        _require_exact_keys(group, REVIEWED_GROUP_KEYS, path)
        if set(group) != REVIEWED_GROUP_KEYS:
            raise ValueError(f"{path} has an incomplete schema")
        _require_string(group["id"], f"{path}.id")
        if group["id"] in reviewed_ids:
            raise ValueError(f"duplicate reviewed group id: {group['id']}")
        reviewed_ids.add(group["id"])
        _require_string(group["status"], f"{path}.status")
        if group["status"] not in RULE_STATUSES:
            raise ValueError(f"unsupported reviewed group status at {path}")
        _require_string_list(group["source_coordinates"], f"{path}.source_coordinates")
        _require_string(group["environment_scope"], f"{path}.environment_scope")
        if group["environment_scope"] not in RULE_ENVIRONMENT_SCOPES:
            raise ValueError(f"unsupported reviewed group environment_scope at {path}")
        _require_string(group["evidence_class"], f"{path}.evidence_class")

    rule_ids: set[str] = set()
    referenced_coordinates: set[str] = set()
    for index, group in enumerate(document["approved_same_identity"]):
        path = f"approved_same_identity[{index}]"
        _validate_rule_group_common(group, index, APPROVED_GROUP_KEYS, "approved_same_identity")
        if group["id"] in rule_ids:
            raise ValueError(f"duplicate consolidation group id: {group['id']}")
        rule_ids.add(group["id"])
        _require_string(group["environment_scope"], f"{path}.environment_scope")
        if group["environment_scope"] != "matching":
            raise ValueError(f"approved group must have matching environment_scope at {path}")
        _validate_rule_target(group["target"], f"{path}.target")
        overlap = referenced_coordinates.intersection(group["handoff_coordinates"])
        if overlap:
            raise ValueError(f"approved consolidation coordinate appears twice: {sorted(overlap)[0]}")
        referenced_coordinates.update(group["handoff_coordinates"])

    for index, group in enumerate(document["preserve_separately"]):
        path = f"preserve_separately[{index}]"
        _validate_rule_group_common(group, index, PRESERVED_GROUP_KEYS, "preserve_separately")
        if group["id"] in rule_ids:
            raise ValueError(f"duplicate consolidation group id: {group['id']}")
        rule_ids.add(group["id"])
        _require_string(group["status"], f"{path}.status")
        if group["status"] not in {"different", "unresolved"}:
            raise ValueError(f"preserved group must be different or unresolved at {path}")
        _require_string(group["reason"], f"{path}.reason")
        if group["reason"] not in RULE_REASONS:
            raise ValueError(f"unsupported preserved-group reason at {path}")
        overlap = referenced_coordinates.intersection(group["handoff_coordinates"])
        if overlap:
            raise ValueError(f"preserved coordinate appears in another group: {sorted(overlap)[0]}")
        referenced_coordinates.update(group["handoff_coordinates"])
    return document


def load_consolidation_rules(
    path: str | Path, *, verify_artifacts: bool | None = None
) -> dict[str, Any]:
    """Load rules and always verify their committed evidence bundle."""
    rules_path = Path(path)
    with rules_path.open("r", encoding="utf-8") as stream:
        document = yaml.load(stream, Loader=UniqueKeySafeLoader)
    validated = validate_consolidation_rules(document)
    # ``verify_artifacts`` remains accepted for callers from the initial
    # migration tooling, but verification is intentionally never optional.
    del verify_artifacts
    validate_reviewed_evidence_artifacts(validated, base_dir=REPOSITORY_ROOT)
    return validated


def entry_target(entry: Mapping[str, Any]) -> tuple[Any, ...]:
    """Return the structural target identity, never a credential value."""
    return (
        entry.get("disposition"),
        entry.get("canonical_vault"),
        entry.get("canonical_item"),
        entry.get("canonical_field"),
        entry.get("environment"),
    )


def validate_consolidation(
    registry: Mapping[str, Any], rules: Mapping[str, Any]
) -> None:
    """Prove approved groups collapse and preserved groups remain separate."""
    validate_consolidation_rules(rules)
    entries = {
        entry["coordinate"]: entry
        for entry in registry.get("entries", [])
        if isinstance(entry, Mapping) and isinstance(entry.get("coordinate"), str)
    }
    approved_coordinates: set[str] = set()
    for group in rules["approved_same_identity"]:
        coordinates = group["handoff_coordinates"]
        if not coordinates:
            continue
        missing = [coordinate for coordinate in coordinates if coordinate not in entries]
        if missing:
            raise ValueError(f"approved group references missing handoff coordinate: {missing[0]}")
        targets = {entry_target(entries[coordinate]) for coordinate in coordinates}
        if len(targets) != 1:
            raise ValueError(f"approved group did not collapse: {group['id']}")
        target = group["target"]
        expected = (
            target["disposition"],
            target["vault"],
            target["item"],
            target["field"],
            target["environment"],
        )
        if next(iter(targets)) != expected:
            raise ValueError(f"approved group target mismatch: {group['id']}")
        approved_coordinates.update(coordinates)

    for group in rules["preserve_separately"]:
        coordinates = group["handoff_coordinates"]
        if not coordinates:
            continue
        missing = [coordinate for coordinate in coordinates if coordinate not in entries]
        if missing:
            raise ValueError(f"preserved group references missing handoff coordinate: {missing[0]}")
        if approved_coordinates.intersection(coordinates):
            raise ValueError(f"coordinate is both approved and preserved: {group['id']}")
        targets = {entry_target(entries[coordinate]) for coordinate in coordinates}
        if len(targets) < 2:
            raise ValueError(f"preserved group was merged: {group['id']}")


def minimal_consolidation_rules() -> dict[str, Any]:
    """Small valid rules document used by the contract tests."""
    return {
        "schema_version": 1,
        "organization": "Ken-Technology",
        "reviewed_evidence": [
            {
                "id": "baseline-authority-resolution",
                "artifact": "infra/github-actions/inventory/evidence/ken-secret-authority-resolution.yaml",
                "sha256": REVIEWED_EVIDENCE_SHA256,
                "value_disclosure": "none",
                "comparison_boundary": "single-process-memory-only",
                "row_count": 1,
            }
        ],
        "reviewed_groups": [
            {
                "id": "reviewed-test",
                "status": "same",
                "source_coordinates": ["source://test"],
                "environment_scope": "matching",
                "evidence_class": "test-only",
            }
        ],
        "approved_same_identity": [
            {
                "id": "approved-test",
                "source_coordinates": ["source://test"],
                "handoff_coordinates": ["test|TOKEN|Ken Deploy Production"],
                "environment_scope": "matching",
                "target": {
                    "disposition": "dedicated-item",
                    "environment": "production",
                    "vault": "Ken Deploy Production",
                    "item": "test-item",
                    "field": "TEST_TOKEN",
                },
                "evidence_group": "reviewed-test",
            }
        ],
        "preserve_separately": [],
    }
