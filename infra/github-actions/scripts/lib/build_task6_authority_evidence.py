#!/usr/bin/env python3
"""Build the value-free authority evidence used by the Task 6 inventory.

The source observations in this file are deliberately limited to names, paths,
types, and existence/readability booleans.  No credential value is embedded or
derived here.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any


EVIDENCE_ID = "task6-authorities-2026-08-19"
PRODUCTION_VAULT = "Ken Deploy Production"
DEFAULT_EVIDENCE_DIR = Path(__file__).resolve().parents[2] / "inventory/evidence"


def _slug(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")


def _deployed_source(
    file: str, key_path: str, value_type: str = "string"
) -> tuple[str, dict[str, Any]]:
    service = Path(file).parent.name.replace(".", "-")
    source_id = f"worldstream-{service}-{_slug(key_path)}"
    return source_id, {
        "kind": "deployed-config",
        "host": "185.183.35.189",
        "scoped_user": "qa",
        "file": file,
        "key_path": key_path,
        "exists": True,
        "readable": True,
        "value_type": value_type,
        "metadata_artifact": "task-6-worldstream-key-metadata.json",
    }


def _op_source(
    vault: str, item: str, field: str, field_type: str
) -> tuple[str, dict[str, Any]]:
    source_id = f"op-{_slug(vault)}-{_slug(item)}-{_slug(field)}"
    return source_id, {
        "kind": "onepassword",
        "vault": vault,
        "item": item,
        "field": field,
        "field_type": field_type,
        "readable": True,
        "value_present": True,
        "metadata_artifact": "task-6-op-field-metadata.json",
    }


def _op_env_source(
    vault: str, item: str, name: str
) -> tuple[str, dict[str, Any]]:
    source_id = f"op-env-{_slug(vault)}-{_slug(item)}-{_slug(name)}"
    return source_id, {
        "kind": "onepassword-env-key",
        "vault": vault,
        "item": item,
        "name": name,
        "declared_type": "environment-string",
        "readable": True,
        "value_present": True,
        "metadata_artifact": "task-6-op-env-key-metadata.json",
    }


def _op_document_source(
    vault: str, item: str, file_name: str
) -> tuple[str, dict[str, Any]]:
    source_id = f"op-file-{_slug(vault)}-{_slug(item)}-{_slug(file_name)}"
    return source_id, {
        "kind": "onepassword-document",
        "vault": vault,
        "item": item,
        "file_name": file_name,
        "readable": True,
        "exists": True,
        "metadata_artifact": "task-6-op-field-metadata.json",
    }


def _op_title_source(
    vault: str, item: str, component: str
) -> tuple[str, dict[str, Any]]:
    source_id = f"op-title-{_slug(vault)}-{_slug(item)}-{_slug(component)}"
    return source_id, {
        "kind": "onepassword-item-title-component",
        "vault": vault,
        "item": item,
        "component": component,
        "readable": True,
        "exists": True,
        "metadata_artifact": "task-6-op-field-metadata.json",
    }


def _deployed_component_source(
    file: str, key_path: str, component: str
) -> tuple[str, dict[str, Any]]:
    service = Path(file).parent.name.replace(".", "-")
    source_id = f"worldstream-component-{service}-{_slug(key_path)}-{_slug(component)}"
    return source_id, {
        "kind": "deployed-connection-component",
        "host": "185.183.35.189",
        "scoped_user": "qa",
        "file": file,
        "key_path": key_path,
        "component": component,
        "exists": True,
        "readable": True,
        "metadata_artifact": "task-6-connection-structure.json",
    }


def _steps(action: str, repository: str, name: str) -> list[str]:
    if action == "move-to-variable":
        return [
            f"Create repository Actions variable {name} in {repository}, update the workflow reference from secrets to vars, and verify without printing the setting."
        ]
    if action == "reconstruct":
        return [
            f"Reconstruct {repository}/{name} from the approved metadata source and populate the exact target 1Password field through the temporary migration writer without printing it.",
            f"Cut every {repository} consumer of {name} over to the local 1Password broker, verify the live consumer, and only then delete the GitHub secret field.",
        ]
    return [
        f"Copy {repository}/{name} from its exact readable authority into the exact target 1Password field through the temporary migration writer without printing it.",
        f"Cut every {repository} consumer of {name} over to the local 1Password broker, verify the live consumer, and only then delete the GitHub secret field.",
    ]


def _unresolved_steps(
    repository: str,
    name: str,
    target_vault: str,
    resolution_class: str,
    handoff_group: str,
) -> list[str]:
    coordinate = f"{repository}/{name} in {target_vault} ({handoff_group})"
    if resolution_class == "workflow-reference-removal":
        return [
            f"Remove every unused {repository} workflow reference to {name} and verify the affected workflow still completes.",
            f"After the default-branch removal is live and verified, delete the matching GitHub secret field for {repository}; do not create a 1Password field.",
        ]
    if resolution_class == "independent-trust-authority":
        return [
            f"Create a new authority dedicated to {coordinate}; do not reuse an authority from another trust boundary.",
            f"Populate the exact target 1Password field through the temporary migration writer, then cut the exact workflow consumers over to the local broker.",
            f"Verify the live consumer, then delete the GitHub secret field and revoke the predecessor authority after the rollback window.",
        ]
    if resolution_class == "provider-rotation":
        return [
            f"Create the provider replacement for {coordinate} and populate the exact target 1Password field through the temporary migration writer.",
            f"Cut the exact workflow consumers over to the local broker and verify the live provider operation.",
            f"Only after verification, delete the GitHub secret field and revoke the predecessor provider credential.",
        ]
    if resolution_class == "target-system-readback":
        return [
            f"Read {coordinate} directly from the named target authority into the exact target 1Password field without displaying it.",
            f"Cut the exact workflow consumers over to the local broker and verify the live target operation.",
            f"Only after verification, delete the GitHub secret field; retain the target authority unless its owner requires replacement.",
        ]
    if resolution_class == "operator-supplied-config":
        return [
            f"Have the named operator supply or reconstruct {coordinate} directly into the exact target 1Password field without chat or terminal output.",
            f"Cut the exact workflow consumers over to the local broker and verify the live operation.",
            f"Only after verification, delete the GitHub secret field; retain the authoritative operator configuration record.",
        ]
    return [
        f"The named owner must identify a readable authority or approved replacement for {coordinate} before migration; stop if that authority cannot be proven.",
        f"Populate only the proven target 1Password field through the temporary migration writer, then cut the exact workflow consumers over to the local broker.",
        f"Verify the live consumer before deleting the GitHub secret field or revoking any predecessor.",
    ]


def _mapping(
    repository: str,
    name: str,
    source_ref: str,
    *,
    action: str = "copy",
    classification: str = "credential",
    target_vault: str = PRODUCTION_VAULT,
    authority_match: str = "reviewed-semantic",
    workflow: str | None = None,
    alias_group: str | None = None,
    target_item: str | None = None,
    target_field: str | None = None,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "mapping_id": f"{_slug(repository)}-{_slug(target_vault)}-{_slug(workflow or 'all-workflows')}-{_slug(name)}",
        "repository": repository,
        "github_secret_name": name,
        "target_vault": target_vault,
        "classification": classification,
        "migration_action": action,
        "authority_match": authority_match,
        "source_ref": source_ref,
        "downstream_update_steps": _steps(action, repository, name),
        "alias_group": alias_group or f"{repository}/{name}",
    }
    if workflow:
        result["workflow"] = workflow
    if target_item:
        result["target_item"] = target_item
    if target_field:
        result["target_field"] = target_field
    return result


def _unresolved_annotation(
    repository: str,
    name: str,
    target_vault: str,
    *,
    resolution_class: str,
    authority_owner: str,
    handoff_group: str,
    reason: str,
    provider_rotation_steps: list[str] | None = None,
    downstream_update_steps: list[str] | None = None,
    workflow: str | None = None,
    data_classification: str = "credential",
    required_runtime_identity: str | None = None,
    execution_boundary: dict[str, Any] | None = None,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "annotation_id": (
            f"{_slug(repository)}-{_slug(target_vault)}-"
            f"{_slug(workflow or 'all-workflows')}-{_slug(name)}"
        ),
        "repository": repository,
        "github_secret_name": name,
        "target_vault": target_vault,
        "resolution_class": resolution_class,
        "authority_owner": authority_owner,
        "handoff_group": handoff_group,
        "unresolved_reason": reason,
        "provider_rotation_steps": provider_rotation_steps,
        "downstream_update_steps": downstream_update_steps
        or _unresolved_steps(
            repository,
            name,
            target_vault,
            resolution_class,
            handoff_group,
        ),
        "data_classification": data_classification,
    }
    if workflow:
        result["workflow"] = workflow
    if required_runtime_identity:
        result["required_runtime_identity"] = required_runtime_identity
    if execution_boundary:
        result["execution_boundary"] = execution_boundary
    return result


def _direct_onepassword_mapping(
    repository: str,
    workflow: str,
    job: str,
    environment_name: str,
    source_reference: str,
    field_type: str,
) -> dict[str, Any]:
    match = re.fullmatch(r"op://([^/\s]+)/([^/\s]+)/([^/\s]+)", source_reference)
    if not match:
        raise ValueError("direct 1Password mapping requires a fixed source reference")
    source_vault, source_item, source_field = match.groups()
    target_vault = PRODUCTION_VAULT
    target_item = repository
    coordinate = f"{repository}:{workflow}#{job}:{environment_name}"
    return {
        "mapping_id": f"direct-op-{_slug(coordinate)}",
        "repository": repository,
        "workflow": workflow,
        "job": job,
        "environment_name": environment_name,
        "source_reference": source_reference,
        "source_vault": source_vault,
        "source_item": source_item,
        "source_field": source_field,
        "target_vault": target_vault,
        "target_item": target_item,
        "target_field": environment_name,
        "field_type": field_type,
        "consumer": "ken-deploy-production",
        "source_to_target_steps": [
            f"Use task6-temporary-migration-writer to copy {source_reference} directly into {target_vault}/{target_item}/{environment_name} without displaying the value."
        ],
        "broker_cutover_steps": [
            f"Replace the direct {source_reference} env reference in {coordinate} with the fixed production broker field {target_vault}/{target_item}/{environment_name} under ken-deploy-production.",
            "The production runtime account remains read_items-only to Ken Deploy Production and must not receive access to Development or ken-website after cutover.",
        ],
        "live_verification_steps": [
            f"Run {coordinate} and verify its real deployment or synchronization side effect succeeds through the production broker without displaying the field."
        ],
        "retirement_steps": [
            f"Only after live verification, remove the direct {source_reference} workflow reference and retire its old OP_SERVICE_ACCOUNT_TOKEN dependency; retain the source item until its owner confirms no other consumer remains."
        ],
    }


def _load_metadata(evidence_dir: Path, name: str) -> dict[str, Any]:
    path = evidence_dir / name
    try:
        parsed = json.loads(path.read_text())
    except Exception as error:
        raise ValueError(f"source metadata artifact unavailable: {name}") from error
    _validate_raw_metadata(name, parsed)
    return parsed


def _reject_forbidden_raw_fields(value: Any, path: str) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            normalized = str(key).lower().replace("-", "_")
            if normalized in {
                "value",
                "secret",
                "password",
                "token",
                "note",
                "notes",
            } or normalized.endswith(("_hash", "_length", "_prefix")):
                raise ValueError(f"forbidden raw metadata field at {path}.{key}")
            _reject_forbidden_raw_fields(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _reject_forbidden_raw_fields(child, f"{path}[{index}]")


def _object(
    value: Any, *, path: str, fields: dict[str, tuple[type, ...]]
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"invalid raw metadata object at {path}")
    unexpected = sorted(set(value) - set(fields))
    if unexpected:
        raise ValueError(
            f"unexpected raw metadata field at {path}.{unexpected[0]}"
        )
    missing = sorted(set(fields) - set(value))
    if missing:
        raise ValueError(f"missing raw metadata field at {path}.{missing[0]}")
    for key, allowed_types in fields.items():
        if not isinstance(value[key], allowed_types):
            raise ValueError(f"invalid raw metadata type at {path}.{key}")
    return value


def _list_of(value: Any, expected_type: type, path: str) -> list[Any]:
    if not isinstance(value, list) or not all(
        isinstance(item, expected_type) for item in value
    ):
        raise ValueError(f"invalid raw metadata list at {path}")
    return value


def _validate_raw_metadata(name: str, parsed: Any) -> None:
    _reject_forbidden_raw_fields(parsed, name)
    if name == "task-6-op-env-key-metadata.json":
        root = _object(
            parsed,
            path=name,
            fields={"schema_version": (int,), "collection_policy": (str,), "items": (list,)},
        )
        for item_index, item_value in enumerate(_list_of(root["items"], dict, f"{name}.items")):
            item_path = f"{name}.items[{item_index}]"
            item = _object(
                item_value,
                path=item_path,
                fields={
                    "schema_version": (int,),
                    "vault": (str,),
                    "item": (str,),
                    "keys": (list,),
                },
            )
            for key_index, key_value in enumerate(_list_of(item["keys"], dict, f"{item_path}.keys")):
                _object(
                    key_value,
                    path=f"{item_path}.keys[{key_index}]",
                    fields={
                        "name": (str,),
                        "declared_type": (str,),
                        "value_present": (bool,),
                    },
                )
    elif name == "task-6-op-field-metadata.json":
        root = _object(
            parsed,
            path=name,
            fields={"schema_version": (int,), "collection_policy": (str,), "items": (list,)},
        )
        for item_index, item_value in enumerate(_list_of(root["items"], dict, f"{name}.items")):
            item_path = f"{name}.items[{item_index}]"
            item = _object(
                item_value,
                path=item_path,
                fields={
                    "schema_version": (int,),
                    "vault": (str,),
                    "item": (str,),
                    "category": (str,),
                    "fields": (list,),
                    "files": (list,),
                },
            )
            for field_index, field_value in enumerate(_list_of(item["fields"], dict, f"{item_path}.fields")):
                _object(
                    field_value,
                    path=f"{item_path}.fields[{field_index}]",
                    fields={
                        "label": (str,),
                        "field_type": (str,),
                        "purpose": (str, type(None)),
                        "section": (str, type(None)),
                        "value_present": (bool,),
                    },
                )
            for file_index, file_value in enumerate(_list_of(item["files"], dict, f"{item_path}.files")):
                _object(
                    file_value,
                    path=f"{item_path}.files[{file_index}]",
                    fields={"name": (str,)},
                )
    elif name == "task-6-worldstream-key-metadata.json":
        root = _object(
            parsed,
            path=name,
            fields={
                "schema_version": (int,),
                "host": (str,),
                "scoped_user": (str,),
                "collection_policy": (str,),
                "keys": (list,),
            },
        )
        for key_index, key_value in enumerate(_list_of(root["keys"], dict, f"{name}.keys")):
            _object(
                key_value,
                path=f"{name}.keys[{key_index}]",
                fields={
                    "file": (str,),
                    "key_path": (str,),
                    "value_type": (str,),
                    "exists": (bool,),
                    "readable": (bool,),
                },
            )
    elif name == "task-6-connection-structure.json":
        root = _object(
            parsed,
            path=name,
            fields={
                "schema_version": (int,),
                "host": (str,),
                "scoped_user": (str,),
                "file": (str,),
                "collection_policy": (str,),
                "mysql_components": (list,),
                "mongo_connection_present": (bool,),
                "mongo_database_component_present": (bool,),
            },
        )
        _list_of(root["mysql_components"], str, f"{name}.mysql_components")
    else:
        raise ValueError(f"unregistered raw metadata schema: {name}")
    if parsed.get("schema_version") != 1:
        raise ValueError(f"invalid source metadata artifact: {name}")


def _source_is_proven(source: dict[str, Any], artifact: dict[str, Any]) -> bool:
    kind = source.get("kind")
    if kind == "deployed-config":
        return any(
            row.get("file") == source.get("file")
            and row.get("key_path") == source.get("key_path")
            and row.get("value_type") == source.get("value_type")
            and row.get("exists") is True
            and row.get("readable") is True
            for row in artifact.get("keys") or []
            if isinstance(row, dict)
        )
    if kind == "onepassword-env-key":
        return any(
            item.get("vault") == source.get("vault")
            and item.get("item") == source.get("item")
            and any(
                key.get("name") == source.get("name")
                and key.get("declared_type") == source.get("declared_type")
                and key.get("value_present") is True
                for key in item.get("keys") or []
                if isinstance(key, dict)
            )
            for item in artifact.get("items") or []
            if isinstance(item, dict)
        )
    if kind in {
        "onepassword",
        "onepassword-document",
        "onepassword-item-title-component",
    }:
        for item in artifact.get("items") or []:
            if not isinstance(item, dict):
                continue
            if item.get("vault") != source.get("vault") or item.get("item") != source.get("item"):
                continue
            if kind == "onepassword":
                return any(
                    field.get("label") == source.get("field")
                    and field.get("value_present") is True
                    for field in item.get("fields") or []
                    if isinstance(field, dict)
                )
            if kind == "onepassword-document":
                return any(
                    file.get("name") == source.get("file_name")
                    for file in item.get("files") or []
                    if isinstance(file, dict)
                )
            title_match = re.search(
                r" - (?P<username>[A-Za-z0-9._-]+)@(?P<host>[A-Za-z0-9.-]+)$",
                str(item.get("item") or ""),
            )
            return bool(title_match and source.get("component") in {"username", "host"})
        return False
    if kind == "deployed-connection-component":
        if source.get("key_path") == "ConnectionStrings.KenDb":
            return source.get("component") in set(artifact.get("mysql_components") or [])
        if source.get("key_path") == "MongoDbConfiguration.ConnectionString":
            return (
                source.get("component") == "database"
                and artifact.get("mongo_connection_present") is True
                and artifact.get("mongo_database_component_present") is True
            )
        return False
    return True


def _validate_source_metadata(
    sources: dict[str, dict[str, Any]], evidence_dir: Path
) -> None:
    cache: dict[str, dict[str, Any]] = {}
    for source_id, source in sources.items():
        artifact_name = source.get("metadata_artifact")
        if not artifact_name:
            continue
        if artifact_name not in cache:
            cache[artifact_name] = _load_metadata(evidence_dir, artifact_name)
        if not _source_is_proven(source, cache[artifact_name]):
            raise ValueError(f"source metadata not proven: {source_id}")


def build_evidence(evidence_dir: Path | None = None) -> dict[str, Any]:
    evidence_dir = evidence_dir or DEFAULT_EVIDENCE_DIR
    sources: dict[str, dict[str, Any]] = {}
    mappings: list[dict[str, Any]] = []
    unresolved_annotations: list[dict[str, Any]] = []
    secretless_migrations: list[dict[str, Any]] = []
    direct_onepassword_mappings: list[dict[str, Any]] = []

    direct_specs = (
        ("ken-vexa-mcp-auth", ".github/workflows/deploy.yml", "deploy", "SERVER_HOST", "op://Development/vexa-mcp-auth-deploy-ssh/host", "string"),
        ("ken-vexa-mcp-auth", ".github/workflows/deploy.yml", "deploy", "SERVER_PORT", "op://Development/vexa-mcp-auth-deploy-ssh/port", "string"),
        ("ken-vexa-mcp-auth", ".github/workflows/deploy.yml", "deploy", "SERVER_SSH_KEY", "op://Development/vexa-mcp-auth-deploy-ssh/private_key", "concealed"),
        ("ken-website", ".github/workflows/beehiiv-sync.yml", "sync", "DEPLOY_SSH_KEY", "op://ken-website/blog-sync-deploy/private_key", "concealed"),
        ("ken-website", ".github/workflows/beehiiv-sync.yml", "sync", "BEEHIIV_API_KEY", "op://ken-website/beehiiv/credential", "concealed"),
        ("ken-website", ".github/workflows/beehiiv-sync.yml", "sync", "BEEHIIV_PUBLICATION_ID", "op://ken-website/beehiiv/publication_id", "string"),
        ("ken-website", ".github/workflows/deploy.yml", "deploy", "NEXT_PUBLIC_POSTHOG_PROJECT_TOKEN", "op://ken-website/posthog/project_token", "string"),
        ("ken-website", ".github/workflows/deploy.yml", "deploy", "POSTHOG_PERSONAL_API_KEY", "op://ken-website/posthog/personal_api_key", "concealed"),
        ("ken-website", ".github/workflows/deploy.yml", "deploy", "WEBSITE_HOST", "op://ken-website/deploy-ssh/host", "string"),
        ("ken-website", ".github/workflows/deploy.yml", "deploy", "WEBSITE_PORT", "op://ken-website/deploy-ssh/port", "string"),
        ("ken-website", ".github/workflows/deploy.yml", "deploy", "WEBSITE_SSH_KEY", "op://ken-website/deploy-ssh/private_key", "concealed"),
    )
    direct_onepassword_mappings.extend(
        _direct_onepassword_mapping(*spec) for spec in direct_specs
    )

    def add_source(source: tuple[str, dict[str, Any]]) -> str:
        source_id, metadata = source
        if source_id in sources and sources[source_id] != metadata:
            raise ValueError(f"conflicting source metadata: {source_id}")
        sources[source_id] = metadata
        return source_id

    def annotate_many(
        repository: str,
        names: tuple[str, ...],
        target_vault: str,
        *,
        resolution_class: str,
        authority_owner: str,
        handoff_group: str,
        reason: str,
        provider_rotation_steps: list[str] | None = None,
        downstream_update_steps: list[str] | None = None,
        data_classification: str = "credential",
        required_runtime_identity: str | None = None,
        execution_boundary: dict[str, Any] | None = None,
    ) -> None:
        for name in names:
            unresolved_annotations.append(
                _unresolved_annotation(
                    repository,
                    name,
                    target_vault,
                    resolution_class=resolution_class,
                    authority_owner=authority_owner,
                    handoff_group=handoff_group,
                    reason=reason,
                    provider_rotation_steps=provider_rotation_steps,
                    downstream_update_steps=downstream_update_steps,
                    data_classification=data_classification,
                    required_runtime_identity=required_runtime_identity,
                    execution_boundary=execution_boundary,
                )
            )

    def provider_steps(provider: str, scope: str) -> list[str]:
        return [
            f"In {provider}, create a replacement credential restricted to {scope}; do not reuse a credential from another trust domain.",
            "Use the temporary migration writer to store it in the named target vault, verify the exact workflow consumer, then revoke the predecessor at the provider.",
        ]

    scraper_file = "/var/www/scraper.api/appsettings.Production.json"
    deployed_specs = [
        ("AWS_ACCESS_KEY", "AmazonBedrockConfiguration.AwsAccessKeyId", "copy", "credential"),
        ("AWS_SECRET_ACCESS_KEY", "AmazonBedrockConfiguration.AwsSecretAccessKey", "copy", "credential"),
        ("ANTHROPIC_API_KEY", "AnthropicConfiguration.ApiKey", "copy", "credential"),
        ("AUTOMATIONS_WEBHOOK_SECRET_KEY", "AutomationsWebhookConfiguration.SecretKey", "copy", "credential"),
        ("CALCOM_CLIENT_ID", "CalComOAuth.ClientId", "move-to-variable", "identifier"),
        ("CALCOM_CLIENT_SECRET", "CalComOAuth.ClientSecret", "copy", "credential"),
        ("CALENDLY_CLIENT_ID", "CalendlyOAuth.ClientId", "move-to-variable", "identifier"),
        ("CALENDLY_CLIENT_SECRET", "CalendlyOAuth.ClientSecret", "copy", "credential"),
        ("CLERK_SECRET_KEY", "Clerk.SecretKey", "copy", "credential"),
        ("CLERK_WEBHOOK_SECRET", "Clerk.WebhookSecret", "copy", "credential"),
        ("CLICKUP_API_TOKEN", "ClickUpAlerting.ApiToken", "copy", "credential"),
        ("CLICKUP_LIST_ID", "ClickUpAlerting.ListId", "move-to-variable", "identifier"),
        ("DB_CONNECTION_STRING2", "ConnectionStrings.KenDb", "copy", "credential"),
        ("READ_REPLICA_CONNECTION_STRING", "ConnectionStrings.KenDbReadReplica", "copy", "credential"),
        ("MONGO_CONNECTION_STRING2", "MongoDbConfiguration.ConnectionString", "copy", "credential"),
        ("DEEPSEEK_API_KEY", "DeepSeekConfiguration.ApiKey", "copy", "credential"),
        ("DEMO_PERSONALIZATION_API_KEY", "DemoPersonalization.ApiKey", "copy", "credential"),
        ("DEMO_PERSONALIZATION_REF_SIGNING_SECRET", "DemoPersonalization.RefSigningSecret", "copy", "credential"),
        ("DOUBLEWORD_API_KEY", "DoublewordConfiguration.ApiKey", "copy", "credential"),
        ("EMAIL_BISON__ADMIN_API_KEY", "EmailBison.ApiKey", "copy", "credential"),
        ("FIRECRAWL_BASE_URL", "FirecrawlConfiguration.BaseUrl", "move-to-variable", "configuration"),
        ("FIREWORKS_ACCOUNT_ID", "FireworksConfiguration.AccountId", "move-to-variable", "identifier"),
        ("FIREWORKS_AI_API_KEY", "FireworksConfiguration.ApiKey", "copy", "credential"),
        ("HUBSPOT_CLIENT_ID", "HubSpotCalendarOptions.ClientId", "move-to-variable", "identifier"),
        ("HUBSPOT_CLIENT_SECRET", "HubSpotCalendarOptions.ClientSecret", "copy", "credential"),
        ("HYPERTIDE_API_TOKEN", "HypertideConfiguration.ApiToken", "copy", "credential"),
        ("INBOXKIT_API_KEY", "InboxkitConfiguration.ApiKey", "copy", "credential"),
        ("INBOXKIT_WORKSPACE_ID", "InboxkitConfiguration.WorkspaceId", "move-to-variable", "identifier"),
        ("INSTANTLY_API_KEY", "InstantlyConfiguration.ApiKey", "copy", "credential"),
        ("JWT_SECRET", "JwtSettings.SecretKey", "copy", "credential"),
        ("KEN_AI_ADMIN_API_KEY", "Security.AdminApiKey", "copy", "credential"),
        ("KEN_REDIRECT_BASE_URL", "KenRedirect.BaseUrl", "move-to-variable", "configuration"),
        ("KEN_REDIRECT_BEARER_TOKEN", "KenRedirect.BearerToken", "copy", "credential"),
        ("KEN_REDIRECT_CLIENT_PFX_PASSWORD", "KenRedirect.ClientCertificatePassword", "copy", "credential"),
        ("KEN_SEARCH_CLERK_USER_ID", "KenSearch.ClerkUserId", "move-to-variable", "identifier"),
        ("KEN_SEARCH_INTERNAL_TOKEN", "KenSearch.ServiceBearerToken", "copy", "credential"),
        ("LANGFUSE_BASE_URL", "Langfuse.BaseUrl", "move-to-variable", "configuration"),
        ("LANGFUSE_PUBLIC_KEY", "Langfuse.PublicKey", "move-to-variable", "identifier"),
        ("LANGFUSE_SECRET_KEY", "Langfuse.SecretKey", "copy", "credential"),
        ("LEAD_MAGIC_API_KEY", "LeadMagicConfiguration.ApiKey", "copy", "credential"),
        ("MOONSHOT_API_KEY", "MoonshotConfiguration.ApiKey", "copy", "credential"),
        ("ONBOARDING_PREFILL_INTERNAL_TOKEN", "Onboarding.PrefillInternalToken", "copy", "credential"),
        ("OPEN_AI_API_KEY", "OpenAi.ApiKey", "copy", "credential"),
        ("OPEN_ROUTER_API_KEY", "OpenRouterConfiguration.ApiKey", "copy", "credential"),
        ("OUT_ENGINE_API_KEY", "OutEngineConfiguration.ApiKey", "copy", "credential"),
        ("OUT_ENGINE_CUSTOMER_ID", "OutEngineConfiguration.CustomerId", "move-to-variable", "identifier"),
        ("PORKBUN_API_KEY", "PorkbunRegistrar.ApiKey", "copy", "credential"),
        ("PORKBUN_SECRET_API_KEY", "PorkbunRegistrar.SecretApiKey", "copy", "credential"),
        ("SECRET_STORE_KEY_V1", "SecretStore.Keys.1", "copy", "credential"),
        ("STRIPE_API_KEY", "StripeConfiguration.ApiKey", "copy", "credential"),
        ("STRIPE_WEBHOOK_SIGNING_SECRET", "StripeConfiguration.WebhookSigningSecret", "copy", "credential"),
        ("SVIX_AUTH_TOKEN", "SvixConfiguration.AuthToken", "copy", "credential"),
        ("TOGETHER_AI_API_KEY", "TogetherAiConfiguration.ApiKey", "copy", "credential"),
        ("TWENTY_CRM_API_KEY", "TwentyCrm.ApiKey", "copy", "credential"),
        ("UNIPILE_API_KEY", "Unipile.ApiKey", "copy", "credential"),
        ("WEBHOOK_SECURITY_API_KEY", "WebhookSecurity.ApiKey", "copy", "credential"),
        ("xAI_API_KEY", "XAIConfiguration.ApiKey", "copy", "credential"),
    ]
    for name, key_path, action, classification in deployed_specs:
        source_ref = add_source(_deployed_source(scraper_file, key_path))
        mappings.append(
            _mapping(
                "ken-backend",
                name,
                source_ref,
                action=action,
                classification=classification,
            )
        )

    worker_specs = [
        ("ENROW_API_KEY", "/var/www/enrow.worker/appsettings.Production.json", "EnrowConfiguration.ApiKey"),
        ("FINDYMAIL_API_KEY", "/var/www/findemail.worker/appsettings.Production.json", "FindymailConfiguration.ApiKey"),
        ("ICYPEAS_API_KEY", "/var/www/icypeas.worker/appsettings.Production.json", "IcypeasConfiguration.ApiKey"),
        ("KITT_API_KEY", "/var/www/kittenrichment.worker/appsettings.Production.json", "KittConfiguration.ApiKey"),
        ("MAIL_TESTER_API_KEY", "/var/www/mailtester.worker/appsettings.Production.json", "MailTesterConfiguration.ApiKey"),
        ("PROSPEO_API_KEY", "/var/www/prospeo.worker/appsettings.Production.json", "ProspeoConfiguration.ApiKey"),
        ("SHORT_IO_API_KEY", "/var/www/deliverability.api/appsettings.Production.json", "ShortIoConfiguration.ApiKey"),
    ]
    for name, file, key_path in worker_specs:
        source_ref = add_source(_deployed_source(file, key_path))
        mappings.append(_mapping("ken-backend", name, source_ref))

    cloudflare_fields = [
        "CLOUDFLARE_API_TOKEN",
        "CLOUDFLARE_EDGE_ACCESS_CLIENT_ID",
        "CLOUDFLARE_EDGE_ACCESS_CLIENT_SECRET",
        "CLOUDFLARE_EDGE_CONTROL_HMAC_SECRET",
        "CLOUDFLARE_EDGE_CONTROL_BEARER",
        "CLOUDFLARE_EDGE_STANDBY_HMAC_SECRET",
        "CLOUDFLARE_EDGE_STANDBY_BEARER",
        "CLOUDFLARE_EDGE_CLICK_INGEST_HMAC_SECRET",
        "CLOUDFLARE_EDGE_CLICK_INGEST_BEARER",
        "CLOUDFLARE_EDGE_PROVIDER_INVENTORY_HMAC_SECRET",
    ]
    for name in cloudflare_fields:
        source_ref = add_source(
            _op_source("Development", "Cloudflare Edge Production Secrets", name, "CONCEALED")
        )
        is_identifier = name == "CLOUDFLARE_EDGE_ACCESS_CLIENT_ID"
        mappings.append(
            _mapping(
                "ken-backend",
                name,
                source_ref,
                action="move-to-variable" if is_identifier else "copy",
                classification="identifier" if is_identifier else "credential",
                authority_match="exact-field",
                alias_group=f"cloudflare-edge/{name}",
            )
        )

    clerk_secret = add_source(
        _op_source("Development", "Clerk Production API", "CLERK_SECRET_KEY", "CONCEALED")
    )
    clerk_public = add_source(
        _op_source(
            "Development",
            "Clerk Production API",
            "NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY",
            "STRING",
        )
    )
    ghcr = add_source(_op_source("Development", "GHCR_PULL_TOKEN", "credential", "CONCEALED"))
    frontend_host = add_source(_op_source("Development", "Frontend Server", "hostname", "STRING"))
    frontend_user = add_source(_op_source("Development", "Frontend Server", "username", "STRING"))
    frontend_key = add_source(_op_source("Development", "Frontend Server", "private key", "CONCEALED"))
    langfuse_secret = add_source(
        _op_source("Development", "Langfuse Production API Credentials", "Secret Key", "CONCEALED")
    )
    langfuse_public = add_source(
        _op_source("Development", "Langfuse Production API Credentials", "Public Key", "STRING")
    )
    langfuse_url = add_source(
        _op_source("Development", "Langfuse Production API Credentials", "Base Url", "STRING")
    )
    frontend_specs = [
        ("CLERK_SECRET_KEY", clerk_secret, "copy", "credential"),
        ("NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY", clerk_public, "move-to-variable", "identifier"),
        ("GHCR_PULL_TOKEN", ghcr, "copy", "credential"),
        ("DEPLOY_HOST", frontend_host, "move-to-variable", "identifier"),
        ("DEPLOY_USER", frontend_user, "move-to-variable", "identifier"),
        ("DEPLOY_SSH_KEY", frontend_key, "copy", "credential"),
        ("LANGFUSE_SECRET_KEY", langfuse_secret, "copy", "credential"),
        ("LANGFUSE_PUBLIC_KEY", langfuse_public, "move-to-variable", "identifier"),
        ("LANGFUSE_BASE_URL", langfuse_url, "move-to-variable", "configuration"),
    ]
    for name, source_ref, action, classification in frontend_specs:
        mappings.append(
            _mapping(
                "ken-frontend",
                name,
                source_ref,
                action=action,
                classification=classification,
                authority_match="exact-field" if name in {"CLERK_SECRET_KEY", "NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY"} else "reviewed-semantic",
            )
        )

    clickup = add_source(_op_source("Development", "ClickUp API Key", "credential", "CONCEALED"))
    for repository in ("ken-agents", "ken-search"):
        mappings.append(_mapping(repository, "CLICKUP_API_TOKEN", clickup))
    for name, source_ref, action, classification in (
        ("LANGFUSE_SECRET_KEY", langfuse_secret, "copy", "credential"),
        ("LANGFUSE_PUBLIC_KEY", langfuse_public, "move-to-variable", "identifier"),
    ):
        mappings.append(
            _mapping(
                "ken-agents",
                name,
                source_ref,
                action=action,
                classification=classification,
            )
        )

    worldstream_host = "inventory-hosts-worldstream-host"
    sources[worldstream_host] = {
        "kind": "evidence-key",
        "artifact": "hosts-2026-08-19.json",
        "key_path": "worldstream.host",
        "exists": True,
        "readable": True,
    }
    worldstream_user = add_source(
        _op_source("Development", "worldstream machine ssh", "username", "STRING")
    )
    worldstream_pass = add_source(
        _op_source("Development", "worldstream machine ssh", "password", "CONCEALED")
    )
    for repository in ("ken-backend", "ken-ai-mcp", "ken-ai-public-mcp"):
        mappings.extend(
            [
                _mapping(
                    repository,
                    "WORLDSTREAM_HOST",
                    worldstream_host,
                    action="reconstruct",
                    classification="identifier",
                    alias_group="worldstream-machine-ssh",
                ),
                _mapping(
                    repository,
                    "WORLDSTREAM_USER",
                    worldstream_user,
                    action="move-to-variable",
                    classification="identifier",
                    alias_group="worldstream-machine-ssh",
                ),
                _mapping(
                    repository,
                    "WORLDSTREAM_PASSWORD",
                    worldstream_pass,
                    alias_group="worldstream-machine-ssh",
                    target_item="worldstream-machine-ssh",
                    target_field="password",
                ),
            ]
        )

    round_two_deployed = [
        ("ABUSEIPDB_API_KEY", "/var/www/deliverability.api/appsettings.Production.json", "DomainHealth.AbuseIpDb.ApiKey", "copy", "credential", "string"),
        ("APIFY_API_KEY", "/var/www/websitescraper.worker/appsettings.Production.json", "ApifyConfiguration.ApiKey", "copy", "credential", "string"),
        ("BACKBLAZE_APPLICATION_KEY", "/var/www/clickevent.processor/appsettings.Production.json", "BackblazeB2.ApplicationKey", "copy", "credential", "string"),
        ("BACKBLAZE_BUCKET_NAME", "/var/www/clickevent.processor/appsettings.Production.json", "BackblazeB2.BucketName", "move-to-variable", "configuration", "string"),
        ("BACKBLAZE_KEY_ID", "/var/www/clickevent.processor/appsettings.Production.json", "BackblazeB2.KeyId", "move-to-variable", "identifier", "string"),
        ("DELIVERABILITY_ADMIN_API_KEY", "/var/www/deliverability.api/appsettings.Production.json", "Security.AdminApiKey", "copy", "credential", "string"),
        ("DELIVERABILITY_INTERNAL_API_KEY", "/var/www/deliverability.api/appsettings.Production.json", "InternalApiSecurity.ApiKey", "copy", "credential", "string"),
        ("MISTRAL_API_KEY", scraper_file, "CampaignBuildOcr.MistralApiKey", "copy", "credential", "string"),
        ("PLUSVIBE_API_KEY", scraper_file, "Warmup.Plusvibe.ApiKey", "copy", "credential", "string"),
        ("PLUSVIBE_WORKSPACE_ID", scraper_file, "Warmup.Plusvibe.WorkspaceId", "move-to-variable", "identifier", "string"),
        ("REDIRECT_INGEST_INTERNAL_TOKEN", scraper_file, "InternalServiceAuth.Tokens.1", "copy", "credential", "string"),
        ("CLOUDFLARE_REDIRECT_INTERNAL_BEARER", scraper_file, "InternalServiceAuth.Tokens.2", "copy", "credential", "string"),
        ("CLOUDFLARE_EDGE_CLICK_INGEST_BEARER_PRODUCTION", scraper_file, "InternalServiceAuth.Tokens.3", "copy", "credential", "string"),
        ("CLOUDFLARE_REDIRECT_HMAC_KEY", scraper_file, "CloudflareRedirectIngress.HmacSecret", "copy", "credential", "string"),
        ("REDIRECT_WATCHDOG_ALERT_TOKEN_SHA256", scraper_file, "RedirectWatchdogAlerting.TokenSha256", "move-to-variable", "configuration", "string"),
        ("RESEND_API_KEY", "/var/www/clickevent.processor/appsettings.Production.json", "Resend.ApiKey", "copy", "credential", "string"),
        ("RESEND_CONTACT_SYNC_ENABLED", "/var/www/clickevent.processor/appsettings.Production.json", "Resend.ContactSync.Enabled", "move-to-variable", "configuration", "boolean"),
        ("RESEND_FREE_SEGMENT_ID", "/var/www/clickevent.processor/appsettings.Production.json", "Resend.ContactSync.FreeSegmentId", "move-to-variable", "identifier", "string"),
        ("RESEND_STARTER_SEGMENT_ID", "/var/www/clickevent.processor/appsettings.Production.json", "Resend.ContactSync.StarterSegmentId", "move-to-variable", "identifier", "string"),
        ("RESEND_GROWTH_SEGMENT_ID", "/var/www/clickevent.processor/appsettings.Production.json", "Resend.ContactSync.GrowthSegmentId", "move-to-variable", "identifier", "string"),
        ("SPAMHAUS_DQS_KEY", "/var/www/deliverability.api/appsettings.Production.json", "DomainHealth.Spamhaus.DqsKey", "copy", "credential", "string"),
    ]
    for name, file, key_path, action, classification, value_type in round_two_deployed:
        source_ref = add_source(_deployed_source(file, key_path, value_type))
        mappings.append(
            _mapping(
                "ken-backend",
                name,
                source_ref,
                action=action,
                classification=classification,
            )
        )

    dbops_user = add_source(
        _op_source("Development", "SSH Backend - dbops", "username", "STRING")
    )
    dbops_key = add_source(
        _op_source("Development", "SSH Backend - dbops", "private_key", "CONCEALED")
    )
    mappings.extend(
        [
            _mapping(
                "ken-backend",
                "SCHEMA_TUNNEL_USER",
                dbops_user,
                action="move-to-variable",
                classification="identifier",
            ),
            _mapping("ken-backend", "SCHEMA_TUNNEL_PRIVATE_KEY", dbops_key),
        ]
    )

    # Source-proven provider rotations. These remain unresolved until the
    # provider issues the replacement; the evidence only makes the handoff
    # owner and procedure explicit.
    provider_publications = [
        ("ken-scraping", ("NUGET_API_KEY",), "NuGet.org", "the Firecrawl .NET package", "publishing/nuget"),
        ("ken-scraping", ("HEX_API_KEY",), "Hex.pm", "the Firecrawl Elixir package", "publishing/hex"),
        ("ken-scraping", ("MAVEN_USERNAME", "MAVEN_PASSWORD"), "Sonatype Maven Central", "the Firecrawl Java package", "publishing/maven-central"),
        ("ken-scraping", ("GPG_SIGNING_KEY", "GPG_SIGNING_PASSWORD"), "Ken release-signing owner", "the Firecrawl Java release-signing identity", "publishing/java-signing"),
        ("ken-scraping", ("NPM_TOKEN",), "npm", "the Firecrawl JavaScript packages", "publishing/npm"),
        ("ken-scraping", ("PACKAGIST_USERNAME", "PACKAGIST_TOKEN"), "Packagist", "the firecrawl/firecrawl-php package", "publishing/packagist"),
        ("ken-scraping", ("PYPI_USERNAME", "PYPI_PASSWORD"), "PyPI", "the Firecrawl Python package", "publishing/pypi"),
        ("ken-scraping", ("RUBYGEMS_API_KEY",), "RubyGems", "the Firecrawl Ruby gem", "publishing/rubygems"),
        ("ken-scraping", ("CRATES_IO_TOKEN",), "crates.io", "the Firecrawl Rust crate", "publishing/crates-io"),
    ]
    for repository, names, provider, scope, group in provider_publications:
        annotate_many(
            repository,
            names,
            PRODUCTION_VAULT,
            resolution_class="provider-rotation",
            authority_owner=f"{provider} project owner",
            handoff_group=group,
            reason=(
                f"The default-branch publisher names {provider}, while GitHub exposes only secret-name metadata and no readable authority was found."
            ),
            provider_rotation_steps=provider_steps(provider, scope),
        )

    github_deploy_key_steps = [
        "Create a dedicated deploy-key pair for the exact target repository and add only its public key with the workflow-required write permission.",
        "Store the private key through the temporary migration writer, verify the repository push, then remove the predecessor deploy key from GitHub.",
    ]
    annotate_many(
        "ken-scraping",
        ("PHP_SDK_DEPLOY_KEY",),
        PRODUCTION_VAULT,
        resolution_class="provider-rotation",
        authority_owner="GitHub firecrawl/firecrawl-php repository administrator",
        handoff_group="publishing/firecrawl-php-deploy-key",
        reason="The publisher pushes over SSH to firecrawl/firecrawl-php, but GitHub exposes only the deploy-key secret name.",
        provider_rotation_steps=github_deploy_key_steps,
    )
    secretless_migrations.extend(
        [
            {
                "migration_id": "ken-sre-pypi-trusted-publisher",
                "repository": "Ken-SRE",
                "workflow": ".github/workflows/python-publish.yml",
                "github_secret_name": "PYPI_API_TOKEN",
                "migration_action": "oidc-trusted-publisher",
                "target_vault": None,
                "target_item": None,
                "target_field": None,
                "target_runner_class": "public-github-hosted",
                "required_permissions": {"contents": "read", "id-token": "write"},
                "trusted_publisher": {
                    "project": "derisk-mono",
                    "owner": "Ken-Technology",
                    "repository": "Ken-SRE",
                    "workflow": "python-publish.yml",
                    "environment": "pypi",
                },
                "packaging_contract": {
                    "source": "pyproject.toml",
                    "backend": "hatchling.build",
                    "project": "derisk-mono",
                    "install_command": "python -m pip install --upgrade build twine",
                    "build_command": "python -m build --sdist --wheel .",
                    "verification_command": "python -m twine check dist/*",
                    "broken_command_to_remove": "python setup.py sdist bdist_wheel",
                    "task": "Task 7",
                    "checked_default_sha": "61622aa518666c30db703acb939cd4ab7f58d128",
                    "pyproject_blob_sha": "a2a0651ca856601492b914c4cdc92ba1955667a4",
                    "root_setup_py_present": False,
                    "status": "task7-change-required",
                },
                "provider_setup_steps": [
                    "In the PyPI derisk-mono project, add a Trusted Publisher for owner Ken-Technology, repository Ken-SRE, workflow python-publish.yml, and environment pypi."
                ],
                "downstream_update_steps": [
                    "Task 7 must remove the broken root python setup.py sdist bdist_wheel path, install build and twine with python -m pip install --upgrade build twine, build the checked root pyproject.toml with python -m build --sdist --wheel ., and pass python -m twine check dist/* before publication.",
                    "Separate the artifact build from the publish job, keep both on GitHub-hosted runners, set top-level workflow permissions to contents: read and id-token: write, ensure the build job overrides permissions to contents: read only, bind the publish job to environment pypi, and configure pypa/gh-action-pypi-publish without a password input or PYPI_API_TOKEN reference."
                ],
                "live_verification_steps": [
                    "Publish one intended derisk-mono release through the exact PyPI Trusted Publisher and verify the expected project version plus provenance before removing the old path."
                ],
                "retirement_steps": [
                    "After the verified OIDC publish, revoke the predecessor PyPI credential and delete PYPI_API_TOKEN from GitHub."
                ],
            },
            {
                "migration_id": "ken-ai-plugin-pull-publisher",
                "repository": "ken-ai-plugin",
                "workflow": ".github/workflows/publish-cold-email-skills.yml",
                "github_secret_name": "COLD_EMAIL_SKILLS_DEPLOY_KEY",
                "migration_action": "pull-based-publisher",
                "target_vault": None,
                "target_item": None,
                "target_field": None,
                "target_runner_class": "public-github-hosted",
                "required_permissions": {"contents": "write"},
                "provider_setup_steps": [
                    "Implement Task 7 in public Ken-Technology/cold-email-skills before changing the source publisher."
                ],
                "downstream_update_steps": [
                    "In cold-email-skills, add a GitHub-hosted scheduled and workflow_dispatch publisher that checks out public ken-ai-plugin@main, runs the existing deterministic build and tests, and commits the generated tree with the target repository GITHUB_TOKEN."
                ],
                "live_verification_steps": [
                    "Run the pull publisher, compare its generated tree with the existing source-push output, and verify a target-repository commit is created with no deploy key."
                ],
                "retirement_steps": [
                    "Only after equivalent live output is verified, remove ken-ai-plugin's source-push workflow and COLD_EMAIL_SKILLS_DEPLOY_KEY, then remove the predecessor deploy key from cold-email-skills."
                ],
                "cross_repo_task": {
                    "task": "Task 7",
                    "source_repository": "Ken-Technology/ken-ai-plugin",
                    "source_ref": "main",
                    "target_repository": "Ken-Technology/cold-email-skills",
                    "authentication": "GITHUB_TOKEN",
                },
            },
        ]
    )

    github_pat_steps = [
        "Create a fine-grained GitHub credential owned by the automation identity and restrict it to the exact repositories and read-only contents/packages permissions named by the workflow.",
        "Store it in only the named trust-domain vault, verify the read-only workflow, then revoke the predecessor credential in GitHub.",
    ]
    for vault, group in (
        (PRODUCTION_VAULT, "github/ken-ai-mcp-backend-read-production"),
        ("Ken CI Runtime", "github/ken-ai-mcp-backend-read-ci"),
    ):
        annotate_many(
            "ken-ai-mcp",
            ("KEN_BACKEND_READ_TOKEN",),
            vault,
            resolution_class="provider-rotation",
            authority_owner="GitHub Ken-Technology/ken-backend repository administrator",
            handoff_group=group,
            reason="The workflow requires a fine-grained GitHub credential with read-only ken-backend contents access; GitHub does not return its current value.",
            provider_rotation_steps=github_pat_steps,
        )
    for vault, group in (
        (PRODUCTION_VAULT, "github/ken-search-packages-read-production"),
        ("Ken CI Runtime", "github/ken-search-packages-read-ci"),
    ):
        annotate_many(
            "ken-search",
            ("KEN_GITHUB_PACKAGES_READ_TOKEN",),
            vault,
            resolution_class="provider-rotation",
            authority_owner="GitHub Ken-Technology package administrator",
            handoff_group=group,
            reason="The workflow consumes private GitHub packages and GitHub returns only the credential name.",
            provider_rotation_steps=github_pat_steps,
        )
    annotate_many(
        "ken-scraping",
        ("SCRAPE_EVALS_PAT",),
        "Ken CI Runtime",
        resolution_class="provider-rotation",
        authority_owner="GitHub repository administrator",
        handoff_group="github/ken-scraping-evals-ci",
        reason="The default-branch workflow identifies a GitHub PAT consumer, but GitHub cannot return the current credential.",
        provider_rotation_steps=github_pat_steps,
    )

    unresolved_annotations.append(
        _unresolved_annotation(
            "ken-scraping",
            "TEST_API_KEY",
            PRODUCTION_VAULT,
            resolution_class="workflow-reference-removal",
            authority_owner="ken-scraping workflow maintainer",
            handoff_group="workflow-cleanup/unused-test-api-key",
            reason="The default-branch JS publisher declares TEST_API_KEY at workflow scope but no step consumes it.",
            data_classification="credential",
        )
    )

    # Remaining source-proven system owners. These do not invent an authority:
    # they collapse the one-stop handoff into coherent target readbacks or
    # independent trust-domain creations.
    annotate_many(
        "ken-backend",
        (
            "CLOUDFLARE_EDGE_RESOURCE_CONTRACT_VERSION",
            "CLOUDFLARE_EDGE_RESOURCE_MANIFEST_BASE64",
            "CLOUDFLARE_EDGE_PHASE0_EVIDENCE_BASE64",
            "CLOUDFLARE_EDGE_PROVIDER_INVENTORY_BASE64",
        ),
        PRODUCTION_VAULT,
        resolution_class="operator-supplied-config",
        authority_owner="Cloudflare edge production operator",
        handoff_group="backend/cloudflare-edge-private-inputs",
        reason="The repository runbook requires a coordinated provider-bootstrap reconstruction; the current private artifacts exist only as GitHub name metadata.",
        data_classification="configuration",
    )
    annotate_many(
        "ken-backend",
        ("CLOUDFLARE_EDGE_SPEND_GUARD_API_TOKEN",),
        PRODUCTION_VAULT,
        resolution_class="provider-rotation",
        authority_owner="Cloudflare Ken AI account administrator",
        handoff_group="backend/cloudflare-spend-guard",
        reason="The edge workflow requires a dedicated Cloudflare spend-guard credential and no readable matching authority was found.",
        provider_rotation_steps=provider_steps(
            "Cloudflare", "the exact read-only spend-guard account and zone permissions"
        ),
    )
    annotate_many(
        "ken-backend",
        ("REDIRECT_DEPLOY_SSH_KEY", "REDIRECT_DEPLOY_HOST", "REDIRECT_DEPLOY_HOST_KEY"),
        PRODUCTION_VAULT,
        resolution_class="target-system-readback",
        authority_owner="Ken redirector production host administrator",
        handoff_group="backend/redirector-deploy-identity",
        reason="The runbook binds these fields to the non-root redirector deploy identity; no readable credential bundle was found.",
    )
    annotate_many(
        "ken-backend",
        ("REDIRECT_RELEASE_SIGNING_PRIVATE_KEY",),
        PRODUCTION_VAULT,
        resolution_class="independent-trust-authority",
        authority_owner="Ken redirector release-signing owner",
        handoff_group="backend/redirector-release-signing",
        reason="The workflow and host runbook prove a dedicated release-signing identity, but the current private key has no readable authority.",
    )
    annotate_many(
        "ken-backend",
        (
            "CLOUDFLARE_REDIRECT_ORIGIN_PULL_CA_BASE64",
            "CLOUDFLARE_REDIRECT_INGRESS_CERT_BASE64",
            "CLOUDFLARE_REDIRECT_INGRESS_KEY_BASE64",
            "CLOUDFLARE_REDIRECT_ORIGIN_ALLOWLIST_BASE64",
            "REDIRECT_SYNC_SERVER_CERT_BASE64",
            "REDIRECT_SYNC_SERVER_KEY_BASE64",
            "REDIRECT_SYNC_CLIENT_CA_BASE64",
            "REDIRECT_SYNC_SOURCE_ALLOWLIST_BASE64",
            "KEN_REDIRECT_CLIENT_PFX_BASE64",
        ),
        PRODUCTION_VAULT,
        resolution_class="target-system-readback",
        authority_owner="Ken redirector production PKI operator",
        handoff_group="backend/redirector-pki-material",
        reason="The deploy workflow maps these fields to the installed redirector PKI and allowlist contract, but no readable source bundle was found.",
    )
    annotate_many(
        "ken-backend",
        (
            "CLOUDFLARE_REDIRECT_ACCESS_CLIENT_ID",
            "CLOUDFLARE_REDIRECT_ACCESS_CLIENT_SECRET",
        ),
        PRODUCTION_VAULT,
        resolution_class="provider-rotation",
        authority_owner="Cloudflare Access administrator",
        handoff_group="backend/redirector-cloudflare-access",
        reason="The backend deploy workflow proves these are a Cloudflare Access service credential, while GitHub exposes names only.",
        provider_rotation_steps=provider_steps(
            "Cloudflare Access", "the redirect ingress service application"
        ),
    )
    annotate_many(
        "ken-backend",
        ("SCHEMA_TUNNEL_KNOWN_HOSTS",),
        PRODUCTION_VAULT,
        resolution_class="target-system-readback",
        authority_owner="Worldstream database tunnel host administrator",
        handoff_group="backend/schema-tunnel-known-hosts",
        reason="The workflow requires the database tunnel host public key; current GitHub metadata is name-only.",
        data_classification="configuration",
    )
    annotate_many(
        "ken-backend",
        ("STAGING_BACKEND_HOST",),
        "Ken Deploy Nonproduction",
        resolution_class="target-system-readback",
        authority_owner="Ken staging host administrator",
        handoff_group="backend/staging-host",
        reason="The staging deploy host is not present in the readable authority metadata.",
        data_classification="identifier",
    )

    notification_reason = "The workflow posts deployment status to this endpoint, but no readable endpoint authority was found."
    for repository in ("ken-frontend", "ken-agents", "ken-daily"):
        annotate_many(
            repository,
            ("CLICKUP_WEBHOOK_URL",),
            PRODUCTION_VAULT,
            resolution_class="unknown-authority",
            authority_owner="Ken deployment-notification integration owner",
            handoff_group="shared/deployment-notification-webhook",
            reason=notification_reason,
            data_classification="configuration",
        )

    annotate_many(
        "ken-frontend",
        ("NEXT_PUBLIC_POSTHOG_PROJECT_TOKEN", "POSTHOG_PERSONAL_API_KEY"),
        PRODUCTION_VAULT,
        resolution_class="provider-rotation",
        authority_owner="PostHog Ken project administrator",
        handoff_group="frontend/posthog",
        reason="The frontend deploy workflow proves these are PostHog project credentials, but no readable authority was found.",
        provider_rotation_steps=provider_steps(
            "PostHog", "the Ken production project and deployment operations"
        ),
    )
    annotate_many(
        "ken-frontend",
        ("POSTHOG_PROJECT_ID",),
        PRODUCTION_VAULT,
        resolution_class="operator-supplied-config",
        authority_owner="PostHog Ken project administrator",
        handoff_group="frontend/posthog",
        reason="The PostHog project identifier can be read from the project settings, but it was not present in readable evidence.",
        data_classification="identifier",
    )
    annotate_many(
        "ken-frontend",
        ("NEXT_SERVER_ACTIONS_ENCRYPTION_KEY",),
        PRODUCTION_VAULT,
        resolution_class="independent-trust-authority",
        authority_owner="ken-frontend runtime owner",
        handoff_group="frontend/server-actions-encryption",
        reason="This application encryption key must remain stable across replicas; no readable runtime authority was found.",
        downstream_update_steps=[
            "Create a new production-only server-actions encryption authority and populate only Ken Deploy Production/ken-frontend/NEXT_SERVER_ACTIONS_ENCRYPTION_KEY through the temporary migration writer.",
            "Task 7 must run build-image on ken-deploy-production through task7-fixed-production-image-build; the wrapper obtains the key from the local production broker and passes it only to the fixed production image build.",
            "The ken-ci pools may run no-secret validation only and must never build or publish the production image artifact.",
            "Verify the production image build and both production replicas before deleting the GitHub field and revoking the predecessor authority after the rollback window.",
        ],
        required_runtime_identity="ken-deploy-production",
        execution_boundary={
            "workflow": ".github/workflows/deploy.yml",
            "production_build_job": "build-image",
            "deployment_job": "deploy",
            "runner_class": "ken-deploy-production",
            "build_wrapper": "task7-fixed-production-image-build",
            "broker_only": True,
            "ci_validation_only": True,
            "forbid_ken_ci_production_artifact": True,
        },
    )
    for repository in ("ken-frontend", "ken-agents"):
        annotate_many(
            repository,
            ("KEN_AGENTS_INTERNAL_KEY",),
            PRODUCTION_VAULT,
            resolution_class="independent-trust-authority",
            authority_owner="Ken agents platform owner",
            handoff_group="shared/ken-agents-internal-key",
            reason="Both production consumers require one coordinated internal-service authority; no readable source was found and no unrelated credential may be reused.",
        )

    annotate_many(
        "ken-search",
        ("ELASTICSEARCH_CERT_FINGERPRINT",),
        PRODUCTION_VAULT,
        resolution_class="target-system-readback",
        authority_owner="Ken Search Elasticsearch administrator",
        handoff_group="search/elasticsearch-tls",
        reason="The deploy workflow maps this to Elasticsearch.CertificateFingerprint; the live certificate fingerprint was not in readable evidence.",
        data_classification="configuration",
    )
    annotate_many(
        "ken-search",
        ("DEEPSEEK_API_KEY",),
        PRODUCTION_VAULT,
        resolution_class="provider-rotation",
        authority_owner="DeepSeek Ken account administrator",
        handoff_group="search/deepseek-production",
        reason="The workflow explicitly calls api.deepseek.com, but no exact readable authority for this Search trust boundary was proven.",
        provider_rotation_steps=provider_steps(
            "DeepSeek", "the Ken Search production expansion service"
        ),
    )
    annotate_many(
        "ken-ai-mcp",
        ("DB_PORT",),
        PRODUCTION_VAULT,
        resolution_class="target-system-readback",
        authority_owner="Worldstream MySQL administrator",
        handoff_group="mcp/mysql-endpoint",
        reason="The deployed connection evidence proves server, user, database, and password components but does not contain an explicit port component.",
        data_classification="identifier",
    )
    annotate_many(
        "ken-ai-mcp",
        ("MCP_SMOKE_TOKEN",),
        PRODUCTION_VAULT,
        resolution_class="independent-trust-authority",
        authority_owner="Ken API credential administrator",
        handoff_group="mcp/production-smoke-identity",
        reason="The workflow identifies this as a Ken API bearer used by post-deploy smoke tests; no readable matching API credential was proven.",
    )

    annotate_many(
        "ken-agents",
        ("DEPLOY_HOST", "DEPLOY_USER", "DEPLOY_SSH_KEY"),
        PRODUCTION_VAULT,
        resolution_class="target-system-readback",
        authority_owner="Ken agents production host administrator",
        handoff_group="agents/deploy-identity",
        reason="The workflow deploys to /var/www/ken-agents, but the target host credential bundle was not readable from approved evidence and devws was not contacted.",
    )
    annotate_many(
        "ken-agents",
        ("LANGSMITH_API_KEY",),
        PRODUCTION_VAULT,
        resolution_class="provider-rotation",
        authority_owner="LangSmith Ken workspace administrator",
        handoff_group="agents/langsmith",
        reason="The runtime workflow names a LangSmith provider credential and no readable authority was found.",
        provider_rotation_steps=provider_steps(
            "LangSmith", "the Ken agents production runtime"
        ),
    )
    annotate_many(
        "ken-agents",
        ("KEN_AGENTS_PLATFORM_DB_PASSWORD",),
        PRODUCTION_VAULT,
        resolution_class="target-system-readback",
        authority_owner="Ken agents platform database administrator",
        handoff_group="agents/platform-database",
        reason="The workflow writes this to the deployed platform env, which could not be read from an approved reachable target.",
    )
    annotate_many(
        "ken-agents",
        ("WORKSPACE_SETUP_CREDIT_COST", "KEN_AGENTS_BACKEND_URL"),
        PRODUCTION_VAULT,
        resolution_class="operator-supplied-config",
        authority_owner="Ken agents platform owner",
        handoff_group="agents/runtime-configuration",
        reason="These are runtime configuration settings, but no authoritative deployed readback was available.",
        data_classification="configuration",
    )
    annotate_many(
        "ken-agents",
        ("LANGGRAPH_OAUTH_CLIENT_ID", "LANGGRAPH_OAUTH_CLIENT_SECRET"),
        PRODUCTION_VAULT,
        resolution_class="independent-trust-authority",
        authority_owner="Ken LangGraph OAuth application owner",
        handoff_group="agents/langgraph-oauth",
        reason="The workflow proves a dedicated LangGraph OAuth application boundary; no exact readable client authority was found and the frontend or MCP Clerk identities must not be reused.",
    )
    annotate_many(
        "ken-agents",
        ("OAUTH2_PROXY_COOKIE_SECRET_LANGGRAPH",),
        PRODUCTION_VAULT,
        resolution_class="independent-trust-authority",
        authority_owner="Ken LangGraph OAuth proxy owner",
        handoff_group="agents/langgraph-oauth-proxy-cookie",
        reason="The OAuth proxy requires a stable independent cookie authority; no readable runtime authority was found.",
    )

    annotate_many(
        "ken-scraping",
        ("OVH_DEPLOY_SSH_KEY", "OVH_HOST_KEY"),
        PRODUCTION_VAULT,
        resolution_class="target-system-readback",
        authority_owner="Firecrawl OVH production host administrator",
        handoff_group="scraping/ovh-deploy-identity",
        reason="The deploy workflow binds these fields to the OVH host identity, but no approved readable host credential bundle was available.",
    )
    ovh_config_names = (
        "OVH_ENV_USE_DB_AUTHENTICATION",
        "OVH_ENV_SEARXNG_ENDPOINT",
        "OVH_ENV_NUQ_WORKER_COUNT",
        "OVH_ENV_CRAWL_CONCURRENT_REQUESTS",
        "OVH_ENV_MAX_CPU",
        "OVH_ENV_MAX_RAM",
        "OVH_ENV_BLOCK_MEDIA",
        "OVH_ENV_NUM_WORKERS_PER_QUEUE",
        "OVH_ENV_MAX_CONCURRENT_JOBS",
        "OVH_ENV_BROWSER_POOL_SIZE",
        "OVH_ENV_PROXY_CHEAP_REFRESH_INTERVAL_MS",
    )
    annotate_many(
        "ken-scraping",
        ovh_config_names,
        PRODUCTION_VAULT,
        resolution_class="target-system-readback",
        authority_owner="Firecrawl OVH runtime administrator",
        handoff_group="scraping/ovh-runtime-env",
        reason="The deploy workflow forwards these names to the OVH runtime; the approved evidence scope did not include an OVH env readback.",
        data_classification="configuration",
    )
    ovh_credential_names = (
        "OVH_ENV_REDIS_PASSWORD",
        "OVH_ENV_REDIS_URL",
        "OVH_ENV_REDIS_RATE_LIMIT_URL",
        "OVH_ENV_RABBITMQ_DEFAULT_USER",
        "OVH_ENV_RABBITMQ_DEFAULT_PASS",
        "OVH_ENV_SEARXNG_SECRET_KEY",
        "OVH_ENV_POSTGRES_USER",
        "OVH_ENV_POSTGRES_PASSWORD",
        "OVH_ENV_POSTGRES_DB",
        "OVH_ENV_CAPTCHA_API_KEY",
    )
    annotate_many(
        "ken-scraping",
        ovh_credential_names,
        PRODUCTION_VAULT,
        resolution_class="target-system-readback",
        authority_owner="Firecrawl OVH runtime administrator",
        handoff_group="scraping/ovh-runtime-env",
        reason="The deploy workflow forwards these names to the OVH runtime; the approved evidence scope did not include an OVH env readback.",
    )
    annotate_many(
        "ken-scraping",
        ("EVAL_API_URL", "EVAL_BENCHMARK_EXPERIMENT_ID"),
        PRODUCTION_VAULT,
        resolution_class="operator-supplied-config",
        authority_owner="Firecrawl production evaluation owner",
        handoff_group="scraping/production-evals",
        reason="The production evaluation workflow requires these settings and no authoritative deployed configuration was found.",
        data_classification="configuration",
    )
    annotate_many(
        "ken-scraping",
        ("EVAL_API_KEY",),
        PRODUCTION_VAULT,
        resolution_class="independent-trust-authority",
        authority_owner="Firecrawl production evaluation API owner",
        handoff_group="scraping/production-evals",
        reason="The production evaluation workflow needs an API credential and no exact readable authority was found.",
    )
    for names, provider, scope, group in (
        (("FIRECRAWL_API_KEY",), "Firecrawl", "the SDK CI test account", "scraping/ci-firecrawl"),
        (("OPENAI_API_KEY",), "OpenAI", "the Firecrawl server CI tests", "scraping/ci-openai"),
        (("GOOGLE_GENERATIVE_AI_API_KEY",), "Google AI", "the Firecrawl server CI tests", "scraping/ci-google-ai"),
    ):
        annotate_many(
            "ken-scraping",
            names,
            "Ken CI Runtime",
            resolution_class="provider-rotation",
            authority_owner=f"{provider} Ken test-account administrator",
            handoff_group=group,
            reason=f"The default-branch CI workflow identifies {provider} as the credential consumer and no readable CI authority was found.",
            provider_rotation_steps=provider_steps(provider, scope),
        )
    annotate_many(
        "ken-scraping",
        ("IDMUX_URL", "TS_OAUTH_CLIENT_ID", "TS_OAUTH_SECRET"),
        "Ken CI Runtime",
        resolution_class="independent-trust-authority",
        authority_owner="Firecrawl test-suite OAuth owner",
        handoff_group="scraping/ci-oauth",
        reason="The JavaScript SDK test workflow proves a dedicated CI OAuth boundary, but no readable authority was found.",
    )
    annotate_many(
        "ken-scraping",
        ("PROXY_SERVER", "PROXY_USERNAME", "PROXY_PASSWORD"),
        "Ken CI Runtime",
        resolution_class="unknown-authority",
        authority_owner="Firecrawl CI proxy owner",
        handoff_group="scraping/ci-proxy",
        reason="The server CI workflow consumes a proxy bundle, but the provider and exact authority are not identified by source or readable metadata.",
    )

    for repository, names, owner, group in (
        ("ken-brain", ("SSH_KNOWN_HOSTS",), "Ken Brain production host administrator", "brain/deploy-host-key"),
        ("ken-help", ("DEPLOY_SSH_KEY", "DEPLOY_KNOWN_HOSTS", "DEPLOY_USER", "DEPLOY_HOST", "DEPLOY_PATH"), "help.ken.so host administrator", "help/deploy-target"),
        ("ken-daily", ("DEPLOY_HOST", "DEPLOY_USER", "DEPLOY_SSH_KEY"), "Ken Daily production host administrator", "daily/deploy-target"),
        ("ken-analytics", ("DEPLOY_USER", "DEPLOY_SSH_KEY"), "Ken Analytics production VM administrator", "analytics/deploy-target"),
        ("ken-cms", ("SSH_HOST", "SSH_USER", "SSH_KEY", "SSH_PORT"), "Ken CMS production host administrator", "cms/deploy-target"),
    ):
        annotate_many(
            repository,
            names,
            PRODUCTION_VAULT,
            resolution_class="target-system-readback",
            authority_owner=owner,
            handoff_group=group,
            reason="The default-branch workflow identifies the target system, but no exact readable deployment bundle was found in approved evidence.",
        )

    hermes_steps = [
        "Recover or rotate the dedicated kenhermes-deploy host, private key, and known-host authority into the Ken Deploy Production item for ken-hermes-clickup; do not substitute root or another service account.",
        "Cut the Hermes deploy workflow over through the production broker while preserving SSH user kenhermes-deploy and the existing narrow sudo contract.",
        "Run one Hermes deployment and verify the service plus the allow-listed sudo operation before deleting any GitHub field.",
        "Delete the four Hermes GitHub deployment fields only after the dedicated identity succeeds, then revoke any predecessor dedicated key from authorized_keys.",
    ]
    for name in (
        "DEPLOY_HOST",
        "DEPLOY_USER",
        "DEPLOY_SSH_KEY",
        "DEPLOY_SSH_KNOWN_HOSTS",
    ):
        unresolved_annotations.append(
            _unresolved_annotation(
                "ken-hermes-clickup",
                name,
                PRODUCTION_VAULT,
                resolution_class="target-system-readback",
                authority_owner="Ken Hermes dedicated deployment identity owner",
                handoff_group="hermes/dedicated-deploy-identity",
                reason="The workflow requires dedicated user kenhermes-deploy, but no exact dedicated host/key/known-host authority was proven. Root credentials are forbidden.",
                downstream_update_steps=hermes_steps,
                data_classification=(
                    "identifier" if name in {"DEPLOY_HOST", "DEPLOY_USER"} else "credential"
                ),
                required_runtime_identity="kenhermes-deploy",
            )
        )

    annotate_many(
        "ken-cms",
        ("POSTGRES_PASSWORD", "POSTGRES_USER", "POSTGRES_DB"),
        PRODUCTION_VAULT,
        resolution_class="target-system-readback",
        authority_owner="Ken CMS PostgreSQL administrator",
        handoff_group="cms/postgres-runtime",
        reason="The CMS workflow writes these fields into the stable deployed runtime env, but that target env was not in the approved readable evidence scope.",
    )
    annotate_many(
        "ken-cms",
        ("OAUTH2_PROXY_CLIENT_ID", "OAUTH2_PROXY_CLIENT_SECRET"),
        PRODUCTION_VAULT,
        resolution_class="provider-rotation",
        authority_owner="Ken CMS Clerk OAuth application administrator",
        handoff_group="cms/clerk-oauth-application",
        reason="The workflow fixes the CMS proxy issuer to clerk.ken.so, proving a dedicated CMS Clerk OAuth application; no readable exact client authority was found.",
        provider_rotation_steps=provider_steps(
            "Clerk", "the cms.getken.dev OAuth callback application"
        ),
    )
    annotate_many(
        "ken-cms",
        ("OAUTH2_PROXY_COOKIE_SECRET",),
        PRODUCTION_VAULT,
        resolution_class="independent-trust-authority",
        authority_owner="Ken CMS OAuth proxy owner",
        handoff_group="cms/oauth-proxy-cookie",
        reason="The CMS OAuth proxy requires its own stable cookie authority; no readable matching runtime authority was found.",
    )
    staging_key = add_source(
        _op_source(
            "Development",
            "Ken Staging Secrets",
            "backend_deploy_private_key",
            "CONCEALED",
        )
    )
    mappings.append(
        _mapping(
            "ken-backend",
            "STAGING_BACKEND_SSH_KEY",
            staging_key,
            target_vault="Ken Deploy Nonproduction",
            authority_match="exact-field",
        )
    )

    staging_clerk = add_source(
        _op_source(
            "Development", "Ken Staging Secrets", "Clerk Secret Key", "CONCEALED"
        )
    )
    mappings.append(
        _mapping(
            "ken-frontend",
            "CLERK_SECRET_KEY",
            staging_clerk,
            target_vault="Ken CI Runtime",
            workflow=".github/workflows/ci.yml",
            authority_match="exact-field",
        )
    )

    frontend_env_specs = [
        ("APP_ORIGINS", "move-to-variable", "configuration"),
        ("BACKEND_API_URL", "move-to-variable", "configuration"),
        ("DEEPSEEK_API_KEY", "copy", "credential"),
        ("KEN_AI_ADMIN_API_KEY", "copy", "credential"),
        ("KEN_AI_MCP_URL", "move-to-variable", "configuration"),
        ("KEN_SEARCH_URL", "move-to-variable", "configuration"),
        ("MOONSHOT_API_KEY", "copy", "credential"),
        ("ONBOARDING_PREFILL_INTERNAL_TOKEN", "copy", "credential"),
        ("ZAI_API_KEY", "copy", "credential"),
    ]
    for name, action, classification in frontend_env_specs:
        source_ref = add_source(
            _op_env_source("Development", "ken-frontend-env", name)
        )
        mappings.append(
            _mapping(
                "ken-frontend",
                name,
                source_ref,
                action=action,
                classification=classification,
                authority_match="exact-field",
            )
        )

    frontend_provider_specs = [
        ("DOUBLEWORD_API_KEY", "DoublewordConfiguration.ApiKey"),
        ("FIREWORKS_API_KEY", "FireworksConfiguration.ApiKey"),
        ("OPENROUTER_API_KEY", "OpenRouterConfiguration.ApiKey"),
        ("XAI_API_KEY", "XAIConfiguration.ApiKey"),
    ]
    for name, key_path in frontend_provider_specs:
        source_ref = add_source(_deployed_source(scraper_file, key_path))
        mappings.append(
            _mapping(
                "ken-frontend",
                name,
                source_ref,
                authority_match="reviewed-semantic",
            )
        )

    agent_env_specs = [
        ("DEEPSEEK_API_KEY", "copy", "credential"),
        ("KEN_AI_ADMIN_API_KEY", "copy", "credential"),
        ("KEN_AI_MCP_URL", "move-to-variable", "configuration"),
        ("MOONSHOT_API_KEY", "copy", "credential"),
        ("ZAI_API_KEY", "copy", "credential"),
    ]
    for name, action, classification in agent_env_specs:
        source_ref = add_source(_op_env_source("Development", "ken-agents-env", name))
        mappings.append(
            _mapping(
                "ken-agents",
                name,
                source_ref,
                action=action,
                classification=classification,
                authority_match="exact-field",
            )
        )

    for name, key_path in (
        ("OPENAI_API_KEY", "OpenAi.ApiKey"),
        ("XAI_API_KEY", "XAIConfiguration.ApiKey"),
    ):
        source_ref = add_source(_deployed_source(scraper_file, key_path))
        mappings.append(
            _mapping(
                "ken-agents",
                name,
                source_ref,
                authority_match="reviewed-semantic",
            )
        )
    agent_xai_proxy = add_source(
        _op_source(
            "Development",
            "ken-backend-env",
            "XAIConfiguration__ProxyUrl",
            "STRING",
        )
    )
    mappings.append(
        _mapping(
            "ken-agents",
            "XAI_PROXY_URL",
            agent_xai_proxy,
            action="move-to-variable",
            classification="configuration",
            authority_match="reviewed-semantic",
        )
    )

    for name in ("CMS_REVALIDATE_SECRET", "PAYLOAD_SECRET"):
        source_ref = add_source(_op_env_source("Development", "ken-cms-env", name))
        mappings.append(
            _mapping(
                "ken-cms",
                name,
                source_ref,
                authority_match="exact-field",
            )
        )

    search_env_specs = [
        ("AWS_ACCESS_KEY_ID", "AWS_ACCESS_KEY_ID"),
        ("AWS_SECRET_ACCESS_KEY", "AWS_SECRET_ACCESS_KEY"),
        ("ELASTICSEARCH_API_KEY", "ES_API_KEY"),
    ]
    for name, env_name in search_env_specs:
        source_ref = add_source(
            _op_env_source("Development", "ken-search-env", env_name)
        )
        mappings.append(
            _mapping(
                "ken-search",
                name,
                source_ref,
                authority_match="exact-field" if name == env_name else "reviewed-semantic",
            )
        )
    search_clerk = add_source(
        _op_source(
            "Development",
            "ken-backend-env",
            "KenSearch__ClerkApiKey",
            "CONCEALED",
        )
    )
    search_root_host = add_source(
        _op_source("Development", "SSH Search - root devws", "host", "CONCEALED")
    )
    search_root_user = add_source(
        _op_source("Development", "SSH Search - root devws", "username", "CONCEALED")
    )
    search_root_key = add_source(
        _op_source("Development", "SSH Search - root devws", "private_key", "CONCEALED")
    )
    search_extra_specs = [
        ("DB_CONNECTION_STRING", add_source(_deployed_source(scraper_file, "ConnectionStrings.KenDb")), "copy", "credential"),
        ("CLICKUP_LIST_ID", add_source(_deployed_source(scraper_file, "ClickUpAlerting.ListId")), "move-to-variable", "identifier"),
        ("KEN_SEARCH_CLERK_SECRET_KEY", search_clerk, "copy", "credential"),
        ("KEN_SEARCH_INTERNAL_TOKEN", add_source(_deployed_source(scraper_file, "KenSearch.ServiceBearerToken")), "copy", "credential"),
        ("VPS_HOST", search_root_host, "move-to-variable", "identifier"),
        ("VPS_SSH_KEY", search_root_key, "copy", "credential"),
    ]
    for name, source_ref, action, classification in search_extra_specs:
        mappings.append(
            _mapping(
                "ken-search",
                name,
                source_ref,
                action=action,
                classification=classification,
            )
        )

    mcp_clerk_specs = [
        ("KEN_CLERK_DOMAIN", "authorization_server", "move-to-variable", "configuration"),
        ("KEN_CLERK_CLIENT_ID", "client_id", "move-to-variable", "identifier"),
        ("KEN_CLERK_CLIENT_SECRET", "client_secret", "copy", "credential"),
        ("MCP_SMOKE_URL", "mcp_url", "move-to-variable", "configuration"),
    ]
    for name, field, action, classification in mcp_clerk_specs:
        source_ref = add_source(
            _op_source(
                "Development",
                "Ken AI MCP - Clerk OAuth client",
                field,
                "CONCEALED" if field == "client_secret" else "STRING",
            )
        )
        mappings.append(
            _mapping(
                "ken-ai-mcp",
                name,
                source_ref,
                action=action,
                classification=classification,
                authority_match="exact-field",
            )
        )
    mysql_component_names = {
        "DB_HOST": "server",
        "DB_USER": "user",
        "DB_PASSWORD": "password",
        "DB_NAME": "database",
    }
    for name, component in mysql_component_names.items():
        source_ref = add_source(
            _deployed_component_source(
                scraper_file, "ConnectionStrings.KenDb", component
            )
        )
        mappings.append(
            _mapping(
                "ken-ai-mcp",
                name,
                source_ref,
                action="reconstruct",
                classification="credential" if component == "password" else "identifier",
            )
        )
    mcp_mongo = add_source(
        _deployed_source(scraper_file, "MongoDbConfiguration.ConnectionString")
    )
    mappings.append(_mapping("ken-ai-mcp", "MONGO_CONNECTION_STRING", mcp_mongo))
    mongo_database = add_source(
        _deployed_component_source(
            scraper_file, "MongoDbConfiguration.ConnectionString", "database"
        )
    )
    mappings.append(
        _mapping(
            "ken-ai-mcp",
            "MONGO_DATABASE",
            mongo_database,
            action="reconstruct",
            classification="identifier",
        )
    )

    brain_item = "SSH ken-brain CI deploy - kenbrain-deploy@167.235.8.250"
    brain_key = add_source(_op_document_source("Development", brain_item, "ci_deploy_key"))
    brain_host = add_source(_op_title_source("Development", brain_item, "host"))
    brain_user = add_source(_op_title_source("Development", brain_item, "username"))
    for name, source_ref, action, classification in (
        ("SSH_HOST", brain_host, "reconstruct", "identifier"),
        ("SSH_USER", brain_user, "reconstruct", "identifier"),
        ("SSH_KEY", brain_key, "copy", "credential"),
    ):
        mappings.append(
            _mapping(
                "ken-brain",
                name,
                source_ref,
                action=action,
                classification=classification,
                authority_match="exact-field",
            )
        )

    proxy_api_key = add_source(
        _op_source("Development", "Proxy-cheap", "API Key", "STRING")
    )
    proxy_api_secret = add_source(
        _op_source("Development", "Proxy-cheap", "API Secret", "STRING")
    )
    mappings.extend(
        [
            _mapping(
                "ken-scraping",
                "OVH_ENV_PROXY_CHEAP_API_KEY",
                proxy_api_key,
            ),
            _mapping(
                "ken-scraping",
                "OVH_ENV_PROXY_CHEAP_API_SECRET",
                proxy_api_secret,
            ),
        ]
    )

    mapping_ids = [mapping["mapping_id"] for mapping in mappings]
    if len(mapping_ids) != len(set(mapping_ids)):
        raise ValueError("duplicate authority mapping selector")
    if any(mapping["source_ref"] not in sources for mapping in mappings):
        raise ValueError("authority mapping references an unknown source")
    annotation_ids = [row["annotation_id"] for row in unresolved_annotations]
    if len(annotation_ids) != len(set(annotation_ids)):
        raise ValueError("duplicate unresolved authority annotation selector")
    migration_ids = [row["migration_id"] for row in secretless_migrations]
    if len(migration_ids) != len(set(migration_ids)):
        raise ValueError("duplicate secretless migration selector")
    direct_mapping_ids = [
        row["mapping_id"] for row in direct_onepassword_mappings
    ]
    if len(direct_mapping_ids) != len(set(direct_mapping_ids)):
        raise ValueError("duplicate direct 1Password mapping selector")
    _validate_source_metadata(sources, evidence_dir)

    return {
        "schema_version": 1,
        "evidence_id": EVIDENCE_ID,
        "policy": "Value-free metadata only. Sources record labels, key paths, types, and existence/readability booleans; no credential value was emitted or stored.",
        "sources": dict(sorted(sources.items())),
        "mappings": sorted(mappings, key=lambda row: row["mapping_id"]),
        "unresolved_annotations": sorted(
            unresolved_annotations, key=lambda row: row["annotation_id"]
        ),
        "secretless_migrations": sorted(
            secretless_migrations, key=lambda row: row["migration_id"]
        ),
        "direct_onepassword_mappings": sorted(
            direct_onepassword_mappings, key=lambda row: row["mapping_id"]
        ),
        "unresolved_observations": [
            {
                "kind": "value-blind-structural-projection",
                "reason": "Selected 1Password notes and structured items were streamed through tested parsers that emitted only key or field names, types, and presence booleans. Right-hand content was never emitted or stored.",
            },
        ],
    }


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    rendered = json.dumps(build_evidence(), indent=2, sort_keys=True) + "\n"
    if not argv:
        sys.stdout.write(rendered)
        return 0
    if len(argv) != 1:
        sys.stderr.write("usage: build_task6_authority_evidence.py [OUTPUT.json]\n")
        return 2
    output = Path(argv[0])
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
