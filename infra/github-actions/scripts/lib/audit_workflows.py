#!/usr/bin/env python3
"""Parse collected Actions metadata into sanitized inventory YAML.

This module never contacts GitHub. The shell collector must only supply
name/metadata payloads. Secret values are rejected if they appear.
"""
from __future__ import annotations

import hashlib
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

SECRET_NAME_RE = re.compile(
    r"""secrets\.(?P<dot>[A-Za-z_][A-Za-z0-9_]*)|secrets\[['\"](?P<brk>[A-Za-z_][A-Za-z0-9_]*)['\"]\]"""
)
VAR_NAME_RE = re.compile(
    r"""vars\.(?P<dot>[A-Za-z_][A-Za-z0-9_]*)|vars\[['\"](?P<brk>[A-Za-z_][A-Za-z0-9_]*)['\"]\]"""
)
VALUE_SHAPED_RE = re.compile(
    r"-----BEGIN [A-Z0-9 ]+PRIVATE KEY-----\s+[A-Za-z0-9+/=\n]{64,}|\bghp_[A-Za-z0-9]{20,}|\bgho_[A-Za-z0-9]{20,}|\bgithub_pat_[A-Za-z0-9_]{20,}|\bAKIA[0-9A-Z]{16}\b"
)
GITHUB_EXPRESSION_RE = re.compile(r"\$\{\{(?P<body>.*?)\}\}", re.DOTALL)

BUILD_HINTS = (
    "docker build",
    "docker/build-push-action",
    "useblacksmith/build-push-action",
    "dotnet publish",
    "dotnet test",
    "dotnet restore",
    "pnpm run build",
    "npm run build",
    "cargo build",
    "python -m build",
    "setup-dotnet",
    "actions/setup-dotnet",
    "actions/setup-node",
    "actions/setup-python",
    "corepack enable",
)
DEPLOY_HINTS = (
    "appleboy/ssh-action",
    "appleboy/scp-action",
    "docker push",
    "docker compose",
    "docker-compose",
    "build-push-action",
    "pypa/gh-action-pypi-publish",
    "pnpm publish",
    "npm publish",
    "cargo publish",
    "ghcr.io",
)
HEAVY_HINTS = (
    "mysql",
    "test-server",
    "scrape-evals",
    "eval-prod",
    "blacksmith-4vcpu",
    "projection-mysql",
    "residual-mysql",
    "technology-full-schedule",
    "technology-refresh",
)
PROD_ENV_NAMES = {
    "production",
    "prod",
    "cloudflare-edge-production",
}
NONPROD_ENV_NAMES = {
    "staging",
}
TARGET_HINT_WORDS = (
    "Worldstream",
    "Hetzner",
    "Cloudflare",
    "GHCR",
    "ghcr.io",
    "PyPI",
    "npm",
    "NuGet",
    "Maven",
    "ClickUp",
    "Langfuse",
    "OVH",
    "1Password",
    "beehiiv",
    "api.getken.ai",
    "crates.io",
    "hex.pm",
    "packagist",
    "rubygems",
)
HOST_SECRET_NAMES = {
    "DEPLOY_HOST",
    "SSH_HOST",
    "VPS_HOST",
    "WORLDSTREAM_HOST",
    "STAGING_BACKEND_HOST",
    "REDIRECT_DEPLOY_HOST",
    "OVH_HOST_KEY",
}
PACKAGE_BY_SECRET = {
    "HEX_API_KEY": "hex.pm",
    "NPM_TOKEN": "npm",
    "PYPI_USERNAME": "pypi",
    "PYPI_PASSWORD": "pypi",
    "PYPI_API_TOKEN": "pypi",
    "CRATES_IO_TOKEN": "crates.io",
    "RUBYGEMS_API_KEY": "rubygems",
    "PACKAGIST_TOKEN": "packagist",
    "PACKAGIST_USERNAME": "packagist",
    "NUGET_API_KEY": "nuget",
    "COLD_EMAIL_SKILLS_DEPLOY_KEY": "git-deploy-key",
    "PHP_SDK_DEPLOY_KEY": "git-deploy-key",
}
OP_BOOTSTRAP_SECRET = "OP_SERVICE_ACCOUNT_TOKEN"
SCHEDULED_PROD_HINTS = (
    "langfuse",
    "clickup",
    "beehiiv",
    "worldstream",
    "1password",
    "op_service",
    "backend",
    "ken_backend",
)


def _parse_json_documents(text: str) -> list[Any]:
    decoder = json.JSONDecoder()
    idx = 0
    docs: list[Any] = []
    length = len(text)
    while idx < length:
        while idx < length and text[idx].isspace():
            idx += 1
        if idx >= length:
            break
        obj, end = decoder.raw_decode(text, idx)
        docs.append(obj)
        idx = end
    return docs


def load_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    text = path.read_text(encoding="utf-8")
    if not text.strip():
        return default
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        docs = _parse_json_documents(text)
        if not docs:
            return default
        if len(docs) == 1:
            return docs[0]
        if all(isinstance(doc, dict) and "runners" in doc for doc in docs):
            merged: list[Any] = []
            for doc in docs:
                merged.extend(doc.get("runners") or [])
            return {"total_count": docs[0].get("total_count", len(merged)), "runners": merged}
        if all(isinstance(doc, list) for doc in docs):
            merged_list: list[Any] = []
            for doc in docs:
                merged_list.extend(doc)
            return merged_list
        return docs


def dump_yaml(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        yaml.safe_dump(
            data,
            fh,
            sort_keys=False,
            allow_unicode=True,
            width=120,
            default_flow_style=False,
        )


def as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def stringify_runs_on(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, list):
        return "[" + ", ".join(str(x) for x in value) + "]"
    return str(value)


def flatten_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (str, int, float, bool)):
        return str(value)
    if isinstance(value, list):
        return "\n".join(flatten_text(v) for v in value)
    if isinstance(value, dict):
        return "\n".join(flatten_text(v) for v in value.values())
    return str(value)


def extract_names(pattern: re.Pattern[str], text: str) -> list[str]:
    names: list[str] = []
    for expression in GITHUB_EXPRESSION_RE.finditer(text):
        for match in pattern.finditer(expression.group("body")):
            name = match.group("dot") or match.group("brk")
            if name and name not in names:
                names.append(name)
    return names


def workflow_triggers(on_block: Any) -> list[str]:
    if on_block is None:
        return []
    if isinstance(on_block, str):
        return [on_block]
    if isinstance(on_block, list):
        return [str(x) for x in on_block]
    if isinstance(on_block, dict):
        triggers: list[str] = []
        for key, val in on_block.items():
            if key == "schedule" and isinstance(val, list):
                triggers.append("schedule")
                for item in val:
                    if isinstance(item, dict) and "cron" in item:
                        triggers.append(f"schedule:{item['cron']}")
            else:
                triggers.append(str(key))
        return triggers
    return [str(on_block)]


def job_environment(job: dict[str, Any]) -> tuple[str, dict[str, Any] | None]:
    env = job.get("environment")
    if env is None:
        return "", None
    if isinstance(env, str):
        return env, None
    if isinstance(env, dict):
        return str(env.get("name") or ""), env
    return str(env), None


def uses_from(obj: Any) -> list[str]:
    found: list[str] = []
    if isinstance(obj, dict):
        uses = obj.get("uses")
        if isinstance(uses, str):
            found.append(uses)
        for value in obj.values():
            found.extend(uses_from(value))
    elif isinstance(obj, list):
        for item in obj:
            found.extend(uses_from(item))
    # preserve order, unique
    out: list[str] = []
    for item in found:
        if item not in out:
            out.append(item)
    return out


def artifact_refs(text: str, uses: list[str]) -> list[str]:
    refs: list[str] = []
    for item in uses:
        if "upload-artifact" in item or "download-artifact" in item:
            refs.append(item)
    for token in ("upload-artifact", "download-artifact"):
        if token in text and token not in " ".join(refs):
            refs.append(token)
    return refs


def target_hints(text: str) -> list[str]:
    hints: list[str] = []
    for word in TARGET_HINT_WORDS:
        if word.lower() in text.lower() and word not in hints:
            hints.append(word)
    return hints


def long_lived_secrets(secrets: list[str]) -> list[str]:
    return [name for name in secrets if name != "GITHUB_TOKEN"]


def is_scheduled(triggers: list[str]) -> bool:
    return any(str(item) == "schedule" or str(item).startswith("schedule:") for item in triggers)


def scheduled_production_side_effect(text: str, secrets: list[str]) -> bool:
    blob = f"{text}\n{' '.join(secrets)}".lower()
    return any(hint in blob for hint in SCHEDULED_PROD_HINTS)


def structured_target(
    job_id: str,
    workflow_path: str,
    text: str,
    uses: list[str],
    secret_names: list[str],
    variable_names: list[str],
) -> dict[str, Any]:
    action_types: list[str] = []
    for item in uses:
        name = str(item).split("@", 1)[0]
        if any(token in name for token in ("ssh-action", "scp-action", "build-push-action", "pypi-publish", "docker/login", "load-secrets-action")):
            if name not in action_types:
                action_types.append(name)
    endpoint_expressions: list[str] = []
    for match in re.finditer(r"\$\{\{\s*(?:secrets|vars)\.([A-Za-z0-9_]+)\s*\}\}", text):
        name = match.group(1)
        if name.endswith("_HOST") or name in HOST_SECRET_NAMES or "HOST" in name:
            expr = match.group(0)
            if expr not in endpoint_expressions:
                endpoint_expressions.append(expr)
    host_secret_names = [
        name for name in secret_names if name.endswith("_HOST") or name in HOST_SECRET_NAMES or name.endswith("_HOSTNAME")
    ]
    host_variable_names = [
        name for name in variable_names if name.endswith("_HOST") or name in HOST_SECRET_NAMES or "HOST" in name
    ]
    registry = None
    for name in secret_names:
        if name in PACKAGE_BY_SECRET:
            registry = PACKAGE_BY_SECRET[name]
            break
    blob = text.lower()
    if registry is None:
        if "ghcr.io" in blob or any("build-push" in item for item in uses):
            registry = "ghcr.io"
        elif "cargo publish" in blob or "crates.io" in blob:
            registry = "crates.io"
        elif "hex.pm" in blob or "HEX_API_KEY" in secret_names:
            registry = "hex.pm"
        elif "rubygems" in blob:
            registry = "rubygems"
        elif "packagist" in blob:
            registry = "packagist"
        elif "pypi" in blob:
            registry = "pypi"
        elif job_id == "publish" and "GITHUB_TOKEN" in secret_names:
            registry = "github-packages"
    kind = None
    if host_secret_names or host_variable_names or any("ssh" in item or "scp" in item for item in action_types):
        kind = "ssh-or-host"
    elif registry:
        kind = "registry-or-package"
    elif action_types:
        kind = "action"
    unknown_reason = None
    if not (action_types or endpoint_expressions or host_secret_names or host_variable_names or registry):
        unknown_reason = (
            f"no action, host expression, secret/variable host, or registry/package signal for {workflow_path}#{job_id}"
        )
    return {
        "kind": kind,
        "action_types": action_types,
        "endpoint_expressions": endpoint_expressions,
        "host_secret_names": host_secret_names,
        "host_variable_names": host_variable_names,
        "registry_or_package": registry,
        "unknown_reason": unknown_reason,
    }


def apply_secret_consumer(entry: dict[str, Any], classified: dict[str, Any]) -> dict[str, Any]:
    if entry.get("github_secret_name") == "GITHUB_TOKEN":
        entry["target_vault"] = None
        entry["rotation_required"] = False
        entry["consumer"] = None
        return entry
    secret_class = str(classified.get("secret_class") or "")
    if secret_class.startswith("deploy") or secret_class.startswith("scheduled-secret"):
        entry["target_vault"] = (
            "Ken Deploy Production" if classified.get("production_impact") else "Ken Deploy Nonproduction"
        )
        entry["consumer"] = classified.get("target_runner_class")
        entry["classification"] = (
            "deployment-production"
            if classified.get("production_impact")
            else "deployment-nonproduction"
        )
    elif secret_class == "public-hosted" and classified.get("production_impact"):
        entry["target_vault"] = "Ken Deploy Production"
        entry["consumer"] = classified.get("target_runner_class")
        entry["classification"] = "deployment-production"
    elif secret_class == "ci-runtime":
        entry["target_vault"] = "Ken CI Runtime"
        entry["consumer"] = classified.get("target_runner_class")
        entry["classification"] = "ci-nonproduction"
    elif secret_class == "grok-review-unchanged":
        for key in ("resolution_class", "authority_owner", "unresolved_reason"):
            entry.pop(key, None)
        entry["target_vault"] = None
        entry["target_item"] = None
        entry["target_field"] = None
        entry["field_type"] = None
        entry["consumer"] = "existing-grok-review"
        entry["source_authority"] = (
            "Existing Grok review workflow reference; do not copy onto ken-ci or ken-deploy."
        )
        entry["authority_status"] = "preserved-existing"
        entry["rotation_required"] = False
        entry["classification"] = "preserve"
        entry["migration_action"] = "preserve"
        entry["alias_status"] = "not-applicable"
    if entry.get("github_secret_name") == OP_BOOTSTRAP_SECRET:
        for key in ("resolution_class", "authority_owner", "unresolved_reason"):
            entry.pop(key, None)
        entry["target_vault"] = None
        entry["target_item"] = None
        entry["target_field"] = None
        entry["field_type"] = None
        entry["authority_status"] = "bootstrap-to-replace"
        entry["rotation_required"] = False
        entry["classification"] = "bootstrap"
        entry["migration_action"] = "replace-bootstrap"
        entry["replacement_required"] = True
        entry["alias_status"] = "not-applicable"
    return entry


def _reject_value_bearing_evidence(value: Any, path: str = "evidence") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if str(key).lower() in {"value", "secret", "password", "token"}:
                raise ValueError(f"value-bearing authority evidence key at {path}.{key}")
            _reject_value_bearing_evidence(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _reject_value_bearing_evidence(child, f"{path}[{index}]")


def apply_authority_evidence(
    entry: dict[str, Any], evidence: dict[str, Any] | None
) -> dict[str, Any]:
    evidence = evidence or {}
    _reject_value_bearing_evidence(evidence)
    matches: list[dict[str, Any]] = []
    for mapping in evidence.get("mappings") or []:
        if not isinstance(mapping, dict):
            raise ValueError("authority evidence mapping must be an object")
        if mapping.get("repository") != entry.get("repository"):
            continue
        if mapping.get("github_secret_name") != entry.get("github_secret_name"):
            continue
        mapping_target_vault = mapping.get("target_vault")
        if not isinstance(mapping_target_vault, str) or not mapping_target_vault.strip():
            raise ValueError("authority mapping requires explicit target_vault")
        if mapping.get("workflow") not in {None, entry.get("workflow")}:
            continue
        if mapping_target_vault != entry.get("target_vault"):
            continue
        matches.append(mapping)
    if not matches:
        return entry
    if len(matches) != 1:
        raise ValueError(
            f"multiple authority mappings for {entry.get('repository')}:"
            f"{entry.get('workflow')}:{entry.get('github_secret_name')}"
        )

    mapping = matches[0]
    action = str(mapping.get("migration_action") or "")
    if action not in {"copy", "reconstruct", "move-to-variable"}:
        raise ValueError(f"unsupported authority migration action: {action!r}")
    classification = str(mapping.get("classification") or "")
    if classification not in {"credential", "identifier", "configuration"}:
        raise ValueError(f"unsupported authority classification: {classification!r}")
    authority_match = str(mapping.get("authority_match") or "")
    if authority_match not in {"exact-field", "reviewed-semantic"}:
        raise ValueError(f"unsupported authority match: {authority_match!r}")
    downstream = mapping.get("downstream_update_steps")
    if not isinstance(downstream, list) or not downstream or not all(
        isinstance(step, str) and step.strip() for step in downstream
    ):
        raise ValueError("resolved authority mapping needs downstream_update_steps")
    source_ref = mapping.get("source_ref")
    if source_ref:
        sources = evidence.get("sources") or {}
        source = sources.get(source_ref) if isinstance(sources, dict) else None
    else:
        source = mapping.get("source")
    if not isinstance(source, dict) or source.get("readable") is not True:
        raise ValueError("resolved authority source must be readable")

    kind = source.get("kind")
    if kind == "onepassword":
        required = ("vault", "item", "field", "field_type")
        if not all(source.get(key) for key in required) or source.get("value_present") is not True:
            raise ValueError("incomplete onepassword authority metadata")
        authority = f"op://{source['vault']}/{source['item']}/{source['field']}"
    elif kind == "deployed-config":
        required = ("host", "file", "key_path", "value_type")
        if not all(source.get(key) for key in required) or source.get("exists") is not True:
            raise ValueError("incomplete deployed-config authority metadata")
        authority = f"deployed://{source['host']}{source['file']}#{source['key_path']}"
    elif kind == "evidence-key":
        required = ("artifact", "key_path")
        if not all(source.get(key) for key in required) or source.get("exists") is not True:
            raise ValueError("incomplete evidence-key authority metadata")
        authority = f"evidence://{source['artifact']}#{source['key_path']}"
    elif kind == "onepassword-env-key":
        required = ("vault", "item", "name", "declared_type", "metadata_artifact")
        if not all(source.get(key) for key in required) or source.get("value_present") is not True:
            raise ValueError("incomplete onepassword env authority metadata")
        authority = f"op-env://{source['vault']}/{source['item']}#{source['name']}"
    elif kind == "onepassword-document":
        required = ("vault", "item", "file_name", "metadata_artifact")
        if not all(source.get(key) for key in required) or source.get("exists") is not True:
            raise ValueError("incomplete onepassword document authority metadata")
        authority = f"op-file://{source['vault']}/{source['item']}/{source['file_name']}"
    elif kind == "onepassword-item-title-component":
        required = ("vault", "item", "component", "metadata_artifact")
        if not all(source.get(key) for key in required) or source.get("exists") is not True:
            raise ValueError("incomplete onepassword title authority metadata")
        authority = f"op-title://{source['vault']}/{source['item']}#{source['component']}"
    elif kind == "deployed-connection-component":
        required = ("host", "file", "key_path", "component", "metadata_artifact")
        if not all(source.get(key) for key in required) or source.get("exists") is not True:
            raise ValueError("incomplete deployed connection authority metadata")
        authority = (
            f"deployed-component://{source['host']}{source['file']}#"
            f"{source['key_path']}[{source['component']}]"
        )
    else:
        raise ValueError(f"unsupported authority source kind: {kind!r}")

    entry["source_authority"] = authority
    entry["source_readable"] = True
    entry["source_evidence_id"] = evidence.get("evidence_id")
    entry["source_ref"] = source_ref
    if mapping.get("mapping_id"):
        entry["authority_mapping_id"] = mapping["mapping_id"]
    entry["authority_status"] = (
        "verified-reconstructable" if action == "reconstruct" else "verified-readable"
    )
    entry["authority_match"] = authority_match
    entry["data_classification"] = classification
    entry["migration_action"] = action
    entry["rotation_required"] = False
    entry["provider_rotation_steps"] = None
    entry["downstream_update_steps"] = downstream
    if action == "move-to-variable":
        entry["target_vault"] = None
        entry["target_item"] = f"GitHub Actions variables:{entry['repository']}"
        entry["target_field"] = entry["github_secret_name"]
        entry["field_type"] = "string"
    if mapping.get("target_item"):
        entry["target_item"] = mapping["target_item"]
    if mapping.get("target_field"):
        entry["target_field"] = mapping["target_field"]
    if mapping.get("alias_group"):
        entry["alias_group"] = mapping["alias_group"]
        entry["alias_status"] = "verified-shared-authority"
    return entry


def apply_unresolved_annotation(
    entry: dict[str, Any], evidence: dict[str, Any] | None
) -> dict[str, Any]:
    """Attach a value-free recovery route without pretending authority is resolved."""
    if entry.get("authority_status") != "unresolved":
        return entry
    evidence = evidence or {}
    _reject_value_bearing_evidence(evidence)
    matches: list[dict[str, Any]] = []
    for annotation in evidence.get("unresolved_annotations") or []:
        if not isinstance(annotation, dict):
            raise ValueError("unresolved authority annotation must be an object")
        if annotation.get("repository") != entry.get("repository"):
            continue
        if annotation.get("github_secret_name") != entry.get("github_secret_name"):
            continue
        if "target_vault" not in annotation:
            raise ValueError("unresolved authority annotation requires explicit target_vault")
        if annotation.get("target_vault") != entry.get("target_vault"):
            continue
        if annotation.get("workflow") not in {None, entry.get("workflow")}:
            continue
        matches.append(annotation)
    if not matches:
        return entry
    if len(matches) != 1:
        raise ValueError(
            f"multiple unresolved annotations for {entry.get('repository')}:"
            f"{entry.get('workflow')}:{entry.get('github_secret_name')}"
        )

    annotation = matches[0]
    annotation_id = str(annotation.get("annotation_id") or "").strip()
    resolution_class = str(annotation.get("resolution_class") or "").strip()
    owner = str(annotation.get("authority_owner") or "").strip()
    handoff_group = str(annotation.get("handoff_group") or "").strip()
    reason = str(annotation.get("unresolved_reason") or "").strip()
    allowed_classes = {
        "provider-rotation",
        "target-system-readback",
        "operator-supplied-config",
        "independent-trust-authority",
        "workflow-reference-removal",
        "unknown-authority",
    }
    if (
        not annotation_id
        or resolution_class not in allowed_classes
        or not owner
        or not handoff_group
        or not reason
    ):
        raise ValueError("incomplete unresolved authority annotation")
    steps = annotation.get("provider_rotation_steps")
    if resolution_class == "provider-rotation":
        if not isinstance(steps, list) or not steps or not all(
            isinstance(step, str) and step.strip() for step in steps
        ):
            raise ValueError("provider rotation annotation requires a concrete rotation procedure")
        entry["rotation_required"] = True
        entry["migration_action"] = "rotate-at-provider"
    elif steps is not None:
        raise ValueError("provider rotation steps require provider-rotation classification")
    elif resolution_class == "workflow-reference-removal":
        entry["rotation_required"] = False
        entry["migration_action"] = "remove-unused-reference"

    entry["authority_annotation_id"] = annotation_id
    entry["resolution_class"] = resolution_class
    entry["authority_owner"] = owner
    entry["handoff_group"] = handoff_group
    entry["unresolved_reason"] = reason
    entry["provider_rotation_steps"] = steps
    if annotation.get("data_classification"):
        entry["data_classification"] = annotation["data_classification"]
    return entry


def validate_authority_mapping_coverage(
    evidence: dict[str, Any], entries: list[dict[str, Any]]
) -> None:
    mappings = evidence.get("mappings") or []
    annotations = evidence.get("unresolved_annotations") or []
    if not mappings and not annotations:
        return
    mapping_ids: list[str] = []
    for mapping in mappings:
        if not isinstance(mapping, dict):
            raise ValueError("authority evidence mapping must be an object")
        mapping_id = str(mapping.get("mapping_id") or "").strip()
        if not mapping_id:
            raise ValueError("authority evidence mapping requires mapping_id")
        mapping_ids.append(mapping_id)
    if len(mapping_ids) != len(set(mapping_ids)):
        raise ValueError("duplicate authority mapping_id")
    used = {
        str(entry["authority_mapping_id"])
        for entry in entries
        if entry.get("authority_mapping_id")
    }
    unused = sorted(set(mapping_ids) - used)
    if unused:
        raise ValueError(f"unused authority mappings: {', '.join(unused)}")

    annotation_ids: list[str] = []
    for annotation in annotations:
        if not isinstance(annotation, dict):
            raise ValueError("unresolved authority annotation must be an object")
        annotation_id = str(annotation.get("annotation_id") or "").strip()
        if not annotation_id:
            raise ValueError("unresolved authority annotation requires annotation_id")
        annotation_ids.append(annotation_id)
    if len(annotation_ids) != len(set(annotation_ids)):
        raise ValueError("duplicate authority annotation_id")
    used_annotations = {
        str(entry["authority_annotation_id"])
        for entry in entries
        if entry.get("authority_annotation_id")
    }
    unused_annotations = sorted(set(annotation_ids) - used_annotations)
    if unused_annotations:
        raise ValueError(f"unused authority annotations: {', '.join(unused_annotations)}")


def load_billing_evidence(path: Path) -> dict[str, Any]:
    raw = load_json(path, {}) if path.exists() else {}
    return load_billing_evidence_data(raw)


def load_billing_evidence_data(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raw = {}
    previous = raw.get("previous_month") if isinstance(raw.get("previous_month"), dict) else {}
    current = raw.get("current_unbilled") if isinstance(raw.get("current_unbilled"), dict) else {}
    return {
        "previous_month": {
            "amount_usd": previous.get("amount_usd"),
            "source": previous.get("source"),
            "captured_at": previous.get("captured_at"),
            "status": previous.get("status") or "unavailable",
        },
        "current_unbilled": {
            "amount_usd": current.get("amount_usd"),
            "source": current.get("source"),
            "captured_at": current.get("captured_at"),
            "status": current.get("status") or "unavailable",
        },
    }


def assert_private_hosted_flag(repo: dict[str, Any]) -> None:
    if str(repo.get("visibility") or "").lower() != "private":
        return
    for workflow in repo.get("workflows") or []:
        for job in workflow.get("jobs") or []:
            runs_on = str(job.get("runs_on") or "")
            hosted = bool(re.search(r"(^|[,\s\[])ubuntu-(latest|[0-9]{2}\.[0-9]{2})($|[,\s\]])", runs_on))
            if hosted and "blacksmith" not in runs_on.lower() and "self-hosted" not in runs_on:
                if "PRIVATE_UBUNTU_HOSTED" not in (job.get("flags") or []):
                    raise AssertionError(
                        f"{repo.get('name')}:{workflow.get('path')}#{job.get('id')} missing PRIVATE_UBUNTU_HOSTED"
                    )


def _stable_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str)


def _secret_names(payload: Any) -> list[str]:
    names: list[str] = []
    if isinstance(payload, list):
        for item in payload:
            if isinstance(item, dict) and item.get("name"):
                names.append(str(item["name"]))
            elif isinstance(item, str):
                names.append(item)
    return sorted(set(names))


STATIC_INPUT_SOURCE_REGISTRY = {
    "org": ("org.json", {}),
    "repos_index": ("repos.json", []),
    "runners": ("runners.json", {}),
    "runner_groups": ("runner-groups.json", {}),
    "org_secret_names": ("org-secrets.json", []),
    "org_variable_names": ("org-variables.json", []),
    "budgets": ("budgets.json", {}),
    "billing": ("blacksmith-billing.json", {}),
    "hosts": ("hosts.json", {}),
    "grok_runners": ("grok-runners.json", {}),
    "worldstream_runners": ("worldstream-runners.json", {}),
    "onepassword_vaults": ("onepassword-vaults.json", []),
    "authority_evidence": ("authority-evidence.json", {}),
    "op_env_key_metadata": ("op-env-key-metadata.json", {}),
    "op_field_metadata": ("op-field-metadata.json", {}),
    "worldstream_key_metadata": ("worldstream-key-metadata.json", {}),
    "connection_structure": ("connection-structure.json", {}),
    "collection_meta": ("collection-meta.json", {}),
}
DYNAMIC_NON_WORKFLOW_INPUT_KINDS = (
    "repository_meta",
    "repository_tree",
    "repository_secret_names",
    "repository_variable_names",
    "environment",
    "environment_branch_policies",
    "environment_secret_names",
)
REGISTERED_NON_WORKFLOW_INPUT_KINDS = (
    tuple(STATIC_INPUT_SOURCE_REGISTRY) + DYNAMIC_NON_WORKFLOW_INPUT_KINDS
)
REGISTERED_INPUT_KINDS = REGISTERED_NON_WORKFLOW_INPUT_KINDS + ("workflow",)


@dataclass(frozen=True)
class LoadedInventoryInputs:
    data: dict[str, Any]
    source_kinds: frozenset[str]
    input_hash: str


class _RegisteredInputReader:
    def __init__(self) -> None:
        self._read_paths: set[Path] = set()
        self.source_kinds: set[str] = set()

    def _claim(self, kind: str, path: Path) -> None:
        if kind not in REGISTERED_INPUT_KINDS:
            raise ValueError(f"unregistered inventory input kind: {kind}")
        resolved = path.resolve()
        if resolved in self._read_paths:
            raise ValueError(f"inventory input read more than once: {path}")
        self._read_paths.add(resolved)
        self.source_kinds.add(kind)

    def json(self, kind: str, path: Path, default: Any) -> Any:
        self._claim(kind, path)
        return load_json(path, default)

    def text(self, kind: str, path: Path) -> str:
        self._claim(kind, path)
        return path.read_text(encoding="utf-8")


def load_inventory_inputs(collect_dir: Path) -> LoadedInventoryInputs:
    reader = _RegisteredInputReader()
    raw = {
        kind: reader.json(kind, collect_dir / filename, default)
        for kind, (filename, default) in STATIC_INPUT_SOURCE_REGISTRY.items()
    }
    repos_index = raw["repos_index"] if isinstance(raw["repos_index"], list) else []
    repository_inputs: list[dict[str, Any]] = []
    for repo_info in repos_index:
        if not isinstance(repo_info, dict):
            continue
        name = repo_info.get("name")
        if not name:
            continue
        repo_dir = collect_dir / "repos" / name
        meta = reader.json("repository_meta", repo_dir / "meta.json", {})
        tree = reader.json("repository_tree", repo_dir / "tree.json", {})
        sha_by_path = {
            item.get("path"): item.get("sha")
            for item in (tree.get("tree") or [])
            if isinstance(item, dict) and item.get("path")
        }
        workflows: list[dict[str, Any]] = []
        wf_dir = repo_dir / "workflows"
        if wf_dir.exists():
            for wf_path in sorted(wf_dir.rglob("*")):
                if wf_path.suffix.lower() not in {".yml", ".yaml"}:
                    continue
                rel = ".github/workflows/" + wf_path.relative_to(wf_dir).as_posix()
                content = reader.text("workflow", wf_path)
                sha = (
                    sha_by_path.get(rel)
                    or hashlib.sha256(content.encode("utf-8")).hexdigest()
                )
                workflows.append({"path": rel, "sha": sha, "content": content})
        environments: dict[str, dict[str, Any]] = {}
        env_dir = repo_dir / "environments"
        if env_dir.exists():
            for env_file in sorted(env_dir.glob("*.json")):
                if env_file.name.endswith(".branches.json"):
                    continue
                record = reader.json("environment", env_file, {})
                if not isinstance(record, dict):
                    record = {}
                record = dict(record)
                branch_file = env_dir / f"{env_file.stem}.branches.json"
                if branch_file.exists():
                    record["deployment_branch_policies"] = reader.json(
                        "environment_branch_policies", branch_file, None
                    )
                environments[str(record.get("name") or env_file.stem)] = record
        env_secret_names: list[str] = []
        env_secret_dir = repo_dir / "environment-secrets"
        if env_secret_dir.exists():
            for secret_file in sorted(env_secret_dir.glob("*.json")):
                env_secret_names.extend(
                    _secret_names(
                        reader.json("environment_secret_names", secret_file, [])
                    )
                )
        repository_inputs.append(
            {
                "name": name,
                "repo_info": repo_info,
                "meta": meta,
                "workflows": workflows,
                "environments": environments,
                "repository_secret_names": _secret_names(
                    reader.json(
                        "repository_secret_names", repo_dir / "secrets.json", []
                    )
                ),
                "repository_variable_names": _secret_names(
                    reader.json(
                        "repository_variable_names", repo_dir / "variables.json", []
                    )
                ),
                "environment_secret_names": sorted(set(env_secret_names)),
            }
        )
    data = {
        "org": raw["org"] if isinstance(raw["org"], dict) else {},
        "repos_index": repos_index,
        "runners": raw["runners"] if isinstance(raw["runners"], dict) else {},
        "runner_groups": raw["runner_groups"]
        if isinstance(raw["runner_groups"], dict)
        else {},
        "org_secret_names": _secret_names(raw["org_secret_names"]),
        "org_variable_names": _secret_names(raw["org_variable_names"]),
        "budgets": raw["budgets"] if isinstance(raw["budgets"], dict) else {},
        "billing": load_billing_evidence_data(raw["billing"]),
        "hosts": raw["hosts"] if isinstance(raw["hosts"], dict) else {},
        "grok_runners": raw["grok_runners"]
        if isinstance(raw["grok_runners"], dict)
        else {},
        "worldstream_runners": raw["worldstream_runners"]
        if isinstance(raw["worldstream_runners"], dict)
        else {},
        "onepassword_vaults": raw["onepassword_vaults"]
        if isinstance(raw["onepassword_vaults"], list)
        else [],
        "authority_evidence": raw["authority_evidence"]
        if isinstance(raw["authority_evidence"], dict)
        else {},
        "op_env_key_metadata": raw["op_env_key_metadata"]
        if isinstance(raw["op_env_key_metadata"], dict)
        else {},
        "op_field_metadata": raw["op_field_metadata"]
        if isinstance(raw["op_field_metadata"], dict)
        else {},
        "worldstream_key_metadata": raw["worldstream_key_metadata"]
        if isinstance(raw["worldstream_key_metadata"], dict)
        else {},
        "connection_structure": raw["connection_structure"]
        if isinstance(raw["connection_structure"], dict)
        else {},
        "collection_meta": raw["collection_meta"]
        if isinstance(raw["collection_meta"], dict)
        else {},
        "repositories": repository_inputs,
    }
    input_hash = hashlib.sha256(_stable_json(data).encode("utf-8")).hexdigest()
    return LoadedInventoryInputs(
        data=data,
        source_kinds=frozenset(REGISTERED_INPUT_KINDS),
        input_hash=input_hash,
    )


def hash_inventory_inputs(inputs: LoadedInventoryInputs) -> str:
    current_hash = hashlib.sha256(_stable_json(inputs.data).encode("utf-8")).hexdigest()
    if current_hash != inputs.input_hash:
        raise ValueError("loaded inventory inputs were modified after hashing")
    return inputs.input_hash


def build_input_manifest(
    inputs: LoadedInventoryInputs, collected_at: str
) -> dict[str, Any]:
    repos_out = [
        {
            "name": repo["name"],
            "default_branch": repo["meta"].get("default_branch")
            or (repo["repo_info"].get("defaultBranchRef") or {}).get("name"),
            "default_sha": repo["meta"].get("default_sha") or repo["meta"].get("sha"),
            "workflows": [
                {"path": workflow["path"], "sha": workflow["sha"]}
                for workflow in repo.get("workflows") or []
            ],
        }
        for repo in inputs.data["repositories"]
    ]
    return {
        "schema_version": 1,
        "collected_at": collected_at,
        "input_hash": hash_inventory_inputs(inputs),
        "covered_inputs": [
            "org",
            "repos_index",
            "repository_default_and_workflow_shas",
            "environments_and_branch_policies",
            "org_and_repo_secret_and_variable_names",
            "runners_and_groups",
            "budgets_and_plan",
            "billing_evidence",
            "host_evidence",
            "grok_runners",
            "worldstream_runners",
            "onepassword_vaults",
            "task6_authority_evidence",
            "task6_op_env_key_metadata",
            "task6_op_field_metadata",
            "task6_worldstream_key_metadata",
            "task6_connection_structure",
            "collection_meta",
        ],
        "repositories": repos_out,
    }


def semantic_output_digest(output_dir: Path) -> str:
    docs: dict[str, Any] = {}
    for name in ("repositories.yaml", "runners.yaml", "secrets.yaml", "input-manifest.yaml"):
        path = output_dir / name
        if not path.exists():
            continue
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            data.pop("generated_at", None)
        docs[name] = data
    return hashlib.sha256(_stable_json(docs).encode("utf-8")).hexdigest()


def jobs_diverging_from_classifier(collect_dir: Path, repos_doc: dict[str, Any]) -> list[str]:
    mismatches: list[str] = []
    for repo in repos_doc.get("repositories") or []:
        repo_dir = collect_dir / "repos" / repo["name"]
        visibility = str(repo.get("visibility") or "")
        for workflow in repo.get("workflows") or []:
            wf_file = repo_dir / "workflows" / Path(workflow["path"]).name
            if not wf_file.exists():
                mismatches.append(f"{repo['name']}:{workflow['path']}:missing-source")
                continue
            parsed = parse_workflow(workflow["path"], wf_file.read_text(encoding="utf-8"))
            by_id = {job["id"]: job for job in parsed["jobs"]}
            for job in workflow.get("jobs") or []:
                source = by_id.get(job["id"])
                if not source:
                    mismatches.append(f"{repo['name']}:{workflow['path']}#{job['id']}:missing-parsed-job")
                    continue
                classified = classify_job(
                    repo["name"],
                    visibility,
                    workflow["path"],
                    source["id"],
                    source["runs_on"],
                    source["resolved_runs_on"],
                    source["environment_name"],
                    source["raw_text"],
                    source["uses"],
                    parsed["triggers"],
                    source["secret_names"],
                )
                for field in ("classification", "target_runner_class", "deploys_or_publishes", "production_impact"):
                    if job.get(field) != classified.get(field):
                        mismatches.append(
                            f"{repo['name']}:{workflow['path']}#{job['id']}:{field} inventory={job.get(field)!r} classifier={classified.get(field)!r}"
                        )
    return mismatches


def resolve_matrix_runs_on(job: dict[str, Any], runs_on: Any) -> list[str]:
    expr = stringify_runs_on(runs_on)
    strategy = job.get("strategy") or {}
    matrix = strategy.get("matrix") if isinstance(strategy, dict) else None
    if not isinstance(matrix, dict):
        return [expr] if expr else []
    if isinstance(runs_on, str) and "matrix.runner" in runs_on:
        return [str(x) for x in as_list(matrix.get("runner"))] or [expr]
    if isinstance(runs_on, str) and "matrix.os" in runs_on:
        return [str(x) for x in as_list(matrix.get("os"))] or [expr]
    return [expr] if expr else []


def is_grok_workflow(path: str) -> bool:
    name = Path(path).name
    return name in {"grok-pr-review.yml", "grok-pr-review.yaml"}


def production_impact(
    repo: str,
    workflow_path: str,
    job_id: str,
    env_name: str,
    text: str,
    deploys: bool,
) -> bool:
    path = workflow_path.lower()
    env_l = env_name.lower()
    if repo == "ken-backend" and path.endswith("deploy.yml") and job_id == "deploy":
        return True
    if repo == "ken-search" and path.endswith("deploy.yml") and job_id == "deploy":
        return True
    if env_l in NONPROD_ENV_NAMES or "staging" in path:
        return False
    if env_l in PROD_ENV_NAMES:
        return True
    if not deploys:
        return False
    if any(token in text.lower() for token in ("worldstream", "api.getken.ai", "ovh", "pypi", "npm publish", "ghcr.io")):
        return True
    if "deploy" in path or job_id in {"deploy", "publish", "pin"}:
        # default: treat real deploy/publish jobs as production-impact unless staging
        return "staging" not in path and "nonprod" not in path
    return False


def is_deploy_or_publish(job_id: str, workflow_path: str, text: str, uses: list[str], env_name: str) -> bool:
    path = workflow_path.lower()
    joined_uses = " ".join(uses)
    if job_id in {"should-deploy", "test", "ci", "security", "validate", "lint", "guardrails", "secrets-guard", "static", "no_stack_yet"}:
        return False
    if any(hint in text.lower() or hint in joined_uses for hint in DEPLOY_HINTS):
        return True
    if job_id in {"deploy", "publish", "pin", "build-and-publish"}:
        return True
    if any(token in path for token in ("deploy", "publish")) and job_id not in {
        "test",
        "should-deploy",
        "validate",
        "secrets-guard",
        "static",
        "no_stack_yet",
    }:
        return True
    if env_name and job_id in {"deploy", "pin", "publish"}:
        return True
    return False


def is_combined(deploys: bool, text: str, uses: list[str]) -> bool:
    if not deploys:
        return False
    blob = text.lower() + "\n" + " ".join(uses).lower()
    has_build = any(hint.lower() in blob for hint in BUILD_HINTS)
    has_deploy = any(hint.lower() in blob for hint in DEPLOY_HINTS)
    return has_build and has_deploy


def is_heavy(runs_on: str, workflow_path: str, job_id: str, text: str) -> bool:
    blob = f"{runs_on}\n{workflow_path}\n{job_id}\n{text}".lower()
    return any(hint in blob for hint in HEAVY_HINTS)


def classify_job(
    repo: str,
    visibility: str,
    workflow_path: str,
    job_id: str,
    runs_on: str,
    resolved_runs_on: list[str],
    env_name: str,
    text: str,
    uses: list[str],
    triggers: list[str],
    secrets: list[str],
) -> dict[str, Any]:
    flags: list[str] = []
    vis = visibility.lower()
    deploys = is_deploy_or_publish(job_id, workflow_path, text, uses, env_name)
    combined = is_combined(deploys, text, uses)
    prod = production_impact(repo, workflow_path, job_id, env_name, text, deploys)
    heavy = is_heavy(runs_on, workflow_path, job_id, text) or any(
        "4vcpu" in item for item in resolved_runs_on
    )
    pr_trigger = any(t.startswith("pull_request") for t in triggers)
    persistent = "self-hosted" in runs_on or "ken-ci" in runs_on or "grok-review" in runs_on
    if "blacksmith" in runs_on.lower() or any("blacksmith" in item for item in resolved_runs_on):
        flags.append("BLACKSMITH")
    if "ken-ci" in runs_on and not is_grok_workflow(workflow_path):
        flags.append("LEGACY_KEN_CI")
    hosted_ubuntu = bool(
        re.search(r"(^|[,\s\[])ubuntu-(latest|[0-9]{2}\.[0-9]{2})($|[,\s\]])", runs_on)
    )
    if vis == "private" and hosted_ubuntu and "blacksmith" not in runs_on.lower() and "self-hosted" not in runs_on:
        flags.append("PRIVATE_UBUNTU_HOSTED")
    if pr_trigger and persistent:
        flags.append("UNTRUSTED_PR_ON_PERSISTENT_SELF_HOSTED")
    if pr_trigger and secrets and job_id not in {"review"}:
        flags.append("SECRET_BEARING_PR")
    if combined:
        flags.append("COMBINED_BUILD_AND_DEPLOY")
    long_lived = long_lived_secrets(secrets)
    scheduled = is_scheduled(triggers)
    op_bootstrap = OP_BOOTSTRAP_SECRET in secrets
    if vis == "private" and scheduled and long_lived:
        flags.append("SCHEDULED_LONG_LIVED_SECRET")
    if vis == "private" and op_bootstrap:
        flags.append("OP_BOOTSTRAP_TOKEN")

    if (
        vis == "private"
        and Path(workflow_path).stem.lower() == "eval-prod"
        and long_lived
    ):
        flags.append("PRODUCTION_SECRET_WORKFLOW_FAIL_CLOSED")
        return {
            "classification": "production-secret-workflow",
            "target_runner_class": "ken-deploy-production",
            "target_runs_on": "[self-hosted, linux, x64, ken-deploy, production]",
            "secret_class": "deploy-production",
            "production_impact": True,
            "deploys_or_publishes": bool(deploys),
            "combined_build_and_deploy": combined,
            "flags": flags,
        }

    if is_grok_workflow(workflow_path):
        flags.append("PRESERVE_GROK_REVIEW_CLASS")
        if job_id == "review" or "grok-review" in runs_on:
            return {
                "classification": "existing-grok-review",
                "target_runner_class": "existing-grok-review",
                "target_runs_on": "[self-hosted, grok-review]",
                "secret_class": "grok-review-unchanged",
                "production_impact": False,
                "deploys_or_publishes": False,
                "combined_build_and_deploy": False,
                "flags": flags,
            }
        return {
            "classification": "existing-grok-review-gate",
            "target_runner_class": "existing-grok-review",
            "target_runs_on": "[self-hosted, linux, x64, ken-ci, standard]",
            "secret_class": "none",
            "production_impact": False,
            "deploys_or_publishes": False,
            "combined_build_and_deploy": False,
            "flags": flags,
        }

    if vis == "private" and ((scheduled and long_lived) or op_bootstrap):
        scheduled_prod = bool(op_bootstrap) or production_impact(
            repo, workflow_path, job_id, env_name, text, True
        ) or scheduled_production_side_effect(text, secrets)
        if deploys and prod:
            scheduled_prod = True
        classification = "production-impact-deploy" if deploys and scheduled_prod else (
            "scheduled-secret-production" if scheduled_prod else "scheduled-secret-nonproduction"
        )
        if deploys and not scheduled_prod:
            classification = "nonproduction-deploy"
        return {
            "classification": classification,
            "target_runner_class": "ken-deploy-production" if scheduled_prod else "ken-deploy-nonproduction",
            "target_runs_on": (
                "[self-hosted, linux, x64, ken-deploy, production]"
                if scheduled_prod
                else "[self-hosted, linux, x64, ken-deploy, nonproduction]"
            ),
            "secret_class": "deploy-production" if scheduled_prod else "deploy-nonproduction",
            "production_impact": bool(scheduled_prod),
            "deploys_or_publishes": bool(deploys),
            "combined_build_and_deploy": combined,
            "flags": flags,
        }

    if not runs_on and any(u.startswith("./") or u.endswith(".yml") or u.endswith(".yaml") for u in uses):
        return {
            "classification": "reusable-workflow-call",
            "target_runner_class": "inherit-called-workflow",
            "target_runs_on": "",
            "secret_class": "inherit",
            "production_impact": prod,
            "deploys_or_publishes": deploys,
            "combined_build_and_deploy": combined,
            "flags": flags,
        }

    if vis == "public":
        if deploys and prod:
            classification = "public-production-impact-deploy"
        elif deploys:
            classification = "public-deploy"
        else:
            classification = "public-standard-ci"
        return {
            "classification": classification,
            "target_runner_class": "public-github-hosted",
            "target_runs_on": "ubuntu-latest",
            "secret_class": "github-token-only" if secrets == ["GITHUB_TOKEN"] or not secrets else "public-hosted",
            "production_impact": prod,
            "deploys_or_publishes": deploys,
            "combined_build_and_deploy": combined,
            "flags": flags,
        }

    if deploys:
        if prod:
            return {
                "classification": "production-impact-deploy",
                "target_runner_class": "ken-deploy-production",
                "target_runs_on": "[self-hosted, linux, x64, ken-deploy, production]",
                "secret_class": "deploy-production",
                "production_impact": True,
                "deploys_or_publishes": True,
                "combined_build_and_deploy": combined,
                "flags": flags,
            }
        return {
            "classification": "nonproduction-deploy",
            "target_runner_class": "ken-deploy-nonproduction",
            "target_runs_on": "[self-hosted, linux, x64, ken-deploy, nonproduction]",
            "secret_class": "deploy-nonproduction",
            "production_impact": False,
            "deploys_or_publishes": True,
            "combined_build_and_deploy": combined,
            "flags": flags,
        }

    if job_id == "should-deploy":
        return {
            "classification": "deploy-gate",
            "target_runner_class": "ken-ci-standard",
            "target_runs_on": "[self-hosted, linux, x64, ken-ci, standard]",
            "secret_class": "none",
            "production_impact": False,
            "deploys_or_publishes": False,
            "combined_build_and_deploy": False,
            "flags": flags,
        }

    if heavy:
        return {
            "classification": "heavy-ci",
            "target_runner_class": "ken-ci-heavy",
            "target_runs_on": "[self-hosted, linux, x64, ken-ci, heavy]",
            "secret_class": "ci-runtime" if [s for s in secrets if s != "GITHUB_TOKEN"] else "none",
            "production_impact": False,
            "deploys_or_publishes": False,
            "combined_build_and_deploy": False,
            "flags": flags,
        }

    return {
        "classification": "standard-ci",
        "target_runner_class": "ken-ci-standard",
        "target_runs_on": "[self-hosted, linux, x64, ken-ci, standard]",
        "secret_class": "ci-runtime" if [s for s in secrets if s != "GITHUB_TOKEN"] else "none",
        "production_impact": False,
        "deploys_or_publishes": False,
        "combined_build_and_deploy": False,
        "flags": flags,
    }


def parse_workflow(path: str, text: str) -> dict[str, Any]:
    if VALUE_SHAPED_RE.search(text):
        text = VALUE_SHAPED_RE.sub("[REDACTED-VALUE-SHAPED]", text)
    data = yaml.safe_load(text) or {}
    if not isinstance(data, dict):
        raise ValueError(f"{path} is not a mapping")
    triggers = workflow_triggers(data.get(True) if True in data else data.get("on"))
    # PyYAML parses unquoted `on:` as boolean True
    if not triggers:
        triggers = workflow_triggers(data.get("on"))
    jobs_block = data.get("jobs") or {}
    workflow_env = data.get("env") if isinstance(data.get("env"), dict) else {}
    inherited_env_text = yaml.safe_dump({"env": workflow_env}, sort_keys=False)
    jobs: list[dict[str, Any]] = []
    if isinstance(jobs_block, dict):
        for job_id, job in jobs_block.items():
            if not isinstance(job, dict):
                job = {}
            job_text = yaml.safe_dump(job, sort_keys=False)
            effective_job_text = inherited_env_text + "\n" + job_text
            uses = uses_from(job)
            secrets = extract_names(SECRET_NAME_RE, effective_job_text)
            variables = extract_names(VAR_NAME_RE, effective_job_text)
            env_name, env_obj = job_environment(job)
            runs_on = job.get("runs-on")
            jobs.append(
                {
                    "id": str(job_id),
                    "name": job.get("name") or str(job_id),
                    "runs_on": stringify_runs_on(runs_on),
                    "resolved_runs_on": resolve_matrix_runs_on(job, runs_on),
                    "environment_name": env_name,
                    "environment_from_yaml": env_obj,
                    "needs": [str(x) for x in as_list(job.get("needs"))],
                    "permissions": job.get("permissions") if job.get("permissions") is not None else None,
                    "uses": uses,
                    "secret_names": secrets,
                    "variable_names": variables,
                    "artifacts": artifact_refs(job_text, uses),
                    "target_hints": target_hints(effective_job_text),
                    "raw_text": effective_job_text,
                }
            )
    # Scan the parsed document so commented-out jobs and examples cannot become
    # workflow references. Job-level extraction above uses the same principle.
    wf_text = yaml.safe_dump(data, sort_keys=False)
    return {
        "path": path,
        "name": data.get("name"),
        "triggers": triggers,
        "permissions": data.get("permissions"),
        "concurrency": data.get("concurrency"),
        "secret_names": extract_names(SECRET_NAME_RE, wf_text),
        "variable_names": extract_names(VAR_NAME_RE, wf_text),
        "jobs": jobs,
    }


def normalize_deployment_branch_policies(payload: Any) -> list[dict[str, Any]] | None:
    if payload is None:
        return None
    if isinstance(payload, dict) and "branch_policies" in payload:
        items = payload.get("branch_policies") or []
    elif isinstance(payload, list):
        items = payload
    elif isinstance(payload, dict) and (payload.get("name") or payload.get("id") or payload.get("node_id")):
        items = [payload]
    else:
        return None
    normalized: list[dict[str, Any]] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        entry: dict[str, Any] = {
            "id": item.get("id"),
            "node_id": item.get("node_id"),
            "name": item.get("name"),
        }
        if item.get("type"):
            entry["type"] = item.get("type")
        normalized.append(entry)
    return normalized


def env_protection(record: dict[str, Any] | None) -> dict[str, Any]:
    if not record:
        return {
            "available": False,
            "required_reviewers": [],
            "prevent_self_review": None,
            "wait_timer": None,
            "deployment_branches": None,
            "external_hard_stop": True,
            "note": "environment protection metadata was not returned",
        }
    reviewers: list[str] = []
    wait_timer = record.get("wait_timer")
    branch_policy = record.get("deployment_branch_policy")
    prevent = record.get("prevent_self_review")
    note = ""
    for rule in record.get("protection_rules") or []:
        if not isinstance(rule, dict):
            continue
        rtype = rule.get("type") or rule.get("id")
        if rtype == "wait_timer" and wait_timer is None:
            wait_timer = rule.get("wait_timer")
        if rtype in {"required_reviewers", "required_reviewers_rule"} or "reviewers" in rule:
            if "prevent_self_review" in rule:
                prevent = rule.get("prevent_self_review")
            for reviewer in rule.get("reviewers") or []:
                if isinstance(reviewer, dict):
                    inner = reviewer.get("reviewer") or reviewer
                    login = inner.get("login") or inner.get("slug") or inner.get("name")
                    if login:
                        reviewers.append(str(login))
    if isinstance(branch_policy, dict):
        if branch_policy.get("protected_branches"):
            branches: Any = "protected_branches"
        elif branch_policy.get("custom_branch_policies"):
            branches = normalize_deployment_branch_policies(record.get("deployment_branch_policies"))
            if not branches:
                branches = None
                note = "custom_branch_policies enabled but policy list was not collected"
        else:
            branches = None
    else:
        branches = None
    hard_stop = False
    for login in reviewers:
        if login.lower() not in {"cristian-frunze", "cristian"}:
            hard_stop = True
    if hard_stop:
        note = "required reviewer outside the cutover operator"
    return {
        "available": True,
        "required_reviewers": reviewers,
        "prevent_self_review": prevent,
        "wait_timer": wait_timer,
        "deployment_branches": branches,
        "external_hard_stop": hard_stop,
        "note": note,
    }


def secret_authority(
    name: str,
    repo: str,
    listed: dict[str, list[str]],
    workflow_path: str,
) -> dict[str, Any]:
    if name == "GITHUB_TOKEN":
        return {
            "github_secret_name": name,
            "repository": repo,
            "workflow": workflow_path,
            "scope": "github-provided",
            "source_authority": "GitHub-provided per-job GITHUB_TOKEN; not a stored long-lived secret",
            "source_readable": False,
            "rotation_required": False,
            "target_vault": None,
            "target_item": None,
            "target_field": None,
            "field_type": None,
            "consumer": "workflow-job",
            "consuming_jobs": [],
            "classification": "github-provided",
            "authority_status": "github-provided",
            "migration_action": "github-provided",
            "provider_rotation_steps": None,
            "downstream_update_steps": [],
            "alias_group": None,
            "alias_status": "not-applicable",
            "replacement_required": False,
        }
    scopes = []
    if name in listed.get("org", []):
        scopes.append("organization")
    if name in listed.get("repo", []):
        scopes.append("repository")
    if name in listed.get("environment", []):
        scopes.append("environment")
    if scopes:
        authority = (
            "GitHub "
            + "/".join(scopes)
            + " secret metadata (name only). Long-lived values are not recoverable through the GitHub API."
        )
    else:
        authority = (
            "Name referenced in default-branch workflow YAML; not listed in org/repo/environment "
            "secret metadata from this collection. Value is not recoverable through the GitHub API."
        )
    return {
        "github_secret_name": name,
        "repository": repo,
        "workflow": workflow_path,
        "scope": ",".join(scopes) if scopes else "workflow-reference",
        "source_authority": authority,
        "source_readable": False,
        "authority_status": "unresolved",
        "resolution_class": "unknown-authority",
        "authority_owner": "Unidentified",
        "unresolved_reason": (
            "No readable matching authority or source-proven rotation procedure was found."
        ),
        "rotation_required": None,
        "target_vault": None,
        "target_item": repo,
        "target_field": name,
        "field_type": "concealed",
        "consumer": None,
        "consuming_jobs": [],
        "classification": "unresolved",
        "migration_action": "resolve-authority",
        "provider_rotation_steps": None,
        "downstream_update_steps": [],
        "alias_group": None,
        "alias_status": "not-evaluated",
        "replacement_required": False,
    }


def summarize_runners(raw: dict[str, Any], snapshot_time: str, groups: dict[str, Any] | None = None) -> dict[str, Any]:
    runners = raw.get("runners") or raw.get("items") or []
    group_name_by_id: dict[Any, str] = {}
    blacksmith_group = None
    group_docs = groups or {}
    for group in group_docs.get("runner_groups") or group_docs.get("groups") or []:
        if not isinstance(group, dict):
            continue
        group_name_by_id[group.get("id")] = str(group.get("name") or "")
        if "blacksmith" in str(group.get("name") or "").lower():
            blacksmith_group = group.get("name")
    grouped_counts: dict[tuple[str, str, bool], int] = {}
    labels_seen: dict[str, int] = {}
    per_runner: list[dict[str, Any]] = []
    for runner in runners:
        labels = [lbl.get("name") if isinstance(lbl, dict) else str(lbl) for lbl in runner.get("labels") or []]
        status = str(runner.get("status") or "unknown")
        busy = bool(runner.get("busy"))
        label_key = tuple(sorted(str(item) for item in labels))
        grouped_counts[(",".join(label_key), status, busy)] = grouped_counts.get((",".join(label_key), status, busy), 0) + 1
        for label in labels:
            labels_seen[str(label)] = labels_seen.get(str(label), 0) + 1
        group_name = group_name_by_id.get(runner.get("runner_group_id"))
        if not group_name and any(str(label).startswith("blacksmith-") for label in labels):
            group_name = blacksmith_group or "Blacksmith runners"
        per_runner.append(
            {
                "name": runner.get("name"),
                "status": status,
                "busy": busy,
                "labels": [str(item) for item in labels],
                "group": group_name,
                "captured_time": snapshot_time,
            }
        )
    grouped = [
        {"count": count, "labels": labels.split(",") if labels else [], "status": status, "busy": busy}
        for (labels, status, busy), count in sorted(grouped_counts.items(), key=lambda item: (-item[1], item[0][0]))
    ]
    return {
        "snapshot_time": snapshot_time,
        "total_count": raw.get("total_count", len(runners)),
        "blacksmith_offline_count": sum(
            item["count"]
            for item in grouped
            if item["status"] == "offline" and any(str(lbl).startswith("blacksmith-") for lbl in item["labels"])
        ),
        "grouped_by_labels_status_busy": grouped,
        "label_counts": labels_seen,
        "runners": per_runner,
        "note": "Count is a point-in-time organization API snapshot and is not a forever invariant.",
    }


def build_target_runners() -> dict[str, Any]:
    standard = [f"ken-ci-standard-{i:02d}" for i in range(1, 9)]
    heavy = ["ken-ci-heavy-01", "ken-ci-heavy-02"]
    return {
        "ci": {
            "count": 10,
            "vm": "ken-ci",
            "names": standard + heavy,
            "reserved_disabled": ["ken-ci-standard-09", "ken-ci-standard-10"],
            "labels": {
                "standard": ["self-hosted", "linux", "x64", "ken-ci", "standard"],
                "heavy": ["self-hosted", "linux", "x64", "ken-ci", "heavy"],
            },
            "resources": {
                "standard": {"vcpu": 2, "memory_gib": 8, "cpu_quota": "200%", "memory_max": "8G"},
                "heavy": {"vcpu": 4, "memory_gib": 16, "cpu_quota": "400%", "memory_max": "16G"},
            },
        },
        "deploy": {
            "count": 2,
            "vm": "ken-deploy",
            "names": ["ken-deploy-nonproduction-01", "ken-deploy-production-01"],
            "labels": {
                "nonproduction": ["self-hosted", "linux", "x64", "ken-deploy", "nonproduction"],
                "production": ["self-hosted", "linux", "x64", "ken-deploy", "production"],
            },
        },
    }


def generate(collect_dir: Path, output_dir: Path) -> dict[str, Any]:
    return generate_from_inputs(load_inventory_inputs(collect_dir), output_dir)


def generate_from_inputs(
    inputs: LoadedInventoryInputs, output_dir: Path
) -> dict[str, Any]:
    data = inputs.data
    org = data["org"]
    repos_meta = data["repos_index"]
    runners_raw = data["runners"]
    groups_raw = data["runner_groups"]
    org_secrets = data["org_secret_names"]
    org_vars = data["org_variable_names"]
    authority_evidence = data["authority_evidence"]
    _reject_value_bearing_evidence(authority_evidence)
    budgets = data["budgets"]
    snapshot_time = data["collection_meta"].get("collected_at")
    if not snapshot_time:
        raise ValueError(
            "collection-meta.json must contain collected_at before inventory generation"
        )
    generated_at = snapshot_time
    billing = data["billing"]

    plan_name = ((org.get("plan") or {}).get("name") or "free").lower()
    organization_plan = {
        "name": plan_name,
        "private_hosted_minutes_allowance": 2000 if plan_name == "free" else None,
        "actions_overage_budget_usd": 0,
        "prevent_further_usage": True,
        "allowance_note": (
            "Official GitHub-hosted private minutes for the current Free plan are 2,000. "
            "Do not assume Team's 3,000-minute allowance."
        ),
    }
    if isinstance(budgets, dict) and budgets.get("actions_overage_budget_usd") is not None:
        organization_plan["actions_overage_budget_usd"] = budgets.get("actions_overage_budget_usd")
        organization_plan["prevent_further_usage"] = bool(budgets.get("prevent_further_usage", True))

    repositories: list[dict[str, Any]] = []
    secret_entries: list[dict[str, Any]] = []
    secret_entries_by_key: dict[tuple[str, str, str], dict[str, Any]] = {}

    repository_inputs = {repo["name"]: repo for repo in data["repositories"]}
    for repo_info in repos_meta:
        name = repo_info["name"]
        repo_inputs = repository_inputs[name]
        meta = repo_inputs["meta"] or repo_info
        visibility = str(
            meta.get("visibility") or repo_info.get("visibility") or ""
        ).lower()
        default_branch = (
            meta.get("default_branch")
            or (repo_info.get("defaultBranchRef") or {}).get("name")
            or "main"
        )
        workflows: list[dict[str, Any]] = []
        listed_secrets = {
            "org": org_secrets,
            "repo": repo_inputs["repository_secret_names"],
            "environment": repo_inputs["environment_secret_names"],
        }
        for workflow_input in repo_inputs["workflows"]:
            rel = workflow_input["path"]
            parsed = parse_workflow(rel, workflow_input["content"])
            jobs_out: list[dict[str, Any]] = []
            for job in parsed["jobs"]:
                env_name = job["environment_name"]
                env_record_raw = (
                    repo_inputs["environments"].get(env_name) if env_name else None
                )
                protection = (
                    env_protection(env_record_raw)
                    if env_name
                    else {
                        "available": False,
                        "required_reviewers": [],
                        "prevent_self_review": None,
                        "wait_timer": None,
                        "deployment_branches": None,
                        "external_hard_stop": False,
                        "note": "",
                    }
                )
                if env_name and protection.get("external_hard_stop"):
                    job_flags_extra = ["EXTERNAL_HARD_STOP"]
                else:
                    job_flags_extra = []
                classified = classify_job(
                    name,
                    visibility,
                    rel,
                    job["id"],
                    job["runs_on"],
                    job["resolved_runs_on"],
                    env_name,
                    job["raw_text"],
                    job["uses"],
                    parsed["triggers"],
                    job["secret_names"],
                )
                flags = classified["flags"] + [
                    f for f in job_flags_extra if f not in classified["flags"]
                ]
                env_record = None
                if env_name:
                    env_record = {
                        "name": env_name,
                        "required_reviewers": protection["required_reviewers"],
                        "prevent_self_review": protection["prevent_self_review"],
                        "wait_timer": protection["wait_timer"],
                        "deployment_branches": protection["deployment_branches"],
                        "protection_available": protection["available"],
                        "external_hard_stop": protection["external_hard_stop"],
                        "note": protection["note"],
                    }
                target = structured_target(
                    job["id"],
                    rel,
                    job["raw_text"],
                    job["uses"],
                    job["secret_names"],
                    job["variable_names"],
                )
                hint_list = list(job["target_hints"])
                for extra in (
                    target["host_secret_names"] + target["host_variable_names"]
                ):
                    if extra not in hint_list:
                        hint_list.append(extra)
                if (
                    target["registry_or_package"]
                    and target["registry_or_package"] not in hint_list
                ):
                    hint_list.append(target["registry_or_package"])
                jobs_out.append(
                    {
                        "id": job["id"],
                        "name": job["name"],
                        "runs_on": job["runs_on"],
                        "resolved_runs_on": job["resolved_runs_on"],
                        "environment": env_record,
                        "environment_name": env_name or None,
                        "needs": job["needs"],
                        "permissions": job["permissions"]
                        if job["permissions"] is not None
                        else parsed["permissions"],
                        "uses": job["uses"],
                        "secret_names": job["secret_names"],
                        "variable_names": job["variable_names"],
                        "artifacts": job["artifacts"],
                        "target_hints": hint_list,
                        "target": target,
                        "classification": classified["classification"],
                        "target_runner_class": classified["target_runner_class"],
                        "target_runs_on": classified["target_runs_on"],
                        "secret_class": classified["secret_class"],
                        "production_impact": classified["production_impact"],
                        "deploys_or_publishes": classified["deploys_or_publishes"],
                        "combined_build_and_deploy": classified[
                            "combined_build_and_deploy"
                        ],
                        "flags": flags,
                    }
                )
                for secret_name in job["secret_names"]:
                    key = (name, rel, secret_name)
                    existing = secret_entries_by_key.get(key)
                    if existing is not None:
                        if job["id"] not in existing["consuming_jobs"]:
                            existing["consuming_jobs"].append(job["id"])
                        continue
                    entry = apply_secret_consumer(
                        secret_authority(secret_name, name, listed_secrets, rel),
                        classified,
                    )
                    entry = apply_authority_evidence(entry, authority_evidence)
                    entry = apply_unresolved_annotation(entry, authority_evidence)
                    entry["consuming_jobs"] = [job["id"]]
                    secret_entries_by_key[key] = entry
                    secret_entries.append(entry)
            workflows.append(
                {
                    "path": rel,
                    "name": parsed["name"],
                    "triggers": parsed["triggers"],
                    "permissions": parsed["permissions"],
                    "concurrency": parsed["concurrency"],
                    "secret_names": parsed["secret_names"],
                    "variable_names": parsed["variable_names"],
                    "jobs": jobs_out,
                }
            )

        repositories.append(
            {
                "name": name,
                "visibility": visibility,
                "archived": bool(meta.get("isArchived") or meta.get("archived") or False),
                "default_branch": default_branch,
                "default_sha": meta.get("default_sha") or meta.get("sha"),
                "workflow_count": len(workflows),
                "job_count": sum(len(wf["jobs"]) for wf in workflows),
                "workflows": workflows,
            }
        )

    repositories.sort(key=lambda item: item["name"].lower())
    validate_authority_mapping_coverage(authority_evidence, secret_entries)
    private = [r for r in repositories if r["visibility"] == "private"]
    public = [r for r in repositories if r["visibility"] == "public"]

    repositories_doc = {
        "schema_version": 1,
        "organization": org.get("login") or "Ken-Technology",
        "generated_at": generated_at,
        "authority": "live GitHub default-branch workflow YAML and environment metadata; names only",
        "counts": {
            "active_repositories": len(repositories),
            "private_repositories": len(private),
            "public_repositories": len(public),
        },
        "organization_plan": organization_plan,
        "repositories": repositories,
    }

    host_snapshot = data["hosts"] or {
        "available": False,
        "note": "Host snapshot was not included in this collection.",
    }
    grok = data["grok_runners"]
    worldstream = data["worldstream_runners"]
    if not grok:
        grok = {
            "count": 6,
            "class": "existing-grok-review",
            "labels": ["self-hosted", "grok-review"],
            "names": [
                "hetzner-grok-review-ken-agents",
                "hetzner-grok-review-ken-ai-mcp",
                "hetzner-grok-review-ken-backend",
                "hetzner-grok-review-ken-frontend",
                "hetzner-grok-review-ken-scraping",
                "hetzner-grok-review-ken-search",
            ],
            "unchanged": True,
        }
    runners_doc = {
        "schema_version": 1,
        "organization": org.get("login") or "Ken-Technology",
        "generated_at": generated_at,
        "snapshot_time": snapshot_time,
        "organization_plan": organization_plan,
        "billing": {
            "actions_overage_budget_usd": organization_plan["actions_overage_budget_usd"],
            "prevent_further_usage": organization_plan["prevent_further_usage"],
            "private_hosted_minutes_allowance": organization_plan["private_hosted_minutes_allowance"],
            "previous_month": billing["previous_month"],
            "current_unbilled": billing["current_unbilled"],
        },
        "current": summarize_runners(runners_raw, snapshot_time, groups_raw),
        "runner_groups": groups_raw.get("runner_groups") or groups_raw.get("groups") or groups_raw,
        "target": build_target_runners(),
        "preserved": {"grok_review": grok},
        "legacy": {"worldstream_ken_ci": worldstream},
        "hosts": host_snapshot,
    }

    secrets_doc = {
        "schema_version": 2,
        "organization": org.get("login") or "Ken-Technology",
        "generated_at": generated_at,
        "policy": (
            "Name-only map. Values were never requested or written. "
            "GitHub-only long-lived secrets remain unresolved until a readable authority "
            "or provider rotation procedure is verified."
        ),
        "organization_secret_names": org_secrets,
        "organization_variable_names": org_vars,
        "onepassword_visible_vaults": data["onepassword_vaults"],
        "authority_evidence_id": authority_evidence.get("evidence_id"),
        "entries": secret_entries,
    }

    manifest = build_input_manifest(inputs, snapshot_time)
    repositories_doc["input_hash"] = manifest["input_hash"]
    dump_yaml(output_dir / "repositories.yaml", repositories_doc)
    dump_yaml(output_dir / "runners.yaml", runners_doc)
    dump_yaml(output_dir / "secrets.yaml", secrets_doc)
    dump_yaml(output_dir / "input-manifest.yaml", manifest)
    return {
        "repositories": len(repositories),
        "jobs": sum(r["job_count"] for r in repositories),
        "secrets": len(secret_entries),
        "input_hash": manifest["input_hash"],
        "output_dir": str(output_dir),
    }


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if len(argv) < 2:
        sys.stderr.write("usage: audit_workflows.py COLLECT_DIR OUTPUT_DIR\n")
        return 2
    summary = generate(Path(argv[0]), Path(argv[1]))
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
