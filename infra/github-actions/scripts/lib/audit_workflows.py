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
OP_REFERENCE_SEGMENT = r"[A-Za-z0-9][A-Za-z0-9._ -]*"
DIRECT_OP_REFERENCE_RE = re.compile(
    rf"^op://(?P<vault>{OP_REFERENCE_SEGMENT})/(?P<item>{OP_REFERENCE_SEGMENT})/(?P<field>{OP_REFERENCE_SEGMENT})$"
)

BROKER_REQUEST_KEYS = ("version", "action_id", "oidc_jwt", "github_token")
FRONTEND_POST_BUILD_FIELDS = frozenset(
    {"POSTHOG_PERSONAL_API_KEY", "POSTHOG_PROJECT_ID"}
)
FRONTEND_VARIABLE_MIGRATIONS = frozenset(
    {"NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY", "NEXT_PUBLIC_POSTHOG_PROJECT_TOKEN"}
)
FRONTEND_EXPLICIT_REVIEWED_VARIABLES = frozenset(
    {
        "NEXT_PUBLIC_CLERK_SIGN_IN_URL",
        "NEXT_PUBLIC_CLERK_SIGN_UP_URL",
        "NEXT_PUBLIC_TECHNOLOGY_FILTER_ENABLED",
        "NEXT_PUBLIC_TECHNOLOGY_FILTER_ALLOWED_CLIENT_IDS",
        "NEXT_PUBLIC_EXPERIMENTS_ALLOWED_CLIENT_IDS",
    }
)
FRONTEND_PRODUCTION_RELEASE_ACTION_ID = "ken-frontend-production-release"
FRONTEND_PRODUCTION_DEPLOY_IDENTITY = "ken-deploy-production"
FRONTEND_SOURCEMAP_UPLOADER_IDENTITY = "ken-action-frontend-posthog"
FRONTEND_PRODUCTION_BUILD_BOUNDARY = {
    "action_id": FRONTEND_PRODUCTION_RELEASE_ACTION_ID,
    "mode": "production_build",
    "workflow": ".github/workflows/deploy.yml",
    "production_build_job": "build-image",
    "deployment_job": "deploy",
    "runner_class": FRONTEND_PRODUCTION_DEPLOY_IDENTITY,
    "broker_only": True,
    "ci_validation_only": True,
    "forbid_ken_ci_production_artifact": True,
}
FRONTEND_POST_BUILD_BOUNDARY = {
    "action_id": FRONTEND_PRODUCTION_RELEASE_ACTION_ID,
    "mode": "post-build-sourcemap-upload",
    "workflow": ".github/workflows/deploy.yml",
    "production_build_job": "build-image",
    "deployment_job": "deploy",
    "runner_class": FRONTEND_PRODUCTION_DEPLOY_IDENTITY,
    "broker_only": True,
    "ci_validation_only": True,
    "forbid_ken_ci_production_artifact": True,
}
FRONTEND_BROKER_METADATA_KEYS = (
    "required_runtime_identity",
    "execution_boundary",
    "broker_action_id",
    "action_phase",
)
FRONTEND_ANNOTATION_CONTRACTS = {
    "NEXT_SERVER_ACTIONS_ENCRYPTION_KEY": {
        "required_runtime_identity": FRONTEND_PRODUCTION_DEPLOY_IDENTITY,
        "execution_boundary": FRONTEND_PRODUCTION_BUILD_BOUNDARY,
        "action_phase": "offline-buildkit-secret-phase",
        "broker_action_id": FRONTEND_PRODUCTION_RELEASE_ACTION_ID,
    },
    "POSTHOG_PERSONAL_API_KEY": {
        "required_runtime_identity": FRONTEND_SOURCEMAP_UPLOADER_IDENTITY,
        "execution_boundary": FRONTEND_POST_BUILD_BOUNDARY,
        "action_phase": "post-build-sourcemap-upload",
        "broker_action_id": FRONTEND_PRODUCTION_RELEASE_ACTION_ID,
    },
    "POSTHOG_PROJECT_ID": {
        "required_runtime_identity": FRONTEND_SOURCEMAP_UPLOADER_IDENTITY,
        "execution_boundary": FRONTEND_POST_BUILD_BOUNDARY,
        "action_phase": "post-build-sourcemap-upload",
        "broker_action_id": FRONTEND_PRODUCTION_RELEASE_ACTION_ID,
    },
}
FIXED_BROKER_ACTION_POLICIES: dict[str, dict[str, Any]] = {
    "ken-vexa-mcp-auth-production-deploy": {
        "repository": "ken-vexa-mcp-auth",
        "workflow": ".github/workflows/deploy.yml",
        "job": "deploy",
        "executor_uid": "ken-action-vexa-deploy",
        "template_path": "/etc/ken-op-broker/templates/ken-vexa-mcp-auth-production-deploy.env.op",
        "wrapper_path": "/usr/local/libexec/ken-actions/ken-vexa-mcp-auth-production-deploy",
        "target_profile": "vexa-mcp-auth-production-ssh-and-public-health",
        "network_profile": "github-source-vexa-production-ssh-mcp-recordings",
        "required_fields": frozenset(
            {
                ("ken-vexa-mcp-auth", "SERVER_HOST", "string"),
                ("ken-vexa-mcp-auth", "SERVER_PORT", "string"),
                ("ken-vexa-mcp-auth", "SERVER_SSH_KEY", "concealed"),
            }
        ),
    },
    "ken-website-beehiiv-production-sync": {
        "repository": "ken-website",
        "workflow": ".github/workflows/beehiiv-sync.yml",
        "job": "sync",
        "executor_uid": "ken-action-website-beehiiv",
        "template_path": "/etc/ken-op-broker/templates/ken-website-beehiiv-production-sync.env.op",
        "wrapper_path": "/usr/local/libexec/ken-actions/ken-website-beehiiv-production-sync",
        "target_profile": "ken-website-main-beehiiv-sync",
        "network_profile": "github-source-beehiiv-api-and-ken-website-push",
        "required_fields": frozenset(
            {
                ("ken-website", "DEPLOY_SSH_KEY", "concealed"),
                ("ken-website", "BEEHIIV_API_KEY", "concealed"),
                ("ken-website", "BEEHIIV_PUBLICATION_ID", "string"),
            }
        ),
    },
    "ken-website-production-deploy": {
        "repository": "ken-website",
        "workflow": ".github/workflows/deploy.yml",
        "job": "deploy",
        "executor_uid": "ken-action-website-deploy",
        "template_path": "/etc/ken-op-broker/templates/ken-website-production-deploy.env.op",
        "wrapper_path": "/usr/local/libexec/ken-actions/ken-website-production-deploy",
        "target_profile": "ken-website-production-ssh-and-public-health",
        "network_profile": "github-source-website-production-ssh-and-public-health",
        "required_fields": frozenset(
            {
                ("ken-website", "WEBSITE_HOST", "string"),
                ("ken-website", "WEBSITE_PORT", "string"),
                ("ken-website", "WEBSITE_SSH_KEY", "concealed"),
            }
        ),
    },
}

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


def _strict_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def _reject_json_constant(_: str) -> None:
    raise ValueError("non-finite JSON number")


def _parse_json_documents(text: str) -> list[Any]:
    decoder = json.JSONDecoder(
        object_pairs_hook=_strict_json_object,
        parse_constant=_reject_json_constant,
    )
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
        return json.loads(
            text,
            object_pairs_hook=_strict_json_object,
            parse_constant=_reject_json_constant,
        )
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


class UniqueKeySafeLoader(yaml.SafeLoader):
    pass


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
            raise ValueError("duplicate YAML mapping key")
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


UniqueKeySafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
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


def extract_direct_onepassword_references(
    workflow_env: dict[str, Any], job: dict[str, Any]
) -> list[dict[str, str]]:
    env_blocks: list[dict[str, Any]] = []
    if workflow_env:
        env_blocks.append(workflow_env)
    job_env = job.get("env")
    if isinstance(job_env, dict):
        env_blocks.append(job_env)
    for step in job.get("steps") or []:
        if isinstance(step, dict) and isinstance(step.get("env"), dict):
            env_blocks.append(step["env"])

    references: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for env in env_blocks:
        for environment_name, raw in env.items():
            if not isinstance(raw, str) or "op://" not in raw:
                continue
            source_reference = raw.strip()
            match = DIRECT_OP_REFERENCE_RE.fullmatch(source_reference)
            if not match:
                raise ValueError(
                    "direct workflow env references must be fixed direct 1Password references"
                )
            key = (str(environment_name), source_reference)
            if key in seen:
                continue
            seen.add(key)
            references.append(
                {
                    "environment_name": str(environment_name),
                    "source_reference": source_reference,
                    "source_vault": match.group("vault"),
                    "source_item": match.group("item"),
                    "source_field": match.group("field"),
                }
            )
    return references


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
        identity = {
            "ken-ci-standard": "ken-ci-runtime",
            "ken-ci-docker": "ken-ci-runtime",
            "ken-ci-heavy": "ken-ci-runtime",
            "ken-deploy-nonproduction": "ken-deploy-nonproduction",
            "ken-deploy-production": "ken-deploy-production",
        }.get(
            str(entry.get("consumer") or ""),
            "the exact workflow-scoped runtime service account",
        )
        entry["downstream_update_steps"] = [
            f"Create or confirm {identity} with read_items only to its single named vault; never copy the predecessor bootstrap credential into a target vault.",
            f"Install the new one-time credential through hidden input as the VM systemd credential, then cut {entry['repository']}/{entry['workflow']} over to the local broker.",
            f"Live-verify the broker-backed workflow before deleting {entry['repository']}/{OP_BOOTSTRAP_SECRET} from GitHub or revoking the predecessor bootstrap credential.",
        ]
    if entry.get("authority_status") == "unresolved" and not entry.get(
        "downstream_update_steps"
    ):
        target = entry.get("target_vault") or "an explicitly approved trust-domain target"
        coordinate = (
            f"{entry['repository']}/{entry['github_secret_name']} "
            f"for {entry['workflow']}"
        )
        entry["downstream_update_steps"] = [
            f"Identify a readable authority or approved replacement for {coordinate}; stop if its trust boundary cannot be proven.",
            f"Populate the exact field in {target} through the temporary migration writer, cut the workflow over to the local broker, and verify the live consumer.",
            f"Only after live verification, delete the matching GitHub secret field and revoke a predecessor when the approved recovery class requires it.",
        ]
    return entry


def assert_secret_trust_compatible(
    existing: dict[str, Any], candidate: dict[str, Any], job_id: str
) -> None:
    for field in (
        "target_vault",
        "consumer",
        "classification",
        "authority_status",
        "migration_action",
        "source_authority",
        "data_classification",
        "target_variable_name",
        "broker_action_id",
        "action_phase",
        "execution_boundary",
    ):
        if existing.get(field) != candidate.get(field):
            raise ValueError(
                "secret trust-boundary collision for "
                f"{existing.get('repository')}:{existing.get('workflow')}:"
                f"{existing.get('github_secret_name')} at job {job_id}: {field}"
            )


def apply_direct_onepassword_mapping(
    repository: str,
    workflow: str,
    job: str,
    reference: dict[str, Any],
    evidence: dict[str, Any] | None,
) -> dict[str, Any]:
    evidence = evidence or {}
    _reject_value_bearing_evidence(evidence)
    matches = [
        mapping
        for mapping in evidence.get("direct_onepassword_mappings") or []
        if isinstance(mapping, dict)
        and mapping.get("repository") == repository
        and mapping.get("workflow") == workflow
        and mapping.get("job") == job
        and mapping.get("environment_name") == reference.get("environment_name")
        and mapping.get("source_reference") == reference.get("source_reference")
    ]
    if not matches:
        raise ValueError(
            "unregistered direct 1Password reference for "
            f"{repository}:{workflow}#{job}:{reference.get('environment_name')}"
        )
    if len(matches) != 1:
        raise ValueError("multiple direct 1Password mappings matched one reference")
    mapping = matches[0]
    mapping_id = str(mapping.get("mapping_id") or "").strip()
    if not mapping_id:
        raise ValueError("direct 1Password mapping requires mapping_id")
    for field in ("source_vault", "source_item", "source_field"):
        if mapping.get(field) != reference.get(field):
            raise ValueError(f"direct 1Password mapping source mismatch: {field}")
    if not all(mapping.get(field) for field in ("target_item", "target_field")):
        raise ValueError("direct 1Password mapping requires exact target item and field")
    if mapping.get("field_type") not in {"concealed", "string"}:
        raise ValueError("direct 1Password mapping requires an explicit field type")
    if mapping.get("consumer") not in {
        "ken-ci-runtime",
        "ken-deploy-nonproduction",
        "ken-deploy-production",
    }:
        raise ValueError("direct 1Password mapping requires a one-vault runtime consumer")
    for field in (
        "source_to_target_steps",
        "broker_cutover_steps",
        "live_verification_steps",
        "retirement_steps",
    ):
        _nonempty_steps(mapping.get(field), field)
    disposition = mapping.get("disposition")
    delivery = mapping.get("delivery")
    migration_action = mapping.get("migration_action")
    broker_action_id = str(mapping.get("broker_action_id") or "").strip()
    if disposition == "broker-action":
        if delivery != "onepassword-broker" or migration_action != "copy-direct-onepassword-reference":
            raise ValueError("invalid direct 1Password broker disposition")
        if mapping.get("target_vault") not in {
            "Ken CI Runtime", "Ken Deploy Nonproduction", "Ken Deploy Production"
        }:
            raise ValueError("direct 1Password mapping requires an approved target vault")
        if not broker_action_id:
            raise ValueError("direct 1Password mapping requires broker_action_id")
        broker_actions = [
            action
            for action in evidence.get("broker_actions") or []
            if isinstance(action, dict) and action.get("action_id") == broker_action_id
        ]
        if len(broker_actions) != 1:
            raise ValueError("direct 1Password mapping requires one fixed broker action")
        broker_action = broker_actions[0]
        if broker_action.get("mode") != "fixed_secret_action":
            raise ValueError("direct 1Password reference requires fixed_secret_action mode")
        for field in ("repository", "workflow", "job", "runner_class", "target_vault"):
            expected = {
                "repository": repository,
                "workflow": workflow,
                "job": job,
                "runner_class": mapping.get("consumer"),
                "target_vault": mapping.get("target_vault"),
            }[field]
            if broker_action.get(field) != expected:
                raise ValueError("direct 1Password broker action trust boundary mismatch")
        exact_field = {
            "target_item": mapping["target_item"],
            "target_field": mapping["target_field"],
            "field_type": mapping["field_type"],
        }
        if exact_field not in (broker_action.get("required_fields") or []):
            raise ValueError("direct 1Password broker action is missing its exact field")
    elif disposition == "github-variable":
        expected = {
            "repository": "ken-website",
            "workflow": ".github/workflows/deploy.yml",
            "job": "deploy",
            "environment_name": "NEXT_PUBLIC_POSTHOG_PROJECT_TOKEN",
            "target_vault": "not-applicable",
            "target_item": "GitHub Actions variables:ken-website",
            "target_field": "NEXT_PUBLIC_POSTHOG_PROJECT_TOKEN",
            "field_type": "string",
            "consumer": "ken-deploy-production",
            "delivery": "github-actions-variable",
            "migration_action": "move-to-variable",
        }
        if broker_action_id or any(mapping.get(key) != value for key, value in expected.items()):
            raise ValueError("invalid direct GitHub variable disposition")
    elif disposition == "obsolete-unused":
        expected = {
            "repository": "ken-website",
            "workflow": ".github/workflows/deploy.yml",
            "job": "deploy",
            "environment_name": "POSTHOG_PERSONAL_API_KEY",
            "target_vault": "not-applicable",
            "target_item": "obsolete-reference",
            "target_field": "POSTHOG_PERSONAL_API_KEY",
            "field_type": "concealed",
            "consumer": "ken-deploy-production",
            "delivery": "none",
            "migration_action": "remove-unused-reference-after-rg-proof",
        }
        if broker_action_id or any(mapping.get(key) != value for key, value in expected.items()):
            raise ValueError("invalid obsolete direct reference disposition")
    else:
        raise ValueError("unsupported direct 1Password disposition")
    result = {
        "reference_class": "direct-onepassword",
        "mapping_id": mapping_id,
        "repository": repository,
        "workflow": workflow,
        "job": job,
        "environment_name": reference["environment_name"],
        "source_reference": reference["source_reference"],
        "source_vault": reference["source_vault"],
        "source_item": reference["source_item"],
        "source_field": reference["source_field"],
        "source_readable": False,
        "authority_status": "existing-direct-reference",
        "target_vault": mapping["target_vault"],
        "target_item": mapping["target_item"],
        "target_field": mapping["target_field"],
        "field_type": mapping["field_type"],
        "consumer": mapping["consumer"],
        "disposition": disposition,
        "delivery": delivery,
        "migration_action": migration_action,
        "source_to_target_steps": list(mapping["source_to_target_steps"]),
        "broker_cutover_steps": list(mapping["broker_cutover_steps"]),
        "live_verification_steps": list(mapping["live_verification_steps"]),
        "retirement_steps": list(mapping["retirement_steps"]),
        "rotation_required": False,
    }
    if broker_action_id:
        result["broker_action_id"] = broker_action_id
    return result


def _reject_value_bearing_evidence(value: Any, path: str = "evidence") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if str(key).lower() in {
                "value",
                "secret",
                "password",
                "token",
                "credential",
                "api_key",
                "private_key",
                "secret_value",
                "access_token",
                "password_hash",
                "values",
            }:
                raise ValueError("value-bearing authority evidence key")
            _reject_value_bearing_evidence(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _reject_value_bearing_evidence(child, f"{path}[{index}]")


def _authority_object(
    value: Any,
    required: set[str],
    optional: set[str] | None = None,
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError("wrong authority evidence type")
    allowed = required | (optional or set())
    if set(value) - allowed:
        raise ValueError("unexpected authority evidence key")
    if required - set(value):
        raise ValueError("missing authority evidence key")
    return value


def _authority_type(value: Any, expected: type | tuple[type, ...]) -> None:
    expected_types = expected if isinstance(expected, tuple) else (expected,)
    if not any(type(value) is expected_type for expected_type in expected_types):
        raise ValueError("wrong authority evidence type")


def _authority_nonempty_string(value: Any) -> None:
    if type(value) is not str or not value.strip():
        raise ValueError("wrong authority evidence type")


def _authority_string_list(value: Any, *, allow_empty: bool = False) -> None:
    if not isinstance(value, list) or (not allow_empty and not value):
        raise ValueError("wrong authority evidence type")
    if not all(type(item) is str and item.strip() for item in value):
        raise ValueError("wrong authority evidence type")


def _validate_authority_source(source: Any) -> None:
    if not isinstance(source, dict) or type(source.get("kind")) is not str:
        raise ValueError("wrong authority evidence type")
    schemas = {
        "deployed-config": {
            "kind", "host", "file", "key_path", "value_type", "readable",
            "exists", "metadata_artifact", "scoped_user",
        },
        "deployed-connection-component": {
            "kind", "host", "file", "key_path", "component", "readable",
            "exists", "metadata_artifact", "scoped_user",
        },
        "evidence-key": {"kind", "artifact", "key_path", "readable", "exists"},
        "onepassword": {
            "kind", "vault", "item", "field", "field_type", "readable",
            "value_present", "metadata_artifact",
        },
        "onepassword-document": {
            "kind", "vault", "item", "file_name", "readable", "exists",
            "metadata_artifact",
        },
        "onepassword-env-key": {
            "kind", "vault", "item", "name", "declared_type", "readable",
            "value_present", "metadata_artifact",
        },
        "onepassword-item-title-component": {
            "kind", "vault", "item", "component", "readable", "exists",
            "metadata_artifact",
        },
    }
    required = schemas.get(source["kind"])
    if required is None:
        raise ValueError("unsupported authority evidence source kind")
    _authority_object(source, required)
    for key, value in source.items():
        if key in {"readable", "exists", "value_present"}:
            _authority_type(value, bool)
        else:
            _authority_type(value, str)


def _validate_fixed_broker_action(action: dict[str, Any]) -> None:
    required = {
        "action_id", "mode", "trust_class", "repository", "workflow", "job",
        "runner_class", "template_path", "template_owner", "wrapper_path",
        "wrapper_owner", "executor_uid", "target_vault", "target_profile",
        "network_profile", "required_fields", "request_allowed_keys",
        "result_contract", "client_receives_field", "client_receives_config",
        "client_receives_fd", "client_receives_output",
    }
    _authority_object(action, required)
    for key, value in action.items():
        if key.startswith("client_receives_"):
            _authority_type(value, bool)
        elif key in {"required_fields"}:
            if not isinstance(value, list) or not value:
                raise ValueError("wrong authority evidence type")
            for field in value:
                field = _authority_object(
                    field, {"target_item", "target_field", "field_type"}
                )
                for part in field.values():
                    _authority_type(part, str)
        elif key == "request_allowed_keys":
            _authority_string_list(value)
        else:
            _authority_type(value, str)
    policy = FIXED_BROKER_ACTION_POLICIES.get(action["action_id"])
    field_coordinates = [
        (field["target_item"], field["target_field"], field["field_type"])
        for field in action["required_fields"]
    ]
    if (
        policy is None
        or action["trust_class"] != "production"
        or action["runner_class"] != "ken-deploy-production"
        or action["target_vault"] != "Ken Deploy Production"
        or action["template_owner"] != "root"
        or action["wrapper_owner"] != "root"
        or not action["template_path"].startswith("/etc/ken-op-broker/")
        or not action["wrapper_path"].startswith("/usr/local/libexec/")
        or tuple(action["request_allowed_keys"]) != BROKER_REQUEST_KEYS
        or action["result_contract"] != "stable-code-only"
        or any(action.get(field) != policy.get(field) for field in (
            "repository", "workflow", "job", "executor_uid", "template_path",
            "wrapper_path", "target_profile", "network_profile",
        ))
        or len(field_coordinates) != len(set(field_coordinates))
        or frozenset(field_coordinates) != policy["required_fields"]
        or any(
            action[key]
            for key in {
                "client_receives_field", "client_receives_config",
                "client_receives_fd", "client_receives_output",
            }
        )
    ):
        raise ValueError("invalid fixed broker action contract")


def _validate_production_build_action(action: dict[str, Any]) -> None:
    required = {
        "action_id", "mode", "status", "trust_class", "repository", "workflow",
        "job", "environment", "runner_class", "request_contract", "runner_contract",
        "authorization", "source_contract", "identity_boundary", "build_contract",
        "post_build_contract", "deploy_contract", "durable_state", "cleanup",
        "risk_acceptance", "pin_gate", "required_mutation_tests",
        "no_fallback_or_rebuild_elsewhere",
    }
    _authority_object(action, required)
    for key in {
        "action_id", "mode", "status", "trust_class", "repository", "workflow",
        "job", "environment", "runner_class",
    }:
        _authority_type(action[key], str)
    _authority_type(action["no_fallback_or_rebuild_elsewhere"], bool)
    _authority_string_list(action["required_mutation_tests"])

    request = _authority_object(
        action["request_contract"],
        {"allowed_keys", "accepts_artifact", "accepts_descriptor", "result"},
    )
    _authority_string_list(request["allowed_keys"])
    _authority_type(request["accepts_artifact"], bool)
    _authority_type(request["accepts_descriptor"], bool)
    _authority_type(request["result"], str)
    runner = _authority_object(
        action["runner_contract"],
        {"checkout", "build", "receives_digest", "receives_output"},
    )
    for value in runner.values():
        _authority_type(value, bool)
    authorization = _authority_object(
        action["authorization"],
        {"checks", "all_before_onepassword", "github_token_use"},
    )
    _authority_string_list(authorization["checks"])
    _authority_type(authorization["all_before_onepassword"], bool)
    _authority_type(authorization["github_token_use"], str)
    source = _authority_object(
        action["source_contract"],
        {
            "mode", "owner", "repository", "default_ref", "source_commit_sha",
            "workflow_blob_sha", "dockerfile_blob_sha", "pnpm_lock_blob_sha",
            "source_addendum", "fetch_before_onepassword", "fallback",
        },
    )
    for key, value in source.items():
        _authority_type(value, bool if key in {"fetch_before_onepassword", "fallback"} else str)
    identities = _authority_object(
        action["identity_boundary"],
        {
            "runner_uid", "broker_uid", "builder_uid", "post_build_uid", "deploy_uid",
            "pairwise_distinct", "runner_can_access_builder_socket",
            "runner_can_access_builder_state", "builder_can_access_deploy_executor",
            "deploy_executor_can_access_builder",
        },
    )
    for key, value in identities.items():
        _authority_type(value, bool if key not in {
            "runner_uid", "broker_uid", "builder_uid", "post_build_uid", "deploy_uid"
        } else str)
    build = _authority_object(
        action["build_contract"],
        {
            "rootless_buildkit", "builder_socket", "builder_state", "wrapper_path",
            "base_image", "base_image_digest", "buildkit_version", "wrapper_sha256",
            "dependencies_and_base_images_secretless", "dependency_network_profile",
            "dependency_endpoints", "secret_phase", "reviewed_github_variables",
            "forbidden_build_fields", "resource_limits", "output",
        },
    )
    for key in {
        "builder_socket", "builder_state", "wrapper_path", "base_image",
        "base_image_digest", "buildkit_version", "wrapper_sha256",
        "dependency_network_profile",
    }:
        _authority_type(build[key], str)
    _authority_type(build["rootless_buildkit"], bool)
    _authority_type(build["dependencies_and_base_images_secretless"], bool)
    for key in {"dependency_endpoints", "reviewed_github_variables", "forbidden_build_fields"}:
        _authority_string_list(build[key])
    phase = _authority_object(
        build["secret_phase"],
        {"command", "network", "delivery", "field", "arg", "env", "cache_metadata", "logs", "layers"},
    )
    for key, value in phase.items():
        _authority_type(value, bool if key in {"arg", "env", "cache_metadata", "logs", "layers"} else str)
    limits = _authority_object(
        build["resource_limits"],
        {"cpu_quota", "memory_max", "tasks_max", "timeout_seconds", "context_bytes_max", "output_bytes_max"},
    )
    _authority_type(limits["cpu_quota"], str)
    _authority_type(limits["memory_max"], str)
    for key in {"tasks_max", "timeout_seconds", "context_bytes_max", "output_bytes_max"}:
        _authority_type(limits[key], int)
    output = _authority_object(
        build["output"],
        {"format", "scan_config_history", "scan_uncompressed_layers", "canary_variants", "push_by_digest", "verified_short_lived_token", "registry"},
    )
    _authority_type(output["format"], str)
    _authority_type(output["registry"], str)
    _authority_string_list(output["canary_variants"])
    for key in {"scan_config_history", "scan_uncompressed_layers", "push_by_digest", "verified_short_lived_token"}:
        _authority_type(output[key], bool)
    post = _authority_object(
        action["post_build_contract"],
        {"executor_uid", "input", "fields", "target", "release", "can_read_build_field", "result"},
    )
    _authority_string_list(post["fields"])
    _authority_type(post["can_read_build_field"], bool)
    for key in {"executor_uid", "input", "target", "release", "result"}:
        _authority_type(post[key], str)
    deploy = _authority_object(
        action["deploy_contract"],
        {"executor_uid", "input", "deploy_by_digest", "accepts_runner_digest"},
    )
    _authority_type(deploy["executor_uid"], str)
    _authority_type(deploy["input"], str)
    _authority_type(deploy["deploy_by_digest"], bool)
    _authority_type(deploy["accepts_runner_digest"], bool)
    durable = _authority_object(
        action["durable_state"], {"fields", "source_run_digest_binding"}
    )
    _authority_string_list(durable["fields"])
    _authority_type(durable["source_run_digest_binding"], bool)
    cleanup = _authority_object(
        action["cleanup"],
        {"every_exit_path", "builder_state", "builder_cache", "request_directory", "process_groups"},
    )
    for value in cleanup.values():
        _authority_type(value, bool)
    risk = _authority_object(
        action["risk_acceptance"],
        {"merged_protected_code_may_consume_build_field", "transformed_embedding_residual_accepted_only_for_reviewed_source", "scope"},
    )
    _authority_type(risk["scope"], str)
    _authority_type(risk["merged_protected_code_may_consume_build_field"], bool)
    _authority_type(risk["transformed_embedding_residual_accepted_only_for_reviewed_source"], bool)
    gate = _authority_object(
        action["pin_gate"], {"cutover_blocked_until_all_exact", "required_exact_pins"}
    )
    _authority_type(gate["cutover_blocked_until_all_exact"], bool)
    _authority_string_list(gate["required_exact_pins"])
    expected_auth_checks = {
        "unix-peer", "class-oidc", "live-job", "workflow", "protected-ref",
        "environment", "durable-replay",
    }
    expected_source = {
        "owner": "Ken-Technology",
        "repository": "ken-frontend",
        "default_ref": "refs/heads/main",
        "source_addendum": "task-6-broker-source-contract-addendum.md",
        "source_commit_sha": "0952ac075f658acd1bc15a3253032507581e1f0d",
        "workflow_blob_sha": "21b01bbfeb3db512a42080ea21dff5276f3fa28b",
        "dockerfile_blob_sha": "6860679d7e023ac3d7828fa97cb32ed0e04bce53",
        "pnpm_lock_blob_sha": "4dadbbdda72a3c1ed23c1ef14240e765fe9a2170",
    }
    expected_mutations = {
        "network-enabled-secret-phase", "secret-in-arg", "secret-in-env",
        "secret-in-cache-metadata", "secret-in-log", "secret-in-layer",
        "secret-in-base64-layer", "secret-in-hex-layer", "source-drift",
        "workflow-drift", "wrong-image-digest", "replay",
        "runner-builder-socket-access", "builder-deploy-cross-access",
        "deploy-builder-cross-access",
    }
    expected_uids = {
        identities["runner_uid"], identities["broker_uid"], identities["builder_uid"],
        identities["post_build_uid"], identities["deploy_uid"],
    }
    expected_identity_values = {
        "runner_uid": "ken-deploy-production-runner",
        "broker_uid": "root",
        "builder_uid": "ken-action-frontend-builder",
        "post_build_uid": "ken-action-frontend-posthog",
        "deploy_uid": "ken-action-frontend-deploy",
    }
    expected_build_strings = {
        "builder_socket": "/run/ken-op-broker/production/builders/ken-frontend-production-release/buildkitd.sock",
        "builder_state": "/run/ken-op-broker/production/builders/ken-frontend-production-release/state",
        "wrapper_path": "/usr/local/libexec/ken-actions/ken-frontend-production-release-build",
        "base_image": "node:22-alpine",
        "base_image_digest": "task7-exact-sha256-required",
        "buildkit_version": "task7-exact-version-required",
        "wrapper_sha256": "task7-exact-sha256-required",
        "dependency_network_profile": "ken-frontend-secretless-dependency-fetch",
    }
    expected_dependency_endpoints = {
        "auth.docker.io:443",
        "registry-1.docker.io:443",
        "registry.npmjs.org:443",
    }
    expected_reviewed_variables = (
        FRONTEND_VARIABLE_MIGRATIONS | FRONTEND_EXPLICIT_REVIEWED_VARIABLES
    )
    expected_resource_limits = {
        "cpu_quota": "400%",
        "memory_max": "16G",
        "tasks_max": 512,
        "timeout_seconds": 1800,
        "context_bytes_max": 1073741824,
        "output_bytes_max": 2147483648,
    }
    expected_durable_fields = {
        "repository_id", "run_id", "run_attempt", "check_run_id", "action_id",
        "source_commit_sha", "image_digest", "result_code",
    }
    expected_exact_pins = {
        "base_image_digest", "pnpm_lock_blob_sha", "source_commit_sha",
        "workflow_blob_sha", "wrapper_sha256", "buildkit_version",
        "resource_limits",
    }
    if (
        action["action_id"] != "ken-frontend-production-release"
        or action["mode"] != "production_build"
        or action["status"] != "blocked-until-task7-pins-and-mutations-pass"
        or action["trust_class"] != "production"
        or action["repository"] != "ken-frontend"
        or action["workflow"] != ".github/workflows/deploy.yml"
        or action["job"] != "build-image"
        or action["environment"] != "production"
        or action["runner_class"] != "ken-deploy-production"
        or tuple(request["allowed_keys"]) != BROKER_REQUEST_KEYS
        or request["accepts_artifact"]
        or request["accepts_descriptor"]
        or request["result"] != "stable-code-only"
        or any(runner.values())
        or len(authorization["checks"]) != len(expected_auth_checks)
        or set(authorization["checks"]) != expected_auth_checks
        or not authorization["all_before_onepassword"]
        or authorization["github_token_use"]
        != "fixed-github-read-and-ghcr-write-only"
        or source["mode"] != "broker-fetched-exact-commit"
        or not source["fetch_before_onepassword"]
        or source["fallback"]
        or any(source[key] != value for key, value in expected_source.items())
        or len(expected_uids) != 5
        or any(
            identities[key] != value
            for key, value in expected_identity_values.items()
        )
        or not identities["pairwise_distinct"]
        or identities["runner_can_access_builder_socket"]
        or identities["runner_can_access_builder_state"]
        or identities["builder_can_access_deploy_executor"]
        or identities["deploy_executor_can_access_builder"]
        or not build["rootless_buildkit"]
        or not build["dependencies_and_base_images_secretless"]
        or any(
            build[key] != value for key, value in expected_build_strings.items()
        )
        or len(build["dependency_endpoints"])
        != len(expected_dependency_endpoints)
        or set(build["dependency_endpoints"]) != expected_dependency_endpoints
        or len(build["reviewed_github_variables"])
        != len(expected_reviewed_variables)
        or set(build["reviewed_github_variables"])
        != expected_reviewed_variables
        or limits != expected_resource_limits
        or phase["command"] != "pnpm build"
        or phase["network"] != "none"
        or phase["delivery"] != "buildkit-secret-mount"
        or phase["field"] != "NEXT_SERVER_ACTIONS_ENCRYPTION_KEY"
        or any(phase[key] for key in {"arg", "env", "cache_metadata", "logs", "layers"})
        or len(build["forbidden_build_fields"]) != 2
        or set(build["forbidden_build_fields"])
        != {"POSTHOG_PERSONAL_API_KEY", "POSTHOG_PROJECT_ID"}
        or output["format"] != "OCI"
        or output["registry"] != "ghcr.io/ken-technology/ken-frontend"
        or not output["scan_config_history"]
        or not output["scan_uncompressed_layers"]
        or len(output["canary_variants"]) != 3
        or set(output["canary_variants"]) != {"raw", "base64", "hex"}
        or not output["push_by_digest"]
        or not output["verified_short_lived_token"]
        or post["can_read_build_field"]
        or post["result"] != "stable-code-only"
        or post["executor_uid"] != "ken-action-frontend-posthog"
        or len(post["fields"]) != len(FRONTEND_POST_BUILD_FIELDS)
        or set(post["fields"]) != FRONTEND_POST_BUILD_FIELDS
        or post["target"] != "https://us.posthog.com"
        or post["input"] != "broker-owned-sourcemap-set-from-scanned-image"
        or post["release"] != "exact-source-commit-sha"
        or deploy["accepts_runner_digest"]
        or not deploy["deploy_by_digest"]
        or deploy["executor_uid"] != "ken-action-frontend-deploy"
        or deploy["input"] != "broker-recorded-image-digest"
        or not durable["source_run_digest_binding"]
        or len(durable["fields"]) != len(expected_durable_fields)
        or set(durable["fields"]) != expected_durable_fields
        or not all(cleanup.values())
        or not risk["merged_protected_code_may_consume_build_field"]
        or not risk["transformed_embedding_residual_accepted_only_for_reviewed_source"]
        or risk["scope"] != "exact-source-workflow-wrapper-and-lock-pins-only"
        or not gate["cutover_blocked_until_all_exact"]
        or len(gate["required_exact_pins"]) != len(expected_exact_pins)
        or set(gate["required_exact_pins"]) != expected_exact_pins
        or len(action["required_mutation_tests"]) != len(expected_mutations)
        or set(action["required_mutation_tests"]) != expected_mutations
        or not action["no_fallback_or_rebuild_elsewhere"]
    ):
        raise ValueError("invalid production build contract")


def _frontend_annotation_contract(
    repository: Any, name: Any
) -> dict[str, Any] | None:
    if repository != "ken-frontend" or name not in FRONTEND_ANNOTATION_CONTRACTS:
        return None
    return FRONTEND_ANNOTATION_CONTRACTS[str(name)]


def _frontend_broker_metadata(row: dict[str, Any]) -> dict[str, Any]:
    return {key: row.get(key) for key in FRONTEND_BROKER_METADATA_KEYS}


def _reject_noncontract_frontend_broker_metadata(row: dict[str, Any]) -> None:
    if (
        row.get("repository") == "ken-frontend"
        and row.get("github_secret_name") not in FRONTEND_ANNOTATION_CONTRACTS
        and any(key in row for key in FRONTEND_BROKER_METADATA_KEYS)
    ):
        raise ValueError("frontend broker semantic mismatch")


def _validate_frontend_broker_semantics(
    evidence: dict[str, Any], action_by_id: dict[str, dict[str, Any]]
) -> None:
    action_id = FRONTEND_PRODUCTION_RELEASE_ACTION_ID
    action = action_by_id.get(action_id)
    if action is None:
        return
    expected_phases = {
        name: contract["action_phase"]
        for name, contract in FRONTEND_ANNOTATION_CONTRACTS.items()
    }
    annotations = [
        row
        for row in evidence["unresolved_annotations"]
        if row.get("repository") == "ken-frontend"
        and row.get("github_secret_name") in expected_phases
    ]
    annotations_by_name: dict[str, list[dict[str, Any]]] = {}
    for annotation in annotations:
        annotations_by_name.setdefault(annotation["github_secret_name"], []).append(
            annotation
        )
    if (
        len(annotations_by_name) != len(FRONTEND_ANNOTATION_CONTRACTS)
        or set(annotations_by_name) != set(FRONTEND_ANNOTATION_CONTRACTS)
        or any(len(rows) != 1 for rows in annotations_by_name.values())
    ):
        raise ValueError("frontend broker semantic mismatch")
    for name, contract in FRONTEND_ANNOTATION_CONTRACTS.items():
        annotation = annotations_by_name[name][0]
        if _frontend_broker_metadata(annotation) != contract:
            raise ValueError("frontend broker semantic mismatch")
    for row in evidence["unresolved_annotations"]:
        _reject_noncontract_frontend_broker_metadata(row)
    expected_names_by_phase = {
        "offline-buildkit-secret-phase": {
            "NEXT_SERVER_ACTIONS_ENCRYPTION_KEY"
        },
        "post-build-sourcemap-upload": set(FRONTEND_POST_BUILD_FIELDS),
    }
    for phase, expected_names in expected_names_by_phase.items():
        phase_names = [
            row.get("github_secret_name")
            for row in evidence["unresolved_annotations"]
            if row.get("repository") == "ken-frontend"
            and row.get("action_phase") == phase
        ]
        if (
            len(phase_names) != len(expected_names)
            or set(phase_names) != expected_names
        ):
            raise ValueError("frontend broker semantic mismatch")
    action_annotations = {
        row.get("github_secret_name")
        for row in evidence["unresolved_annotations"]
        if row.get("broker_action_id") == action_id
    }
    if action_annotations != set(expected_phases):
        raise ValueError("frontend broker semantic mismatch")
    post_fields = action["post_build_contract"]["fields"]
    if (
        len(post_fields) != len(FRONTEND_POST_BUILD_FIELDS)
        or set(post_fields) != FRONTEND_POST_BUILD_FIELDS
        or action["build_contract"]["secret_phase"]["field"]
        != "NEXT_SERVER_ACTIONS_ENCRYPTION_KEY"
    ):
        raise ValueError("frontend broker semantic mismatch")

    migrations = [
        row
        for row in evidence["workflow_variable_migrations"]
        if row.get("repository") == "ken-frontend"
        and row.get("workflow") == ".github/workflows/deploy.yml"
    ]
    migration_names = [row.get("github_secret_name") for row in migrations]
    if (
        len(migration_names) != len(FRONTEND_VARIABLE_MIGRATIONS)
        or set(migration_names) != FRONTEND_VARIABLE_MIGRATIONS
        or any(
            row.get("target_variable_name") != row.get("github_secret_name")
            for row in migrations
        )
    ):
        raise ValueError("frontend broker semantic mismatch")
    reviewed_variables = action["build_contract"]["reviewed_github_variables"]
    expected_reviewed = (
        set(migration_names) | FRONTEND_EXPLICIT_REVIEWED_VARIABLES
    )
    if (
        len(reviewed_variables) != len(expected_reviewed)
        or set(reviewed_variables) != expected_reviewed
    ):
        raise ValueError("frontend broker semantic mismatch")


def validate_authority_evidence(evidence: Any) -> None:
    """Reject any unregistered field or type before evidence can enter a hash."""
    if evidence == {}:
        return
    _reject_value_bearing_evidence(evidence)
    root = _authority_object(
        evidence,
        {
            "schema_version", "evidence_id", "policy", "sources", "mappings",
            "unresolved_annotations", "secretless_migrations",
            "workflow_variable_migrations", "direct_onepassword_mappings",
            "broker_actions", "unresolved_observations",
        },
    )
    _authority_type(root["schema_version"], int)
    if root["schema_version"] != 2:
        raise ValueError("unsupported authority evidence schema version")
    _authority_type(root["evidence_id"], str)
    _authority_type(root["policy"], str)
    _authority_type(root["sources"], dict)
    for key in {
        "mappings", "unresolved_annotations", "secretless_migrations",
        "workflow_variable_migrations", "direct_onepassword_mappings",
        "broker_actions", "unresolved_observations",
    }:
        _authority_type(root[key], list)
    for source_id, source in root["sources"].items():
        _authority_type(source_id, str)
        _validate_authority_source(source)

    mapping_ids: set[str] = set()
    for mapping in root["mappings"]:
        row = _authority_object(
            mapping,
            {"mapping_id", "repository", "github_secret_name", "target_vault", "source_ref", "authority_match", "classification", "migration_action", "downstream_update_steps", "alias_group"},
            {"workflow", "target_item", "target_field"},
        )
        for key, value in row.items():
            if key == "downstream_update_steps":
                _authority_string_list(value)
            elif key in {"workflow", "target_item", "target_field", "alias_group"} and value is None:
                continue
            else:
                _authority_type(value, str)
        if row["mapping_id"] in mapping_ids or row["source_ref"] not in root["sources"]:
            raise ValueError("invalid authority mapping cross-reference")
        mapping_ids.add(row["mapping_id"])

    annotation_ids: set[str] = set()
    for annotation in root["unresolved_annotations"]:
        row = _authority_object(
            annotation,
            {"annotation_id", "repository", "github_secret_name", "target_vault", "resolution_class", "authority_owner", "handoff_group", "unresolved_reason", "provider_rotation_steps", "downstream_update_steps", "data_classification"},
            {"workflow", "required_runtime_identity", "execution_boundary", "broker_action_id", "action_phase"},
        )
        for key, value in row.items():
            if key in {"downstream_update_steps", "provider_rotation_steps"}:
                if value is not None:
                    _authority_string_list(value)
            elif key == "execution_boundary":
                boundary = _authority_object(
                    value,
                    {"action_id", "mode", "workflow", "production_build_job", "deployment_job", "runner_class", "broker_only", "ci_validation_only", "forbid_ken_ci_production_artifact"},
                )
                for boundary_key, boundary_value in boundary.items():
                    _authority_type(boundary_value, bool if boundary_key in {"broker_only", "ci_validation_only", "forbid_ken_ci_production_artifact"} else str)
            elif key == "workflow" and value is None:
                continue
            elif key in {"required_runtime_identity", "broker_action_id", "action_phase"}:
                _authority_nonempty_string(value)
            elif key == "target_vault" and value is None:
                continue
            else:
                _authority_type(value, str)
        if row["annotation_id"] in annotation_ids:
            raise ValueError("duplicate authority annotation id")
        annotation_ids.add(row["annotation_id"])

    migration_ids: set[str] = set()
    for migration in root["secretless_migrations"]:
        action = migration.get("migration_action") if isinstance(migration, dict) else None
        common = {"migration_id", "repository", "workflow", "github_secret_name", "migration_action", "target_runner_class", "target_vault", "target_item", "target_field", "required_permissions", "provider_setup_steps", "downstream_update_steps", "live_verification_steps", "retirement_steps"}
        extra = {"trusted_publisher", "packaging_contract"} if action == "oidc-trusted-publisher" else {"cross_repo_task"}
        row = _authority_object(migration, common | extra)
        for key in common - {"required_permissions", "provider_setup_steps", "downstream_update_steps", "live_verification_steps", "retirement_steps"}:
            value = row[key]
            if key in {"target_vault", "target_item", "target_field"} and value is None:
                continue
            _authority_type(value, str)
        for key in {"provider_setup_steps", "downstream_update_steps", "live_verification_steps", "retirement_steps"}:
            _authority_string_list(row[key])
        permissions = row["required_permissions"]
        required_permissions = {"contents", "id-token"} if action == "oidc-trusted-publisher" else {"contents"}
        _authority_object(permissions, required_permissions)
        for value in permissions.values():
            _authority_type(value, str)
        if action == "oidc-trusted-publisher":
            publisher = _authority_object(row["trusted_publisher"], {"project", "owner", "repository", "workflow", "environment"})
            packaging = _authority_object(row["packaging_contract"], {"source", "backend", "project", "install_command", "build_command", "verification_command", "broken_command_to_remove", "task", "checked_default_sha", "pyproject_blob_sha", "root_setup_py_present", "status"})
            for value in publisher.values(): _authority_type(value, str)
            for key, value in packaging.items(): _authority_type(value, bool if key == "root_setup_py_present" else str)
        elif action == "pull-based-publisher":
            cross = _authority_object(row["cross_repo_task"], {"task", "source_repository", "source_ref", "target_repository", "authentication"})
            for value in cross.values(): _authority_type(value, str)
        else:
            raise ValueError("unsupported secretless authority evidence action")
        if row["migration_id"] in migration_ids:
            raise ValueError("duplicate secretless migration id")
        migration_ids.add(row["migration_id"])

    variable_ids: set[str] = set()
    for migration in root["workflow_variable_migrations"]:
        row = _authority_object(migration, {"migration_id", "repository", "workflow", "github_secret_name", "target_variable_name", "migration_action", "review_required", "downstream_update_steps", "live_verification_steps", "retirement_steps"})
        for key, value in row.items():
            if key in {"downstream_update_steps", "live_verification_steps", "retirement_steps"}: _authority_string_list(value)
            elif key == "review_required": _authority_type(value, bool)
            else: _authority_type(value, str)
        if row["migration_id"] in variable_ids:
            raise ValueError("duplicate workflow variable migration id")
        variable_ids.add(row["migration_id"])

    direct_ids: set[str] = set()
    direct_specials: dict[str, dict[str, Any]] = {}
    for mapping in root["direct_onepassword_mappings"]:
        row = _authority_object(
            mapping,
            {"mapping_id", "repository", "workflow", "job", "environment_name", "source_reference", "source_vault", "source_item", "source_field", "target_vault", "target_item", "target_field", "field_type", "consumer", "disposition", "delivery", "migration_action", "source_to_target_steps", "broker_cutover_steps", "live_verification_steps", "retirement_steps"},
            {"broker_action_id"},
        )
        for key, value in row.items():
            if key.endswith("_steps"): _authority_string_list(value)
            else: _authority_type(value, str)
        disposition_contract = {
            "broker-action": ("onepassword-broker", "copy-direct-onepassword-reference", True),
            "github-variable": ("github-actions-variable", "move-to-variable", False),
            "obsolete-unused": ("none", "remove-unused-reference-after-rg-proof", False),
        }.get(row["disposition"])
        if (disposition_contract is None
                or (row["delivery"], row["migration_action"]) != disposition_contract[:2]
                or ("broker_action_id" in row) is not disposition_contract[2]):
            raise ValueError("invalid direct 1Password disposition")
        if row["mapping_id"] in direct_ids:
            raise ValueError("duplicate direct 1Password mapping id")
        direct_ids.add(row["mapping_id"])
        if row["disposition"] != "broker-action":
            if row["environment_name"] in direct_specials:
                raise ValueError("invalid direct PostHog disposition contract")
            direct_specials[row["environment_name"]] = row
    expected_direct_specials = {
        "NEXT_PUBLIC_POSTHOG_PROJECT_TOKEN": {
            "repository": "ken-website", "workflow": ".github/workflows/deploy.yml", "job": "deploy",
            "source_reference": "op://ken-website/posthog/project_token", "target_vault": "not-applicable",
            "target_item": "GitHub Actions variables:ken-website", "target_field": "NEXT_PUBLIC_POSTHOG_PROJECT_TOKEN",
            "field_type": "string", "consumer": "ken-deploy-production", "disposition": "github-variable",
            "delivery": "github-actions-variable", "migration_action": "move-to-variable",
        },
        "POSTHOG_PERSONAL_API_KEY": {
            "repository": "ken-website", "workflow": ".github/workflows/deploy.yml", "job": "deploy",
            "source_reference": "op://ken-website/posthog/personal_api_key", "target_vault": "not-applicable",
            "target_item": "obsolete-reference", "target_field": "POSTHOG_PERSONAL_API_KEY",
            "field_type": "concealed", "consumer": "ken-deploy-production", "disposition": "obsolete-unused",
            "delivery": "none", "migration_action": "remove-unused-reference-after-rg-proof",
        },
    }
    if root["broker_actions"] and set(direct_specials) != set(expected_direct_specials):
        raise ValueError("invalid direct PostHog disposition contract")
    if root["broker_actions"]:
        for name, expected in expected_direct_specials.items():
            if any(direct_specials[name].get(key) != value for key, value in expected.items()):
                raise ValueError("invalid direct PostHog disposition contract")

    action_ids: set[str] = set()
    for action in root["broker_actions"]:
        if not isinstance(action, dict):
            raise ValueError("wrong authority evidence type")
        if action.get("mode") == "fixed_secret_action":
            _validate_fixed_broker_action(action)
        elif action.get("mode") == "production_build":
            _validate_production_build_action(action)
        else:
            raise ValueError("unsupported broker action mode")
        if action["action_id"] in action_ids:
            raise ValueError("duplicate broker action id")
        action_ids.add(action["action_id"])
    if action_ids and action_ids != {
        "ken-frontend-production-release",
        "ken-vexa-mcp-auth-production-deploy",
        "ken-website-beehiiv-production-sync",
        "ken-website-production-deploy",
    }:
        raise ValueError("incomplete authority broker action set")
    _validate_frontend_broker_semantics(
        root,
        {str(action["action_id"]): action for action in root["broker_actions"]},
    )
    for mapping in root["direct_onepassword_mappings"]:
        if mapping.get("broker_action_id") is not None and mapping["broker_action_id"] not in action_ids:
            raise ValueError("invalid direct broker action cross-reference")
    for annotation in root["unresolved_annotations"]:
        if annotation.get("broker_action_id") not in {None, *action_ids}:
            raise ValueError("invalid annotation broker action cross-reference")

    for observation in root["unresolved_observations"]:
        row = _authority_object(observation, {"kind", "reason"})
        _authority_type(row["kind"], str)
        _authority_type(row["reason"], str)


def apply_secretless_migration(
    entry: dict[str, Any], evidence: dict[str, Any] | None
) -> dict[str, Any]:
    evidence = evidence or {}
    _reject_value_bearing_evidence(evidence)
    matches = [
        row
        for row in evidence.get("secretless_migrations") or []
        if isinstance(row, dict)
        and row.get("repository") == entry.get("repository")
        and row.get("github_secret_name") == entry.get("github_secret_name")
        and row.get("workflow") in {None, entry.get("workflow")}
    ]
    if not matches:
        return entry
    if len(matches) != 1:
        raise ValueError(
            f"multiple secretless migrations for {entry.get('repository')}:"
            f"{entry.get('workflow')}:{entry.get('github_secret_name')}"
        )
    migration = matches[0]
    action = str(migration.get("migration_action") or "")
    if action not in {"oidc-trusted-publisher", "pull-based-publisher"}:
        raise ValueError(f"unsupported secretless migration action: {action!r}")
    if any(migration.get(key) is not None for key in ("target_vault", "target_item", "target_field")):
        raise ValueError("secretless migration must not target 1Password")
    if migration.get("target_runner_class") != "public-github-hosted":
        raise ValueError("public secretless migration must remain GitHub-hosted")
    if entry.get("consumer") != "public-github-hosted":
        raise ValueError("secretless migration matched a non-public consumer")
    required_permissions = migration.get("required_permissions")
    if not isinstance(required_permissions, dict) or not required_permissions:
        raise ValueError("secretless migration requires explicit workflow permissions")
    if action == "oidc-trusted-publisher" and required_permissions.get("id-token") != "write":
        raise ValueError("OIDC trusted publisher requires id-token: write")
    if action == "oidc-trusted-publisher":
        publisher = migration.get("trusted_publisher")
        packaging = migration.get("packaging_contract")
        if not isinstance(publisher, dict) or publisher != {
            "project": "derisk-mono",
            "owner": "Ken-Technology",
            "repository": "Ken-SRE",
            "workflow": "python-publish.yml",
            "environment": "pypi",
        }:
            raise ValueError("OIDC trusted publisher requires the exact derisk-mono contract")
        if (
            not isinstance(packaging, dict)
            or packaging.get("source") != "pyproject.toml"
            or packaging.get("backend") != "hatchling.build"
            or packaging.get("project") != "derisk-mono"
            or packaging.get("build_command")
            != "python -m build --sdist --wheel ."
            or packaging.get("verification_command")
            != "python -m twine check dist/*"
            or "setup.py" not in str(packaging.get("broken_command_to_remove") or "")
            or packaging.get("task") != "Task 7"
            or packaging.get("checked_default_sha")
            != "61622aa518666c30db703acb939cd4ab7f58d128"
            or packaging.get("pyproject_blob_sha")
            != "a2a0651ca856601492b914c4cdc92ba1955667a4"
            or packaging.get("root_setup_py_present") is not False
            or packaging.get("status") != "task7-change-required"
        ):
            raise ValueError("OIDC publication requires the checked packaging contract")
    if action == "pull-based-publisher":
        cross_repo = migration.get("cross_repo_task")
        if (
            not isinstance(cross_repo, dict)
            or cross_repo.get("task") != "Task 7"
            or cross_repo.get("authentication") != "GITHUB_TOKEN"
        ):
            raise ValueError("pull-based publisher requires the exact Task 7 contract")
    for key in (
        "provider_setup_steps",
        "downstream_update_steps",
        "live_verification_steps",
        "retirement_steps",
    ):
        steps = migration.get(key)
        if not isinstance(steps, list) or not steps or not all(
            isinstance(step, str) and step.strip() for step in steps
        ):
            raise ValueError(f"secretless migration requires nonempty {key}")

    for key in (
        "resolution_class",
        "authority_owner",
        "unresolved_reason",
        "handoff_group",
        "authority_annotation_id",
    ):
        entry.pop(key, None)
    entry["source_authority"] = f"planned-secretless://{migration['migration_id']}"
    entry["source_readable"] = False
    entry["authority_status"] = "planned-secretless"
    entry["migration_action"] = action
    entry["secretless_migration_id"] = migration["migration_id"]
    entry["target_vault"] = None
    entry["target_item"] = None
    entry["target_field"] = None
    entry["field_type"] = None
    entry["classification"] = "secretless-publication"
    entry["data_classification"] = "secretless"
    entry["rotation_required"] = False
    entry["provider_rotation_steps"] = None
    entry["provider_setup_steps"] = migration["provider_setup_steps"]
    entry["downstream_update_steps"] = migration["downstream_update_steps"]
    entry["live_verification_steps"] = migration["live_verification_steps"]
    entry["retirement_steps"] = migration["retirement_steps"]
    entry["required_permissions"] = required_permissions
    entry["trusted_publisher"] = migration.get("trusted_publisher")
    entry["packaging_contract"] = migration.get("packaging_contract")
    entry["cross_repo_task"] = migration.get("cross_repo_task")
    entry["replacement_required"] = True
    entry["alias_group"] = None
    entry["alias_status"] = "not-applicable"
    return entry


def apply_workflow_variable_migration(
    entry: dict[str, Any], evidence: dict[str, Any] | None
) -> dict[str, Any]:
    """Plan reviewed public configuration as a GitHub variable, never a secret."""
    evidence = evidence or {}
    _reject_value_bearing_evidence(evidence)
    matches = [
        row
        for row in evidence.get("workflow_variable_migrations") or []
        if isinstance(row, dict)
        and row.get("repository") == entry.get("repository")
        and row.get("workflow") == entry.get("workflow")
        and row.get("github_secret_name") == entry.get("github_secret_name")
    ]
    if not matches:
        return entry
    if len(matches) != 1:
        raise ValueError("multiple workflow variable migrations matched one reference")
    migration = matches[0]
    if migration.get("migration_action") != "move-to-github-variable":
        raise ValueError("unsupported workflow variable migration action")
    if migration.get("review_required") is not True:
        raise ValueError("workflow variable migration requires explicit review")
    if migration.get("target_variable_name") != entry.get("github_secret_name"):
        raise ValueError("workflow variable migration target name mismatch")
    for field in (
        "downstream_update_steps",
        "live_verification_steps",
        "retirement_steps",
    ):
        _nonempty_steps(migration.get(field), field)
    for key in (
        "resolution_class",
        "authority_owner",
        "unresolved_reason",
        "handoff_group",
        "authority_annotation_id",
    ):
        entry.pop(key, None)
    entry.update(
        {
            "source_authority": f"planned-github-variable://{migration['migration_id']}",
            "source_readable": False,
            "authority_status": "planned-variable",
            "migration_action": "move-to-github-variable",
            "workflow_variable_migration_id": migration["migration_id"],
            "target_variable_name": migration["target_variable_name"],
            "target_vault": None,
            "target_item": None,
            "target_field": None,
            "field_type": None,
            "classification": "public-build-configuration",
            "data_classification": "configuration",
            "rotation_required": False,
            "provider_rotation_steps": None,
            "downstream_update_steps": list(migration["downstream_update_steps"]),
            "live_verification_steps": list(migration["live_verification_steps"]),
            "retirement_steps": list(migration["retirement_steps"]),
            "replacement_required": True,
            "alias_group": None,
            "alias_status": "not-applicable",
        }
    )
    return entry


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
    for key in (
        "resolution_class",
        "authority_owner",
        "unresolved_reason",
        "handoff_group",
        "authority_annotation_id",
    ):
        entry.pop(key, None)
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
    downstream = annotation.get("downstream_update_steps")
    if not isinstance(downstream, list) or not downstream or not all(
        isinstance(step, str) and step.strip() for step in downstream
    ):
        raise ValueError(
            "unresolved authority annotation requires nonempty downstream_update_steps"
        )
    if resolution_class == "provider-rotation":
        if not isinstance(steps, list) or not steps or not all(
            isinstance(step, str) and step.strip() for step in steps
        ):
            raise ValueError("provider rotation annotation requires a concrete rotation procedure")
        entry["rotation_required"] = True
        entry["migration_action"] = "rotate-at-provider"
    elif steps is not None:
        raise ValueError("provider rotation steps require provider-rotation classification")
    elif resolution_class == "independent-trust-authority":
        entry["rotation_required"] = True
        entry["migration_action"] = "create-independent-authority"
    elif resolution_class == "workflow-reference-removal":
        entry["rotation_required"] = False
        entry["migration_action"] = "remove-unused-reference"

    entry["authority_annotation_id"] = annotation_id
    entry["resolution_class"] = resolution_class
    entry["authority_owner"] = owner
    entry["handoff_group"] = handoff_group
    entry["unresolved_reason"] = reason
    entry["provider_rotation_steps"] = steps
    entry["downstream_update_steps"] = downstream
    contract = _frontend_annotation_contract(
        entry.get("repository"), entry.get("github_secret_name")
    )
    if contract is not None:
        if _frontend_broker_metadata(annotation) != contract:
            raise ValueError("frontend broker semantic mismatch")
        entry["required_runtime_identity"] = contract["required_runtime_identity"]
        entry["execution_boundary"] = dict(contract["execution_boundary"])
        entry["broker_action_id"] = contract["broker_action_id"]
        entry["action_phase"] = contract["action_phase"]
    else:
        _reject_noncontract_frontend_broker_metadata(annotation)
        if "required_runtime_identity" in annotation:
            _authority_nonempty_string(annotation["required_runtime_identity"])
            entry["required_runtime_identity"] = annotation[
                "required_runtime_identity"
            ]
        if "execution_boundary" in annotation:
            boundary = annotation["execution_boundary"]
            if boundary != FRONTEND_PRODUCTION_BUILD_BOUNDARY:
                raise ValueError("invalid fixed production build execution boundary")
            entry["execution_boundary"] = dict(boundary)
        if "broker_action_id" in annotation:
            _authority_nonempty_string(annotation["broker_action_id"])
            entry["broker_action_id"] = annotation["broker_action_id"]
        if "action_phase" in annotation:
            _authority_nonempty_string(annotation["action_phase"])
            entry["action_phase"] = annotation["action_phase"]
    if annotation.get("data_classification"):
        entry["data_classification"] = annotation["data_classification"]
    return entry


def validate_authority_mapping_coverage(
    evidence: dict[str, Any],
    entries: list[dict[str, Any]],
    direct_entries: list[dict[str, Any]] | None = None,
) -> None:
    mappings = evidence.get("mappings") or []
    annotations = evidence.get("unresolved_annotations") or []
    migrations = evidence.get("secretless_migrations") or []
    variable_migrations = evidence.get("workflow_variable_migrations") or []
    direct_mappings = evidence.get("direct_onepassword_mappings") or []
    broker_actions = evidence.get("broker_actions") or []
    if not any(
        (mappings, annotations, migrations, variable_migrations, direct_mappings, broker_actions)
    ):
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

    migration_ids: list[str] = []
    for migration in migrations:
        if not isinstance(migration, dict):
            raise ValueError("secretless migration must be an object")
        migration_id = str(migration.get("migration_id") or "").strip()
        if not migration_id:
            raise ValueError("secretless migration requires migration_id")
        migration_ids.append(migration_id)
    if len(migration_ids) != len(set(migration_ids)):
        raise ValueError("duplicate secretless migration_id")
    used_migrations = {
        str(entry["secretless_migration_id"])
        for entry in entries
        if entry.get("secretless_migration_id")
    }
    unused_migrations = sorted(set(migration_ids) - used_migrations)
    if unused_migrations:
        raise ValueError(f"unused secretless migrations: {', '.join(unused_migrations)}")

    variable_migration_ids: list[str] = []
    for migration in variable_migrations:
        if not isinstance(migration, dict):
            raise ValueError("workflow variable migration must be an object")
        migration_id = str(migration.get("migration_id") or "").strip()
        if not migration_id:
            raise ValueError("workflow variable migration requires migration_id")
        variable_migration_ids.append(migration_id)
    if len(variable_migration_ids) != len(set(variable_migration_ids)):
        raise ValueError("duplicate workflow variable migration_id")
    used_variable_migrations = {
        str(entry["workflow_variable_migration_id"])
        for entry in entries
        if entry.get("workflow_variable_migration_id")
    }
    unused_variable_migrations = sorted(
        set(variable_migration_ids) - used_variable_migrations
    )
    if unused_variable_migrations:
        raise ValueError(
            "unused workflow variable migrations: "
            + ", ".join(unused_variable_migrations)
        )

    direct_mapping_ids: list[str] = []
    for mapping in direct_mappings:
        if not isinstance(mapping, dict):
            raise ValueError("direct 1Password mapping must be an object")
        mapping_id = str(mapping.get("mapping_id") or "").strip()
        if not mapping_id:
            raise ValueError("direct 1Password mapping requires mapping_id")
        direct_mapping_ids.append(mapping_id)
    if len(direct_mapping_ids) != len(set(direct_mapping_ids)):
        raise ValueError("duplicate direct 1Password mapping_id")
    used_direct = {
        str(entry["mapping_id"])
        for entry in direct_entries or []
        if entry.get("mapping_id")
    }
    unused_direct = sorted(set(direct_mapping_ids) - used_direct)
    if unused_direct:
        raise ValueError(
            f"unused direct 1Password mappings: {', '.join(unused_direct)}"
        )

    action_ids = [str(action.get("action_id") or "") for action in broker_actions]
    if any(not action_id for action_id in action_ids):
        raise ValueError("broker action requires action_id")
    if len(action_ids) != len(set(action_ids)):
        raise ValueError("duplicate broker action_id")
    action_by_id = {str(action["action_id"]): action for action in broker_actions}
    for action_id, action in action_by_id.items():
        if action.get("mode") != "fixed_secret_action":
            continue
        action_fields = [
            (
                field.get("target_item"),
                field.get("target_field"),
                field.get("field_type"),
            )
            for field in action.get("required_fields") or []
        ]
        mapping_fields = [
            (
                mapping.get("target_item"),
                mapping.get("target_field"),
                mapping.get("field_type"),
            )
            for mapping in direct_mappings
            if mapping.get("broker_action_id") == action_id
        ]
        if (
            len(action_fields) != len(set(action_fields))
            or len(mapping_fields) != len(set(mapping_fields))
            or set(action_fields) != set(mapping_fields)
        ):
            raise ValueError("fixed broker action required fields mismatch")
    for entry in entries:
        contract = _frontend_annotation_contract(
            entry.get("repository"), entry.get("github_secret_name")
        )
        if contract is not None:
            if _frontend_broker_metadata(entry) != contract:
                raise ValueError("frontend broker semantic mismatch")
        else:
            _reject_noncontract_frontend_broker_metadata(entry)
        action_id = entry.get("broker_action_id")
        if not action_id:
            continue
        action = action_by_id.get(str(action_id))
        if (
            not action
            or action.get("repository") != entry.get("repository")
            or action.get("workflow") != entry.get("workflow")
            or action.get("runner_class") != entry.get("consumer")
        ):
            raise ValueError("secret broker action trust boundary mismatch")
        if contract is None:
            boundary = entry.get("execution_boundary")
            if boundary and (
                boundary.get("action_id") != action.get("action_id")
                or boundary.get("mode") != action.get("mode")
                or boundary.get("workflow") != action.get("workflow")
                or boundary.get("production_build_job") != action.get("job")
                or boundary.get("runner_class") != action.get("runner_class")
            ):
                raise ValueError("production build execution boundary mismatch")
    used_action_ids = {
        str(entry["broker_action_id"])
        for entry in [*entries, *(direct_entries or [])]
        if entry.get("broker_action_id")
    }
    unused_actions = sorted(set(action_ids) - used_action_ids)
    if unused_actions:
        raise ValueError("unused broker actions: " + ", ".join(unused_actions))


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
    validate_authority_evidence(raw["authority_evidence"])
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
    for name in (
        "repositories.yaml",
        "runners.yaml",
        "secrets.yaml",
        "secret-handoff.yaml",
        "input-manifest.yaml",
    ):
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
        and repo == "ken-frontend"
        and Path(workflow_path).name in {"deploy.yml", "deploy.yaml"}
        and job_id == "build-image"
    ):
        flags.append("FIXED_PRODUCTION_BUILD_BOUNDARY")
        return {
            "classification": "production-build",
            "target_runner_class": "ken-deploy-production",
            "target_runs_on": "[self-hosted, linux, x64, ken-deploy, production]",
            "secret_class": "deploy-production",
            "production_impact": True,
            "deploys_or_publishes": True,
            "combined_build_and_deploy": combined,
            "flags": flags,
        }

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
    data = yaml.load(text, Loader=UniqueKeySafeLoader) or {}
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
            direct_onepassword_references = extract_direct_onepassword_references(
                workflow_env, job
            )
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
                    "direct_onepassword_references": direct_onepassword_references,
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
        "direct_onepassword_references": [
            {"job": job["id"], **reference}
            for job in jobs
            for reference in job["direct_onepassword_references"]
        ],
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


def _nonempty_steps(value: Any, label: str) -> list[str]:
    if not isinstance(value, list) or not value or not all(
        isinstance(step, str) and step.strip() for step in value
    ):
        raise ValueError(f"handoff row requires nonempty {label}")
    return list(value)


def _handoff_procedure(entry: dict[str, Any]) -> dict[str, list[str]]:
    repository = str(entry["repository"])
    name = str(entry["github_secret_name"])
    workflow = str(entry["workflow"])
    action = str(entry["migration_action"])
    source = str(entry.get("source_authority") or "unproven authority")
    target_vault = entry.get("target_vault")
    target_item = entry.get("target_item")
    target_field = entry.get("target_field")
    target = (
        f"{target_vault}/{target_item}/{target_field}"
        if all((target_vault, target_item, target_field))
        else "no 1Password target"
    )
    coordinate = f"{repository}/{name}"

    if entry.get("authority_status") == "planned-secretless":
        return {
            "source_to_target_steps": _nonempty_steps(
                entry.get("provider_setup_steps"), "provider_setup_steps"
            ),
            "broker_or_workflow_cutover_steps": _nonempty_steps(
                entry.get("downstream_update_steps"), "downstream_update_steps"
            ),
            "live_verification_steps": _nonempty_steps(
                entry.get("live_verification_steps"), "live_verification_steps"
            ),
            "github_deletion_steps": _nonempty_steps(
                entry.get("retirement_steps"), "retirement_steps"
            ),
            "revocation_steps": [
                f"Complete the retirement steps for {coordinate} only after the secretless publisher passes its live verification."
            ],
        }

    if action == "replace-bootstrap":
        identity_by_consumer = {
            "ken-ci-standard": "ken-ci-runtime",
            "ken-ci-docker": "ken-ci-runtime",
            "ken-ci-heavy": "ken-ci-runtime",
            "ken-deploy-nonproduction": "ken-deploy-nonproduction",
            "ken-deploy-production": "ken-deploy-production",
        }
        identity = identity_by_consumer.get(
            str(entry.get("consumer") or ""), "the exact workflow-scoped runtime account"
        )
        return {
            "source_to_target_steps": [
                f"Create or confirm {identity} as the dedicated one-vault read_items-only runtime service account; never copy the old GitHub bootstrap credential into a target vault.",
                f"Save its one-time credential only in Cristian's built-in Private vault and install it as the VM systemd credential for {workflow} through hidden input.",
            ],
            "broker_or_workflow_cutover_steps": [
                f"Cut {repository}/{workflow} over to the local broker under {identity}; do not store a 1Password service-account credential in GitHub."
            ],
            "live_verification_steps": [
                f"Run {repository}/{workflow}, verify the exact 1Password references resolve under {identity}, and confirm the job never reads the old GitHub field."
            ],
            "github_deletion_steps": [
                f"Delete {repository}/{name} from GitHub only after the broker-backed workflow is live-verified and the rollback record is captured."
            ],
            "revocation_steps": [
                f"Revoke the predecessor bootstrap service-account credential after every workflow that used {repository}/{name} has passed the broker-backed verification."
            ],
        }

    if action == "move-to-variable":
        return {
            "source_to_target_steps": [
                f"Reconstruct {coordinate} from {source} and create the exact repository Actions variable {name}; no 1Password field is created."
            ],
            "broker_or_workflow_cutover_steps": _nonempty_steps(
                entry.get("downstream_update_steps"), "downstream_update_steps"
            ),
            "live_verification_steps": [
                f"Run every listed {repository} workflow and verify it reads vars.{name} successfully without displaying the setting."
            ],
            "github_deletion_steps": [
                f"Delete the GitHub secret field {repository}/{name} only after every listed workflow uses vars.{name} and live verification passes."
            ],
            "revocation_steps": [
                f"Retain {source}; this is a configuration move and has no predecessor credential to revoke."
            ],
        }

    if action == "remove-unused-reference":
        downstream = _nonempty_steps(
            entry.get("downstream_update_steps"), "downstream_update_steps"
        )
        return {
            "source_to_target_steps": [
                f"Do not create a 1Password field for {coordinate}; remove the unused workflow reference."
            ],
            "broker_or_workflow_cutover_steps": downstream,
            "live_verification_steps": [
                f"Run the affected {repository} workflow after default-branch removal and verify equivalent behavior without {name}."
            ],
            "github_deletion_steps": [
                f"Delete the GitHub secret field {repository}/{name} only after the reference-removal workflow is live and verified."
            ],
            "revocation_steps": [
                f"Revoke any predecessor for {coordinate} only if the named owner confirms it has no other consumer."
            ],
        }

    downstream = _nonempty_steps(
        entry.get("downstream_update_steps"), "downstream_update_steps"
    )
    if entry.get("authority_status") in {
        "verified-readable",
        "verified-reconstructable",
    }:
        source_to_target = [
            f"Populate {target} from {source} through task6-temporary-migration-writer without displaying the value."
        ]
    elif entry.get("resolution_class") == "provider-rotation":
        source_to_target = _nonempty_steps(
            entry.get("provider_rotation_steps"), "provider_rotation_steps"
        )
    elif entry.get("resolution_class") == "independent-trust-authority":
        source_to_target = [downstream[0]]
    else:
        source_to_target = [
            f"The named authority owner must prove or reconstruct {coordinate} for {target} before task6-temporary-migration-writer populates it; stop on ambiguity."
        ]

    rotation = entry.get("rotation_required") is True
    return {
        "source_to_target_steps": source_to_target,
        "broker_or_workflow_cutover_steps": downstream,
        "live_verification_steps": [
            f"Run every listed {repository} workflow against its real consumer and verify {name} is obtained from {target} through the local broker without displaying it."
        ],
        "github_deletion_steps": [
            f"Delete the matching GitHub secret field {repository}/{name} only after all listed workflow consumers pass live verification and rollback evidence is recorded."
        ],
        "revocation_steps": [
            (
                f"Revoke the predecessor authority for {coordinate} after the verified rollback window."
                if rotation
                else f"Retain {source} unless its named owner separately approves retirement; no revocation is implied by this handoff."
            )
        ],
    }


def build_secret_handoff(
    entries: list[dict[str, Any]],
    organization: str,
    generated_at: str,
    direct_onepassword_entries: list[dict[str, Any]] | None = None,
    broker_actions: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    grouped: dict[tuple[str, str, str | None], list[dict[str, Any]]] = {}
    excluded = {"github-provided": 0, "preserved-existing": 0}
    for entry in entries:
        status = str(entry.get("authority_status") or "")
        if status in excluded:
            excluded[status] += 1
            continue
        key = (
            str(entry.get("repository") or ""),
            str(entry.get("github_secret_name") or ""),
            entry.get("target_vault"),
        )
        grouped.setdefault(key, []).append(entry)

    rows: list[dict[str, Any]] = []
    invariant_fields = (
        "authority_status",
        "migration_action",
        "resolution_class",
        "authority_owner",
        "handoff_group",
        "source_authority",
        "target_item",
        "target_field",
        "field_type",
        "rotation_required",
        "required_runtime_identity",
        "execution_boundary",
        "trusted_publisher",
        "packaging_contract",
        "target_variable_name",
        "broker_action_id",
        "action_phase",
    )
    for (repository, name, target_vault), members in sorted(
        grouped.items(), key=lambda item: (item[0][0].lower(), item[0][1], item[0][2] or "")
    ):
        first = members[0]
        for member in members[1:]:
            for field in invariant_fields:
                if member.get(field) != first.get(field):
                    raise ValueError(
                        f"conflicting handoff coordinate {repository}/{name}/{target_vault}: {field}"
                    )
        procedure = _handoff_procedure(first)
        workflows = sorted({str(member["workflow"]) for member in members})
        consumers = sorted(
            {str(member["consumer"]) for member in members if member.get("consumer")}
        )
        consuming_jobs = sorted(
            {
                f"{member['workflow']}#{job}"
                for member in members
                for job in member.get("consuming_jobs") or []
            }
        )
        coordinate = f"{repository}|{name}|{target_vault or 'no-1password-target'}"
        row = {
            "reference_class": "github-secret",
            "coordinate": coordinate,
            "repository": repository,
            "github_secret_name": name,
            "target_vault": target_vault,
            "target_item": first.get("target_item"),
            "target_field": first.get("target_field"),
            "field_type": first.get("field_type"),
            "authority_status": first.get("authority_status"),
            "migration_action": first.get("migration_action"),
            "resolution_class": first.get("resolution_class"),
            "source_authority": first.get("source_authority"),
            "authority_owner": first.get("authority_owner"),
            "handoff_group": first.get("handoff_group") or coordinate,
            "rotation_required": first.get("rotation_required"),
            "required_runtime_identity": first.get("required_runtime_identity"),
            "execution_boundary": first.get("execution_boundary"),
            "trusted_publisher": first.get("trusted_publisher"),
            "packaging_contract": first.get("packaging_contract"),
            "target_variable_name": first.get("target_variable_name"),
            "broker_action_id": first.get("broker_action_id"),
            "action_phase": first.get("action_phase"),
            "workflows": workflows,
            "consumers": consumers,
            "consuming_jobs": consuming_jobs,
            **procedure,
            "user_only_actions": [
                f"Complete the named authority-owner or 1Password-admin action for {coordinate} without pasting a value into chat."
            ],
        }
        for field in (
            "source_to_target_steps",
            "broker_or_workflow_cutover_steps",
            "live_verification_steps",
            "github_deletion_steps",
            "revocation_steps",
            "user_only_actions",
        ):
            _nonempty_steps(row[field], field)
        rows.append(row)

    direct_rows: list[dict[str, Any]] = []
    for entry in sorted(
        direct_onepassword_entries or [],
        key=lambda row: (
            row["repository"].lower(),
            row["workflow"],
            row["job"],
            row["environment_name"],
            row["source_reference"],
            row["target_vault"],
        ),
    ):
        coordinate = "|".join(
            (
                "direct-op",
                entry["repository"],
                entry["workflow"],
                entry["job"],
                entry["environment_name"],
                entry["source_reference"],
                entry["target_vault"],
            )
        )
        row = {
            "reference_class": "direct-onepassword",
            "coordinate": coordinate,
            "repository": entry["repository"],
            "workflow": entry["workflow"],
            "job": entry["job"],
            "environment_name": entry["environment_name"],
            "source_reference": entry["source_reference"],
            "source_vault": entry["source_vault"],
            "source_item": entry["source_item"],
            "source_field": entry["source_field"],
            "target_vault": entry["target_vault"],
            "target_item": entry["target_item"],
            "target_field": entry["target_field"],
            "field_type": entry["field_type"],
            "authority_status": entry["authority_status"],
            "migration_action": entry["migration_action"],
            "disposition": entry["disposition"],
            "delivery": entry["delivery"],
            "consumer": entry["consumer"],
            "handoff_group": (
                f"direct-op/{entry['repository']}/{Path(entry['workflow']).stem}/"
                f"{entry['job']}"
            ),
            "rotation_required": False,
            "source_to_target_steps": _nonempty_steps(
                entry["source_to_target_steps"], "source_to_target_steps"
            ),
            "broker_or_workflow_cutover_steps": _nonempty_steps(
                entry["broker_cutover_steps"], "broker_cutover_steps"
            ),
            "live_verification_steps": _nonempty_steps(
                entry["live_verification_steps"], "live_verification_steps"
            ),
            "github_deletion_steps": _nonempty_steps(
                entry["retirement_steps"], "retirement_steps"
            ),
            "revocation_steps": [
                f"Retain {entry['source_reference']} until its owner confirms no other consumer remains; no source-vault access is granted to {entry['consumer']}."
            ],
            "user_only_actions": (
                [f"Copy {entry['source_reference']} into the exact target field through task6-temporary-migration-writer without placing a value in chat."]
                if entry["disposition"] == "broker-action"
                else [
                    "Create the reviewed ken-website GitHub Actions variable without creating or updating a 1Password target and without placing its value in chat."
                    if entry["disposition"] == "github-variable"
                    else "Confirm repository-wide unused-reference proof before removal; do not copy the obsolete field into 1Password, a variable, or the broker."
                ]
            ),
        }
        if entry.get("broker_action_id"):
            row["broker_action_id"] = entry["broker_action_id"]
        for field in (
            "source_to_target_steps",
            "broker_or_workflow_cutover_steps",
            "live_verification_steps",
            "github_deletion_steps",
            "revocation_steps",
            "user_only_actions",
        ):
            _nonempty_steps(row[field], field)
        direct_rows.append(row)
    rows.extend(direct_rows)
    coordinates = [row["coordinate"] for row in rows]
    if len(coordinates) != len(set(coordinates)):
        raise ValueError("duplicate combined handoff coordinate")

    def counts(field: str) -> dict[str, int]:
        output: dict[str, int] = {}
        for row in rows:
            label = str(row.get(field) or "none")
            output[label] = output.get(label, 0) + 1
        return dict(sorted(output.items()))

    return {
        "schema_version": 3,
        "organization": organization,
        "generated_at": generated_at,
        "policy": (
            "One value-free row per GitHub-field trust coordinate plus one row per direct 1Password repository, workflow, job, environment name, source reference, and target trust-domain coordinate. "
            "GitHub deletion or direct-reference retirement and predecessor revocation are delayed until live verification passes."
        ),
        "runtime_access": {
            "runtime_accounts": [
                {
                    "identity": "ken-ci-runtime",
                    "vault": "Ken CI Runtime",
                    "access": "read_items only",
                },
                {
                    "identity": "ken-deploy-nonproduction",
                    "vault": "Ken Deploy Nonproduction",
                    "access": "read_items only",
                },
                {
                    "identity": "ken-deploy-production",
                    "vault": "Ken Deploy Production",
                    "access": "read_items only",
                },
            ],
            "temporary_writer": {
                "role": "task6-temporary-migration-writer",
                "identity": "separate existing 1Password admin or automation identity selected by Cristian",
                "access": "temporary item-write only to the three named target vaults",
                "grant_steps": [
                    "Grant the selected identity temporary item-write access only to each target vault it must populate; grant no runtime token or Environment access."
                ],
                "revocation_and_readback_steps": [
                    "After every handoff row is live-verified, remove all target-vault write grants from task6-temporary-migration-writer.",
                    "Re-read 1Password permissions and confirm the writer has no target-vault access and each runtime account has read_items only for exactly its one named vault.",
                ],
            },
        },
        "counts": {
            "rows": len(rows),
            "github_field_rows": len(rows) - len(direct_rows),
            "direct_onepassword_rows": len(direct_rows),
            "excluded_no_action_references": excluded,
            "by_authority_status": counts("authority_status"),
            "by_target_vault": counts("target_vault"),
            "by_handoff_group": counts("handoff_group"),
        },
        "broker_actions": list(broker_actions or []),
        "rows": rows,
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
    direct_onepassword_entries: list[dict[str, Any]] = []
    direct_onepassword_coordinates: set[
        tuple[str, str, str, str, str, str]
    ] = set()

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
                job_direct_entries: list[dict[str, Any]] = []
                for reference in job["direct_onepassword_references"]:
                    direct_entry = apply_direct_onepassword_mapping(
                        name,
                        rel,
                        job["id"],
                        reference,
                        authority_evidence,
                    )
                    if direct_entry["consumer"] != classified["target_runner_class"]:
                        raise ValueError(
                            "direct 1Password trust-boundary collision for "
                            f"{name}:{rel}#{job['id']}:{reference['environment_name']}"
                        )
                    coordinate = (
                        name,
                        rel,
                        job["id"],
                        reference["environment_name"],
                        reference["source_reference"],
                        direct_entry["target_vault"],
                    )
                    if coordinate in direct_onepassword_coordinates:
                        raise ValueError("duplicate direct 1Password reference coordinate")
                    direct_onepassword_coordinates.add(coordinate)
                    direct_onepassword_entries.append(direct_entry)
                    job_direct_entries.append(direct_entry)
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
                        "direct_onepassword_references": [
                            {
                                "environment_name": entry["environment_name"],
                                "source_reference": entry["source_reference"],
                                "source_vault": entry["source_vault"],
                                "source_item": entry["source_item"],
                                "source_field": entry["source_field"],
                                "target_vault": entry["target_vault"],
                                "target_item": entry["target_item"],
                                "target_field": entry["target_field"],
                                "field_type": entry["field_type"],
                                "consumer": entry["consumer"],
                                "disposition": entry["disposition"],
                                "delivery": entry["delivery"],
                                "migration_action": entry["migration_action"],
                                **(
                                    {"broker_action_id": entry["broker_action_id"]}
                                    if entry.get("broker_action_id") else {}
                                ),
                            }
                            for entry in job_direct_entries
                        ],
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
                    candidate = apply_secret_consumer(
                        secret_authority(secret_name, name, listed_secrets, rel),
                        classified,
                    )
                    candidate = apply_secretless_migration(
                        candidate, authority_evidence
                    )
                    candidate = apply_workflow_variable_migration(
                        candidate, authority_evidence
                    )
                    candidate = apply_authority_evidence(
                        candidate, authority_evidence
                    )
                    candidate = apply_unresolved_annotation(
                        candidate, authority_evidence
                    )
                    if existing is not None:
                        assert_secret_trust_compatible(
                            existing, candidate, job["id"]
                        )
                        if job["id"] not in existing["consuming_jobs"]:
                            existing["consuming_jobs"].append(job["id"])
                        continue
                    entry = candidate
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
                    "direct_onepassword_references": parsed[
                        "direct_onepassword_references"
                    ],
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
    validate_authority_mapping_coverage(
        authority_evidence, secret_entries, direct_onepassword_entries
    )
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
        "schema_version": 4,
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
        "direct_onepassword_entries": direct_onepassword_entries,
        "broker_actions": authority_evidence.get("broker_actions") or [],
    }
    handoff_doc = build_secret_handoff(
        secret_entries,
        str(org.get("login") or "Ken-Technology"),
        generated_at,
        direct_onepassword_entries,
        authority_evidence.get("broker_actions") or [],
    )

    manifest = build_input_manifest(inputs, snapshot_time)
    repositories_doc["input_hash"] = manifest["input_hash"]
    dump_yaml(output_dir / "repositories.yaml", repositories_doc)
    dump_yaml(output_dir / "runners.yaml", runners_doc)
    dump_yaml(output_dir / "secrets.yaml", secrets_doc)
    dump_yaml(output_dir / "secret-handoff.yaml", handoff_doc)
    dump_yaml(output_dir / "input-manifest.yaml", manifest)
    return {
        "repositories": len(repositories),
        "jobs": sum(r["job_count"] for r in repositories),
        "secrets": len(secret_entries),
        "handoff_rows": len(handoff_doc["rows"]),
        "direct_onepassword_references": len(direct_onepassword_entries),
        "broker_actions": len(authority_evidence.get("broker_actions") or []),
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
