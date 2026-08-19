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


def _slug(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")


def _deployed_source(file: str, key_path: str) -> tuple[str, dict[str, Any]]:
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
        "value_type": "string",
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
    }


def _steps(action: str, repository: str, name: str) -> list[str]:
    if action == "move-to-variable":
        return [
            f"Create repository Actions variable {name} in {repository}, update the workflow reference from secrets to vars, and verify without printing the setting."
        ]
    if action == "reconstruct":
        return [
            f"Reconstruct {name} from the approved metadata source, write it through a concealed handoff, and verify existence only."
        ]
    return [
        f"Copy {name} through a concealed 1Password-to-GitHub handoff and verify existence only; never print the value."
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


def build_evidence() -> dict[str, Any]:
    sources: dict[str, dict[str, Any]] = {}
    mappings: list[dict[str, Any]] = []

    def add_source(source: tuple[str, dict[str, Any]]) -> str:
        source_id, metadata = source
        if source_id in sources and sources[source_id] != metadata:
            raise ValueError(f"conflicting source metadata: {source_id}")
        sources[source_id] = metadata
        return source_id

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

    mapping_ids = [mapping["mapping_id"] for mapping in mappings]
    if len(mapping_ids) != len(set(mapping_ids)):
        raise ValueError("duplicate authority mapping selector")
    if any(mapping["source_ref"] not in sources for mapping in mappings):
        raise ValueError("authority mapping references an unknown source")

    return {
        "schema_version": 1,
        "evidence_id": EVIDENCE_ID,
        "policy": "Value-free metadata only. Sources record labels, key paths, types, and existence/readability booleans; no values were retrieved or stored.",
        "sources": dict(sorted(sources.items())),
        "mappings": sorted(mappings, key=lambda row: row["mapping_id"]),
        "unresolved_observations": [
            {
                "kind": "onepassword-notes-only",
                "items": [
                    "client-system-env",
                    "gtm-env",
                    "ken-agents-env",
                    "ken-automations-env",
                    "ken-cms-env",
                    "ken-frontend-env",
                    "ken-search-env",
                ],
                "reason": "Only a notes field was visible; notes were not parsed because doing so could expose values.",
            },
            {
                "kind": "trust-boundary",
                "repository": "ken-frontend",
                "github_secret_name": "CLERK_SECRET_KEY",
                "target_vault": "Ken CI Runtime",
                "reason": "The production Clerk authority must not be copied into the nonproduction CI trust domain without a separate approved authority.",
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
