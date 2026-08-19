#!/usr/bin/env python3
"""Parse collected Actions metadata into sanitized inventory YAML.

This module never contacts GitHub. The shell collector must only supply
name/metadata payloads. Secret values are rejected if they appear.
"""
from __future__ import annotations

import json
import re
import sys
from datetime import datetime, timezone
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
)


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


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
    for match in pattern.finditer(text):
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
    if job_id in {"should-deploy"}:
        return False
    if any(hint in text.lower() or hint in joined_uses for hint in DEPLOY_HINTS):
        if job_id in {"test", "ci", "security", "validate", "lint", "guardrails"} and "deploy" not in path:
            return False
        return True
    if job_id in {"deploy", "publish", "pin", "build-and-publish"}:
        return True
    if any(token in path for token in ("deploy", "publish")) and job_id not in {
        "test",
        "should-deploy",
        "validate",
        "secrets-guard",
        "static",
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

    uses_reusable = bool(re.search(r"^\s*uses:\s*", text, re.M)) and "runs-on" not in text.split("steps:", 1)[0]
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
    jobs: list[dict[str, Any]] = []
    if isinstance(jobs_block, dict):
        for job_id, job in jobs_block.items():
            if not isinstance(job, dict):
                job = {}
            job_text = yaml.safe_dump(job, sort_keys=False)
            uses = uses_from(job)
            secrets = extract_names(SECRET_NAME_RE, job_text)
            variables = extract_names(VAR_NAME_RE, job_text)
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
                    "target_hints": target_hints(job_text),
                    "raw_text": job_text,
                }
            )
    wf_text = text
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
    if prevent is None:
        prevent = False
    for rule in record.get("protection_rules") or []:
        if not isinstance(rule, dict):
            continue
        rtype = rule.get("type") or rule.get("id")
        if rtype == "wait_timer" and wait_timer is None:
            wait_timer = rule.get("wait_timer")
        if rtype in {"required_reviewers", "required_reviewers_rule"} or "reviewers" in rule:
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
            branches = "custom_branch_policies"
        else:
            branches = "unrestricted"
    elif branch_policy is None:
        branches = "unrestricted"
    else:
        branches = branch_policy
    hard_stop = False
    for login in reviewers:
        if login.lower() not in {"cristian-frunze", "cristian"}:
            hard_stop = True
    return {
        "available": True,
        "required_reviewers": reviewers,
        "prevent_self_review": prevent,
        "wait_timer": wait_timer if wait_timer is not None else 0,
        "deployment_branches": branches,
        "external_hard_stop": hard_stop,
        "note": "required reviewer outside the cutover operator" if hard_stop else "",
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
            "consumer": "workflow-job",
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
    consumer = "ken-deploy-production"
    vault = "Ken Deploy Production"
    return {
        "github_secret_name": name,
        "repository": repo,
        "workflow": workflow_path,
        "scope": ",".join(scopes) if scopes else "workflow-reference",
        "source_authority": authority,
        "source_readable": False,
        "rotation_required": True,
        "target_vault": vault,
        "consumer": consumer,
    }


def summarize_runners(raw: dict[str, Any], snapshot_time: str) -> dict[str, Any]:
    runners = raw.get("runners") or raw.get("items") or []
    groups: dict[tuple[str, str, bool], int] = {}
    labels_seen: dict[str, int] = {}
    for runner in runners:
        labels = tuple(sorted(lbl.get("name") if isinstance(lbl, dict) else str(lbl) for lbl in runner.get("labels") or []))
        status = str(runner.get("status") or "unknown")
        busy = bool(runner.get("busy"))
        key = (",".join(labels), status, busy)
        groups[key] = groups.get(key, 0) + 1
        for label in labels:
            labels_seen[label] = labels_seen.get(label, 0) + 1
    grouped = [
        {"count": count, "labels": labels.split(",") if labels else [], "status": status, "busy": busy}
        for (labels, status, busy), count in sorted(groups.items(), key=lambda item: (-item[1], item[0][0]))
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


def load_host_snapshot(collect_dir: Path) -> dict[str, Any]:
    path = collect_dir / "hosts.json"
    if path.exists():
        return load_json(path, {})
    return {
        "available": False,
        "note": "Host snapshot was not included in this collection.",
    }


def generate(collect_dir: Path, output_dir: Path) -> dict[str, Any]:
    generated_at = utc_now()
    org = load_json(collect_dir / "org.json", {})
    repos_meta = load_json(collect_dir / "repos.json", [])
    runners_raw = load_json(collect_dir / "runners.json", {})
    groups_raw = load_json(collect_dir / "runner-groups.json", {})
    org_secrets = [item.get("name") for item in load_json(collect_dir / "org-secrets.json", []) if item.get("name")]
    org_vars = [item.get("name") for item in load_json(collect_dir / "org-variables.json", []) if item.get("name")]
    budgets = load_json(collect_dir / "budgets.json", {})
    snapshot_time = load_json(collect_dir / "collection-meta.json", {}).get("collected_at") or generated_at

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
    seen_secret_keys: set[tuple[str, str, str]] = set()

    for repo_info in repos_meta:
        name = repo_info["name"]
        repo_dir = collect_dir / "repos" / name
        meta = load_json(repo_dir / "meta.json", repo_info)
        visibility = str(meta.get("visibility") or repo_info.get("visibility") or "").lower()
        default_branch = (
            (meta.get("default_branch") or (repo_info.get("defaultBranchRef") or {}).get("name") or "main")
        )
        workflows: list[dict[str, Any]] = []
        wf_dir = repo_dir / "workflows"
        listed_secrets = {
            "org": org_secrets,
            "repo": [item.get("name") for item in load_json(repo_dir / "secrets.json", []) if item.get("name")],
            "environment": [],
        }
        env_secret_names: list[str] = []
        for env_secret_file in sorted((repo_dir / "environment-secrets").glob("*.json")) if (repo_dir / "environment-secrets").exists() else []:
            for item in load_json(env_secret_file, []):
                if item.get("name"):
                    env_secret_names.append(item["name"])
        listed_secrets["environment"] = env_secret_names

        if wf_dir.exists():
            for wf_path in sorted(wf_dir.rglob("*")):
                if wf_path.suffix.lower() not in {".yml", ".yaml"}:
                    continue
                rel = ".github/workflows/" + wf_path.relative_to(wf_dir).as_posix()
                parsed = parse_workflow(rel, wf_path.read_text(encoding="utf-8"))
                jobs_out: list[dict[str, Any]] = []
                for job in parsed["jobs"]:
                    env_name = job["environment_name"]
                    env_file = repo_dir / "environments" / f"{env_name}.json" if env_name else None
                    protection = env_protection(load_json(env_file, None) if env_file and env_file.exists() else None) if env_name else {
                        "available": False,
                        "required_reviewers": [],
                        "prevent_self_review": None,
                        "wait_timer": None,
                        "deployment_branches": None,
                        "external_hard_stop": False,
                        "note": "",
                    }
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
                    flags = classified["flags"] + [f for f in job_flags_extra if f not in classified["flags"]]
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
                    jobs_out.append(
                        {
                            "id": job["id"],
                            "name": job["name"],
                            "runs_on": job["runs_on"],
                            "resolved_runs_on": job["resolved_runs_on"],
                            "environment": env_record,
                            "environment_name": env_name or None,
                            "needs": job["needs"],
                            "permissions": job["permissions"] if job["permissions"] is not None else parsed["permissions"],
                            "uses": job["uses"],
                            "secret_names": job["secret_names"],
                            "variable_names": job["variable_names"],
                            "artifacts": job["artifacts"],
                            "target_hints": job["target_hints"],
                            "classification": classified["classification"],
                            "target_runner_class": classified["target_runner_class"],
                            "target_runs_on": classified["target_runs_on"],
                            "secret_class": classified["secret_class"],
                            "production_impact": classified["production_impact"],
                            "deploys_or_publishes": classified["deploys_or_publishes"],
                            "combined_build_and_deploy": classified["combined_build_and_deploy"],
                            "flags": flags,
                        }
                    )
                    for secret_name in job["secret_names"]:
                        key = (name, rel, secret_name)
                        if key in seen_secret_keys:
                            continue
                        seen_secret_keys.add(key)
                        entry = secret_authority(secret_name, name, listed_secrets, rel)
                        if classified["secret_class"].startswith("deploy"):
                            entry["target_vault"] = (
                                "Ken Deploy Production"
                                if classified["production_impact"]
                                else "Ken Deploy Nonproduction"
                            )
                            entry["consumer"] = classified["target_runner_class"]
                        elif classified["secret_class"] == "ci-runtime":
                            entry["target_vault"] = "Ken CI Runtime"
                            entry["consumer"] = classified["target_runner_class"]
                        elif classified["secret_class"] == "grok-review-unchanged":
                            entry["target_vault"] = None
                            entry["consumer"] = "existing-grok-review"
                            entry["source_authority"] = (
                                "Existing Grok review workflow reference; do not copy onto ken-ci or ken-deploy."
                            )
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

    host_snapshot = load_host_snapshot(collect_dir)
    grok = load_json(collect_dir / "grok-runners.json", {})
    worldstream = load_json(collect_dir / "worldstream-runners.json", {})
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
            "blacksmith_previous_month_usd": budgets.get("blacksmith_previous_month_usd"),
            "blacksmith_previous_month_status": budgets.get(
                "blacksmith_previous_month_status",
                "unverified-planning-baseline",
            ),
            "blacksmith_current_unbilled": budgets.get("blacksmith_current_unbilled", "unavailable"),
        },
        "current": summarize_runners(runners_raw, snapshot_time),
        "runner_groups": groups_raw.get("runner_groups") or groups_raw.get("groups") or groups_raw,
        "target": build_target_runners(),
        "preserved": {"grok_review": grok},
        "legacy": {"worldstream_ken_ci": worldstream},
        "hosts": host_snapshot,
    }

    secrets_doc = {
        "schema_version": 1,
        "organization": org.get("login") or "Ken-Technology",
        "generated_at": generated_at,
        "policy": (
            "Name-only map. Values were never requested or written. "
            "GitHub-only long-lived secrets are unrecoverable and require rotation."
        ),
        "organization_secret_names": org_secrets,
        "organization_variable_names": org_vars,
        "onepassword_visible_vaults": load_json(collect_dir / "onepassword-vaults.json", []),
        "entries": secret_entries,
        "secrets": secret_entries,
    }

    dump_yaml(output_dir / "repositories.yaml", repositories_doc)
    dump_yaml(output_dir / "runners.yaml", runners_doc)
    dump_yaml(output_dir / "secrets.yaml", secrets_doc)
    return {
        "repositories": len(repositories),
        "jobs": sum(r["job_count"] for r in repositories),
        "secrets": len(secret_entries),
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
