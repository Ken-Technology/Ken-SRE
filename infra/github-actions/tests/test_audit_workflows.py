#!/usr/bin/env python3
"""Focused collector/classifier tests. These assert behavior, not file existence."""
from __future__ import annotations

import hashlib
import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
LIB = ROOT / "infra/github-actions/scripts/lib"
FIXTURE_DIR = ROOT / "infra/github-actions/tests/fixtures/offline-org"
sys.path.insert(0, str(LIB))

import audit_workflows as aw  # noqa: E402


class OnePasswordEnvMetadataTests(unittest.TestCase):
    def test_emits_only_env_lhs_names_and_presence(self):
        import extract_op_env_metadata as extractor

        github_canary = "".join(("g", "hp", "_", "A" * 30))
        private_key_canary = "".join(
            ("-----BEGIN ", "PRI", "VATE ", "KEY-----")
        )
        private_key_end = "".join(("-----END ", "PRI", "VATE ", "KEY-----"))
        canaries = [
            "RIGHT_HAND_CANARY_7fca2c",
            github_canary,
            private_key_canary,
        ]
        item = {
            "title": "ken-frontend-env",
            "vault": {"name": "Development"},
            "fields": [
                {
                    "id": "notesPlain",
                    "purpose": "NOTES",
                    "type": "STRING",
                    "value": (
                        "PUBLIC_URL=https://example.invalid/RIGHT_HAND_CANARY_7fca2c\n"
                        f"export API_TOKEN={github_canary}\n"
                        "EMPTY=\n"
                        f"PRIVATE_KEY='{private_key_canary}\n"
                        "right-hand-only material\n"
                        f"{private_key_end}'\n"
                    ),
                }
            ],
        }

        output = extractor.extract_item_metadata(item)
        rendered = json.dumps(output, sort_keys=True)

        self.assertEqual(output["schema_version"], 1)
        self.assertEqual(output["vault"], "Development")
        self.assertEqual(output["item"], "ken-frontend-env")
        self.assertEqual(
            output["keys"],
            [
                {
                    "name": "API_TOKEN",
                    "declared_type": "environment-string",
                    "value_present": True,
                },
                {
                    "name": "EMPTY",
                    "declared_type": "environment-string",
                    "value_present": False,
                },
                {
                    "name": "PRIVATE_KEY",
                    "declared_type": "environment-string",
                    "value_present": True,
                },
                {
                    "name": "PUBLIC_URL",
                    "declared_type": "environment-string",
                    "value_present": True,
                },
            ],
        )
        for canary in canaries:
            self.assertNotIn(canary, rendered)
        self.assertNotIn("value", output)
        self.assertNotIn("notes", rendered.lower())

    def test_multiline_right_hand_cannot_create_false_key(self):
        import extract_op_env_metadata as extractor

        item = {
            "title": "ken-agents-env",
            "vault": {"name": "Development"},
            "fields": [
                {
                    "id": "notesPlain",
                    "purpose": "NOTES",
                    "type": "STRING",
                    "value": (
                        'JSON_BLOB="{\n'
                        'FAKE_KEY=must-not-be-emitted\n'
                        '}"\n'
                        "REAL_KEY=present\n"
                    ),
                }
            ],
        }

        output = extractor.extract_item_metadata(item)

        self.assertEqual(
            [key["name"] for key in output["keys"]], ["JSON_BLOB", "REAL_KEY"]
        )

    def test_error_never_echoes_right_hand_input(self):
        import extract_op_env_metadata as extractor

        canary = "ERROR_CANARY_must_not_escape"
        with self.assertRaises(ValueError) as caught:
            extractor.extract_item_metadata({"unexpected": canary})
        self.assertNotIn(canary, str(caught.exception))


class DirectOnePasswordReferenceTests(unittest.TestCase):
    EXPECTED_CHECKED_REFERENCES = {
        (
            "ken-vexa-mcp-auth",
            ".github/workflows/deploy.yml",
            "deploy",
            "SERVER_HOST",
            "op://Development/vexa-mcp-auth-deploy-ssh/host",
            "Ken Deploy Production",
        ),
        (
            "ken-vexa-mcp-auth",
            ".github/workflows/deploy.yml",
            "deploy",
            "SERVER_PORT",
            "op://Development/vexa-mcp-auth-deploy-ssh/port",
            "Ken Deploy Production",
        ),
        (
            "ken-vexa-mcp-auth",
            ".github/workflows/deploy.yml",
            "deploy",
            "SERVER_SSH_KEY",
            "op://Development/vexa-mcp-auth-deploy-ssh/private_key",
            "Ken Deploy Production",
        ),
        (
            "ken-website",
            ".github/workflows/beehiiv-sync.yml",
            "sync",
            "DEPLOY_SSH_KEY",
            "op://ken-website/blog-sync-deploy/private_key",
            "Ken Deploy Production",
        ),
        (
            "ken-website",
            ".github/workflows/beehiiv-sync.yml",
            "sync",
            "BEEHIIV_API_KEY",
            "op://ken-website/beehiiv/credential",
            "Ken Deploy Production",
        ),
        (
            "ken-website",
            ".github/workflows/beehiiv-sync.yml",
            "sync",
            "BEEHIIV_PUBLICATION_ID",
            "op://ken-website/beehiiv/publication_id",
            "Ken Deploy Production",
        ),
        (
            "ken-website",
            ".github/workflows/deploy.yml",
            "deploy",
            "NEXT_PUBLIC_POSTHOG_PROJECT_TOKEN",
            "op://ken-website/posthog/project_token",
            "Ken Deploy Production",
        ),
        (
            "ken-website",
            ".github/workflows/deploy.yml",
            "deploy",
            "POSTHOG_PERSONAL_API_KEY",
            "op://ken-website/posthog/personal_api_key",
            "Ken Deploy Production",
        ),
        (
            "ken-website",
            ".github/workflows/deploy.yml",
            "deploy",
            "WEBSITE_HOST",
            "op://ken-website/deploy-ssh/host",
            "Ken Deploy Production",
        ),
        (
            "ken-website",
            ".github/workflows/deploy.yml",
            "deploy",
            "WEBSITE_PORT",
            "op://ken-website/deploy-ssh/port",
            "Ken Deploy Production",
        ),
        (
            "ken-website",
            ".github/workflows/deploy.yml",
            "deploy",
            "WEBSITE_SSH_KEY",
            "op://ken-website/deploy-ssh/private_key",
            "Ken Deploy Production",
        ),
    }

    def test_parser_emits_only_active_fixed_env_references(self):
        workflow = """
on: push
env:
  GLOBAL_HOST: op://Development/global/host
# COMMENTED_REF: op://Development/commented/credential
jobs:
  deploy:
    runs-on: ubuntu-latest
    env:
      JOB_PORT: op://Development/service/port
    steps:
      - env:
          STEP_KEY: op://Development/service/private_key
        run: deploy
  # inactive:
  #   runs-on: ubuntu-latest
  #   env:
  #     INACTIVE_KEY: op://Development/inactive/credential
"""
        parsed = aw.parse_workflow(".github/workflows/deploy.yml", workflow)
        refs = parsed["jobs"][0]["direct_onepassword_references"]
        self.assertEqual(
            refs,
            [
                {
                    "environment_name": "GLOBAL_HOST",
                    "source_reference": "op://Development/global/host",
                    "source_vault": "Development",
                    "source_item": "global",
                    "source_field": "host",
                },
                {
                    "environment_name": "JOB_PORT",
                    "source_reference": "op://Development/service/port",
                    "source_vault": "Development",
                    "source_item": "service",
                    "source_field": "port",
                },
                {
                    "environment_name": "STEP_KEY",
                    "source_reference": "op://Development/service/private_key",
                    "source_vault": "Development",
                    "source_item": "service",
                    "source_field": "private_key",
                },
            ],
        )
        self.assertNotIn("commented", str(refs).lower())
        self.assertNotIn("inactive", str(refs).lower())

    def test_parser_rejects_dynamic_or_malformed_direct_reference(self):
        workflow = """
on: push
jobs:
  deploy:
    runs-on: ubuntu-latest
    env:
      BAD: op://Development/${{ vars.ITEM }}/credential
"""
        with self.assertRaisesRegex(ValueError, "fixed direct 1Password"):
            aw.parse_workflow(".github/workflows/deploy.yml", workflow)

    def test_parser_rejects_compact_actions_expression_in_every_op_segment(self):
        bad_references = (
            "op://${{vars.VAULT}}/item/field",
            "op://Development/${{vars.ITEM}}/field",
            "op://Development/item/${{vars.FIELD}}",
        )
        for reference in bad_references:
            with self.subTest(reference=reference):
                workflow = f"""
on: push
jobs:
  deploy:
    runs-on: ubuntu-latest
    env:
      BAD: {reference}
"""
                with self.assertRaisesRegex(ValueError, "fixed direct 1Password"):
                    aw.parse_workflow(".github/workflows/deploy.yml", workflow)

    def test_authority_builder_rejects_expression_or_control_syntax_in_segments(self):
        import build_task6_authority_evidence as builder

        for reference in (
            "op://${{vars.VAULT}}/item/field",
            "op://Development/${{vars.ITEM}}/field",
            "op://Development/item/${{vars.FIELD}}",
            "op://Development/item/field`whoami`",
        ):
            with self.subTest(reference=reference):
                with self.assertRaisesRegex(ValueError, "fixed source reference"):
                    builder._direct_onepassword_mapping(
                        "repo", ".github/workflows/deploy.yml", "deploy", "KEY", reference, "concealed"
                    )

    def test_workflow_loader_rejects_duplicate_mapping_keys_at_every_level(self):
        workflows = (
            """
on: push
env:
  FIRST: op://Development/item/field
env:
  SECOND: op://Development/item/field
jobs:
  deploy:
    runs-on: ubuntu-latest
""",
            """
on: push
jobs:
  deploy:
    runs-on: ubuntu-latest
    env:
      FIRST: op://Development/item/field
    env:
      SECOND: op://Development/item/field
""",
            """
on: push
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - run: deploy
        env:
          FIRST: op://Development/item/field
        env:
          SECOND: op://Development/item/field
""",
        )
        for workflow in workflows:
            with self.subTest(workflow=workflow):
                with self.assertRaisesRegex(ValueError, "duplicate YAML mapping key"):
                    aw.parse_workflow(".github/workflows/deploy.yml", workflow)

    def test_committed_checked_inventory_has_exact_direct_reference_handoff(self):
        import yaml

        inventory = ROOT / "infra/github-actions/inventory"
        repositories = yaml.safe_load((inventory / "repositories.yaml").read_text())
        secrets = yaml.safe_load((inventory / "secrets.yaml").read_text())
        handoff = yaml.safe_load((inventory / "secret-handoff.yaml").read_text())

        parsed = {
            (
                repo["name"],
                workflow["path"],
                job["id"],
                ref["environment_name"],
                ref["source_reference"],
                ref["target_vault"],
            )
            for repo in repositories["repositories"]
            for workflow in repo["workflows"]
            for job in workflow["jobs"]
            for ref in job.get("direct_onepassword_references") or []
        }
        direct_entries = {
            (
                row["repository"],
                row["workflow"],
                row["job"],
                row["environment_name"],
                row["source_reference"],
                row["target_vault"],
            )
            for row in secrets["direct_onepassword_entries"]
        }
        direct_handoff = {
            (
                row["repository"],
                row["workflow"],
                row["job"],
                row["environment_name"],
                row["source_reference"],
                row["target_vault"],
            )
            for row in handoff["rows"]
            if row.get("reference_class") == "direct-onepassword"
        }
        self.assertEqual(len(secrets["entries"]), 343)
        self.assertEqual(len(secrets["direct_onepassword_entries"]), 11)
        self.assertEqual(parsed, self.EXPECTED_CHECKED_REFERENCES)
        self.assertEqual(direct_entries, parsed)
        self.assertEqual(direct_handoff, parsed)
        self.assertEqual(handoff["counts"]["direct_onepassword_rows"], 11)
        self.assertEqual(
            {row["broker_action_id"] for row in secrets["direct_onepassword_entries"]},
            {
                "ken-vexa-mcp-auth-production-deploy",
                "ken-website-beehiiv-production-sync",
                "ken-website-production-deploy",
            },
        )
        self.assertEqual(
            secrets["broker_actions"], handoff["broker_actions"]
        )

    def test_unregistered_direct_reference_fails_closed(self):
        reference = {
            "environment_name": "UNKNOWN",
            "source_reference": "op://Development/unknown/credential",
            "source_vault": "Development",
            "source_item": "unknown",
            "source_field": "credential",
        }
        with self.assertRaisesRegex(ValueError, "unregistered direct 1Password"):
            aw.apply_direct_onepassword_mapping(
                "ken-website",
                ".github/workflows/deploy.yml",
                "deploy",
                reference,
                {"direct_onepassword_mappings": []},
            )

    def test_authority_builder_registers_exact_checked_direct_references(self):
        import build_task6_authority_evidence as builder

        mappings = builder.build_evidence()["direct_onepassword_mappings"]
        actual = {
            (
                row["repository"],
                row["workflow"],
                row["job"],
                row["environment_name"],
                row["source_reference"],
                row["target_vault"],
            )
            for row in mappings
        }
        self.assertEqual(actual, self.EXPECTED_CHECKED_REFERENCES)
        self.assertEqual(len(mappings), 11)
        for row in mappings:
            self.assertEqual(row["consumer"], "ken-deploy-production")
            self.assertIn(row["broker_action_id"], {
                "ken-vexa-mcp-auth-production-deploy",
                "ken-website-beehiiv-production-sync",
                "ken-website-production-deploy",
            })
            self.assertIn(row["field_type"], {"concealed", "string"})
            self.assertTrue(row["source_to_target_steps"])
            self.assertTrue(row["broker_cutover_steps"])
            self.assertTrue(row["live_verification_steps"])
            self.assertTrue(row["retirement_steps"])

    def test_direct_rows_bind_to_three_fixed_output_free_broker_actions(self):
        import build_task6_authority_evidence as builder

        evidence = builder.build_evidence()
        direct_actions = {
            row["action_id"]: row
            for row in evidence["broker_actions"]
            if row["mode"] == "fixed_secret_action"
        }
        self.assertEqual(
            set(direct_actions),
            {
                "ken-vexa-mcp-auth-production-deploy",
                "ken-website-beehiiv-production-sync",
                "ken-website-production-deploy",
            },
        )
        for action in direct_actions.values():
            self.assertEqual(action["trust_class"], "production")
            self.assertEqual(action["template_owner"], "root")
            self.assertEqual(action["wrapper_owner"], "root")
            self.assertTrue(action["template_path"].startswith("/etc/ken-op-broker/"))
            self.assertTrue(action["wrapper_path"].startswith("/usr/local/libexec/"))
            self.assertTrue(action["executor_uid"].startswith("ken-action-"))
            self.assertTrue(action["target_profile"])
            self.assertTrue(action["network_profile"])
            self.assertEqual(action["result_contract"], "stable-code-only")
            self.assertFalse(action["client_receives_field"])
            self.assertFalse(action["client_receives_config"])
            self.assertFalse(action["client_receives_fd"])
            self.assertFalse(action["client_receives_output"])


class StrictAuthorityEvidenceSchemaTests(unittest.TestCase):
    FRONTEND_PRODUCTION_BUILD_BOUNDARY = {
        "action_id": "ken-frontend-production-release",
        "mode": "production_build",
        "workflow": ".github/workflows/deploy.yml",
        "production_build_job": "build-image",
        "deployment_job": "deploy",
        "runner_class": "ken-deploy-production",
        "broker_only": True,
        "ci_validation_only": True,
        "forbid_ken_ci_production_artifact": True,
    }
    FRONTEND_POST_BUILD_BOUNDARY = {
        "action_id": "ken-frontend-production-release",
        "mode": "post-build-sourcemap-upload",
        "workflow": ".github/workflows/deploy.yml",
        "production_build_job": "build-image",
        "deployment_job": "deploy",
        "runner_class": "ken-deploy-production",
        "broker_only": True,
        "ci_validation_only": True,
        "forbid_ken_ci_production_artifact": True,
    }
    FRONTEND_POSTHOG_FIELDS = (
        "POSTHOG_PERSONAL_API_KEY",
        "POSTHOG_PROJECT_ID",
    )

    @staticmethod
    def _production_action(evidence):
        return next(
            row
            for row in evidence["broker_actions"]
            if row["action_id"] == "ken-frontend-production-release"
        )

    @staticmethod
    def _frontend_annotation(evidence, name):
        return next(
            row
            for row in evidence["unresolved_annotations"]
            if row["repository"] == "ken-frontend"
            and row["github_secret_name"] == name
        )

    @staticmethod
    def _unrelated_frontend_annotation(evidence):
        return next(
            row
            for row in evidence["unresolved_annotations"]
            if row["repository"] == "ken-frontend"
            and row["github_secret_name"]
            not in {
                "NEXT_SERVER_ACTIONS_ENCRYPTION_KEY",
                "POSTHOG_PERSONAL_API_KEY",
                "POSTHOG_PROJECT_ID",
            }
        )

    @staticmethod
    def _set_path(target, path, value):
        current = target
        for segment in path[:-1]:
            current = current[segment]
        current[path[-1]] = value

    def _assert_full_generation_rejects(self, evidence, message):
        import shutil

        with tempfile.TemporaryDirectory() as temp:
            collect = Path(temp) / "collect"
            output = Path(temp) / "output"
            shutil.copytree(FIXTURE_DIR, collect)
            (collect / "authority-evidence.json").write_text(
                json.dumps(evidence), encoding="utf-8"
            )
            with self.assertRaisesRegex(ValueError, message):
                aw.generate(collect, output)

    def test_duplicate_json_keys_fail_before_inventory_hashing(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "authority-evidence.json"
            path.write_text(
                '{"schema_version":1,"direct_onepassword_mappings":[],"direct_onepassword_mappings":[]}',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "duplicate JSON object key"):
                aw.load_json(path, {})

    def test_complete_builder_evidence_matches_exact_recursive_schema(self):
        import build_task6_authority_evidence as builder

        aw.validate_authority_evidence(builder.build_evidence())

    def test_value_bearing_aliases_reject_before_hashing_without_echoing_canary(self):
        import build_task6_authority_evidence as builder

        aliases = (
            "credential",
            "api_key",
            "private_key",
            "secret_value",
            "access_token",
            "password_hash",
            "values",
        )
        for alias in aliases:
            evidence = copy.deepcopy(builder.build_evidence())
            canary = "RIGHT_HAND_CANARY_must_not_escape"
            evidence["direct_onepassword_mappings"][0][alias] = canary
            with self.subTest(alias=alias):
                with self.assertRaises(ValueError) as caught:
                    aw.validate_authority_evidence(evidence)
                self.assertNotIn(canary, str(caught.exception))

    def test_unknown_nested_and_wrong_type_authority_keys_fail_closed(self):
        import build_task6_authority_evidence as builder

        unknown = copy.deepcopy(builder.build_evidence())
        oidc = next(
            row
            for row in unknown["secretless_migrations"]
            if row["migration_action"] == "oidc-trusted-publisher"
        )
        oidc["trusted_publisher"]["unexpected"] = True
        with self.assertRaisesRegex(ValueError, "unexpected authority evidence key"):
            aw.validate_authority_evidence(unknown)

        wrong_type = copy.deepcopy(builder.build_evidence())
        wrong_type["direct_onepassword_mappings"][0]["field_type"] = ["concealed"]
        with self.assertRaisesRegex(ValueError, "wrong authority evidence type"):
            aw.validate_authority_evidence(wrong_type)

    def test_production_build_boundary_mutations_fail_closed(self):
        import build_task6_authority_evidence as builder

        mutations = (
            ("network", lambda action: action["build_contract"]["secret_phase"].__setitem__("network", "default")),
            ("secret-arg", lambda action: action["build_contract"]["secret_phase"].__setitem__("arg", True)),
            ("secret-env", lambda action: action["build_contract"]["secret_phase"].__setitem__("env", True)),
            ("secret-cache", lambda action: action["build_contract"]["secret_phase"].__setitem__("cache_metadata", True)),
            ("secret-log", lambda action: action["build_contract"]["secret_phase"].__setitem__("logs", True)),
            ("secret-layer", lambda action: action["build_contract"]["secret_phase"].__setitem__("layers", True)),
            ("source-drift", lambda action: action["source_contract"].__setitem__("source_commit_sha", "0" * 40)),
            ("workflow-drift", lambda action: action["source_contract"].__setitem__("workflow_blob_sha", "0" * 40)),
            ("wrong-digest-input", lambda action: action["deploy_contract"].__setitem__("accepts_runner_digest", True)),
            ("replay-disabled", lambda action: action["authorization"].__setitem__("checks", [check for check in action["authorization"]["checks"] if check != "durable-replay"])),
            ("runner-socket", lambda action: action["identity_boundary"].__setitem__("runner_can_access_builder_socket", True)),
            ("builder-deploy", lambda action: action["identity_boundary"].__setitem__("builder_can_access_deploy_executor", True)),
            ("deploy-builder", lambda action: action["identity_boundary"].__setitem__("deploy_executor_can_access_builder", True)),
        )
        for name, mutate in mutations:
            evidence = copy.deepcopy(builder.build_evidence())
            action = next(
                row
                for row in evidence["broker_actions"]
                if row["action_id"] == "ken-frontend-production-release"
            )
            mutate(action)
            with self.subTest(name=name):
                with self.assertRaisesRegex(ValueError, "production build contract"):
                    aw.validate_authority_evidence(evidence)

    def test_production_build_security_constants_fail_closed(self):
        import build_task6_authority_evidence as builder

        mutations = (
            (("trust_class",), "nonproduction"),
            (("authorization", "github_token_use"), "unrestricted"),
            (("authorization", "checks"), [
                "unix-peer", "class-oidc", "live-job", "workflow",
                "protected-ref", "environment", "durable-replay", "unix-peer",
            ]),
            (("source_contract", "owner"), "attacker"),
            (("source_contract", "repository"), "attacker"),
            (("source_contract", "default_ref"), "refs/heads/unreviewed"),
            (("source_contract", "source_addendum"), "unreviewed.md"),
            (("identity_boundary", "runner_uid"), "unreviewed-runner"),
            (("identity_boundary", "broker_uid"), "unreviewed-broker"),
            (("identity_boundary", "builder_uid"), "unreviewed-builder"),
            (("identity_boundary", "post_build_uid"), "unreviewed-post"),
            (("identity_boundary", "deploy_uid"), "unreviewed-deploy"),
            (("build_contract", "builder_socket"), "/tmp/buildkit.sock"),
            (("build_contract", "builder_state"), "/tmp/buildkit-state"),
            (("build_contract", "wrapper_path"), "/tmp/build"),
            (("build_contract", "base_image"), "attacker/image:latest"),
            (("build_contract", "base_image_digest"), "sha256:unreviewed"),
            (("build_contract", "buildkit_version"), "unreviewed"),
            (("build_contract", "wrapper_sha256"), "unreviewed"),
            (("build_contract", "dependency_network_profile"), "allow-anywhere"),
            (("build_contract", "dependency_endpoints"), ["attacker.invalid:443"]),
            (("build_contract", "reviewed_github_variables"), ["NEXT_PUBLIC_UNREVIEWED"]),
            (("build_contract", "forbidden_build_fields"), [
                "POSTHOG_PERSONAL_API_KEY", "POSTHOG_PROJECT_ID",
                "POSTHOG_PERSONAL_API_KEY",
            ]),
            (("build_contract", "resource_limits", "cpu_quota"), "999%"),
            (("build_contract", "resource_limits", "memory_max"), "1T"),
            (("build_contract", "resource_limits", "tasks_max"), -1),
            (("build_contract", "resource_limits", "timeout_seconds"), -1),
            (("build_contract", "resource_limits", "context_bytes_max"), -1),
            (("build_contract", "resource_limits", "output_bytes_max"), -1),
            (("build_contract", "output", "format"), "local"),
            (("build_contract", "output", "registry"), "attacker.invalid/repo"),
            (("build_contract", "output", "canary_variants"), [
                "raw", "base64", "hex", "raw",
            ]),
            (("post_build_contract", "executor_uid"), "unreviewed-post"),
            (("post_build_contract", "fields"), ["NEXT_SERVER_ACTIONS_ENCRYPTION_KEY"]),
            (("post_build_contract", "target"), "https://attacker.invalid"),
            (("post_build_contract", "input"), "runner-output"),
            (("post_build_contract", "release"), "unreviewed-ref"),
            (("deploy_contract", "executor_uid"), "unreviewed-deploy"),
            (("deploy_contract", "input"), "runner-image-digest"),
            (("durable_state", "fields"), ["run_id"]),
            (("risk_acceptance", "scope"), "any-source"),
            (("pin_gate", "required_exact_pins"), ["source_commit_sha"]),
        )
        for path, value in mutations:
            evidence = copy.deepcopy(builder.build_evidence())
            self._set_path(self._production_action(evidence), path, value)
            with self.subTest(path=path):
                with self.assertRaisesRegex(ValueError, "production build contract"):
                    aw.validate_authority_evidence(evidence)

    def test_fixed_actions_reject_semantic_and_field_set_mutations(self):
        import build_task6_authority_evidence as builder

        action_ids = {
            "ken-vexa-mcp-auth-production-deploy",
            "ken-website-beehiiv-production-sync",
            "ken-website-production-deploy",
        }
        mutations = (
            ("repository", "unreviewed-repository"),
            ("workflow", ".github/workflows/unreviewed.yml"),
            ("job", "unreviewed-job"),
            ("executor_uid", "unreviewed-executor"),
            ("template_path", "/etc/ken-op-broker/templates/unreviewed.env.op"),
            ("wrapper_path", "/usr/local/libexec/ken-actions/unreviewed"),
            ("target_profile", "unreviewed-target"),
            ("network_profile", "allow-internet-anywhere"),
        )
        for action_id in action_ids:
            for field, value in mutations:
                evidence = copy.deepcopy(builder.build_evidence())
                action = next(row for row in evidence["broker_actions"] if row["action_id"] == action_id)
                action[field] = value
                with self.subTest(action=action_id, field=field):
                    with self.assertRaisesRegex(ValueError, "fixed broker action contract"):
                        aw.validate_authority_evidence(evidence)

            for field_mutation in ("extra", "duplicate"):
                evidence = copy.deepcopy(builder.build_evidence())
                action = next(row for row in evidence["broker_actions"] if row["action_id"] == action_id)
                if field_mutation == "extra":
                    action["required_fields"].append(
                        {
                            "target_item": "unreviewed",
                            "target_field": "UNREVIEWED_FIELD",
                            "field_type": "concealed",
                        }
                    )
                else:
                    action["required_fields"].append(copy.deepcopy(action["required_fields"][0]))
                with self.subTest(action=action_id, fields=field_mutation):
                    with self.assertRaisesRegex(ValueError, "fixed broker action contract"):
                        aw.validate_authority_evidence(evidence)

    def test_fixed_action_fields_equal_assigned_direct_mappings(self):
        import build_task6_authority_evidence as builder

        built = builder.build_evidence()
        action = copy.deepcopy(
            next(
                row
                for row in built["broker_actions"]
                if row["action_id"] == "ken-website-production-deploy"
            )
        )
        mappings = [
            copy.deepcopy(row)
            for row in built["direct_onepassword_mappings"]
            if row["broker_action_id"] == action["action_id"]
        ]
        action["required_fields"].append(
            {
                "target_item": "unreviewed",
                "target_field": "UNREVIEWED_FIELD",
                "field_type": "concealed",
            }
        )
        evidence = {
            "mappings": [],
            "unresolved_annotations": [],
            "secretless_migrations": [],
            "workflow_variable_migrations": [],
            "direct_onepassword_mappings": mappings,
            "broker_actions": [action],
        }
        direct_entries = [
            {
                "mapping_id": row["mapping_id"],
                "broker_action_id": row["broker_action_id"],
            }
            for row in mappings
        ]
        with self.assertRaisesRegex(ValueError, "required fields mismatch"):
            aw.validate_authority_mapping_coverage(evidence, [], direct_entries)

    def test_frontend_action_phase_and_variable_mismatches_fail_full_generation(self):
        import build_task6_authority_evidence as builder

        cases = []
        wrong_phase = builder.build_evidence()
        next(
            row
            for row in wrong_phase["unresolved_annotations"]
            if row["github_secret_name"] == "POSTHOG_PERSONAL_API_KEY"
            and row["repository"] == "ken-frontend"
        )["action_phase"] = "offline-buildkit-secret-phase"
        cases.append(("posthog-phase", wrong_phase))

        missing_post_field = builder.build_evidence()
        self._production_action(missing_post_field)["post_build_contract"]["fields"].remove(
            "POSTHOG_PERSONAL_API_KEY"
        )
        cases.append(("posthog-field", missing_post_field))

        encryption_in_post = builder.build_evidence()
        self._production_action(encryption_in_post)["post_build_contract"]["fields"].append(
            "NEXT_SERVER_ACTIONS_ENCRYPTION_KEY"
        )
        cases.append(("encryption-field", encryption_in_post))

        missing_variable = builder.build_evidence()
        self._production_action(missing_variable)["build_contract"]["reviewed_github_variables"].remove(
            "NEXT_PUBLIC_POSTHOG_PROJECT_TOKEN"
        )
        cases.append(("reviewed-variable", missing_variable))

        wrong_action = builder.build_evidence()
        next(
            row
            for row in wrong_action["unresolved_annotations"]
            if row["github_secret_name"] == "NEXT_SERVER_ACTIONS_ENCRYPTION_KEY"
            and row["repository"] == "ken-frontend"
        )["broker_action_id"] = "ken-website-production-deploy"
        cases.append(("encryption-action", wrong_action))

        extra_offline_phase = builder.build_evidence()
        next(
            row
            for row in extra_offline_phase["unresolved_annotations"]
            if row["repository"] == "ken-frontend"
            and row["github_secret_name"] not in {
                "NEXT_SERVER_ACTIONS_ENCRYPTION_KEY",
                "POSTHOG_PERSONAL_API_KEY",
                "POSTHOG_PROJECT_ID",
            }
        )["action_phase"] = "offline-buildkit-secret-phase"
        cases.append(("extra-offline-field", extra_offline_phase))

        for name, evidence in cases:
            with self.subTest(name=name):
                self._assert_full_generation_rejects(
                    evidence,
                    "production build contract|frontend broker semantic mismatch",
                )

    def test_frontend_runtime_identity_and_boundary_fail_closed(self):
        import build_task6_authority_evidence as builder

        mutations = []
        encryption = "NEXT_SERVER_ACTIONS_ENCRYPTION_KEY"

        missing_identity = copy.deepcopy(builder.build_evidence())
        self._frontend_annotation(missing_identity, encryption).pop(
            "required_runtime_identity", None
        )
        mutations.append(("encryption-missing-identity", missing_identity))

        missing_boundary = copy.deepcopy(builder.build_evidence())
        self._frontend_annotation(missing_boundary, encryption).pop(
            "execution_boundary", None
        )
        mutations.append(("encryption-missing-boundary", missing_boundary))

        ci_identity = copy.deepcopy(builder.build_evidence())
        self._frontend_annotation(ci_identity, encryption)[
            "required_runtime_identity"
        ] = "ken-ci-runtime"
        mutations.append(("encryption-ci-identity", ci_identity))

        changed_boundary = copy.deepcopy(builder.build_evidence())
        self._frontend_annotation(changed_boundary, encryption)["execution_boundary"][
            "broker_only"
        ] = False
        mutations.append(("encryption-changed-boundary", changed_boundary))

        unrelated_boundary = copy.deepcopy(builder.build_evidence())
        self._frontend_annotation(unrelated_boundary, encryption)[
            "execution_boundary"
        ] = dict(self.FRONTEND_POST_BUILD_BOUNDARY)
        mutations.append(("encryption-unrelated-boundary", unrelated_boundary))

        for field in self.FRONTEND_POSTHOG_FIELDS:
            missing_posthog_identity = copy.deepcopy(builder.build_evidence())
            self._frontend_annotation(missing_posthog_identity, field).pop(
                "required_runtime_identity", None
            )
            mutations.append((f"{field}-missing-identity", missing_posthog_identity))

            wrong_posthog_identity = copy.deepcopy(builder.build_evidence())
            self._frontend_annotation(wrong_posthog_identity, field)[
                "required_runtime_identity"
            ] = "ken-ci-runtime"
            mutations.append((f"{field}-wrong-identity", wrong_posthog_identity))

            missing_posthog_boundary = copy.deepcopy(builder.build_evidence())
            self._frontend_annotation(missing_posthog_boundary, field).pop(
                "execution_boundary", None
            )
            mutations.append((f"{field}-missing-boundary", missing_posthog_boundary))

            wrong_posthog_boundary = copy.deepcopy(builder.build_evidence())
            self._frontend_annotation(wrong_posthog_boundary, field)[
                "execution_boundary"
            ] = {
                **self.FRONTEND_POST_BUILD_BOUNDARY,
                "broker_only": False,
            }
            mutations.append((f"{field}-wrong-boundary", wrong_posthog_boundary))

            production_boundary = copy.deepcopy(builder.build_evidence())
            self._frontend_annotation(production_boundary, field)[
                "required_runtime_identity"
            ] = "ken-action-frontend-posthog"
            self._frontend_annotation(production_boundary, field)[
                "execution_boundary"
            ] = dict(self.FRONTEND_PRODUCTION_BUILD_BOUNDARY)
            mutations.append(
                (f"{field}-production-build-boundary", production_boundary)
            )

            encryption_phase = copy.deepcopy(builder.build_evidence())
            self._frontend_annotation(encryption_phase, field)[
                "action_phase"
            ] = "offline-buildkit-secret-phase"
            mutations.append((f"{field}-encryption-phase", encryption_phase))

        extra_identity = copy.deepcopy(builder.build_evidence())
        extra = self._unrelated_frontend_annotation(extra_identity)
        extra["required_runtime_identity"] = "ken-deploy-production"
        extra["execution_boundary"] = dict(self.FRONTEND_PRODUCTION_BUILD_BOUNDARY)
        mutations.append(("unrelated-frontend-boundary", extra_identity))

        cross_phase = copy.deepcopy(builder.build_evidence())
        self._frontend_annotation(cross_phase, encryption)[
            "required_runtime_identity"
        ] = "ken-action-frontend-posthog"
        self._frontend_annotation(cross_phase, "POSTHOG_PERSONAL_API_KEY")[
            "required_runtime_identity"
        ] = "ken-deploy-production"
        self._frontend_annotation(cross_phase, "POSTHOG_PERSONAL_API_KEY")[
            "execution_boundary"
        ] = dict(self.FRONTEND_PRODUCTION_BUILD_BOUNDARY)
        mutations.append(("cross-phase-identities", cross_phase))

        for name, evidence in mutations:
            with self.subTest(name=name, path="validate"):
                with self.assertRaisesRegex(
                    ValueError, "frontend broker semantic mismatch"
                ):
                    aw.validate_authority_evidence(evidence)

        full_generation_names = {
            "encryption-missing-identity",
            "encryption-missing-boundary",
            "encryption-ci-identity",
            "encryption-changed-boundary",
            "encryption-unrelated-boundary",
            "POSTHOG_PERSONAL_API_KEY-missing-identity",
            "POSTHOG_PERSONAL_API_KEY-wrong-identity",
            "POSTHOG_PERSONAL_API_KEY-missing-boundary",
            "POSTHOG_PERSONAL_API_KEY-wrong-boundary",
            "POSTHOG_PERSONAL_API_KEY-production-build-boundary",
            "POSTHOG_PERSONAL_API_KEY-encryption-phase",
            "POSTHOG_PROJECT_ID-missing-identity",
            "POSTHOG_PROJECT_ID-production-build-boundary",
            "unrelated-frontend-boundary",
            "cross-phase-identities",
        }
        for name, evidence in mutations:
            if name not in full_generation_names:
                continue
            with self.subTest(name=name, path="generate"):
                self._assert_full_generation_rejects(
                    evidence,
                    "frontend broker semantic mismatch",
                )


class ConnectionMetadataTests(unittest.TestCase):
    def test_emits_only_mysql_component_names_and_mongo_presence(self):
        import extract_connection_metadata as extractor

        canaries = [
            "MYSQL_PASSWORD_CANARY_9a18",
            "MONGO_PASSWORD_CANARY_d81e",
            "database-name-canary",
        ]
        payload = {
            "mysql": (
                "Server=db.invalid;Port=3306;Database=database-name-canary;"
                "User Id=svc;Password=MYSQL_PASSWORD_CANARY_9a18"
            ),
            "mongo": (
                "mongodb://svc:MONGO_PASSWORD_CANARY_d81e@mongo.invalid/"
                "database-name-canary?authSource=admin"
            ),
        }

        output = extractor.extract_connection_metadata(payload)
        rendered = json.dumps(output, sort_keys=True)

        self.assertEqual(
            output["mysql_components"],
            ["database", "password", "port", "server", "user"],
        )
        self.assertTrue(output["mongo_connection_present"])
        self.assertTrue(output["mongo_database_component_present"])
        for canary in canaries:
            self.assertNotIn(canary, rendered)

    def test_connection_error_never_echoes_input(self):
        import extract_connection_metadata as extractor

        canary = "CONNECTION_ERROR_CANARY_4d19"
        with self.assertRaises(ValueError) as caught:
            extractor.extract_connection_metadata({"mysql": canary})
        self.assertNotIn(canary, str(caught.exception))


class EnvFileMetadataTests(unittest.TestCase):
    def test_env_file_projection_never_emits_right_hand_content(self):
        import extract_env_key_metadata as extractor

        canary = "ENV_FILE_CANARY_726f"
        output = extractor.extract_env_metadata(
            f"PORT=3306\nPRIVATE={canary}\nEMPTY=\n",
            source_file=".env.example",
        )
        rendered = json.dumps(output, sort_keys=True)
        self.assertEqual(output["source_file"], ".env.example")
        self.assertEqual(
            [entry["name"] for entry in output["keys"]],
            ["EMPTY", "PORT", "PRIVATE"],
        )
        self.assertNotIn(canary, rendered)


class OnePasswordFieldMetadataTests(unittest.TestCase):
    def test_field_projection_omits_values_ids_and_file_paths(self):
        import extract_op_field_metadata as extractor

        canary = "OP_FIELD_CANARY_e7d2"
        item = {
            "id": "item-id-must-not-escape",
            "title": "Provider production",
            "vault": {"name": "Development", "id": "vault-id-must-not-escape"},
            "category": "API_CREDENTIAL",
            "fields": [
                {
                    "id": "secret-id",
                    "label": "API Key",
                    "type": "CONCEALED",
                    "value": canary,
                    "section": {"label": "credential"},
                }
            ],
            "files": [
                {
                    "name": "deploy_key",
                    "content_path": f"/content/{canary}",
                }
            ],
        }

        output = extractor.extract_field_metadata(item)
        rendered = json.dumps(output, sort_keys=True)

        self.assertEqual(output["item"], "Provider production")
        self.assertEqual(output["vault"], "Development")
        self.assertEqual(
            output["fields"],
            [
                {
                    "label": "API Key",
                    "field_type": "CONCEALED",
                    "purpose": None,
                    "section": "credential",
                    "value_present": True,
                }
            ],
        )
        self.assertEqual(output["files"], [{"name": "deploy_key"}])
        self.assertNotIn(canary, rendered)
        self.assertNotIn("secret-id", rendered)
        self.assertNotIn("content_path", rendered)



def classify(**overrides):
    args = {
        "repo": "example-private",
        "visibility": "private",
        "workflow_path": ".github/workflows/ci.yml",
        "job_id": "test",
        "runs_on": "blacksmith-2vcpu-ubuntu-2404",
        "resolved_runs_on": ["blacksmith-2vcpu-ubuntu-2404"],
        "env_name": "",
        "text": "steps: []\n",
        "uses": ["actions/checkout@v4"],
        "triggers": ["push"],
        "secrets": [],
    }
    args.update(overrides)
    return aw.classify_job(**args)


class ScheduledSecretRoutingTests(unittest.TestCase):
    def test_public_production_publish_secret_routes_to_deploy_vault(self):
        classified = classify(
            repo="Ken-SRE",
            visibility="public",
            workflow_path=".github/workflows/python-publish.yml",
            job_id="deploy",
            triggers=["release"],
            secrets=["PYPI_API_TOKEN"],
            text="pypa/gh-action-pypi-publish",
        )
        self.assertTrue(classified["production_impact"])
        self.assertEqual(classified["target_runner_class"], "public-github-hosted")
        entry = aw.apply_secret_consumer(
            aw.secret_authority(
                "PYPI_API_TOKEN",
                "Ken-SRE",
                {"org": [], "repo": ["PYPI_API_TOKEN"], "environment": []},
                ".github/workflows/python-publish.yml",
            ),
            classified,
        )
        self.assertEqual(entry["target_vault"], "Ken Deploy Production")
        self.assertEqual(entry["classification"], "deployment-production")
        self.assertEqual(entry["consumer"], "public-github-hosted")

    def test_ken_agents_eval_weekly_goes_to_ken_deploy(self):
        result = classify(
            repo="ken-agents",
            workflow_path=".github/workflows/eval-weekly.yml",
            job_id="scoreboard",
            triggers=["schedule", "workflow_dispatch"],
            secrets=["LANGFUSE_PUBLIC_KEY", "LANGFUSE_SECRET_KEY", "CLICKUP_API_TOKEN"],
            text="uses langfuse clickup api\n",
        )
        self.assertTrue(str(result["target_runner_class"]).startswith("ken-deploy"))
        self.assertNotIn("ken-ci", result["target_runner_class"])
        self.assertFalse(result["deploys_or_publishes"])

    def test_ken_agents_prompt_parity_goes_to_ken_deploy(self):
        result = classify(
            repo="ken-agents",
            workflow_path=".github/workflows/prompt-parity.yml",
            job_id="parity",
            triggers=["schedule", "workflow_dispatch"],
            secrets=["LANGFUSE_PUBLIC_KEY", "LANGFUSE_SECRET_KEY"],
            text="langfuse prompt parity\n",
        )
        self.assertTrue(str(result["target_runner_class"]).startswith("ken-deploy"))
        self.assertFalse(result["deploys_or_publishes"])

    def test_ken_ai_mcp_contract_drift_goes_to_ken_deploy(self):
        result = classify(
            repo="ken-ai-mcp",
            workflow_path=".github/workflows/contracts-drift.yml",
            job_id="drift-check",
            triggers=["schedule", "workflow_dispatch"],
            secrets=["KEN_BACKEND_READ_TOKEN"],
            text="compare live backend contracts\n",
        )
        self.assertTrue(str(result["target_runner_class"]).startswith("ken-deploy"))
        self.assertFalse(result["deploys_or_publishes"])

    def test_ken_website_beehiiv_sync_goes_to_ken_deploy(self):
        result = classify(
            repo="ken-website",
            workflow_path=".github/workflows/beehiiv-sync.yml",
            job_id="sync",
            triggers=["schedule", "schedule:0 7 * * *", "workflow_dispatch"],
            secrets=["OP_SERVICE_ACCOUNT_TOKEN"],
            text="1password load-secrets-action beehiiv sync\n",
        )
        self.assertEqual(result["target_runner_class"], "ken-deploy-production")
        self.assertTrue(result["production_impact"])
        self.assertFalse(result["deploys_or_publishes"])

    def test_frontend_production_image_build_is_pinned_to_deploy_boundary(self):
        result = classify(
            repo="ken-frontend",
            workflow_path=".github/workflows/deploy.yml",
            job_id="build-image",
            env_name="",
            runs_on="blacksmith-4vcpu-ubuntu-2404",
            secrets=[
                "GITHUB_TOKEN",
                "NEXT_SERVER_ACTIONS_ENCRYPTION_KEY",
            ],
            uses=["docker/build-push-action@v6"],
            text="docker/build-push-action push ghcr production image",
        )
        self.assertEqual(result["classification"], "production-build")
        self.assertEqual(result["target_runner_class"], "ken-deploy-production")
        self.assertEqual(result["secret_class"], "deploy-production")
        self.assertTrue(result["production_impact"])
        self.assertIn("FIXED_PRODUCTION_BUILD_BOUNDARY", result["flags"])

    def test_frontend_production_key_cannot_join_ci_coordinate(self):
        existing = {
            "repository": "ken-frontend",
            "workflow": ".github/workflows/deploy.yml",
            "github_secret_name": "NEXT_SERVER_ACTIONS_ENCRYPTION_KEY",
            "target_vault": "Ken Deploy Production",
            "consumer": "ken-deploy-production",
            "classification": "deployment-production",
        }
        candidate = dict(existing)
        candidate.update(
            {
                "target_vault": "Ken CI Runtime",
                "consumer": "ken-ci-heavy",
                "classification": "ci-nonproduction",
            }
        )
        with self.assertRaisesRegex(ValueError, "trust-boundary collision"):
            aw.assert_secret_trust_compatible(existing, candidate, "build-image")

    def test_op_bootstrap_token_never_targets_ken_ci(self):
        result = classify(
            repo="ken-website",
            workflow_path=".github/workflows/ci.yml",
            job_id="sync",
            triggers=["push"],
            secrets=["OP_SERVICE_ACCOUNT_TOKEN"],
            text="OP_SERVICE_ACCOUNT_TOKEN beehiiv\n",
        )
        self.assertNotIn("ken-ci", result["target_runner_class"])
        self.assertTrue(str(result["target_runner_class"]).startswith("ken-deploy"))


class GithubTokenPolicyTests(unittest.TestCase):
    def test_github_token_is_never_assigned_a_vault(self):
        entry = aw.secret_authority("GITHUB_TOKEN", "ken-cms", {"org": [], "repo": [], "environment": []}, ".github/workflows/deploy.yml")
        entry = aw.apply_secret_consumer(entry, {"secret_class": "deploy-production", "production_impact": True, "target_runner_class": "ken-deploy-production"})
        self.assertIsNone(entry["target_vault"])
        self.assertFalse(entry["rotation_required"])
        self.assertNotEqual(entry.get("consumer"), "ken-deploy-production")
        self.assertIsNone(entry.get("consumer"))

    def test_generate_never_overrides_github_token_vault(self):
        with tempfile.TemporaryDirectory() as tmp:
            collect = Path(tmp) / "collect"
            out = Path(tmp) / "out"
            self._write_minimal_collect(collect, include_github_token=True)
            aw.generate(collect, out)
            import yaml

            data = yaml.safe_load((out / "secrets.yaml").read_text())
            tokens = [e for e in data["entries"] if e["github_secret_name"] == "GITHUB_TOKEN"]
            self.assertGreaterEqual(len(tokens), 1)
            for entry in tokens:
                self.assertIsNone(entry["target_vault"])
                self.assertFalse(entry["rotation_required"])
                self.assertIsNone(entry.get("consumer"))

    def _write_minimal_collect(self, collect: Path, include_github_token: bool = False) -> None:
        collect.mkdir(parents=True)
        (collect / "collection-meta.json").write_text(json.dumps({"collected_at": "2026-08-19T16:00:00Z"}))
        (collect / "org.json").write_text(json.dumps({"login": "Ken-Technology", "plan": {"name": "free"}}))
        (collect / "repos.json").write_text(json.dumps([{"name": "ken-cms", "visibility": "PRIVATE", "isArchived": False, "defaultBranchRef": {"name": "main"}}]))
        (collect / "runners.json").write_text(json.dumps({"total_count": 0, "runners": []}))
        (collect / "runner-groups.json").write_text(json.dumps({"runner_groups": []}))
        (collect / "org-secrets.json").write_text("[]")
        (collect / "org-variables.json").write_text("[]")
        repo = collect / "repos" / "ken-cms"
        (repo / "workflows").mkdir(parents=True)
        (repo / "meta.json").write_text(json.dumps({"name": "ken-cms", "visibility": "private", "default_branch": "main", "default_sha": "abc"}))
        (repo / "secrets.json").write_text("[]")
        token_env = (
            "        env:\n          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}\n" if include_github_token else ""
        )
        (repo / "workflows" / "deploy.yml").write_text(
            "on: [push]\njobs:\n  deploy:\n    runs-on: blacksmith-2vcpu-ubuntu-2404\n    steps:\n"
            "      - uses: appleboy/ssh-action@v1\n"
            f"{token_env}"
            "        with:\n          host: ${{ secrets.DEPLOY_HOST }}\n"
        )


class EnvironmentProtectionTests(unittest.TestCase):
    def test_unknown_protection_stays_null(self):
        missing = aw.env_protection(None)
        self.assertIsNone(missing["prevent_self_review"])
        self.assertIsNone(missing["wait_timer"])
        self.assertIsNone(missing["deployment_branches"])
        empty = aw.env_protection({"name": "Preprod", "protection_rules": [], "deployment_branch_policy": None})
        self.assertIsNone(empty["prevent_self_review"])
        self.assertIsNone(empty["wait_timer"])
        self.assertIsNone(empty["deployment_branches"])
        self.assertEqual(empty["required_reviewers"], [])

    def test_prevent_self_review_from_required_reviewer_rule(self):
        record = {
            "name": "production",
            "protection_rules": [
                {
                    "type": "required_reviewers",
                    "prevent_self_review": True,
                    "reviewers": [{"type": "User", "reviewer": {"login": "other-human"}}],
                }
            ],
        }
        got = aw.env_protection(record)
        self.assertTrue(got["prevent_self_review"])
        self.assertEqual(got["required_reviewers"], ["other-human"])
        self.assertTrue(got["external_hard_stop"])

    def test_custom_deployment_branch_envelope_is_normalized(self):
        envelope = {
            "total_count": 2,
            "branch_policies": [
                {"id": 361199, "node_id": "MDE2OkRlcGxveW1lbnRCcmFuY2hQb2xpY3kzNjExOTk=", "name": "main"},
                {"id": 361200, "node_id": "MDE2OkRlcGxveW1lbnRCcmFuY2hQb2xpY3kzNjEyMDA=", "name": "release/*"},
            ],
        }
        record = {
            "name": "production",
            "deployment_branch_policy": {"protected_branches": False, "custom_branch_policies": True},
            "deployment_branch_policies": envelope,
        }
        got = aw.env_protection(record)
        self.assertEqual(
            got["deployment_branches"],
            [
                {"id": 361199, "node_id": "MDE2OkRlcGxveW1lbnRCcmFuY2hQb2xpY3kzNjExOTk=", "name": "main"},
                {"id": 361200, "node_id": "MDE2OkRlcGxveW1lbnRCcmFuY2hQb2xpY3kzNjEyMDA=", "name": "release/*"},
            ],
        )
        self.assertNotIn("total_count", got["deployment_branches"][0] if got["deployment_branches"] else {})
        self.assertIsNone(
            aw.env_protection(
                {
                    "name": "production",
                    "deployment_branch_policy": {"protected_branches": False, "custom_branch_policies": True},
                }
            )["deployment_branches"]
        )

    def test_branches_json_fixture_uses_github_envelope(self):
        import yaml

        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            aw.generate(FIXTURE_DIR, out)
            repos = yaml.safe_load((out / "repositories.yaml").read_text())
            env_job = next(
                job
                for r in repos["repositories"]
                for wf in r["workflows"]
                for job in wf["jobs"]
                if job.get("environment") and job["environment"].get("name") == "production-protected"
            )
            branches = env_job["environment"]["deployment_branches"]
            self.assertIsInstance(branches, list)
            self.assertEqual(branches[0]["name"], "main")
            self.assertEqual(branches[0]["id"], 361199)
            self.assertTrue(branches[0]["node_id"])
            self.assertNotIn("total_count", branches[0])
            self.assertNotIn("branch_policies", env_job["environment"])


class BillingEvidenceTests(unittest.TestCase):
    def test_billing_fields_are_independent_and_not_invented(self):
        evidence = {
            "previous_month": {
                "amount_usd": 130,
                "source": "task-2-brief planning baseline",
                "captured_at": "2026-08-19T16:05:06Z",
                "status": "unverified-planning-baseline",
            },
            "current_unbilled": {
                "amount_usd": None,
                "source": None,
                "captured_at": "2026-08-19T16:27:01Z",
                "status": "unavailable",
            },
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "blacksmith-billing.json"
            path.write_text(json.dumps(evidence))
            loaded = aw.load_billing_evidence(path)
        self.assertEqual(loaded["previous_month"]["amount_usd"], 130)
        self.assertIsNone(loaded["current_unbilled"]["amount_usd"])
        self.assertEqual(loaded["current_unbilled"]["status"], "unavailable")
        self.assertNotEqual(loaded["previous_month"]["status"], loaded["current_unbilled"]["status"])

    def test_missing_billing_evidence_does_not_invent_current_amount(self):
        loaded = aw.load_billing_evidence(Path("/tmp/does-not-exist-blacksmith-billing.json"))
        self.assertIsNone(loaded["previous_month"]["amount_usd"])
        self.assertIsNone(loaded["current_unbilled"]["amount_usd"])
        self.assertEqual(loaded["current_unbilled"]["status"], "unavailable")


class RunnerInventoryTests(unittest.TestCase):
    def test_summarize_runners_retains_per_runner_names(self):
        raw = {
            "total_count": 2,
            "runners": [
                {
                    "name": "blacksmith-aaa-2vcpu",
                    "status": "offline",
                    "busy": False,
                    "labels": [{"name": "linux"}, {"name": "blacksmith-2vcpu-ubuntu-2404"}],
                },
                {
                    "name": "blacksmith-bbb-4vcpu",
                    "status": "offline",
                    "busy": False,
                    "labels": [{"name": "linux"}, {"name": "blacksmith-4vcpu-ubuntu-2404"}],
                },
            ],
        }
        groups = {"runner_groups": [{"id": 3, "name": "Blacksmith runners fixture"}]}
        summary = aw.summarize_runners(raw, "2026-08-19T16:27:01Z", groups)
        names = [item["name"] for item in summary["runners"]]
        self.assertEqual(names, ["blacksmith-aaa-2vcpu", "blacksmith-bbb-4vcpu"])
        self.assertEqual(summary["runners"][0]["status"], "offline")
        self.assertFalse(summary["runners"][0]["busy"])
        self.assertIn("blacksmith-2vcpu-ubuntu-2404", summary["runners"][0]["labels"])
        self.assertEqual(summary["runners"][0]["captured_time"], "2026-08-19T16:27:01Z")
        self.assertTrue(summary["runners"][0]["group"])


class StructuredTargetTests(unittest.TestCase):
    def test_ssh_variable_host_is_a_structured_target(self):
        target = aw.structured_target(
            job_id="deploy",
            workflow_path=".github/workflows/deploy-production.yml",
            text="host: ${{ vars.DEPLOY_HOST }}\nkey: ${{ secrets.DEPLOY_SSH_KEY }}\n",
            uses=["appleboy/ssh-action@v1"],
            secret_names=["DEPLOY_USER", "DEPLOY_SSH_KEY"],
            variable_names=["DEPLOY_HOST", "DEPLOY_PORT", "DEPLOY_PATH", "ANALYTICS_URL"],
        )
        self.assertIn("appleboy/ssh-action", " ".join(target["action_types"]))
        self.assertIn("DEPLOY_HOST", target["host_variable_names"])
        self.assertTrue(target["endpoint_expressions"] or target["host_variable_names"])
        self.assertIsNone(target.get("unknown_reason"))

    def test_registry_publish_records_package_target(self):
        target = aw.structured_target(
            job_id="publish",
            workflow_path=".github/workflows/publish-rust-sdk.yml",
            text="cargo publish\n",
            uses=["dtolnay/rust-toolchain@631a55b12751854ce901bb631d5902ceb48146f7"],
            secret_names=["CRATES_IO_TOKEN"],
            variable_names=[],
        )
        self.assertEqual(target["registry_or_package"], "crates.io")
        self.assertIsNone(target.get("unknown_reason"))

    def test_deploy_job_without_signal_has_unknown_reason(self):
        target = aw.structured_target(
            job_id="no_stack_yet",
            workflow_path=".github/workflows/deploy-production.yml",
            text="echo skip until stack exists\n",
            uses=[],
            secret_names=[],
            variable_names=[],
        )
        self.assertTrue(target.get("unknown_reason"))

    def test_ken_analytics_validate_is_standard_ci(self):
        result = classify(
            repo="ken-analytics",
            workflow_path=".github/workflows/deploy-production.yml",
            job_id="validate",
            triggers=["push", "workflow_dispatch"],
            secrets=[],
            uses=["actions/checkout@v4"],
            text="Validate repository config\nif [ -f docker-compose.yml ]; then echo has_stack=true; fi\n",
        )
        self.assertEqual(result["classification"], "standard-ci")
        self.assertEqual(result["target_runner_class"], "ken-ci-standard")
        self.assertFalse(result["deploys_or_publishes"])


class PrivateHostedFlagTests(unittest.TestCase):
    def test_private_ubuntu_latest_is_flagged(self):
        result = classify(
            runs_on="ubuntu-latest",
            resolved_runs_on=["ubuntu-latest"],
            workflow_path=".github/workflows/ci.yml",
        )
        self.assertIn("PRIVATE_UBUNTU_HOSTED", result["flags"])

    def test_blacksmith_ubuntu_label_is_not_private_hosted_flag(self):
        result = classify(runs_on="blacksmith-2vcpu-ubuntu-2404")
        self.assertNotIn("PRIVATE_UBUNTU_HOSTED", result["flags"])


class RegenerationAndManifestTests(unittest.TestCase):
    def test_offline_fixture_generation_is_semantically_stable(self):
        with tempfile.TemporaryDirectory() as tmp:
            first = Path(tmp) / "a"
            second = Path(tmp) / "b"
            aw.generate(FIXTURE_DIR, first)
            aw.generate(FIXTURE_DIR, second)
            import yaml

            a = yaml.safe_load((first / "repositories.yaml").read_text())
            b = yaml.safe_load((second / "repositories.yaml").read_text())
            self.assertEqual(self._semantic(a), self._semantic(b))
            analytics = next(r for r in a["repositories"] if r["name"] == "example-private")
            validate = None
            for wf in analytics["workflows"]:
                for job in wf["jobs"]:
                    if job["id"] == "validate":
                        validate = job
            if validate:
                self.assertEqual(validate["classification"], "standard-ci")

            first_jobs = {
                (r["name"], wf["path"], job["id"], job["target_runner_class"], job["classification"])
                for r in a["repositories"]
                for wf in r["workflows"]
                for job in wf["jobs"]
            }
            self.assertIn(
                ("example-private", ".github/workflows/eval-weekly.yml", "scoreboard"),
                {(n, p, j) for n, p, j, _, _ in first_jobs},
            )
            scoreboard = next(item for item in first_jobs if item[2] == "scoreboard")
            self.assertTrue(scoreboard[3].startswith("ken-deploy"))

            beehiiv = next(item for item in first_jobs if item[2] == "sync")
            self.assertEqual(beehiiv[3], "ken-deploy-production")

            deploy = next(
                job
                for r in a["repositories"]
                for wf in r["workflows"]
                for job in wf["jobs"]
                if r["name"] == "example-private" and job["id"] == "deploy"
            )
            self.assertTrue(deploy.get("target") or deploy.get("target_hints"))
            if deploy.get("target"):
                self.assertTrue(
                    deploy["target"].get("host_secret_names")
                    or deploy["target"].get("host_variable_names")
                    or deploy["target"].get("unknown_reason")
                )

            env_job = next(
                job
                for r in a["repositories"]
                for wf in r["workflows"]
                for job in wf["jobs"]
                if job.get("environment") and job["environment"].get("name") == "production-protected"
            )
            self.assertTrue(env_job["environment"]["prevent_self_review"])
            self.assertEqual(env_job["environment"]["required_reviewers"], ["other-human"])
            self.assertIsInstance(env_job["environment"]["deployment_branches"], list)

            runners = yaml.safe_load((first / "runners.yaml").read_text())
            self.assertGreaterEqual(len(runners["current"].get("runners") or []), 1)
            self.assertIn("previous_month", runners["billing"])
            self.assertIn("current_unbilled", runners["billing"])
            self.assertIsNone(runners["billing"]["current_unbilled"]["amount_usd"])

            secrets = yaml.safe_load((first / "secrets.yaml").read_text())
            for entry in secrets["entries"]:
                if entry["github_secret_name"] == "GITHUB_TOKEN":
                    self.assertIsNone(entry["target_vault"])
                    self.assertFalse(entry["rotation_required"])
                    self.assertIsNone(entry.get("consumer"))
                if entry["github_secret_name"] == "OP_SERVICE_ACCOUNT_TOKEN":
                    self.assertNotIn("ken-ci", str(entry.get("consumer") or ""))

            manifest = yaml.safe_load((first / "input-manifest.yaml").read_text())
            self.assertTrue(manifest["input_hash"])
            self.assertGreaterEqual(len(manifest["repositories"]), 1)
            for repo in manifest["repositories"]:
                self.assertIn("default_sha", repo)
                for wf in repo.get("workflows") or []:
                    self.assertTrue(wf.get("path"))
                    self.assertTrue(wf.get("sha"))

            second_manifest = yaml.safe_load((second / "input-manifest.yaml").read_text())
            self.assertEqual(manifest["input_hash"], second_manifest["input_hash"])
            self.assertJobsMatchClassifier(FIXTURE_DIR, a)
            expected = json.loads((FIXTURE_DIR / "expected-digests.json").read_text())
            self.assertEqual(aw.semantic_output_digest(first), expected["semantic_digest"])
            self.assertEqual(manifest["input_hash"], expected["input_hash"])

    def test_non_workflow_input_change_changes_input_hash(self):
        with tempfile.TemporaryDirectory() as tmp:
            collect = Path(tmp) / "collect"
            out_a = Path(tmp) / "a"
            out_b = Path(tmp) / "b"
            self._copy_fixture(collect)
            aw.generate(collect, out_a)
            hosts = json.loads((collect / "hosts.json").read_text())
            hosts["devws"] = {"kvm": False, "note": "hash-probe"}
            (collect / "hosts.json").write_text(json.dumps(hosts))
            aw.generate(collect, out_b)
            import yaml

            hash_a = yaml.safe_load((out_a / "input-manifest.yaml").read_text())["input_hash"]
            hash_b = yaml.safe_load((out_b / "input-manifest.yaml").read_text())["input_hash"]
            self.assertNotEqual(hash_a, hash_b)

    def test_onepassword_vaults_change_hash_and_secret_inventory(self):
        with tempfile.TemporaryDirectory() as tmp:
            collect = Path(tmp) / "collect"
            out_a = Path(tmp) / "a"
            out_b = Path(tmp) / "b"
            self._copy_fixture(collect)
            aw.generate(collect, out_a)
            (collect / "onepassword-vaults.json").write_text(
                json.dumps(["Development", "New Vault"])
            )
            aw.generate(collect, out_b)
            import yaml

            hash_a = yaml.safe_load((out_a / "input-manifest.yaml").read_text())[
                "input_hash"
            ]
            hash_b = yaml.safe_load((out_b / "input-manifest.yaml").read_text())[
                "input_hash"
            ]
            self.assertNotEqual(hash_a, hash_b)
            secrets_b = yaml.safe_load((out_b / "secrets.yaml").read_text())
            self.assertEqual(
                secrets_b["onepassword_visible_vaults"], ["Development", "New Vault"]
            )
            secrets_a = yaml.safe_load((out_a / "secrets.yaml").read_text())
            self.assertNotEqual(
                secrets_a["onepassword_visible_vaults"],
                secrets_b["onepassword_visible_vaults"],
            )

    def test_loader_reads_each_registered_source_once(self):
        reads: dict[Path, int] = {}
        original = Path.read_text

        def tracked_read(path: Path, *args, **kwargs):
            resolved = path.resolve()
            if resolved.is_relative_to(FIXTURE_DIR.resolve()):
                reads[resolved] = reads.get(resolved, 0) + 1
            return original(path, *args, **kwargs)

        with mock.patch.object(Path, "read_text", tracked_read):
            loaded = aw.load_inventory_inputs(FIXTURE_DIR)

        self.assertTrue(reads)
        self.assertEqual(set(reads.values()), {1})
        self.assertEqual(loaded.source_kinds, frozenset(aw.REGISTERED_INPUT_KINDS))
        serialized = aw._stable_json(loaded.data)
        self.assertNotIn(str(FIXTURE_DIR.resolve()), serialized)
        for generated_name in ("repositories.yaml", "runners.yaml", "secrets.yaml", "input-manifest.yaml"):
            self.assertNotIn(generated_name, serialized)

    def test_each_registered_non_workflow_input_changes_hash(self):
        mutations = {
            "org": (
                "org.json",
                {"login": "Ken-Technology", "plan": {"name": "team"}, "id": 1},
            ),
            "repos_index": (
                "repos.json",
                [
                    {
                        "name": "example-private",
                        "visibility": "PRIVATE",
                        "isArchived": False,
                        "defaultBranchRef": {"name": "trunk"},
                    }
                ],
            ),
            "runners": ("runners.json", {"total_count": 0, "runners": []}),
            "runner_groups": (
                "runner-groups.json",
                {"total_count": 1, "runner_groups": [{"id": 9, "name": "Probe"}]},
            ),
            "org_secret_names": ("org-secrets.json", [{"name": "PROBE_SECRET"}]),
            "org_variable_names": ("org-variables.json", [{"name": "PROBE_VARIABLE"}]),
            "budgets": (
                "budgets.json",
                {"actions_overage_budget_usd": 7, "prevent_further_usage": False},
            ),
            "billing": (
                "blacksmith-billing.json",
                {
                    "previous_month": {"amount_usd": 131, "status": "captured"},
                    "current_unbilled": {"amount_usd": None, "status": "unavailable"},
                },
            ),
            "hosts": ("hosts.json", {"available": False, "note": "probe"}),
            "grok_runners": (
                "grok-runners.json",
                {"count": 0, "names": [], "unchanged": True},
            ),
            "worldstream_runners": (
                "worldstream-runners.json",
                {"count": 9, "unchanged_until_teardown_gate": True},
            ),
            "onepassword_vaults": ("onepassword-vaults.json", ["Development", "Probe"]),
            "authority_evidence": (
                "authority-evidence.json",
                {
                    "schema_version": 2,
                    "evidence_id": "probe",
                    "policy": "value-free probe",
                    "sources": {},
                    "mappings": [],
                    "unresolved_annotations": [],
                    "secretless_migrations": [],
                    "workflow_variable_migrations": [],
                    "direct_onepassword_mappings": [],
                    "broker_actions": [],
                    "unresolved_observations": [],
                },
            ),
            "op_env_key_metadata": (
                "op-env-key-metadata.json",
                {"schema_version": 1, "items": [{"item": "probe", "keys": []}]},
            ),
            "op_field_metadata": (
                "op-field-metadata.json",
                {"schema_version": 1, "items": [{"item": "probe", "fields": []}]},
            ),
            "worldstream_key_metadata": (
                "worldstream-key-metadata.json",
                {"schema_version": 1, "keys": [{"key_path": "probe"}]},
            ),
            "connection_structure": (
                "connection-structure.json",
                {"schema_version": 1, "mysql_components": ["probe"]},
            ),
            "collection_meta": (
                "collection-meta.json",
                {"collected_at": "2026-08-19T17:00:00Z", "mode": "offline-fixture"},
            ),
            "repository_meta": (
                "repos/example-private/meta.json",
                {
                    "name": "example-private",
                    "visibility": "private",
                    "default_branch": "main",
                    "default_sha": "b" * 40,
                },
            ),
            "repository_tree": (
                "repos/example-private/tree.json",
                {"tree": [{"path": ".github/workflows/ci.yml", "sha": "c" * 40}]},
            ),
            "repository_secret_names": (
                "repos/example-private/secrets.json",
                [{"name": "PROBE_SECRET"}],
            ),
            "repository_variable_names": (
                "repos/example-private/variables.json",
                [{"name": "PROBE_VARIABLE"}],
            ),
            "environment": (
                "repos/example-private/environments/Preprod.json",
                {
                    "name": "Preprod",
                    "protection_rules": [{"type": "wait_timer", "wait_timer": 9}],
                },
            ),
            "environment_branch_policies": (
                "repos/example-private/environments/production-protected.branches.json",
                {
                    "total_count": 1,
                    "branch_policies": [
                        {"id": 7, "node_id": "probe", "name": "probe/*"}
                    ],
                },
            ),
            "environment_secret_names": (
                "repos/example-private/environment-secrets/production-protected.json",
                [{"name": "PROBE_ENV_SECRET"}],
            ),
        }
        self.assertEqual(set(mutations), set(aw.REGISTERED_NON_WORKFLOW_INPUT_KINDS))
        baseline = aw.hash_inventory_inputs(aw.load_inventory_inputs(FIXTURE_DIR))
        output_affecting = set(mutations) - {
            "repository_variable_names",
            "environment_secret_names",
            "op_env_key_metadata",
            "op_field_metadata",
            "worldstream_key_metadata",
            "connection_structure",
        }

        def semantic_without_hash(output: Path) -> str:
            import yaml

            documents = {}
            for name in (
                "repositories.yaml",
                "runners.yaml",
                "secrets.yaml",
                "input-manifest.yaml",
            ):
                document = yaml.safe_load((output / name).read_text())
                document.pop("generated_at", None)
                document.pop("input_hash", None)
                documents[name] = document
            return json.dumps(documents, sort_keys=True, separators=(",", ":"))

        with tempfile.TemporaryDirectory() as tmp:
            temp_root = Path(tmp)
            baseline_output = temp_root / "baseline-output"
            aw.generate(FIXTURE_DIR, baseline_output)
            baseline_semantic = semantic_without_hash(baseline_output)
            for kind, (relative_path, payload) in mutations.items():
                collect = temp_root / kind / "collect"
                output = temp_root / kind / "output"
                self._copy_fixture(collect)
                path = collect / relative_path
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(json.dumps(payload))
                changed = aw.hash_inventory_inputs(aw.load_inventory_inputs(collect))
                with self.subTest(kind=kind):
                    self.assertNotEqual(baseline, changed)
                    if kind in output_affecting:
                        aw.generate(collect, output)
                        self.assertNotEqual(
                            baseline_semantic, semantic_without_hash(output)
                        )

    def test_generation_consumes_loaded_inputs_without_source_reads(self):
        loaded = aw.load_inventory_inputs(FIXTURE_DIR)
        with tempfile.TemporaryDirectory() as tmp:
            with (
                mock.patch.object(
                    aw,
                    "load_json",
                    side_effect=AssertionError("unexpected source read"),
                ),
                mock.patch.object(
                    Path,
                    "read_text",
                    side_effect=AssertionError("unexpected source read"),
                ),
            ):
                aw.generate_from_inputs(loaded, Path(tmp))

    def test_missing_billing_is_explicitly_unavailable_without_repository_fallback(
        self,
    ):
        with tempfile.TemporaryDirectory() as tmp:
            collect = Path(tmp) / "collect"
            output = Path(tmp) / "output"
            self._copy_fixture(collect)
            (collect / "blacksmith-billing.json").unlink()
            aw.generate(collect, output)
            import yaml

            runners = yaml.safe_load((output / "runners.yaml").read_text())
            self.assertIsNone(runners["billing"]["previous_month"]["amount_usd"])
            self.assertEqual(
                runners["billing"]["previous_month"]["status"], "unavailable"
            )
            self.assertIsNone(runners["billing"]["current_unbilled"]["amount_usd"])

    def test_no_stack_yet_is_not_a_deploy(self):
        result = classify(
            repo="ken-analytics",
            workflow_path=".github/workflows/deploy-production.yml",
            job_id="no_stack_yet",
            triggers=["push", "workflow_dispatch"],
            secrets=[],
            uses=[],
            text='echo "docker-compose.yml is not present yet."\necho "production deploy is intentionally skipped"\n',
        )
        self.assertEqual(result["classification"], "standard-ci")
        self.assertEqual(result["target_runner_class"], "ken-ci-standard")
        self.assertFalse(result["deploys_or_publishes"])

    def _copy_fixture(self, dest: Path) -> None:
        import shutil

        shutil.copytree(FIXTURE_DIR, dest)

    def assertJobsMatchClassifier(self, collect_dir: Path, repos_doc: dict) -> None:
        mismatches = aw.jobs_diverging_from_classifier(collect_dir, repos_doc)
        self.assertEqual(mismatches, [])

    def _semantic(self, doc: dict) -> dict:
        copy = json.loads(json.dumps(doc))
        copy.pop("generated_at", None)
        return copy


class PrivateUbuntuInventoryAssertionTests(unittest.TestCase):
    def test_private_hosted_flag_check_fails_when_missing(self):
        job = {
            "id": "ci",
            "runs_on": "ubuntu-latest",
            "flags": [],
            "classification": "standard-ci",
            "target_runner_class": "ken-ci-standard",
        }
        with self.assertRaises(AssertionError):
            aw.assert_private_hosted_flag({"name": "private-repo", "visibility": "private", "workflows": [{"path": "ci.yml", "jobs": [job]}]})


class Task6SecretMapTests(unittest.TestCase):
    def test_secret_references_only_parse_inside_actions_expressions(self):
        workflow = """
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: |
          cp generated-secrets.json artifact-secrets.json
          ./scripts/export-secrets.sh
          echo '${{ secrets.REAL_TOKEN }}'
"""
        parsed = aw.parse_workflow(".github/workflows/test.yml", workflow)
        self.assertEqual(parsed["secret_names"], ["REAL_TOKEN"])
        self.assertEqual(parsed["jobs"][0]["secret_names"], ["REAL_TOKEN"])

    def test_commented_out_jobs_do_not_create_workflow_secret_references(self):
        workflow = """
on: push
jobs:
  active:
    runs-on: ubuntu-latest
    env:
      ACTIVE_TOKEN: ${{ secrets.ACTIVE_TOKEN }}
    steps:
      - run: true
  # disabled:
  #   runs-on: ubuntu-latest
  #   env:
  #     RETIRED_TOKEN: ${{ secrets.RETIRED_TOKEN }}
"""
        parsed = aw.parse_workflow(".github/workflows/test.yml", workflow)
        self.assertEqual(parsed["secret_names"], ["ACTIVE_TOKEN"])
        self.assertEqual(parsed["jobs"][0]["secret_names"], ["ACTIVE_TOKEN"])

    def test_active_ken_scraping_workflow_env_references_are_inherited(self):
        references = {
            "eval-prod.yml": [
                "EVAL_API_URL",
                "EVAL_API_KEY",
                "EVAL_BENCHMARK_EXPERIMENT_ID",
            ],
            "publish-js-sdk.yml": ["TEST_API_KEY"],
            "test-js-sdk.yml": ["IDMUX_URL"],
        }
        self.assertEqual(sum(len(names) for names in references.values()), 5)
        for workflow_name, names in references.items():
            env = "\n".join(
                f"  {name}: ${{{{ secrets.{name} }}}}" for name in names
            )
            workflow = f"""
on: push
env:
{env}
jobs:
  consuming-job:
    runs-on: blacksmith-4vcpu-ubuntu-2404
    steps:
      - run: npm test
"""
            parsed = aw.parse_workflow(
                f".github/workflows/{workflow_name}", workflow
            )
            with self.subTest(workflow=workflow_name):
                self.assertEqual(parsed["jobs"][0]["secret_names"], names)

    def test_eval_prod_with_inherited_secrets_fails_closed_to_production(self):
        workflow = """
on: workflow_dispatch
env:
  EVAL_API_URL: ${{ secrets.EVAL_API_URL }}
  EVAL_API_KEY: ${{ secrets.EVAL_API_KEY }}
  EVAL_BENCHMARK_EXPERIMENT_ID: ${{ secrets.EVAL_BENCHMARK_EXPERIMENT_ID }}
jobs:
  run-eval-benchmark-prod:
    runs-on: blacksmith-4vcpu-ubuntu-2404
    steps:
      - run: npm run eval
"""
        parsed = aw.parse_workflow(".github/workflows/eval-prod.yml", workflow)
        job = parsed["jobs"][0]
        result = classify(
            repo="ken-scraping",
            workflow_path=".github/workflows/eval-prod.yml",
            job_id=job["id"],
            runs_on=job["runs_on"],
            resolved_runs_on=job["resolved_runs_on"],
            text=job["raw_text"],
            uses=job["uses"],
            triggers=parsed["triggers"],
            secrets=job["secret_names"],
        )
        self.assertEqual(result["target_runner_class"], "ken-deploy-production")
        self.assertEqual(result["secret_class"], "deploy-production")
        self.assertTrue(result["production_impact"])

    def test_generated_secret_map_is_canonical_and_conservatively_unresolved(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp)
            aw.generate(FIXTURE_DIR, output)
            import yaml

            raw = (output / "secrets.yaml").read_text()
            document = yaml.safe_load(raw)
            self.assertNotIn("secrets", document)
            self.assertNotIn("&id", raw)
            self.assertNotIn("*id", raw)
            required = {
                "github_secret_name",
                "repository",
                "workflow",
                "target_vault",
                "target_item",
                "target_field",
                "field_type",
                "consumer",
                "consuming_jobs",
                "source_authority",
                "source_readable",
                "authority_status",
                "rotation_required",
                "migration_action",
                "provider_rotation_steps",
                "downstream_update_steps",
                "alias_group",
                "alias_status",
            }
            for entry in document["entries"]:
                self.assertTrue(required.issubset(entry), entry)
                self.assertTrue(entry["consuming_jobs"])
                if entry["migration_action"] == "resolve-authority":
                    self.assertEqual(entry["authority_status"], "unresolved")
                    self.assertIsNone(entry["rotation_required"])
                    self.assertTrue(entry["target_item"])
                    self.assertTrue(entry["target_field"])
                    self.assertEqual(entry["field_type"], "concealed")
                    self.assertIsNone(entry["provider_rotation_steps"])
                    self.assertTrue(entry["downstream_update_steps"])
                    self.assertEqual(entry["alias_status"], "not-evaluated")

            handoff = yaml.safe_load((output / "secret-handoff.yaml").read_text())
            self.assertEqual(
                handoff["runtime_access"]["runtime_accounts"],
                [
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
            )
            writer = handoff["runtime_access"]["temporary_writer"]
            self.assertEqual(writer["role"], "task6-temporary-migration-writer")
            self.assertTrue(writer["revocation_and_readback_steps"])
            coordinates = [row["coordinate"] for row in handoff["rows"]]
            self.assertEqual(len(coordinates), len(set(coordinates)))
            for row in handoff["rows"]:
                for field in (
                    "source_to_target_steps",
                    "broker_or_workflow_cutover_steps",
                    "live_verification_steps",
                    "github_deletion_steps",
                    "revocation_steps",
                ):
                    self.assertTrue(row[field], (field, row))

    def test_special_secret_semantics_are_not_reclassified_as_app_secrets(self):
        empty = {"org": [], "repo": [], "environment": []}
        production = {
            "secret_class": "deploy-production",
            "production_impact": True,
            "target_runner_class": "ken-deploy-production",
        }
        grok = {
            "secret_class": "grok-review-unchanged",
            "production_impact": False,
            "target_runner_class": "existing-grok-review",
        }
        github = aw.apply_secret_consumer(
            aw.secret_authority("GITHUB_TOKEN", "ken-backend", empty, "ci.yml"),
            production,
        )
        grok_token = aw.apply_secret_consumer(
            aw.secret_authority("GROK_REVIEW_GH_TOKEN", "ken-backend", empty, "grok-pr-review.yml"),
            grok,
        )
        bootstrap = aw.apply_secret_consumer(
            aw.secret_authority("OP_SERVICE_ACCOUNT_TOKEN", "ken-website", empty, "deploy.yml"),
            production,
        )
        self.assertEqual(github["migration_action"], "github-provided")
        self.assertFalse(github["rotation_required"])
        self.assertEqual(grok_token["migration_action"], "preserve")
        self.assertFalse(grok_token["rotation_required"])
        self.assertNotIn("unresolved_reason", grok_token)
        self.assertNotIn("resolution_class", grok_token)
        self.assertEqual(bootstrap["migration_action"], "replace-bootstrap")
        self.assertIsNone(bootstrap["target_vault"])
        self.assertFalse(bootstrap["rotation_required"])
        self.assertNotIn("unresolved_reason", bootstrap)
        self.assertNotIn("resolution_class", bootstrap)
        self.assertTrue(bootstrap["downstream_update_steps"])

    def test_unknown_consumer_does_not_default_to_production(self):
        entry = aw.secret_authority(
            "UNRESOLVED_TOKEN",
            "ken-backend",
            {"org": [], "repo": [], "environment": []},
            "reusable.yml",
        )
        self.assertIsNone(entry["target_vault"])
        self.assertIsNone(entry["consumer"])
        self.assertEqual(entry["authority_status"], "unresolved")
        self.assertIsNone(entry["rotation_required"])

    def test_handoff_deduplicates_workflows_by_unique_trust_coordinate(self):
        classified = {
            "secret_class": "deploy-production",
            "production_impact": True,
            "target_runner_class": "ken-deploy-production",
        }
        entries = []
        for workflow, job in (("deploy.yml", "deploy"), ("scheduled.yml", "run")):
            entry = aw.apply_secret_consumer(
                aw.secret_authority(
                    "SHARED_ENDPOINT",
                    "ken-help",
                    {"org": [], "repo": [], "environment": []},
                    workflow,
                ),
                classified,
            )
            entry["consuming_jobs"] = [job]
            entries.append(entry)

        handoff = aw.build_secret_handoff(
            entries, "Ken-Technology", "2026-08-19T00:00:00Z"
        )
        self.assertEqual(len(handoff["rows"]), 1)
        self.assertEqual(
            handoff["rows"][0]["workflows"], ["deploy.yml", "scheduled.yml"]
        )
        self.assertEqual(
            handoff["rows"][0]["consuming_jobs"],
            ["deploy.yml#deploy", "scheduled.yml#run"],
        )


class Task6AuthorityEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.empty_scopes = {"org": [], "repo": [], "environment": []}
        self.production = {
            "secret_class": "deploy-production",
            "production_impact": True,
            "target_runner_class": "ken-deploy-production",
        }
        self.ci = {
            "secret_class": "ci-runtime",
            "production_impact": False,
            "target_runner_class": "ken-ci-standard",
        }

    def _entry(self, classified):
        return aw.apply_secret_consumer(
            aw.secret_authority(
                "CLERK_SECRET_KEY",
                "ken-frontend",
                self.empty_scopes,
                ".github/workflows/deploy.yml",
            ),
            classified,
        )

    def test_verified_onepassword_copy_resolves_exact_trust_scope(self):
        evidence = {
            "evidence_id": "task6-authorities-2026-08-19",
            "sources": {
                "op-clerk-production-secret": {
                    "kind": "onepassword",
                    "vault": "Development",
                    "item": "Clerk Production API",
                    "field": "CLERK_SECRET_KEY",
                    "field_type": "STRING",
                    "readable": True,
                    "value_present": True,
                }
            },
            "mappings": [
                {
                    "repository": "ken-frontend",
                    "github_secret_name": "CLERK_SECRET_KEY",
                    "target_vault": "Ken Deploy Production",
                    "classification": "credential",
                    "migration_action": "copy",
                    "authority_match": "exact-field",
                    "source_ref": "op-clerk-production-secret",
                    "downstream_update_steps": [
                        "Copy through the value-safe Task 6 handoff."
                    ],
                }
            ],
        }
        entry = aw.apply_authority_evidence(self._entry(self.production), evidence)
        self.assertEqual(entry["migration_action"], "copy")
        self.assertEqual(entry["authority_status"], "verified-readable")
        self.assertEqual(
            entry["source_authority"],
            "op://Development/Clerk Production API/CLERK_SECRET_KEY",
        )
        self.assertTrue(entry["source_readable"])
        self.assertFalse(entry["rotation_required"])
        self.assertEqual(entry["source_evidence_id"], evidence["evidence_id"])
        for field in (
            "resolution_class",
            "authority_owner",
            "unresolved_reason",
            "handoff_group",
        ):
            self.assertNotIn(field, entry)

    def test_production_mapping_does_not_resolve_ci_collision(self):
        evidence = {
            "evidence_id": "task6-authorities-2026-08-19",
            "mappings": [
                {
                    "repository": "ken-frontend",
                    "github_secret_name": "CLERK_SECRET_KEY",
                    "target_vault": "Ken Deploy Production",
                    "classification": "credential",
                    "migration_action": "copy",
                    "authority_match": "exact-field",
                    "source": {
                        "kind": "onepassword",
                        "vault": "Development",
                        "item": "Clerk Production API",
                        "field": "CLERK_SECRET_KEY",
                        "field_type": "STRING",
                        "readable": True,
                        "value_present": True,
                    },
                    "downstream_update_steps": ["Copy through the handoff."],
                }
            ],
        }
        entry = aw.apply_authority_evidence(self._entry(self.ci), evidence)
        self.assertEqual(entry["migration_action"], "resolve-authority")
        self.assertEqual(entry["authority_status"], "unresolved")
        self.assertIsNone(entry["rotation_required"])

    def test_mapping_without_explicit_trust_scope_fails_closed(self):
        evidence = {
            "evidence_id": "task6-authorities-2026-08-19",
            "mappings": [
                {
                    "repository": "ken-frontend",
                    "github_secret_name": "CLERK_SECRET_KEY",
                    "classification": "credential",
                    "migration_action": "copy",
                    "authority_match": "exact-field",
                    "source": {
                        "kind": "onepassword",
                        "vault": "Development",
                        "item": "Clerk Production API",
                        "field": "CLERK_SECRET_KEY",
                        "field_type": "CONCEALED",
                        "readable": True,
                        "value_present": True,
                    },
                    "downstream_update_steps": ["Copy through the handoff."],
                }
            ],
        }
        with self.assertRaisesRegex(ValueError, "explicit target_vault"):
            aw.apply_authority_evidence(self._entry(self.production), evidence)

    def test_move_to_variable_removes_secret_vault_target(self):
        entry = aw.apply_secret_consumer(
            aw.secret_authority(
                "NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY",
                "ken-frontend",
                self.empty_scopes,
                ".github/workflows/deploy.yml",
            ),
            self.production,
        )
        evidence = {
            "evidence_id": "task6-authorities-2026-08-19",
            "mappings": [
                {
                    "repository": "ken-frontend",
                    "github_secret_name": "NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY",
                    "target_vault": "Ken Deploy Production",
                    "classification": "identifier",
                    "migration_action": "move-to-variable",
                    "authority_match": "exact-field",
                    "source": {
                        "kind": "onepassword",
                        "vault": "Development",
                        "item": "Clerk Production API",
                        "field": "NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY",
                        "field_type": "STRING",
                        "readable": True,
                        "value_present": True,
                    },
                    "downstream_update_steps": [
                        "Create the repository Actions variable and change the workflow to vars."
                    ],
                }
            ],
        }
        moved = aw.apply_authority_evidence(entry, evidence)
        self.assertEqual(moved["migration_action"], "move-to-variable")
        self.assertIsNone(moved["target_vault"])
        self.assertEqual(
            moved["target_item"], "GitHub Actions variables:ken-frontend"
        )
        self.assertEqual(
            moved["target_field"], "NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY"
        )
        self.assertEqual(moved["field_type"], "string")

    def test_incomplete_or_value_bearing_evidence_fails_closed(self):
        evidence = {
            "evidence_id": "task6-authorities-2026-08-19",
            "mappings": [
                {
                    "repository": "ken-frontend",
                    "github_secret_name": "CLERK_SECRET_KEY",
                    "target_vault": "Ken Deploy Production",
                    "classification": "credential",
                    "migration_action": "copy",
                    "authority_match": "exact-field",
                    "source": {
                        "kind": "onepassword",
                        "vault": "Development",
                        "item": "Clerk Production API",
                        "field": "CLERK_SECRET_KEY",
                        "readable": True,
                        "value_present": True,
                        "value": "must-never-enter-evidence",
                    },
                    "downstream_update_steps": ["Copy through the handoff."],
                }
            ],
        }
        with self.assertRaisesRegex(ValueError, "value-bearing"):
            aw.apply_authority_evidence(self._entry(self.production), evidence)

    def test_structural_source_kinds_emit_value_free_authorities(self):
        cases = [
            (
                {
                    "kind": "onepassword-env-key",
                    "vault": "Development",
                    "item": "ken-frontend-env",
                    "name": "CLERK_SECRET_KEY",
                    "declared_type": "environment-string",
                    "readable": True,
                    "value_present": True,
                    "metadata_artifact": "task-6-op-env-key-metadata.json",
                },
                "op-env://Development/ken-frontend-env#CLERK_SECRET_KEY",
                "copy",
            ),
            (
                {
                    "kind": "onepassword-document",
                    "vault": "Development",
                    "item": "SSH deploy",
                    "file_name": "deploy_key",
                    "readable": True,
                    "exists": True,
                    "metadata_artifact": "task-6-op-field-metadata.json",
                },
                "op-file://Development/SSH deploy/deploy_key",
                "copy",
            ),
            (
                {
                    "kind": "onepassword-item-title-component",
                    "vault": "Development",
                    "item": "SSH deploy - user@host",
                    "component": "username",
                    "readable": True,
                    "exists": True,
                    "metadata_artifact": "task-6-op-field-metadata.json",
                },
                "op-title://Development/SSH deploy - user@host#username",
                "reconstruct",
            ),
            (
                {
                    "kind": "deployed-connection-component",
                    "host": "185.183.35.189",
                    "file": "/var/www/app/appsettings.Production.json",
                    "key_path": "ConnectionStrings.KenDb",
                    "component": "password",
                    "readable": True,
                    "exists": True,
                    "metadata_artifact": "task-6-connection-structure.json",
                },
                "deployed-component://185.183.35.189/var/www/app/appsettings.Production.json#ConnectionStrings.KenDb[password]",
                "reconstruct",
            ),
        ]
        for index, (source, expected, action) in enumerate(cases):
            with self.subTest(kind=source["kind"]):
                evidence = {
                    "evidence_id": "structural-fixture",
                    "mappings": [
                        {
                            "repository": "ken-frontend",
                            "github_secret_name": "CLERK_SECRET_KEY",
                            "target_vault": "Ken Deploy Production",
                            "classification": "credential",
                            "migration_action": action,
                            "authority_match": "reviewed-semantic",
                            "source": source,
                            "downstream_update_steps": [
                                "Use the value-blind structural handoff."
                            ],
                        }
                    ],
                }
                entry = aw.apply_authority_evidence(
                    self._entry(self.production), evidence
                )
                self.assertEqual(entry["source_authority"], expected)

    def test_generation_hashes_and_applies_authority_evidence(self):
        import shutil
        import yaml

        evidence = {
            "schema_version": 2,
            "evidence_id": "fixture-authorities",
            "policy": "value-free fixture",
            "sources": {
                "fixture-host": {
                    "kind": "evidence-key",
                    "artifact": "hosts.json",
                    "key_path": "worldstream.host",
                    "readable": True,
                    "exists": True,
                }
            },
            "mappings": [
                {
                    "mapping_id": "fixture-example-private-deploy-host",
                    "repository": "example-private",
                    "github_secret_name": "DEPLOY_HOST",
                    "target_vault": "Ken Deploy Production",
                    "classification": "identifier",
                    "migration_action": "reconstruct",
                    "authority_match": "reviewed-semantic",
                    "source_ref": "fixture-host",
                    "alias_group": None,
                    "downstream_update_steps": [
                        "Set the deployment host from the approved host inventory."
                    ],
                }
            ],
            "unresolved_annotations": [],
            "secretless_migrations": [],
            "workflow_variable_migrations": [],
            "direct_onepassword_mappings": [],
            "broker_actions": [],
            "unresolved_observations": [],
        }
        with tempfile.TemporaryDirectory() as tmp:
            collect = Path(tmp) / "collect"
            first = Path(tmp) / "first"
            second = Path(tmp) / "second"
            shutil.copytree(FIXTURE_DIR, collect)
            (collect / "authority-evidence.json").write_text(json.dumps(evidence))
            aw.generate(collect, first)
            secrets = yaml.safe_load((first / "secrets.yaml").read_text())
            hosts = [
                entry
                for entry in secrets["entries"]
                if entry["github_secret_name"] == "DEPLOY_HOST"
            ]
            self.assertTrue(hosts)
            self.assertTrue(
                all(entry["migration_action"] == "reconstruct" for entry in hosts)
            )
            first_hash = yaml.safe_load(
                (first / "input-manifest.yaml").read_text()
            )["input_hash"]
            evidence["sources"]["fixture-host"]["key_path"] = "worldstream.hostname"
            (collect / "authority-evidence.json").write_text(json.dumps(evidence))
            aw.generate(collect, second)
            second_hash = yaml.safe_load(
                (second / "input-manifest.yaml").read_text()
            )["input_hash"]
            self.assertNotEqual(first_hash, second_hash)

    def test_generation_rejects_unused_authority_mapping(self):
        import shutil

        evidence = {
            "schema_version": 2,
            "evidence_id": "fixture-authorities",
            "policy": "value-free fixture",
            "sources": {
                "fixture-secret": {
                    "kind": "onepassword",
                    "vault": "Development",
                    "item": "fixture",
                    "field": "NOT_USED_BY_ANY_WORKFLOW",
                    "field_type": "CONCEALED",
                    "readable": True,
                    "value_present": True,
                    "metadata_artifact": "fixture.json",
                }
            },
            "mappings": [
                {
                    "mapping_id": "fixture-missing-secret",
                    "repository": "example-private",
                    "github_secret_name": "NOT_USED_BY_ANY_WORKFLOW",
                    "target_vault": "Ken Deploy Production",
                    "classification": "credential",
                    "migration_action": "copy",
                    "authority_match": "exact-field",
                    "source_ref": "fixture-secret",
                    "alias_group": None,
                    "downstream_update_steps": ["Use a concealed handoff."],
                }
            ],
            "unresolved_annotations": [],
            "secretless_migrations": [],
            "workflow_variable_migrations": [],
            "direct_onepassword_mappings": [],
            "broker_actions": [],
            "unresolved_observations": [],
        }
        with tempfile.TemporaryDirectory() as tmp:
            collect = Path(tmp) / "collect"
            output = Path(tmp) / "output"
            shutil.copytree(FIXTURE_DIR, collect)
            (collect / "authority-evidence.json").write_text(json.dumps(evidence))
            with self.assertRaisesRegex(ValueError, "unused authority mappings"):
                aw.generate(collect, output)

    def test_live_collector_registers_sanitized_authority_evidence(self):
        collector = (
            ROOT / "infra/github-actions/scripts/audit-workflows.sh"
        ).read_text()
        self.assertIn(
            "inventory/evidence/task-6-authority-metadata.json", collector
        )
        self.assertIn('"${COLLECT_DIR}/authority-evidence.json"', collector)
        for name in (
            "task-6-op-env-key-metadata.json",
            "task-6-op-field-metadata.json",
            "task-6-worldstream-key-metadata.json",
            "task-6-connection-structure.json",
        ):
            self.assertIn(name, collector)

    def test_structural_authority_inputs_are_registered_for_hashing(self):
        expected = {
            "op_env_key_metadata": "op-env-key-metadata.json",
            "op_field_metadata": "op-field-metadata.json",
            "worldstream_key_metadata": "worldstream-key-metadata.json",
            "connection_structure": "connection-structure.json",
        }
        for kind, filename in expected.items():
            self.assertEqual(aw.STATIC_INPUT_SOURCE_REGISTRY[kind][0], filename)

    def test_authority_evidence_builder_emits_only_reviewed_metadata(self):
        import build_task6_authority_evidence as builder

        evidence = builder.build_evidence()
        aw._reject_value_bearing_evidence(evidence)
        self.assertEqual(evidence["schema_version"], 2)
        self.assertEqual(evidence["evidence_id"], "task6-authorities-2026-08-19")
        self.assertGreaterEqual(len(evidence["sources"]), 60)
        self.assertGreaterEqual(len(evidence["mappings"]), 75)
        self.assertTrue(
            any(
                mapping["repository"] == "ken-backend"
                and mapping["github_secret_name"] == "ANTHROPIC_API_KEY"
                and mapping["source_ref"]
                == "worldstream-scraper-api-anthropicconfiguration-apikey"
                for mapping in evidence["mappings"]
            )
        )
        self.assertTrue(
            any(
                mapping["repository"] == "ken-frontend"
                and mapping["github_secret_name"] == "CLERK_SECRET_KEY"
                and mapping["target_vault"] == "Ken Deploy Production"
                for mapping in evidence["mappings"]
            )
        )
        self.assertFalse(
            any(
                mapping["repository"] == "ken-frontend"
                and mapping["github_secret_name"] == "CLERK_SECRET_KEY"
                and mapping["target_vault"] == "Ken CI Runtime"
                and mapping["source_ref"]
                == "op-development-clerk-production-api-clerk-secret-key"
                for mapping in evidence["mappings"]
            )
        )
        edge_client_id = next(
            mapping
            for mapping in evidence["mappings"]
            if mapping["repository"] == "ken-backend"
            and mapping["github_secret_name"]
            == "CLOUDFLARE_EDGE_ACCESS_CLIENT_ID"
        )
        self.assertEqual(edge_client_id["classification"], "identifier")
        self.assertEqual(edge_client_id["migration_action"], "move-to-variable")

    def test_round_two_builder_uses_structural_sources_without_crossing_trust(self):
        import build_task6_authority_evidence as builder

        evidence = builder.build_evidence()
        mappings = evidence["mappings"]

        frontend_ci_clerk = next(
            mapping
            for mapping in mappings
            if mapping["repository"] == "ken-frontend"
            and mapping["github_secret_name"] == "CLERK_SECRET_KEY"
            and mapping["target_vault"] == "Ken CI Runtime"
        )
        self.assertEqual(
            frontend_ci_clerk["source_ref"],
            "op-development-ken-staging-secrets-clerk-secret-key",
        )
        self.assertEqual(frontend_ci_clerk["workflow"], ".github/workflows/ci.yml")

        self.assertTrue(
            any(
                mapping["repository"] == "ken-ai-mcp"
                and mapping["github_secret_name"] == "KEN_CLERK_CLIENT_SECRET"
                and mapping["source_ref"]
                == "op-development-ken-ai-mcp-clerk-oauth-client-client-secret"
                for mapping in mappings
            )
        )
        self.assertTrue(
            any(
                mapping["repository"] == "ken-backend"
                and mapping["github_secret_name"] == "BACKBLAZE_APPLICATION_KEY"
                and mapping["source_ref"]
                == "worldstream-clickevent-processor-backblazeb2-applicationkey"
                for mapping in mappings
            )
        )
        self.assertTrue(
            any(
                mapping["repository"] == "ken-search"
                and mapping["github_secret_name"] == "VPS_SSH_KEY"
                and mapping["source_ref"]
                == "op-development-ssh-search-root-devws-private-key"
                for mapping in mappings
            )
        )
        self.assertFalse(
            any(
                mapping["repository"] == "ken-frontend"
                and mapping["github_secret_name"] == "CLERK_SECRET_KEY"
                and mapping["target_vault"] == "Ken CI Runtime"
                and mapping["source_ref"]
                == "op-development-clerk-production-api-clerk-secret-key"
                for mapping in mappings
            )
        )

    def test_round_two_builder_fails_when_raw_metadata_does_not_prove_source(self):
        import build_task6_authority_evidence as builder
        import shutil

        evidence_dir = ROOT / "infra/github-actions/inventory/evidence"
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            for name in (
                "task-6-op-env-key-metadata.json",
                "task-6-op-field-metadata.json",
                "task-6-worldstream-key-metadata.json",
                "task-6-connection-structure.json",
            ):
                shutil.copy2(evidence_dir / name, tmp_path / name)
            op_env_path = tmp_path / "task-6-op-env-key-metadata.json"
            op_env = json.loads(op_env_path.read_text())
            frontend = next(
                item for item in op_env["items"] if item["item"] == "ken-frontend-env"
            )
            frontend["keys"] = [
                key for key in frontend["keys"] if key["name"] != "DEEPSEEK_API_KEY"
            ]
            op_env_path.write_text(json.dumps(op_env))

            with self.assertRaisesRegex(ValueError, "source metadata not proven"):
                builder.build_evidence(tmp_path)

    def test_raw_metadata_rejects_value_bearing_fields_at_any_depth(self):
        import build_task6_authority_evidence as builder
        import shutil

        evidence_dir = ROOT / "infra/github-actions/inventory/evidence"
        for forbidden in (
            "value",
            "secret",
            "password",
            "token",
            "note",
            "notes",
            "value_hash",
            "value_length",
            "value_prefix",
        ):
            with self.subTest(forbidden=forbidden), tempfile.TemporaryDirectory() as tmp:
                tmp_path = Path(tmp)
                for name in (
                    "task-6-op-env-key-metadata.json",
                    "task-6-op-field-metadata.json",
                    "task-6-worldstream-key-metadata.json",
                    "task-6-connection-structure.json",
                ):
                    shutil.copy2(evidence_dir / name, tmp_path / name)
                path = tmp_path / "task-6-op-env-key-metadata.json"
                payload = json.loads(path.read_text())
                payload["items"][0]["keys"][0][forbidden] = "must-not-be-accepted"
                path.write_text(json.dumps(payload))
                with self.assertRaisesRegex(ValueError, "forbidden raw metadata field"):
                    builder.build_evidence(tmp_path)

    def test_every_raw_metadata_schema_rejects_unexpected_nested_fields(self):
        import build_task6_authority_evidence as builder
        import shutil

        evidence_dir = ROOT / "infra/github-actions/inventory/evidence"
        mutations = {
            "task-6-op-env-key-metadata.json": lambda doc: doc["items"][0].update(
                {"unexpected_nested": {"safe_looking": True}}
            ),
            "task-6-op-field-metadata.json": lambda doc: doc["items"][0][
                "fields"
            ][0].update({"unexpected_nested": []}),
            "task-6-worldstream-key-metadata.json": lambda doc: doc["keys"][0].update(
                {"unexpected_nested": {}}
            ),
            "task-6-connection-structure.json": lambda doc: doc.update(
                {"unexpected_nested": {"safe_looking": True}}
            ),
        }
        for mutated_name, mutate in mutations.items():
            with self.subTest(artifact=mutated_name), tempfile.TemporaryDirectory() as tmp:
                tmp_path = Path(tmp)
                for name in mutations:
                    shutil.copy2(evidence_dir / name, tmp_path / name)
                path = tmp_path / mutated_name
                payload = json.loads(path.read_text())
                mutate(payload)
                path.write_text(json.dumps(payload))
                with self.assertRaisesRegex(ValueError, "unexpected raw metadata field"):
                    builder.build_evidence(tmp_path)

    def test_round_two_reuses_only_production_provider_authorities(self):
        import build_task6_authority_evidence as builder

        mappings = builder.build_evidence()["mappings"]
        self.assertTrue(
            any(
                mapping["repository"] == "ken-frontend"
                and mapping["github_secret_name"] == "XAI_API_KEY"
                and mapping["target_vault"] == "Ken Deploy Production"
                and mapping["source_ref"]
                == "worldstream-scraper-api-xaiconfiguration-apikey"
                for mapping in mappings
            )
        )
        self.assertTrue(
            any(
                mapping["repository"] == "ken-agents"
                and mapping["github_secret_name"] == "OPENAI_API_KEY"
                and mapping["target_vault"] == "Ken Deploy Production"
                and mapping["source_ref"]
                == "worldstream-scraper-api-openai-apikey"
                for mapping in mappings
            )
        )
        self.assertTrue(
            any(
                mapping["repository"] == "ken-agents"
                and mapping["github_secret_name"] == "XAI_PROXY_URL"
                and mapping["source_ref"]
                == "op-development-ken-backend-env-xaiconfiguration-proxyurl"
                for mapping in mappings
            )
        )
        self.assertFalse(
            any(
                mapping["github_secret_name"] in {"XAI_API_KEY", "OPENAI_API_KEY"}
                and mapping["target_vault"] == "Ken CI Runtime"
                for mapping in mappings
            )
        )

    def test_unresolved_provider_annotation_keeps_authority_unresolved(self):
        entry = aw.apply_secret_consumer(
            aw.secret_authority(
                "PYPI_API_TOKEN",
                "Ken-SRE",
                self.empty_scopes,
                ".github/workflows/publish.yml",
            ),
            self.production,
        )
        evidence = {
            "unresolved_annotations": [
                {
                    "annotation_id": "ken-sre-pypi-api-token",
                    "repository": "Ken-SRE",
                    "github_secret_name": "PYPI_API_TOKEN",
                    "target_vault": "Ken Deploy Production",
                    "resolution_class": "provider-rotation",
                    "authority_owner": "PyPI project owner",
                    "handoff_group": "publishing/pypi",
                    "unresolved_reason": "GitHub metadata is name-only and no readable authority was found.",
                    "provider_rotation_steps": [
                        "Create a replacement project-scoped PyPI publishing credential.",
                        "Store it through the concealed migration handoff, verify the package publish, then revoke the predecessor.",
                    ],
                    "downstream_update_steps": [
                        "Populate the named target 1Password field through the temporary writer.",
                        "Cut the exact workflow over to the local broker and verify a live package publish.",
                        "Delete the GitHub secret and revoke the predecessor only after verification.",
                    ],
                }
            ]
        }
        annotated = aw.apply_unresolved_annotation(entry, evidence)
        self.assertEqual(annotated["authority_status"], "unresolved")
        self.assertEqual(annotated["resolution_class"], "provider-rotation")
        self.assertEqual(annotated["authority_owner"], "PyPI project owner")
        self.assertEqual(annotated["handoff_group"], "publishing/pypi")
        self.assertTrue(annotated["rotation_required"])
        self.assertEqual(annotated["migration_action"], "rotate-at-provider")
        self.assertEqual(annotated["authority_annotation_id"], "ken-sre-pypi-api-token")

    def test_unresolved_annotation_fails_closed_on_scope_or_incomplete_procedure(self):
        entry = aw.apply_secret_consumer(
            aw.secret_authority(
                "PYPI_API_TOKEN",
                "Ken-SRE",
                self.empty_scopes,
                ".github/workflows/publish.yml",
            ),
            self.production,
        )
        wrong_scope = {
            "unresolved_annotations": [
                {
                    "annotation_id": "wrong-scope",
                    "repository": "Ken-SRE",
                    "github_secret_name": "PYPI_API_TOKEN",
                    "target_vault": "Ken CI Runtime",
                    "resolution_class": "provider-rotation",
                    "authority_owner": "PyPI project owner",
                    "handoff_group": "publishing/pypi",
                    "unresolved_reason": "No readable authority was found.",
                    "provider_rotation_steps": ["Create and revoke a project token."],
                    "downstream_update_steps": [
                        "Populate the named target 1Password field, cut over, verify, then retire the GitHub field."
                    ],
                }
            ]
        }
        self.assertIs(aw.apply_unresolved_annotation(entry, wrong_scope), entry)

        incomplete = {
            "unresolved_annotations": [
                {
                    "annotation_id": "missing-procedure",
                    "repository": "Ken-SRE",
                    "github_secret_name": "PYPI_API_TOKEN",
                    "target_vault": "Ken Deploy Production",
                    "resolution_class": "provider-rotation",
                    "authority_owner": "PyPI project owner",
                    "handoff_group": "publishing/pypi",
                    "unresolved_reason": "No readable authority was found.",
                    "provider_rotation_steps": None,
                    "downstream_update_steps": [
                        "Populate the target, cut over the consumer, verify, then retire the GitHub field."
                    ],
                }
            ]
        }
        with self.assertRaisesRegex(ValueError, "rotation procedure"):
            aw.apply_unresolved_annotation(entry, incomplete)

    def test_round_two_builder_classifies_source_proven_recovery_routes(self):
        import build_task6_authority_evidence as builder

        annotations = builder.build_evidence()["unresolved_annotations"]
        self.assertFalse(
            any(
                row["repository"] == "Ken-SRE"
                and row["github_secret_name"] == "PYPI_API_TOKEN"
                for row in annotations
            )
        )

        mcp_read = [
            row
            for row in annotations
            if row["repository"] == "ken-ai-mcp"
            and row["github_secret_name"] == "KEN_BACKEND_READ_TOKEN"
        ]
        self.assertEqual(
            {row["target_vault"] for row in mcp_read},
            {"Ken CI Runtime", "Ken Deploy Production"},
        )
        self.assertEqual(len({row["handoff_group"] for row in mcp_read}), 2)

        self.assertFalse(
            any(
                row["repository"] == "ken-cms"
                and row["github_secret_name"] == "OAUTH2_PROXY_CLIENT_SECRET"
                and "frontend" in row["handoff_group"]
                for row in annotations
            )
        )
        for annotation in annotations:
            self.assertTrue(annotation["downstream_update_steps"], annotation)

    def test_independent_authority_requires_rotation_and_full_cutover_steps(self):
        entry = aw.apply_secret_consumer(
            aw.secret_authority(
                "DEDICATED_SIGNING_KEY",
                "ken-backend",
                self.empty_scopes,
                ".github/workflows/deploy.yml",
            ),
            self.production,
        )
        evidence = {
            "unresolved_annotations": [
                {
                    "annotation_id": "dedicated-signing-key",
                    "repository": "ken-backend",
                    "github_secret_name": "DEDICATED_SIGNING_KEY",
                    "target_vault": "Ken Deploy Production",
                    "resolution_class": "independent-trust-authority",
                    "authority_owner": "Release signing owner",
                    "handoff_group": "backend/release-signing",
                    "unresolved_reason": "A new independent authority must be created.",
                    "provider_rotation_steps": None,
                    "downstream_update_steps": [
                        "Create a dedicated authority and populate the named target field through the temporary writer.",
                        "Cut the workflow over to the local broker and verify a live signed release.",
                        "Delete the GitHub field and revoke the predecessor only after verification.",
                    ],
                }
            ]
        }
        annotated = aw.apply_unresolved_annotation(entry, evidence)
        self.assertTrue(annotated["rotation_required"])
        self.assertEqual(
            annotated["migration_action"], "create-independent-authority"
        )
        self.assertEqual(
            annotated["downstream_update_steps"],
            evidence["unresolved_annotations"][0]["downstream_update_steps"],
        )

    def test_unresolved_annotation_rejects_missing_downstream_cutover_steps(self):
        entry = aw.apply_secret_consumer(
            aw.secret_authority(
                "DEPLOY_HOST",
                "ken-help",
                self.empty_scopes,
                ".github/workflows/deploy.yml",
            ),
            self.production,
        )
        evidence = {
            "unresolved_annotations": [
                {
                    "annotation_id": "help-deploy-host",
                    "repository": "ken-help",
                    "github_secret_name": "DEPLOY_HOST",
                    "target_vault": "Ken Deploy Production",
                    "resolution_class": "target-system-readback",
                    "authority_owner": "Deployment target owner",
                    "handoff_group": "help/deploy",
                    "unresolved_reason": "Target readback is required.",
                    "provider_rotation_steps": None,
                    "downstream_update_steps": [],
                }
            ]
        }
        with self.assertRaisesRegex(ValueError, "downstream_update_steps"):
            aw.apply_unresolved_annotation(entry, evidence)

    def test_resolved_builder_steps_target_1password_not_github(self):
        import build_task6_authority_evidence as builder

        evidence = builder.build_evidence()
        copy_mapping = next(
            row
            for row in evidence["mappings"]
            if row["migration_action"] == "copy"
        )
        rendered = " ".join(copy_mapping["downstream_update_steps"])
        self.assertIn("target 1Password", rendered)
        self.assertNotIn("1Password-to-GitHub", rendered)

    def test_frontend_encryption_authority_has_fixed_production_build_boundary(self):
        import build_task6_authority_evidence as builder

        evidence = builder.build_evidence()
        annotation = next(
            row
            for row in evidence["unresolved_annotations"]
            if row["repository"] == "ken-frontend"
            and row["github_secret_name"]
            == "NEXT_SERVER_ACTIONS_ENCRYPTION_KEY"
        )
        self.assertEqual(
            annotation["execution_boundary"],
            {
                "action_id": "ken-frontend-production-release",
                "mode": "production_build",
                "workflow": ".github/workflows/deploy.yml",
                "production_build_job": "build-image",
                "deployment_job": "deploy",
                "runner_class": "ken-deploy-production",
                "broker_only": True,
                "ci_validation_only": True,
                "forbid_ken_ci_production_artifact": True,
            },
        )

        entry = aw.apply_secret_consumer(
            aw.secret_authority(
                "NEXT_SERVER_ACTIONS_ENCRYPTION_KEY",
                "ken-frontend",
                self.empty_scopes,
                ".github/workflows/deploy.yml",
            ),
            self.production,
        )
        annotated = aw.apply_unresolved_annotation(entry, evidence)
        self.assertEqual(
            annotated["execution_boundary"], annotation["execution_boundary"]
        )
        self.assertEqual(
            annotated["required_runtime_identity"], "ken-deploy-production"
        )

    def test_frontend_production_build_action_is_complete_and_fail_closed(self):
        import build_task6_authority_evidence as builder

        evidence = builder.build_evidence()
        action = next(
            row
            for row in evidence["broker_actions"]
            if row["action_id"] == "ken-frontend-production-release"
        )
        self.assertEqual(action["mode"], "production_build")
        self.assertEqual(action["status"], "blocked-until-task7-pins-and-mutations-pass")
        self.assertEqual(
            action["request_contract"]["allowed_keys"],
            ["version", "action_id", "oidc_jwt", "github_token"],
        )
        self.assertFalse(action["request_contract"]["accepts_artifact"])
        self.assertFalse(action["request_contract"]["accepts_descriptor"])
        self.assertEqual(action["request_contract"]["result"], "stable-code-only")
        self.assertFalse(action["runner_contract"]["checkout"])
        self.assertFalse(action["runner_contract"]["build"])
        self.assertFalse(action["runner_contract"]["receives_digest"])
        self.assertFalse(action["runner_contract"]["receives_output"])
        self.assertEqual(
            set(action["authorization"]["checks"]),
            {
                "unix-peer",
                "class-oidc",
                "live-job",
                "workflow",
                "protected-ref",
                "environment",
                "durable-replay",
            },
        )
        self.assertTrue(action["authorization"]["all_before_onepassword"])
        source = action["source_contract"]
        self.assertEqual(source["mode"], "broker-fetched-exact-commit")
        self.assertTrue(source["fetch_before_onepassword"])
        self.assertEqual(
            source["source_commit_sha"],
            "0952ac075f658acd1bc15a3253032507581e1f0d",
        )
        self.assertEqual(
            source["workflow_blob_sha"],
            "21b01bbfeb3db512a42080ea21dff5276f3fa28b",
        )
        self.assertEqual(
            source["dockerfile_blob_sha"],
            "6860679d7e023ac3d7828fa97cb32ed0e04bce53",
        )
        self.assertEqual(
            source["pnpm_lock_blob_sha"],
            "4dadbbdda72a3c1ed23c1ef14240e765fe9a2170",
        )
        self.assertFalse(source["fallback"])

        identities = action["identity_boundary"]
        self.assertTrue(identities["pairwise_distinct"])
        self.assertEqual(
            len(
                {
                    identities["runner_uid"],
                    identities["broker_uid"],
                    identities["builder_uid"],
                    identities["post_build_uid"],
                    identities["deploy_uid"],
                }
            ),
            5,
        )
        self.assertFalse(identities["runner_can_access_builder_socket"])
        self.assertFalse(identities["runner_can_access_builder_state"])
        self.assertFalse(identities["builder_can_access_deploy_executor"])
        self.assertFalse(identities["deploy_executor_can_access_builder"])

        build = action["build_contract"]
        self.assertTrue(build["rootless_buildkit"])
        self.assertTrue(build["dependencies_and_base_images_secretless"])
        self.assertEqual(build["secret_phase"]["command"], "pnpm build")
        self.assertEqual(build["secret_phase"]["network"], "none")
        self.assertEqual(build["secret_phase"]["delivery"], "buildkit-secret-mount")
        self.assertEqual(
            build["secret_phase"]["field"],
            "NEXT_SERVER_ACTIONS_ENCRYPTION_KEY",
        )
        for channel in ("arg", "env", "cache_metadata", "logs", "layers"):
            self.assertFalse(build["secret_phase"][channel])
        self.assertEqual(
            set(build["reviewed_github_variables"]),
            {
                "NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY",
                "NEXT_PUBLIC_CLERK_SIGN_IN_URL",
                "NEXT_PUBLIC_CLERK_SIGN_UP_URL",
                "NEXT_PUBLIC_POSTHOG_PROJECT_TOKEN",
                "NEXT_PUBLIC_TECHNOLOGY_FILTER_ENABLED",
                "NEXT_PUBLIC_TECHNOLOGY_FILTER_ALLOWED_CLIENT_IDS",
                "NEXT_PUBLIC_EXPERIMENTS_ALLOWED_CLIENT_IDS",
            },
        )
        self.assertEqual(
            set(build["forbidden_build_fields"]),
            {"POSTHOG_PERSONAL_API_KEY", "POSTHOG_PROJECT_ID"},
        )
        self.assertEqual(build["output"]["format"], "OCI")
        self.assertTrue(build["output"]["scan_config_history"])
        self.assertTrue(build["output"]["scan_uncompressed_layers"])
        self.assertEqual(
            build["output"]["canary_variants"], ["raw", "base64", "hex"]
        )
        self.assertTrue(build["output"]["push_by_digest"])
        self.assertTrue(build["output"]["verified_short_lived_token"])

        post_build = action["post_build_contract"]
        self.assertEqual(
            set(post_build["fields"]),
            {"POSTHOG_PERSONAL_API_KEY", "POSTHOG_PROJECT_ID"},
        )
        self.assertEqual(post_build["target"], "https://us.posthog.com")
        self.assertFalse(post_build["can_read_build_field"])
        self.assertEqual(post_build["result"], "stable-code-only")
        self.assertEqual(action["deploy_contract"]["input"], "broker-recorded-image-digest")
        self.assertFalse(action["deploy_contract"]["accepts_runner_digest"])
        self.assertTrue(action["durable_state"]["source_run_digest_binding"])
        self.assertTrue(action["cleanup"]["every_exit_path"])
        self.assertTrue(action["cleanup"]["builder_state"])
        self.assertTrue(action["cleanup"]["builder_cache"])
        self.assertTrue(action["cleanup"]["request_directory"])
        self.assertTrue(action["risk_acceptance"]["merged_protected_code_may_consume_build_field"])
        self.assertTrue(action["risk_acceptance"]["transformed_embedding_residual_accepted_only_for_reviewed_source"])
        self.assertTrue(action["pin_gate"]["cutover_blocked_until_all_exact"])
        self.assertEqual(
            set(action["pin_gate"]["required_exact_pins"]),
            {
                "base_image_digest",
                "pnpm_lock_blob_sha",
                "source_commit_sha",
                "workflow_blob_sha",
                "wrapper_sha256",
                "buildkit_version",
                "resource_limits",
            },
        )
        self.assertTrue(
            {
                "network-enabled-secret-phase",
                "secret-in-arg",
                "secret-in-env",
                "secret-in-cache-metadata",
                "secret-in-log",
                "secret-in-layer",
                "source-drift",
                "workflow-drift",
                "wrong-image-digest",
                "replay",
                "runner-builder-socket-access",
                "builder-deploy-cross-access",
                "deploy-builder-cross-access",
            }.issubset(set(action["required_mutation_tests"]))
        )

    def test_frontend_public_build_inputs_move_to_reviewed_variables(self):
        import build_task6_authority_evidence as builder

        evidence = builder.build_evidence()
        migrations = {
            row["github_secret_name"]: row
            for row in evidence["workflow_variable_migrations"]
            if row["repository"] == "ken-frontend"
        }
        self.assertEqual(
            set(migrations),
            {
                "NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY",
                "NEXT_PUBLIC_POSTHOG_PROJECT_TOKEN",
            },
        )
        for name, migration in migrations.items():
            self.assertEqual(migration["target_variable_name"], name)
            self.assertEqual(migration["migration_action"], "move-to-github-variable")
            self.assertTrue(migration["review_required"])

        entry = aw.apply_secret_consumer(
            aw.secret_authority(
                "NEXT_PUBLIC_POSTHOG_PROJECT_TOKEN",
                "ken-frontend",
                self.empty_scopes,
                ".github/workflows/deploy.yml",
            ),
            self.production,
        )
        migrated = aw.apply_workflow_variable_migration(entry, evidence)
        self.assertEqual(migrated["authority_status"], "planned-variable")
        self.assertEqual(migrated["migration_action"], "move-to-github-variable")
        self.assertEqual(
            migrated["target_variable_name"],
            "NEXT_PUBLIC_POSTHOG_PROJECT_TOKEN",
        )
        self.assertIsNone(migrated["target_vault"])
        self.assertIsNone(migrated["target_item"])
        self.assertIsNone(migrated["target_field"])

    def test_frontend_posthog_fields_are_separate_post_build_phase(self):
        import build_task6_authority_evidence as builder

        evidence = builder.build_evidence()
        annotations = {
            row["github_secret_name"]: row
            for row in evidence["unresolved_annotations"]
            if row["repository"] == "ken-frontend"
            and row["github_secret_name"] in {
                "POSTHOG_PERSONAL_API_KEY",
                "POSTHOG_PROJECT_ID",
            }
        }
        self.assertEqual(set(annotations), {"POSTHOG_PERSONAL_API_KEY", "POSTHOG_PROJECT_ID"})
        for annotation in annotations.values():
            self.assertEqual(
                annotation["broker_action_id"],
                "ken-frontend-production-release",
            )
            self.assertEqual(annotation["action_phase"], "post-build-sourcemap-upload")
            self.assertEqual(
                annotation["required_runtime_identity"],
                "ken-action-frontend-posthog",
            )
            self.assertEqual(
                annotation["execution_boundary"],
                {
                    "action_id": "ken-frontend-production-release",
                    "mode": "post-build-sourcemap-upload",
                    "workflow": ".github/workflows/deploy.yml",
                    "production_build_job": "build-image",
                    "deployment_job": "deploy",
                    "runner_class": "ken-deploy-production",
                    "broker_only": True,
                    "ci_validation_only": True,
                    "forbid_ken_ci_production_artifact": True,
                },
            )

    def test_hermes_keeps_dedicated_deploy_identity_unresolved(self):
        import build_task6_authority_evidence as builder

        evidence = builder.build_evidence()
        self.assertFalse(
            any(
                row["repository"] == "ken-hermes-clickup"
                and row["github_secret_name"]
                in {"DEPLOY_HOST", "DEPLOY_USER", "DEPLOY_SSH_KEY"}
                for row in evidence["mappings"]
            )
        )
        hermes = {
            row["github_secret_name"]: row
            for row in evidence["unresolved_annotations"]
            if row["repository"] == "ken-hermes-clickup"
        }
        self.assertEqual(
            set(hermes),
            {
                "DEPLOY_HOST",
                "DEPLOY_USER",
                "DEPLOY_SSH_KEY",
                "DEPLOY_SSH_KNOWN_HOSTS",
            },
        )
        for row in hermes.values():
            self.assertEqual(row["required_runtime_identity"], "kenhermes-deploy")
            self.assertEqual(row["resolution_class"], "target-system-readback")
            self.assertTrue(row["downstream_update_steps"])

        entry = aw.apply_secret_consumer(
            aw.secret_authority(
                "DEPLOY_SSH_KEY",
                "ken-hermes-clickup",
                self.empty_scopes,
                ".github/workflows/deploy.yml",
            ),
            self.production,
        )
        annotated = aw.apply_unresolved_annotation(entry, evidence)
        self.assertEqual(
            annotated["required_runtime_identity"], "kenhermes-deploy"
        )

    def test_public_publishers_have_secretless_github_hosted_migrations(self):
        import build_task6_authority_evidence as builder

        evidence = builder.build_evidence()
        migrations = {
            (row["repository"], row["github_secret_name"]): row
            for row in evidence["secretless_migrations"]
        }
        pypi = migrations[("Ken-SRE", "PYPI_API_TOKEN")]
        self.assertEqual(pypi["migration_action"], "oidc-trusted-publisher")
        self.assertIsNone(pypi["target_vault"])
        self.assertIsNone(pypi["target_item"])
        self.assertIsNone(pypi["target_field"])
        self.assertEqual(pypi["target_runner_class"], "public-github-hosted")
        self.assertEqual(
            pypi["required_permissions"],
            {"contents": "read", "id-token": "write"},
        )
        self.assertTrue(pypi["provider_setup_steps"])
        self.assertTrue(pypi["downstream_update_steps"])
        self.assertTrue(pypi["live_verification_steps"])
        self.assertTrue(pypi["retirement_steps"])
        self.assertEqual(
            pypi["trusted_publisher"],
            {
                "project": "derisk-mono",
                "owner": "Ken-Technology",
                "repository": "Ken-SRE",
                "workflow": "python-publish.yml",
                "environment": "pypi",
            },
        )
        self.assertEqual(
            pypi["packaging_contract"],
            {
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
        )
        self.assertIn("environment pypi", " ".join(pypi["provider_setup_steps"]))
        self.assertIn(
            "python -m build --sdist --wheel .",
            " ".join(pypi["downstream_update_steps"]),
        )
        self.assertIn(
            "build job overrides permissions to contents: read only",
            " ".join(pypi["downstream_update_steps"]),
        )

        plugin = migrations[("ken-ai-plugin", "COLD_EMAIL_SKILLS_DEPLOY_KEY")]
        self.assertEqual(plugin["migration_action"], "pull-based-publisher")
        self.assertEqual(plugin["target_runner_class"], "public-github-hosted")
        self.assertEqual(plugin["cross_repo_task"]["task"], "Task 7")
        self.assertEqual(
            plugin["cross_repo_task"]["target_repository"],
            "Ken-Technology/cold-email-skills",
        )
        self.assertEqual(plugin["cross_repo_task"]["authentication"], "GITHUB_TOKEN")
        self.assertTrue(plugin["downstream_update_steps"])
        self.assertTrue(plugin["live_verification_steps"])
        self.assertTrue(plugin["retirement_steps"])

    def test_secretless_migration_clears_vault_and_unresolved_defaults(self):
        classified = classify(
            repo="Ken-SRE",
            visibility="public",
            workflow_path=".github/workflows/python-publish.yml",
            job_id="deploy",
            triggers=["release"],
            secrets=["PYPI_API_TOKEN"],
            text="pypa/gh-action-pypi-publish",
        )
        entry = aw.apply_secret_consumer(
            aw.secret_authority(
                "PYPI_API_TOKEN",
                "Ken-SRE",
                self.empty_scopes,
                ".github/workflows/python-publish.yml",
            ),
            classified,
        )
        evidence = {
            "secretless_migrations": [
                {
                    "migration_id": "ken-sre-pypi",
                    "repository": "Ken-SRE",
                    "workflow": ".github/workflows/python-publish.yml",
                    "github_secret_name": "PYPI_API_TOKEN",
                    "migration_action": "oidc-trusted-publisher",
                    "target_vault": None,
                    "target_item": None,
                    "target_field": None,
                    "target_runner_class": "public-github-hosted",
                    "required_permissions": {
                        "contents": "read",
                        "id-token": "write",
                    },
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
                    "provider_setup_steps": ["Register the exact trusted publisher."],
                    "downstream_update_steps": ["Remove password input."],
                    "live_verification_steps": ["Publish and verify the release."],
                    "retirement_steps": ["Revoke the predecessor token."],
                }
            ]
        }
        migrated = aw.apply_secretless_migration(entry, evidence)
        self.assertEqual(migrated["authority_status"], "planned-secretless")
        self.assertEqual(migrated["migration_action"], "oidc-trusted-publisher")
        self.assertIsNone(migrated["target_vault"])
        self.assertEqual(migrated["consumer"], "public-github-hosted")
        for field in (
            "resolution_class",
            "authority_owner",
            "unresolved_reason",
            "handoff_group",
        ):
            self.assertNotIn(field, migrated)


if __name__ == "__main__":
    unittest.main()
