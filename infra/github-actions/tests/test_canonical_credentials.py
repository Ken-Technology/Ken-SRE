#!/usr/bin/env python3
"""Contract tests for the value-free canonical credential registry."""

from __future__ import annotations

import copy
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[3]
LIB = ROOT / "infra/github-actions/scripts/lib"
INVENTORY = ROOT / "infra/github-actions/inventory"
sys.path.insert(0, str(LIB))

import canonical_credentials as registry  # noqa: E402


class CanonicalCredentialRegistryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.handoff = yaml.safe_load(
            (INVENTORY / "secret-handoff.yaml").read_text(encoding="utf-8")
        )
        self.rules_path = INVENTORY / "evidence" / "org-secret-consolidation-rules.yaml"

    def test_committed_registry_covers_every_handoff_coordinate(self) -> None:
        document = registry.load_registry(
            INVENTORY / "canonical-credentials.yaml",
            handoff=self.handoff,
        )

        self.assertEqual(len(document["entries"]), 308)
        registry.validate_complete_coverage(document, self.handoff)

    def test_duplicate_yaml_keys_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "duplicate.yaml"
            path.write_text(
                "schema_version: 1\nschema_version: 1\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "duplicate"):
                registry.load_registry(path)

    def test_unknown_keys_are_rejected_recursively(self) -> None:
        document = registry.minimal_document()
        document["entries"][0]["unexpected"] = "must fail"
        with self.assertRaisesRegex(ValueError, "unknown key"):
            registry.validate_registry(document)

        document = registry.minimal_document()
        document["canonical_items"][0]["unexpected"] = "must fail"
        with self.assertRaisesRegex(ValueError, "unknown key"):
            registry.validate_registry(document)

    def test_exact_scalar_types_are_enforced(self) -> None:
        document = registry.minimal_document()
        document["schema_version"] = True
        with self.assertRaisesRegex(ValueError, "schema_version"):
            registry.validate_registry(document)

        document = registry.minimal_document()
        document["entries"][0]["consumer_repositories"] = "ken-backend"
        with self.assertRaisesRegex(ValueError, "consumer_repositories"):
            registry.validate_registry(document)

    def test_ids_and_aliases_must_be_unique(self) -> None:
        document = registry.minimal_document()
        document["canonical_items"].append(
            copy.deepcopy(document["canonical_items"][0])
        )
        with self.assertRaisesRegex(ValueError, "canonical item id"):
            registry.validate_registry(document)

        document = registry.minimal_document()
        document["entries"].append(copy.deepcopy(document["entries"][0]))
        document["entries"][1]["coordinate"] = "another-coordinate"
        with self.assertRaisesRegex(ValueError, "alias"):
            registry.validate_registry(document)

        document = registry.minimal_document()
        document["canonical_items"][0]["aliases"] = ["SHARED_ALIAS"]
        document["entries"][0]["aliases"] = ["SHARED_ALIAS"]
        with self.assertRaisesRegex(ValueError, "alias"):
            registry.validate_registry(document)

    def test_coverage_rejects_missing_or_extra_coordinates(self) -> None:
        document = registry.minimal_document()
        handoff = {"rows": [{"coordinate": document["entries"][0]["coordinate"]}]}
        with self.assertRaisesRegex(ValueError, "exactly 308"):
            registry.validate_complete_coverage(document, handoff)

    def test_coverage_requires_308_even_without_declared_count(self) -> None:
        handoff = copy.deepcopy(self.handoff)
        handoff.pop("counts", None)
        document = registry.load_registry(
            INVENTORY / "canonical-credentials.yaml", handoff=self.handoff
        )
        registry.validate_complete_coverage(document, handoff)

    def test_item_backed_field_type_is_required_and_matches_handoff(self) -> None:
        document = registry.load_registry(
            INVENTORY / "canonical-credentials.yaml", handoff=self.handoff
        )
        entry = next(
            entry
            for entry in document["entries"]
            if entry["coordinate"]
            == "ken-agents|DEEPSEEK_API_KEY|Ken Deploy Production"
        )
        del entry["field_type"]
        with self.assertRaisesRegex(ValueError, "field_type"):
            registry.validate_registry(document, handoff=self.handoff)

        document = registry.load_registry(
            INVENTORY / "canonical-credentials.yaml", handoff=self.handoff
        )
        entry = next(
            entry
            for entry in document["entries"]
            if entry["coordinate"]
            == "ken-agents|DEEPSEEK_API_KEY|Ken Deploy Production"
        )
        entry["field_type"] = "STRING"
        with self.assertRaisesRegex(ValueError, "field_type mismatch"):
            registry.validate_complete_coverage(document, self.handoff)

    def test_only_deployment_vaults_are_accepted(self) -> None:
        document = registry.minimal_document()
        document["canonical_items"][0]["vault"] = "Development"
        with self.assertRaisesRegex(ValueError, "vault"):
            registry.validate_registry(document)

    def test_value_derived_keys_are_rejected_at_any_depth(self) -> None:
        for key in (
            "value",
            "secret_value",
            "digest",
            "sha256",
            "prefix",
            "length",
            "secretHash",
            "value_sha256",
            "token_length",
        ):
            document = registry.minimal_document()
            document["entries"][0][key] = "must fail"
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "forbidden"):
                registry.validate_registry(document)

    def test_coordinate_uses_the_handoff_identity_without_values(self) -> None:
        github_row = {
            "reference_class": "github-secret",
            "repository": "ken-backend",
            "github_secret_name": "OPEN_AI_API_KEY",
            "target_vault": "Ken Deploy Production",
        }
        direct_row = {
            "reference_class": "direct-onepassword",
            "coordinate": (
                "direct-op|ken-website|deploy|deploy|op://ken-website/deploy-ssh/host|"
                "Ken Deploy Production"
            ),
        }
        self.assertEqual(
            registry.canonical_coordinate(github_row),
            "ken-backend|OPEN_AI_API_KEY|Ken Deploy Production",
        )
        self.assertEqual(
            registry.canonical_coordinate(direct_row), direct_row["coordinate"]
        )

    def test_proven_renames_are_canonical_and_unresolved_rows_stay_unresolved(
        self,
    ) -> None:
        document = registry.load_registry(
            INVENTORY / "canonical-credentials.yaml",
            handoff=self.handoff,
        )
        entries = {entry["coordinate"]: entry for entry in document["entries"]}

        self.assertIn(
            "OPEN_AI_API_KEY",
            entries["ken-backend|OPEN_AI_API_KEY|Ken Deploy Production"]["aliases"],
        )
        self.assertEqual(
            entries["ken-backend|OPEN_AI_API_KEY|Ken Deploy Production"][
                "canonical_field"
            ],
            "OPENAI_API_KEY",
        )
        unresolved = entries["ken-agents|DEPLOY_HOST|Ken Deploy Production"]
        self.assertEqual(unresolved["verification_status"], "unresolved")
        self.assertIsNone(unresolved["source_authority"])

    def test_reviewed_rules_are_value_free_and_cover_the_reviewed_groups(self) -> None:
        rules = registry.load_consolidation_rules(self.rules_path)

        evidence = {
            item["id"]: item for item in rules["reviewed_evidence"]
        }
        self.assertEqual(
            evidence["baseline-authority-resolution"]["artifact"],
            "infra/github-actions/inventory/evidence/ken-secret-authority-resolution.yaml",
        )
        self.assertEqual(
            evidence["baseline-authority-resolution"]["sha256"],
            "51113962b9cb1705f66ff51700afacf9f65da37753e215b3e0d4606d9211c5c0",
        )
        self.assertEqual(evidence["baseline-authority-resolution"]["value_disclosure"], "none")
        self.assertGreaterEqual(len(rules["reviewed_groups"]), 15)
        self.assertGreaterEqual(len(rules["approved_same_identity"]), 15)
        self.assertGreaterEqual(len(rules["preserve_separately"]), 15)

    def test_final_reports_are_registered_by_exact_sha_without_secret_hashes(self) -> None:
        rules = registry.load_consolidation_rules(self.rules_path)
        evidence = {
            item["id"]: item for item in rules["reviewed_evidence"]
        }
        self.assertEqual(
            evidence["production-credential-comparison"]["sha256"],
            "4b2f27dbd8de06c2b8c725a8dd68d5e2b4cc9b77acce1494735bd34a0b1afe96",
        )
        self.assertEqual(
            evidence["unresolved-authority-resolution"]["sha256"],
            "317b3ed71f1128d80b9b890059d5e7b0a4c0e6400779709c2ec178b31a77d250",
        )
        self.assertEqual(evidence["production-credential-comparison"]["row_count"], 57)
        self.assertEqual(evidence["unresolved-authority-resolution"]["row_count"], 124)

        candidate = registry.minimal_consolidation_rules()
        candidate["reviewed_evidence"][0]["value_free_report_body_sha256"] = "must fail"
        with self.assertRaisesRegex(ValueError, "forbidden"):
            registry.validate_consolidation_rules(candidate)

    def test_reviewed_artifacts_are_hashed_and_row_counted(self):
        rules = registry.load_consolidation_rules(self.rules_path, verify_artifacts=True)
        self.assertTrue(rules["reviewed_evidence"])

        with tempfile.TemporaryDirectory() as directory:
            artifact = Path(directory) / "report.yaml"
            artifact.write_text(
                "value_disclosure: none\nrows:\n- id: one\n", encoding="utf-8"
            )
            candidate = copy.deepcopy(registry.minimal_consolidation_rules())
            item = candidate["reviewed_evidence"][0]
            item["artifact"] = str(artifact)
            item["sha256"] = registry.artifact_sha256(artifact)
            item["row_count"] = 1
            registry.validate_reviewed_evidence_artifacts(candidate)

            item["row_count"] = 1
            artifact.write_text(
                "value_disclosure: none\nrows:\n- id: one\n- id: two\n",
                encoding="utf-8",
            )
            item["sha256"] = registry.artifact_sha256(artifact)
            with self.assertRaisesRegex(ValueError, "row count"):
                registry.validate_reviewed_evidence_artifacts(candidate)

    def test_reviewed_evidence_is_committed_and_repo_relative(self):
        rules = registry.load_consolidation_rules(self.rules_path)
        for item in rules["reviewed_evidence"]:
            artifact = Path(item["artifact"])
            self.assertFalse(artifact.is_absolute())
            self.assertEqual(artifact.parts[:4], ("infra", "github-actions", "inventory", "evidence"))
            self.assertTrue((ROOT / artifact).is_file())

    def test_artifact_validation_is_mandatory_even_when_legacy_flag_is_false(self):
        with mock.patch.object(
            registry, "validate_reviewed_evidence_artifacts", side_effect=ValueError("must verify")
        ) as validate:
            with self.assertRaisesRegex(ValueError, "must verify"):
                registry.load_consolidation_rules(self.rules_path, verify_artifacts=False)
        validate.assert_called_once()

    def test_repo_relative_artifact_paths_reject_traversal_and_symlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifact = root / "evidence.yaml"
            artifact.write_text("value_disclosure: none\nrows:\n- id: one\n", encoding="utf-8")
            candidate = copy.deepcopy(registry.minimal_consolidation_rules())
            item = candidate["reviewed_evidence"][0]
            item["artifact"] = "evidence.yaml"
            item["sha256"] = registry.artifact_sha256(artifact)
            item["row_count"] = 1
            registry.validate_reviewed_evidence_artifacts(candidate, base_dir=root)

            item["artifact"] = "../evidence.yaml"
            with self.assertRaisesRegex(ValueError, "relative|traversal"):
                registry.validate_reviewed_evidence_artifacts(candidate, base_dir=root)

            item["artifact"] = "link.yaml"
            (root / "link.yaml").symlink_to(artifact)
            with self.assertRaisesRegex(ValueError, "symlink|regular"):
                registry.validate_reviewed_evidence_artifacts(candidate, base_dir=root)

    def test_artifact_bytes_are_verified_not_just_row_counted(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifact = root / "evidence.yaml"
            artifact.write_text("value_disclosure: none\nrows:\n- id: one\n", encoding="utf-8")
            candidate = copy.deepcopy(registry.minimal_consolidation_rules())
            item = candidate["reviewed_evidence"][0]
            item["artifact"] = "evidence.yaml"
            item["sha256"] = registry.artifact_sha256(artifact)
            item["row_count"] = 1
            artifact.write_text("value_disclosure: none\nrows:\n- id: two\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "sha256 mismatch"):
                registry.validate_reviewed_evidence_artifacts(candidate, base_dir=root)

    def test_final_shared_production_targets_are_applied(self) -> None:
        document = registry.load_registry(
            INVENTORY / "canonical-credentials.yaml", handoff=self.handoff
        )
        rules = registry.load_consolidation_rules(self.rules_path)
        registry.validate_consolidation(document, rules)
        entries = {entry["coordinate"]: entry for entry in document["entries"]}

        expected = {
            "ken-backend|DOUBLEWORD_API_KEY|Ken Deploy Production": "doubleword-production",
            "ken-frontend|DOUBLEWORD_API_KEY|Ken Deploy Production": "doubleword-production",
            "ken-backend|FIREWORKS_AI_API_KEY|Ken Deploy Production": "fireworks-production",
            "ken-frontend|FIREWORKS_API_KEY|Ken Deploy Production": "fireworks-production",
            "ken-backend|KEN_SEARCH_INTERNAL_TOKEN|Ken Deploy Production": "ken-search-service-production",
            "ken-search|KEN_SEARCH_INTERNAL_TOKEN|Ken Deploy Production": "ken-search-service-production",
            "ken-backend|LANGFUSE_BASE_URL|no-1password-target": "langfuse-production",
            "ken-frontend|LANGFUSE_BASE_URL|no-1password-target": "langfuse-production",
            "ken-agents|LANGFUSE_PUBLIC_KEY|no-1password-target": "langfuse-production",
            "ken-backend|LANGFUSE_PUBLIC_KEY|no-1password-target": "langfuse-production",
            "ken-frontend|LANGFUSE_PUBLIC_KEY|no-1password-target": "langfuse-production",
            "ken-agents|LANGFUSE_SECRET_KEY|Ken Deploy Production": "langfuse-production",
            "ken-backend|LANGFUSE_SECRET_KEY|Ken Deploy Production": "langfuse-production",
            "ken-frontend|LANGFUSE_SECRET_KEY|Ken Deploy Production": "langfuse-production",
            "ken-ai-mcp|MONGO_CONNECTION_STRING|Ken Deploy Production": "ken-mongo-production",
            "ken-backend|MONGO_CONNECTION_STRING2|Ken Deploy Production": "ken-mongo-production",
            "ken-backend|OPEN_ROUTER_API_KEY|Ken Deploy Production": "openrouter-production",
            "ken-frontend|OPENROUTER_API_KEY|Ken Deploy Production": "openrouter-production",
            "ken-agents|XAI_API_KEY|Ken Deploy Production": "xai-production",
            "ken-backend|xAI_API_KEY|Ken Deploy Production": "xai-production",
            "ken-frontend|XAI_API_KEY|Ken Deploy Production": "xai-production",
        }
        for coordinate, canonical_id in expected.items():
            self.assertEqual(entries[coordinate]["canonical_id"], canonical_id)

    def test_final_resolution_special_cases_are_recorded(self) -> None:
        document = registry.load_registry(
            INVENTORY / "canonical-credentials.yaml", handoff=self.handoff
        )
        entries = {entry["coordinate"]: entry for entry in document["entries"]}
        backend_url = entries[
            "ken-agents|KEN_AGENTS_BACKEND_URL|Ken Deploy Production"
        ]
        self.assertEqual(backend_url["verification_status"], "verified-readable")
        self.assertEqual(
            backend_url["source_authority"],
            "deployed://185.183.35.189/var/www/ken-agents/.env#KEN_BACKEND_URL",
        )
        retired = entries["ken-scraping|TEST_API_KEY|Ken Deploy Production"]
        self.assertEqual(retired["disposition"], "retired")
        self.assertEqual(retired["verification_status"], "planned-secretless")

    def test_approved_same_identity_groups_collapse_to_one_target(self) -> None:
        document = registry.load_registry(
            INVENTORY / "canonical-credentials.yaml", handoff=self.handoff
        )
        rules = registry.load_consolidation_rules(self.rules_path)

        registry.validate_consolidation(document, rules)
        entries = {entry["coordinate"]: entry for entry in document["entries"]}

        for group in rules["approved_same_identity"]:
            if not group["handoff_coordinates"]:
                continue
            targets = {
                registry.entry_target(entries[coordinate])
                for coordinate in group["handoff_coordinates"]
            }
            self.assertEqual(
                len(targets),
                1,
                msg=f"approved group did not collapse: {group['id']}",
            )

    def test_disallowed_groups_remain_split_even_when_labels_match(self) -> None:
        document = registry.load_registry(
            INVENTORY / "canonical-credentials.yaml", handoff=self.handoff
        )
        rules = registry.load_consolidation_rules(self.rules_path)
        registry.validate_consolidation(document, rules)

        entries = {entry["coordinate"]: entry for entry in document["entries"]}
        for group in rules["preserve_separately"]:
            if not group["handoff_coordinates"]:
                continue
            targets = {
                registry.entry_target(entries[coordinate])
                for coordinate in group["handoff_coordinates"]
            }
            self.assertGreaterEqual(
                len(targets),
                2,
                msg=f"disallowed group was merged: {group['id']}",
            )

    def test_deepseek_agents_and_frontend_are_explicitly_split(self) -> None:
        document = registry.load_registry(
            INVENTORY / "canonical-credentials.yaml", handoff=self.handoff
        )
        rules = registry.load_consolidation_rules(self.rules_path)
        group = next(
            group
            for group in rules["preserve_separately"]
            if group["id"] == "deepseek-agents-frontend"
        )
        entries = {entry["coordinate"]: entry for entry in document["entries"]}
        self.assertNotEqual(
            registry.entry_target(entries[group["handoff_coordinates"][0]]),
            registry.entry_target(entries[group["handoff_coordinates"][1]]),
        )

    def test_target_field_normalization_is_structural_only(self) -> None:
        document = registry.load_registry(
            INVENTORY / "canonical-credentials.yaml", handoff=self.handoff
        )
        entries = {entry["coordinate"]: entry for entry in document["entries"]}
        self.assertEqual(
            entries[
                "ken-ai-mcp|WORLDSTREAM_PASSWORD|Ken Deploy Production"
            ]["canonical_field"],
            "WORLDSTREAM_PASSWORD",
        )
        self.assertEqual(
            entries["ken-search|VPS_HOST|no-1password-target"]["canonical_field"],
            "DEPLOY_HOST",
        )
        self.assertEqual(
            entries[
                "ken-ai-mcp|WORLDSTREAM_HOST|Ken Deploy Production"
            ]["canonical_field"],
            "WORLDSTREAM_HOST",
        )
        self.assertEqual(
            entries["ken-ai-mcp|WORLDSTREAM_USER|no-1password-target"][
                "canonical_field"
            ],
            "WORLDSTREAM_USER",
        )

    def test_rules_reject_value_derived_keys(self) -> None:
        rules = registry.minimal_consolidation_rules()
        rules["approved_same_identity"][0]["secret_prefix"] = "must fail"
        with self.assertRaisesRegex(ValueError, "forbidden"):
            registry.validate_consolidation_rules(rules)


if __name__ == "__main__":
    unittest.main()
