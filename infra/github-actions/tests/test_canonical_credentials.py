#!/usr/bin/env python3
"""Contract tests for the value-free canonical credential registry."""

from __future__ import annotations

import copy
import sys
import tempfile
import unittest
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
        registry.validate_complete_coverage(document, handoff)

        handoff["rows"].append({"coordinate": "missing-coordinate"})
        with self.assertRaisesRegex(ValueError, "missing-coordinate"):
            registry.validate_complete_coverage(document, handoff)

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


if __name__ == "__main__":
    unittest.main()
