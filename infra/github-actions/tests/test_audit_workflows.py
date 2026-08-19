#!/usr/bin/env python3
"""Focused collector/classifier tests. These assert behavior, not file existence."""
from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
LIB = ROOT / "infra/github-actions/scripts/lib"
FIXTURE_DIR = ROOT / "infra/github-actions/tests/fixtures/offline-org"
sys.path.insert(0, str(LIB))

import audit_workflows as aw  # noqa: E402


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
            (collect / "onepassword-vaults.json").write_text(json.dumps(["Development", "New Vault"]))
            aw.generate(collect, out_b)
            import yaml

            hash_a = yaml.safe_load((out_a / "input-manifest.yaml").read_text())["input_hash"]
            hash_b = yaml.safe_load((out_b / "input-manifest.yaml").read_text())["input_hash"]
            self.assertNotEqual(hash_a, hash_b)
            secrets_b = yaml.safe_load((out_b / "secrets.yaml").read_text())
            self.assertEqual(secrets_b["onepassword_visible_vaults"], ["Development", "New Vault"])
            secrets_a = yaml.safe_load((out_a / "secrets.yaml").read_text())
            self.assertNotEqual(secrets_a["onepassword_visible_vaults"], secrets_b["onepassword_visible_vaults"])

    def test_covered_inputs_include_every_generator_collect_source(self):
        snapshot = aw.collect_input_snapshot(FIXTURE_DIR)
        covered = set(aw.build_input_manifest(FIXTURE_DIR, [], "2026-08-19T16:00:00Z")["covered_inputs"])
        for key in aw.COLLECT_DIR_INPUT_KEYS:
            self.assertIn(key, snapshot, f"snapshot missing {key}")
        self.assertIn("onepassword_vaults", snapshot)
        self.assertIn("onepassword_vaults", covered)
        for banned in ("repositories.yaml", "runners.yaml", "secrets.yaml", "input-manifest.yaml"):
            self.assertNotIn(banned, snapshot)
            self.assertNotIn(banned, covered)
        for source in aw.collect_dir_files_read_by_generate():
            self.assertTrue(source, "empty generator source")
            self.assertFalse(str(source).endswith(".yaml") and "inventory/" in str(source))

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


if __name__ == "__main__":
    unittest.main()
