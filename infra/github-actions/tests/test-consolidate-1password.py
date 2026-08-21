import importlib.util
import json
import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "consolidate-1password.py"


def load_module():
    spec = importlib.util.spec_from_file_location("consolidate_onepassword", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class ConsolidateOnePasswordTests(unittest.TestCase):
    def test_duplicate_json_keys_are_rejected(self):
        tool = load_module()
        with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
            tool.strict_json_loads('{"title":"one","title":"two"}')

    def test_value_comparison_returns_only_classification(self):
        tool = load_module()
        self.assertEqual(tool.classify_values("secret-sentinel", "secret-sentinel"), "same-value")
        self.assertEqual(tool.classify_values("one", "two"), "different-value")
        self.assertNotIn(
            "secret-sentinel",
            json.dumps(tool.classify_values("secret-sentinel", "secret-sentinel")),
        )

    def test_status_schema_rejects_value_derived_fields(self):
        tool = load_module()
        baseline = {
            "coordinate": "ken-agents|OPENAI_API_KEY|Ken Deploy Production",
            "status": "verified",
            "vault_id": "vault-id",
            "item_id": "item-id",
            "field_label": "OPENAI_API_KEY",
            "field_type": "CONCEALED",
        }
        tool.validate_status_record(baseline)
        for forbidden in ("value", "hash", "sha256", "prefix", "length"):
            mutated = dict(baseline)
            mutated[forbidden] = "forbidden"
            with self.subTest(forbidden=forbidden), self.assertRaisesRegex(
                ValueError, "status record key"
            ):
                tool.validate_status_record(mutated)

    def test_item_template_uses_concealed_fields_and_contains_no_token(self):
        tool = load_module()
        template = tool.build_item_template(
            title="openai-production",
            fields={"OPENAI_API_KEY": "provider-secret"},
            text_fields={"ACCOUNT": "ken-production"},
        )
        self.assertEqual(template["category"], "API_CREDENTIAL")
        fields = {field["label"]: field for field in template["fields"]}
        self.assertEqual(fields["OPENAI_API_KEY"]["type"], "CONCEALED")
        self.assertEqual(fields["ACCOUNT"]["type"], "STRING")
        self.assertEqual(fields["OPENAI_API_KEY"]["value"], "provider-secret")
        self.assertNotIn("OP_SERVICE_ACCOUNT_TOKEN", json.dumps(template))

    def test_op_runner_uses_minimal_environment_and_stdin(self):
        tool = load_module()
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            log_path = root / "log.json"
            fake_op = root / "op"
            fake_op.write_text(
                "#!/usr/bin/env python3\n"
                "import json, os, sys\n"
                "payload = sys.stdin.read()\n"
                "json.dump({'argv': sys.argv[1:], 'env': dict(os.environ), 'stdin': payload}, open(os.environ['FAKE_LOG'], 'w'))\n"
                "print(json.dumps({'id':'item-id','vault':{'id':'vault-id'},'fields':[]}))\n"
            )
            fake_op.chmod(0o755)
            result = tool.run_op_json(
                op_bin=fake_op,
                argv=["item", "create", "--vault", "Ken Deploy Production", "-"],
                token="service-account-token",
                stdin_document={"title": "openai-production"},
                extra_env={"FAKE_LOG": str(log_path)},
            )
            self.assertEqual(result["id"], "item-id")
            logged = json.loads(log_path.read_text())
            self.assertEqual(
                logged["argv"],
                ["item", "create", "--vault", "Ken Deploy Production", "-"],
            )
            self.assertEqual(json.loads(logged["stdin"]), {"title": "openai-production"})
            self.assertEqual(logged["env"]["OP_SERVICE_ACCOUNT_TOKEN"], "service-account-token")
            allowed = {
                "FAKE_LOG",
                "HOME",
                "LANG",
                "LC_ALL",
                "OP_SERVICE_ACCOUNT_TOKEN",
                "PATH",
                "TMPDIR",
                "__CF_USER_TEXT_ENCODING",
            }
            self.assertFalse(set(logged["env"]) - allowed, logged["env"])
            self.assertNotIn("service-account-token", " ".join(logged["argv"]))

    def test_service_account_scope_requires_exactly_one_named_vault(self):
        tool = load_module()
        identity = {"type": "SERVICE_ACCOUNT", "name": "ken-deploy-production"}
        vaults = [{"id": "prod-id", "name": "Ken Deploy Production"}]
        tool.validate_service_account_scope(identity, vaults, "Ken Deploy Production")
        with self.assertRaisesRegex(ValueError, "exactly one vault"):
            tool.validate_service_account_scope(identity, vaults + [{"id": "x", "name": "Other"}], "Ken Deploy Production")
        with self.assertRaisesRegex(ValueError, "service account"):
            tool.validate_service_account_scope({"type": "USER"}, vaults, "Ken Deploy Production")

    def test_populate_item_validates_scope_and_writes_template_over_stdin(self):
        tool = load_module()
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            log_path = root / "calls.jsonl"
            fake_op = root / "op"
            fake_op.write_text(
                "#!/usr/bin/env python3\n"
                "import json, os, sys\n"
                "args = sys.argv[1:]\n"
                "stdin = sys.stdin.read()\n"
                "with open(os.environ['FAKE_LOG'], 'a') as log:\n"
                "    log.write(json.dumps({'argv': args, 'stdin': stdin}) + '\\n')\n"
                "if args == ['whoami', '--format=json']:\n"
                "    result = {'type':'SERVICE_ACCOUNT','name':'ken-deploy-production'}\n"
                "elif args == ['vault', 'list', '--format=json']:\n"
                "    result = [{'id':'vault-id','name':'Ken Deploy Production'}]\n"
                "elif args == ['item', 'list', '--vault', 'Ken Deploy Production', '--format=json']:\n"
                "    result = []\n"
                "elif args == ['item', 'create', '--vault', 'Ken Deploy Production', '-']:\n"
                "    template = json.loads(stdin)\n"
                "    result = {'id':'item-id','title':template['title'],'vault':{'id':'vault-id'},'fields':template['fields']}\n"
                "elif args == ['item', 'get', 'item-id', '--vault', 'Ken Deploy Production', '--format=json']:\n"
                "    result = {'id':'item-id','title':'openai-production','vault':{'id':'vault-id'},'fields':[{'id':'openai-api-key','label':'OPENAI_API_KEY','type':'CONCEALED','value':'provider-secret'}]}\n"
                "else:\n"
                "    raise SystemExit(7)\n"
                "print(json.dumps(result))\n"
            )
            fake_op.chmod(0o755)
            status = tool.populate_item(
                op_bin=fake_op,
                token="service-account-token",
                expected_vault="Ken Deploy Production",
                coordinate="ken-agents|OPENAI_API_KEY|Ken Deploy Production",
                title="openai-production",
                concealed_fields={"OPENAI_API_KEY": "provider-secret"},
                text_fields={},
                extra_env={"FAKE_LOG": str(log_path)},
            )
            self.assertEqual(status["status"], "verified")
            calls = [json.loads(line) for line in log_path.read_text().splitlines()]
            create = next(call for call in calls if call["argv"][:2] == ["item", "create"])
            self.assertNotIn("provider-secret", " ".join(create["argv"]))
            self.assertEqual(
                next(field for field in json.loads(create["stdin"])["fields"] if field["label"] == "OPENAI_API_KEY")["value"],
                "provider-secret",
            )

    def test_populate_item_refuses_duplicate_title(self):
        tool = load_module()
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            fake_op = root / "op"
            fake_op.write_text(
                "#!/usr/bin/env python3\n"
                "import json, sys\n"
                "args = sys.argv[1:]\n"
                "if args == ['whoami', '--format=json']:\n"
                "    result = {'type':'SERVICE_ACCOUNT','name':'ken-deploy-production'}\n"
                "elif args == ['vault', 'list', '--format=json']:\n"
                "    result = [{'id':'vault-id','name':'Ken Deploy Production'}]\n"
                "elif args == ['item', 'list', '--vault', 'Ken Deploy Production', '--format=json']:\n"
                "    result = [{'id':'one','title':'openai-production'},{'id':'two','title':'openai-production'}]\n"
                "else:\n"
                "    raise SystemExit(7)\n"
                "print(json.dumps(result))\n"
            )
            fake_op.chmod(0o755)
            with self.assertRaisesRegex(ValueError, "duplicate item title"):
                tool.populate_item(
                    op_bin=fake_op,
                    token="service-account-token",
                    expected_vault="Ken Deploy Production",
                    coordinate="x",
                    title="openai-production",
                    concealed_fields={"OPENAI_API_KEY": "provider-secret"},
                    text_fields={},
                )

    def test_item_readback_requires_exact_structural_shape(self):
        tool = load_module()
        item = {
            "id": "item-id",
            "title": "openai-production",
            "vault": {"id": "vault-id"},
            "fields": [
                {"id": "api-key", "label": "OPENAI_API_KEY", "type": "CONCEALED", "value": "not-returned"},
                {"id": "account", "label": "ACCOUNT", "type": "STRING", "value": "not-returned"},
            ],
        }
        status = tool.verify_item_shape(
            coordinate="ken-agents|OPENAI_API_KEY|Ken Deploy Production",
            item=item,
            expected_vault_id="vault-id",
            expected_title="openai-production",
            expected_fields={"OPENAI_API_KEY": "CONCEALED", "ACCOUNT": "STRING"},
        )
        self.assertNotIn("not-returned", json.dumps(status))
        self.assertEqual(status["item_id"], "item-id")
        self.assertEqual(status["fields"]["OPENAI_API_KEY"], "CONCEALED")
        with self.assertRaisesRegex(ValueError, "unexpected field"):
            tool.verify_item_shape(
                coordinate="x",
                item={**item, "fields": item["fields"] + [{"id": "extra", "label": "EXTRA", "type": "STRING", "value": "x"}]},
                expected_vault_id="vault-id",
                expected_title="openai-production",
                expected_fields={"OPENAI_API_KEY": "CONCEALED", "ACCOUNT": "STRING"},
            )

    def test_cli_output_is_value_free(self):
        with tempfile.TemporaryDirectory() as temp:
            request = Path(temp) / "request.json"
            request.write_text(
                json.dumps(
                    {
                        "left": "secret-one",
                        "right": "secret-two",
                    }
                )
            )
            request.chmod(stat.S_IRUSR | stat.S_IWUSR)
            completed = subprocess.run(
                [str(SCRIPT), "compare", "--request", str(request)],
                check=False,
                text=True,
                capture_output=True,
                env={"PATH": os.environ.get("PATH", ""), "LANG": "C.UTF-8"},
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(json.loads(completed.stdout), {"status": "different-value"})
            self.assertNotIn("secret-one", completed.stdout + completed.stderr)
            self.assertNotIn("secret-two", completed.stdout + completed.stderr)

    def test_populate_cli_reads_secret_envelope_from_stdin(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            fake_op = root / "op"
            fake_op.write_text(
                "#!/usr/bin/env python3\n"
                "import json, sys\n"
                "args = sys.argv[1:]\n"
                "stdin = sys.stdin.read()\n"
                "if args == ['whoami', '--format=json']:\n"
                "    result = {'type':'SERVICE_ACCOUNT','name':'ken-ci-runtime'}\n"
                "elif args == ['vault', 'list', '--format=json']:\n"
                "    result = [{'id':'ci-id','name':'Ken CI Runtime'}]\n"
                "elif args == ['item', 'list', '--vault', 'Ken CI Runtime', '--format=json']:\n"
                "    result = []\n"
                "elif args == ['item', 'create', '--vault', 'Ken CI Runtime', '-']:\n"
                "    template = json.loads(stdin)\n"
                "    result = {'id':'item-id','title':template['title'],'vault':{'id':'ci-id'},'fields':template['fields']}\n"
                "elif args == ['item', 'get', 'item-id', '--vault', 'Ken CI Runtime', '--format=json']:\n"
                "    result = {'id':'item-id','title':'openai-ci','vault':{'id':'ci-id'},'fields':[{'id':'openai-api-key','label':'OPENAI_API_KEY','type':'CONCEALED','value':'provider-secret'}]}\n"
                "else:\n"
                "    raise SystemExit(7)\n"
                "print(json.dumps(result))\n"
            )
            fake_op.chmod(0o755)
            envelope = {
                "token": "service-account-token",
                "vault": "Ken CI Runtime",
                "coordinate": "ken-scraping|OPENAI_API_KEY|Ken CI Runtime",
                "title": "openai-ci",
                "concealed_fields": {"OPENAI_API_KEY": "provider-secret"},
                "text_fields": {},
            }
            completed = subprocess.run(
                [str(SCRIPT), "populate", "--op-bin", str(fake_op)],
                input=json.dumps(envelope),
                check=False,
                text=True,
                capture_output=True,
                env={"PATH": os.environ.get("PATH", ""), "LANG": "C.UTF-8"},
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            status = json.loads(completed.stdout)
            self.assertEqual(status["status"], "verified")
            combined = completed.stdout + completed.stderr
            self.assertNotIn("service-account-token", combined)
            self.assertNotIn("provider-secret", combined)


if __name__ == "__main__":
    unittest.main()
