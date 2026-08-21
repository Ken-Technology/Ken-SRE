import importlib.util
import json
import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "consolidate-1password.py"
CANONICAL = ROOT / "inventory" / "canonical-credentials.yaml"


def load_module():
    spec = importlib.util.spec_from_file_location("consolidate_onepassword", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class ConsolidateOnePasswordTests(unittest.TestCase):
    def test_source_authority_dispatch_reads_each_committed_scheme(self):
        tool = load_module()
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            op_log = root / "op-log.jsonl"
            fake_op = root / "op"
            fake_op.write_text(
                "#!/usr/bin/env python3\n"
                "import json, os, sys\n"
                "args = sys.argv[1:]\n"
                "with open(os.environ['OP_LOG'], 'a') as log: log.write(json.dumps(args) + '\\n')\n"
                "if '--file' in args:\n"
                "    sys.stdout.buffer.write(b'PRIVATE KEY BYTES\\n')\n"
                "elif 'SSH deploy - deploy@host.example' in args:\n"
                "    print(json.dumps({'title':'SSH deploy - deploy@host.example', 'notesPlain':'TOKEN=env-secret\\n', 'files':[{'name':'deploy_key'}]}))\n"
                "else:\n"
                "    print(json.dumps({'notesPlain':'TOKEN=env-secret\\n', 'fields':[{'label':'credential','value':'field-secret'}]}))\n"
            )
            fake_op.chmod(0o755)
            evidence = root / "hosts.json"
            evidence.write_text(json.dumps({"worldstream": {"host": "host.example"}}))
            adapter = tool.SourceOrchestrationAdapter(
                op_adapter=tool.OpSourceAdapter(
                    op_bin=fake_op,
                    source_token="source-token",
                    extra_env={"OP_LOG": str(op_log)},
                ),
                ssh_adapter=tool.DeployedSourceAdapter(
                    ssh_bin=fake_op,
                    source_token="ssh-source-token",
                    files={"185.183.35.189": root / "deployed.json"},
                ),
                evidence_adapter=tool.EvidenceSourceAdapter(root),
            )
            (root / "deployed.json").write_text(
                json.dumps({"OpenAi": {"ApiKey": "deployed-secret"}})
            )
            self.assertEqual(
                adapter.resolve("op://Development/source/credential"), "field-secret"
            )
            self.assertEqual(
                adapter.resolve("op-env://Development/source#TOKEN"), "env-secret"
            )
            self.assertEqual(
                adapter.resolve("op-title://Development/SSH deploy - deploy@host.example#host"),
                "host.example",
            )
            self.assertEqual(
                adapter.resolve("op-file://Development/SSH deploy - deploy@host.example/deploy_key"),
                "PRIVATE KEY BYTES\n",
            )
            self.assertEqual(
                adapter.resolve(
                    "deployed://185.183.35.189/var/www/appsettings.json#OpenAi.ApiKey"
                ),
                "deployed-secret",
            )
            self.assertEqual(
                adapter.resolve("evidence://hosts.json#worldstream.host"), "host.example"
            )
            calls = [json.loads(line) for line in op_log.read_text().splitlines()]
            self.assertEqual(calls[0][:2], ["item", "get"])
            self.assertEqual(calls[-1][-1], "deploy_key")

    def test_deployed_reader_uses_fixed_ssh_cat_and_strict_component_parser(self):
        tool = load_module()
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            log = root / "ssh.log"
            fake_ssh = root / "ssh"
            fake_ssh.write_text(
                "#!/usr/bin/env python3\n"
                "import json, os, sys\n"
                "args = sys.argv[1:]\n"
                "open(os.environ['SSH_LOG'], 'a').write(json.dumps(args) + '\\n')\n"
                "if args[-1] != '/etc/appsettings.json': raise SystemExit(2)\n"
                "print(json.dumps({'OpenAi': {'ApiKey': 'deployed-secret'}, 'ConnectionStrings': {'Db': 'Server=db;Database=ken;User Id=reader;Password=pw'}}))\n"
            )
            fake_ssh.chmod(0o755)
            adapter = tool.DeployedSourceAdapter(
                ssh_bin=fake_ssh,
                ssh_user="reader",
                extra_env={"SSH_LOG": str(log)},
            )
            self.assertEqual(
                adapter.resolve("deployed://host.example/etc/appsettings.json#OpenAi.ApiKey"),
                "deployed-secret",
            )
            self.assertEqual(
                adapter.resolve(
                    "deployed-component://host.example/etc/appsettings.json#ConnectionStrings.Db[password]"
                ),
                "pw",
            )
            calls = [json.loads(line) for line in log.read_text().splitlines()]
            self.assertEqual(calls[0], ["reader@host.example", "cat", "--", "/etc/appsettings.json"])
            self.assertTrue(all("source" not in arg for call in calls for arg in call))
            with self.assertRaisesRegex(ValueError, "connection string"):
                tool._parse_connection_string("Server=db;Password=pw;Password=other")

    def test_deployed_authority_rejects_shell_metacharacters(self):
        tool = load_module()
        shell_metacharacters = ";|&$`()<>*?!\\"
        for character in shell_metacharacters:
            authority = (
                "deployed://host.example/var/www/appsettings.json"
                f"{character}id#OpenAi.ApiKey"
            )
            with self.subTest(character=character), self.assertRaisesRegex(
                ValueError, "deployed path"
            ):
                tool._parse_source_authority(authority)

    def test_source_token_is_read_from_protected_file_not_cli_value(self):
        tool = load_module()
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            token_file = root / "source-token"
            token_file.write_text("source-account-token\n")
            token_file.chmod(0o600)
            args = type(
                "Args",
                (),
                {
                    "source_token_file": token_file,
                    "source_op_bin": Path("/usr/local/bin/op"),
                    "source_ssh_bin": None,
                    "source_ssh_key": None,
                    "source_ssh_user": None,
                    "evidence_root": None,
                },
            )()
            adapter = tool._source_adapter_from_options(args)
            self.assertEqual(adapter.op_adapter.source_token, "source-account-token")
            self.assertFalse(hasattr(args, "source_token"))

            token_file.chmod(0o644)
            with self.assertRaisesRegex(ValueError, "0600"):
                tool._source_adapter_from_options(args)

    def test_source_session_is_explicit_and_cannot_inherit_target_token(self):
        tool = load_module()
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            log_path = root / "source-session.json"
            fake_op = root / "op"
            fake_op.write_text(
                "#!/usr/bin/env python3\n"
                "import json, os\n"
                "json.dump({'has_service_token': 'OP_SERVICE_ACCOUNT_TOKEN' in os.environ}, open(os.environ['LOG'], 'w'))\n"
                "print(json.dumps({'fields':[{'label':'username','value':'source-secret'}]}))\n"
            )
            fake_op.chmod(0o755)
            adapter = tool.OpSourceAdapter(
                op_bin=fake_op,
                source_session=True,
                extra_env={"LOG": str(log_path), "OP_SERVICE_ACCOUNT_TOKEN": "must-reject"},
            )
            with self.assertRaisesRegex(ValueError, "extra environment"):
                adapter.resolve("op://Development/source/username")

            adapter = tool.OpSourceAdapter(
                op_bin=fake_op,
                source_session=True,
                extra_env={"LOG": str(log_path)},
            )
            adapter.resolve("op://Development/source/username")
            self.assertFalse(json.loads(log_path.read_text())["has_service_token"])

    def test_source_and_target_tokens_are_distinct(self):
        tool = load_module()
        with self.assertRaises(TypeError):
            tool.OpSourceAdapter(op_bin=Path("/no/such/op"), token="same")
        adapter = tool.MappingSourceAdapter({"authority": "secret"})
        adapter.source_token = "writer-token"
        with self.assertRaisesRegex(ValueError, "distinct"):
            tool._assert_distinct_source_target_tokens(adapter, "writer-token")

    def test_discovery_resolves_every_unique_selected_authority(self):
        tool = load_module()
        entries = self._batch_registry()["entries"]
        entries[1]["source_authority"] = entries[0]["source_authority"]
        calls = []

        class Spy(tool.ProtectedSourceAdapter):
            def resolve(self, authority):
                calls.append(authority)
                return "same-secret"

        result = tool.discover_batch(
            registry=self._batch_registry(entries=entries), source_adapter=Spy()
        )
        self.assertEqual(result["status"], "discovered")
        self.assertEqual(set(calls), {entries[0]["source_authority"]})
        self.assertNotIn("same-secret", json.dumps(result))

    def test_shared_target_rejects_mixed_field_types(self):
        tool = load_module()
        entries = self._batch_registry()["entries"]
        entries[1]["canonical_field"] = entries[0]["canonical_field"]
        entries[1]["field_type"] = "string"
        with self.assertRaisesRegex(ValueError, "field type"):
            tool.plan_batch(
                registry=self._batch_registry(entries=entries),
                source_adapter=tool.MappingSourceAdapter(
                    {entry["source_authority"]: "same" for entry in entries}
                ),
            )

    def test_populate_registry_requires_exact_item_field_partition(self):
        tool = load_module()
        registry = self._batch_registry()
        registry["entries"][1]["canonical_field"] = "SECOND_TOKEN"
        request = {
            "token": "writer-token",
            "vault": "Ken Deploy Production",
            "coordinate": registry["entries"][0]["coordinate"],
            "title": "shared-production",
            "concealed_fields": {"FIRST_TOKEN": "secret"},
            "text_fields": {},
        }
        with self.assertRaisesRegex(ValueError, "exact.*field|complete"):
            tool._registered_populate_target(document=registry, request=request)

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

    def test_existing_item_merge_preserves_unrelated_fields_sections_and_metadata(self):
        tool = load_module()
        existing = {
            "id": "item-id",
            "category": "API_CREDENTIAL",
            "title": "openai-production",
            "vault": {"id": "vault-id"},
            "fields": [
                {"id": "openai-api-key", "label": "OPENAI_API_KEY", "type": "CONCEALED", "value": "old"},
                {"id": "account", "label": "ACCOUNT", "type": "STRING", "value": "ken"},
            ],
            "sections": [{"id": "custom", "label": "Custom", "fields": [{"id": "url", "label": "URL", "type": "STRING", "value": "https://example.test"}]}],
            "notesPlain": "keep this note",
        }
        merged, preserved = tool.merge_item_template(
            existing=existing,
            title="openai-production",
            fields={"OPENAI_API_KEY": "new"},
            text_fields={},
        )
        self.assertEqual(merged["sections"], existing["sections"])
        self.assertEqual(merged["notesPlain"], existing["notesPlain"])
        self.assertEqual(next(field for field in merged["fields"] if field["label"] == "ACCOUNT"), existing["fields"][1])
        self.assertEqual(next(field for field in merged["fields"] if field["label"] == "OPENAI_API_KEY")["value"], "new")
        self.assertNotIn("old", json.dumps(preserved))

    def test_existing_passkey_item_is_rejected_before_edit(self):
        tool = load_module()
        with self.assertRaisesRegex(ValueError, "passkey"):
            tool.merge_item_template(
                existing={"category": "LOGIN", "title": "openai-production", "fields": [{"type": "PASSKEY", "label": "passkey"}], "sections": []},
                title="openai-production",
                fields={"OPENAI_API_KEY": "new"},
            )

    def test_op_runner_uses_minimal_environment_and_stdin(self):
        tool = load_module()
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            log_path = root / "log.json"
            fake_op = root / "op"
            fake_op.write_text(
                "#!/usr/bin/env python3\n"
                "import json, os, stat, sys\n"
                "payload = sys.stdin.read()\n"
                "json.dump({'argv': sys.argv[1:], 'env': dict(os.environ), 'stdin': payload, 'home_mode': stat.S_IMODE(os.stat(os.environ['HOME']).st_mode)}, open(os.environ['FAKE_LOG'], 'w'))\n"
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
            self.assertNotEqual(logged["env"]["HOME"], "/nonexistent")
            self.assertEqual(logged["home_mode"], 0o700)
            self.assertFalse(Path(logged["env"]["HOME"]).exists())
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
            registry = self._single_target_registry(
                coordinate="ken-scraping|OPENAI_API_KEY|Ken CI Runtime",
                vault="Ken CI Runtime",
                item="openai-ci",
                field="OPENAI_API_KEY",
            )
            registry_path = root / "canonical.yaml"
            registry_path.write_text(yaml.safe_dump(registry, sort_keys=False))
            completed = subprocess.run(
                [
                    str(SCRIPT),
                    "populate",
                    "--op-bin",
                    str(fake_op),
                    "--registry",
                    str(registry_path),
                ],
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

    def _batch_registry(self, *, entries=None):
        item = {"id": "shared-production", "vault": "Ken Deploy Production", "aliases": []}
        base = {
            "schema_version": 1,
            "organization": "Ken-Technology",
            "allowed_vaults": [
                "Ken CI Runtime",
                "Ken Deploy Nonproduction",
                "Ken Deploy Production",
            ],
            "canonical_items": [item],
            "entries": entries
            or [
                {
                    "coordinate": "repo|FIRST_TOKEN|Ken Deploy Production",
                    "canonical_id": "shared-production",
                    "aliases": [],
                    "disposition": "canonical-item",
                    "verification_status": "verified-readable",
                    "source_authority": "op://Development/source/first",
                    "canonical_vault": "Ken Deploy Production",
                    "canonical_item": "shared-production",
                    "canonical_field": "FIRST_TOKEN",
                    "field_type": "concealed",
                    "environment": "production",
                    "consumer_repositories": ["repo"],
                },
                {
                    "coordinate": "repo|SECOND_TOKEN|Ken Deploy Production",
                    "canonical_id": "shared-production",
                    "aliases": [],
                    "disposition": "canonical-item",
                    "verification_status": "existing-direct-reference",
                    "source_authority": "op://Development/source/second",
                    "canonical_vault": "Ken Deploy Production",
                    "canonical_item": "shared-production",
                    "canonical_field": "SECOND_TOKEN",
                    "field_type": "concealed",
                    "environment": "production",
                    "consumer_repositories": ["repo"],
                },
            ],
        }
        return base

    def _single_target_registry(self, *, coordinate, vault, item, field):
        return {
            "schema_version": 1,
            "organization": "Ken-Technology",
            "allowed_vaults": [
                "Ken CI Runtime",
                "Ken Deploy Nonproduction",
                "Ken Deploy Production",
            ],
            "canonical_items": [{"id": item, "vault": vault, "aliases": []}],
            "entries": [
                {
                    "coordinate": coordinate,
                    "canonical_id": item,
                    "aliases": [],
                    "disposition": "dedicated-item",
                    "verification_status": "verified-readable",
                    "source_authority": "op://Development/source/value",
                    "canonical_vault": vault,
                    "canonical_item": item,
                    "canonical_field": field,
                    "field_type": "concealed",
                    "environment": {
                        "Ken CI Runtime": "ci",
                        "Ken Deploy Nonproduction": "nonproduction",
                        "Ken Deploy Production": "production",
                    }[vault],
                    "consumer_repositories": ["ken-scraping"],
                }
            ],
        }

    def _write_registry(self, root, document):
        path = root / "canonical.yaml"
        path.write_text(yaml.safe_dump(document, sort_keys=False))
        return path

    def test_batch_plan_loads_strict_registry_and_groups_exact_target_fields(self):
        tool = load_module()
        with tempfile.TemporaryDirectory() as temp:
            path = self._write_registry(Path(temp), self._batch_registry())
            plan = tool.plan_batch(
                registry_path=path,
                source_adapter=tool.MappingSourceAdapter(
                    {
                        "op://Development/source/first": "first-secret",
                        "op://Development/source/second": "second-secret",
                    }
                ),
            )
        self.assertEqual(plan["status"], "planned")
        self.assertEqual(plan["item_count"], 1)
        self.assertEqual(plan["field_count"], 2)
        self.assertEqual(plan["items"][0]["vault"], "Ken Deploy Production")
        self.assertEqual(plan["items"][0]["item"], "shared-production")
        self.assertEqual(
            [field["label"] for field in plan["items"][0]["fields"]],
            ["FIRST_TOKEN", "SECOND_TOKEN"],
        )
        serialized = json.dumps(plan)
        self.assertNotIn("first-secret", serialized)
        self.assertNotIn("second-secret", serialized)

    def test_batch_plan_rejects_duplicate_target_field_with_different_sources(self):
        tool = load_module()
        entries = self._batch_registry()["entries"]
        entries[1]["canonical_field"] = entries[0]["canonical_field"]
        with self.assertRaisesRegex(ValueError, "conflicting values"):
            tool.plan_batch(
                registry=self._batch_registry(entries=entries),
                source_adapter=tool.MappingSourceAdapter(
                    {
                        entries[0]["source_authority"]: "one",
                        entries[1]["source_authority"]: "two",
                    }
                ),
            )

        plan = tool.plan_batch(
            registry=self._batch_registry(entries=entries),
            source_adapter=tool.MappingSourceAdapter(
                {
                    entries[0]["source_authority"]: "same-secret",
                    entries[1]["source_authority"]: "same-secret",
                }
            ),
        )
        self.assertEqual(plan["field_count"], 1)

    def test_batch_selector_ignores_verified_non_item_rows(self):
        tool = load_module()
        entries = self._batch_registry()["entries"]
        entries.append(
            {
                "coordinate": "repo|CI_URL|no-1password-target",
                "canonical_id": None,
                "aliases": [],
                "disposition": "github-variable",
                "verification_status": "verified-readable",
                "source_authority": "op://Development/source/url",
                "canonical_vault": None,
                "canonical_item": None,
                "canonical_field": None,
                "environment": "none",
                "consumer_repositories": ["repo"],
            }
        )
        plan = tool.plan_batch(
            registry=self._batch_registry(entries=entries),
            source_adapter=tool.MappingSourceAdapter(
                {
                    "op://Development/source/first": "first-secret",
                    "op://Development/source/second": "second-secret",
                }
            ),
        )
        self.assertEqual(plan["item_count"], 1)
        self.assertEqual(plan["field_count"], 2)

    def test_missing_field_type_fails_closed(self):
        tool = load_module()
        entries = self._batch_registry()["entries"]
        entries[0].pop("field_type")
        with self.assertRaisesRegex(ValueError, "field type"):
            tool.plan_batch(
                registry=self._batch_registry(entries=entries),
                source_adapter=tool.MappingSourceAdapter(
                    {
                        "op://Development/source/first": "first-secret",
                        "op://Development/source/second": "second-secret",
                    }
                ),
            )

    def test_op_authority_parser_supports_source_vault_titles_and_files(self):
        tool = load_module()
        self.assertEqual(
            tool._parse_op_authority("op-env://Development/ken-agents-env#TOKEN"),
            ("Development", "ken-agents-env", "TOKEN"),
        )
        self.assertEqual(
            tool._parse_op_authority("op-title://Development/SSH deploy - user@host#username"),
            ("Development", "SSH deploy - user@host", "username"),
        )
        self.assertEqual(
            tool._parse_op_authority("op-file://Development/SSH deploy/deploy_key"),
            ("Development", "SSH deploy", "deploy_key"),
        )

    def test_op_source_adapter_uses_explicit_source_token_for_spaced_authority(self):
        tool = load_module()
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            log_path = root / "source-call.json"
            fake_op = root / "op"
            fake_op.write_text(
                "#!/usr/bin/env python3\n"
                "import json, os, sys\n"
                "json.dump({'argv':sys.argv[1:], 'token':os.environ['OP_SERVICE_ACCOUNT_TOKEN']}, open(os.environ['LOG'], 'w'))\n"
                "print(json.dumps({'fields':[{'label':'username','value':'source-secret'}]}))\n"
            )
            fake_op.chmod(0o755)
            value = tool.OpSourceAdapter(
                op_bin=fake_op,
                source_token="source-account-token",
                extra_env={"LOG": str(log_path)},
            ).resolve("op-title://Development/SSH deploy - user@host#username")
            self.assertEqual(value, "source-secret")
            call = json.loads(log_path.read_text())
            self.assertEqual(call["token"], "source-account-token")
            self.assertEqual(
                call["argv"],
                [
                    "item",
                    "get",
                    "SSH deploy - user@host",
                    "--vault",
                    "Development",
                    "--format=json",
                ],
            )
            self.assertNotIn("source-secret", json.dumps(call))

    def test_discover_cli_reads_protected_source_request_without_printing_values(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            registry_path = root / "canonical.yaml"
            registry_path.write_text(
                yaml.safe_dump(self._single_target_registry(
                    coordinate="repo|TOKEN|Ken Deploy Production",
                    vault="Ken Deploy Production",
                    item="service-production",
                    field="TOKEN",
                ), sort_keys=False)
            )
            request_path = root / "sources.json"
            request_path.write_text(json.dumps({
                "sources": {
                    "deployed://185.183.35.189/config#TOKEN": "deployed-secret",
                }
            }))
            request_path.chmod(0o600)
            document = yaml.safe_load(registry_path.read_text())
            document["entries"][0]["source_authority"] = "deployed://185.183.35.189/config#TOKEN"
            registry_path.write_text(yaml.safe_dump(document, sort_keys=False))
            completed = subprocess.run(
                [str(SCRIPT), "discover", "--registry", str(registry_path), "--request", str(request_path)],
                check=False,
                text=True,
                capture_output=True,
                env={"PATH": os.environ.get("PATH", ""), "LANG": "C.UTF-8"},
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(json.loads(completed.stdout)["status"], "discovered")
            self.assertNotIn("deployed-secret", completed.stdout + completed.stderr)

    def test_verify_cli_is_standalone_and_value_free(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            registry_path = root / "canonical.yaml"
            registry_path.write_text(yaml.safe_dump(self._single_target_registry(
                coordinate="repo|TOKEN|Ken Deploy Production",
                vault="Ken Deploy Production",
                item="service-production",
                field="TOKEN",
            ), sort_keys=False))
            ledger_path = root / "ledger.yaml"
            ledger_path.write_text(yaml.safe_dump({
                "items": [{
                    "vault": "Ken Deploy Production",
                    "item": "service-production",
                    "item_id": "item-id",
                    "fields": {"TOKEN": "CONCEALED"},
                }],
            }, sort_keys=False))
            completed = subprocess.run(
                [
                    str(SCRIPT),
                    "verify",
                    "--registry",
                    str(registry_path),
                    "--ledger",
                    str(ledger_path),
                ],
                check=False,
                text=True,
                capture_output=True,
                env={"PATH": os.environ.get("PATH", ""), "LANG": "C.UTF-8"},
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(json.loads(completed.stdout)["status"], "verified")

    def test_populate_cli_refuses_target_not_declared_in_registry(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            registry_path = root / "canonical.yaml"
            registry_path.write_text(yaml.safe_dump(self._single_target_registry(
                coordinate="repo|OTHER|Ken CI Runtime",
                vault="Ken CI Runtime",
                item="other",
                field="OTHER",
            ), sort_keys=False))
            envelope = {
                "token": "service-account-token",
                "vault": "Ken CI Runtime",
                "coordinate": "repo|TOKEN|Ken CI Runtime",
                "title": "unregistered",
                "concealed_fields": {"TOKEN": "provider-secret"},
                "text_fields": {},
            }
            completed = subprocess.run(
                [str(SCRIPT), "populate", "--registry", str(registry_path), "--op-bin", "/no/such/op"],
                input=json.dumps(envelope),
                check=False,
                text=True,
                capture_output=True,
                env={"PATH": os.environ.get("PATH", ""), "LANG": "C.UTF-8"},
            )
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("registry", completed.stderr)
            self.assertNotIn("provider-secret", completed.stdout + completed.stderr)

    def test_populate_item_rejects_unapproved_vault_before_invoking_op(self):
        tool = load_module()
        with self.assertRaisesRegex(ValueError, "approved vault"):
            tool.populate_item(
                op_bin=Path("/no/such/op"),
                token="service-account-token",
                expected_vault="Other",
                coordinate="repo|TOKEN|Other",
                title="other",
                concealed_fields={"TOKEN": "provider-secret"},
                text_fields={},
            )

    def test_batch_plan_rejects_unresolved_and_unprotected_non_op_authorities(self):
        tool = load_module()
        unresolved = self._batch_registry()["entries"][:1]
        unresolved[0]["verification_status"] = "unresolved"
        unresolved[0]["source_authority"] = None
        with self.assertRaisesRegex(ValueError, "unresolved"):
            tool.plan_batch(registry=self._batch_registry(entries=unresolved))

        non_op = self._batch_registry()["entries"][:1]
        non_op[0]["source_authority"] = "deployed://host/config#TOKEN"
        with self.assertRaisesRegex(ValueError, "protected source adapter"):
            tool.plan_batch(registry=self._batch_registry(entries=non_op))

    def test_batch_plan_allows_non_op_source_only_through_protected_adapter(self):
        tool = load_module()
        entries = self._batch_registry()["entries"][:1]
        entries[0]["source_authority"] = "deployed://host/config#TOKEN"
        plan = tool.plan_batch(
            registry=self._batch_registry(entries=entries),
            source_adapter=tool.MappingSourceAdapter(
                {"deployed://host/config#TOKEN": "deployed-secret"}
            ),
        )
        self.assertEqual(plan["field_count"], 1)
        self.assertNotIn("deployed-secret", json.dumps(plan))

    def test_batch_execution_is_idempotent_create_edit_and_readback_value_free(self):
        tool = load_module()
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            registry_path = self._write_registry(root, self._batch_registry())
            state_path = root / "state.json"
            calls_path = root / "calls.jsonl"
            fake_op = root / "op"
            fake_op.write_text(
                "#!/usr/bin/env python3\n"
                "import json, os, sys\n"
                "args = sys.argv[1:]\n"
                "stdin = sys.stdin.read()\n"
                "with open(os.environ['CALLS'], 'a') as f: f.write(json.dumps({'argv': args}) + '\\n')\n"
                "state_path = os.environ['STATE']\n"
                "try: state = json.load(open(state_path))\n"
                "except FileNotFoundError: state = {'items': {}}\n"
                "if args == ['whoami', '--format=json']: result = {'type':'SERVICE_ACCOUNT'}\n"
                "elif args == ['vault', 'list', '--format=json']: result = [{'id':'vault-id','name':'Ken Deploy Production'}]\n"
                "elif args == ['item', 'list', '--vault', 'Ken Deploy Production', '--format=json']:\n"
                "    result = [{'id': item['id'], 'title': item['title']} for item in state['items'].values()]\n"
                "elif args[:2] == ['item', 'create']:\n"
                "    template = json.loads(stdin); item_id = 'item-' + str(len(state['items']) + 1)\n"
                "    state['items'][item_id] = {'id':item_id, 'title':template['title'], 'vault':{'id':'vault-id'}, 'fields':template['fields']}\n"
                "    result = state['items'][item_id]; json.dump(state, open(state_path, 'w'))\n"
                "elif args[:2] == ['item', 'edit']:\n"
                "    template = json.loads(stdin); item_id = args[2]; state['items'][item_id].update({'title':template['title'], 'fields':template['fields']})\n"
                "    result = state['items'][item_id]; json.dump(state, open(state_path, 'w'))\n"
                "elif args[:2] == ['item', 'get']:\n"
                "    result = state['items'][args[2]]\n"
                "else: raise SystemExit(7)\n"
                "print(json.dumps(result))\n"
            )
            fake_op.chmod(0o755)
            adapter = tool.MappingSourceAdapter(
                {
                    "op://Development/source/first": "first-secret",
                    "op://Development/source/second": "second-secret",
                }
            )
            env = {"STATE": str(state_path), "CALLS": str(calls_path)}
            plan = tool.plan_batch(registry_path=registry_path, source_adapter=adapter)
            first = tool.execute_batch(
                plan=plan,
                op_bin=fake_op,
                token="service-account-token",
                source_adapter=adapter,
                extra_env=env,
            )
            second = tool.execute_batch(
                plan=plan,
                op_bin=fake_op,
                token="service-account-token",
                source_adapter=adapter,
                extra_env=env,
            )
            self.assertEqual(first["status"], "completed")
            self.assertEqual(second["status"], "completed")
            self.assertEqual(first["items"], second["items"])
            calls = [json.loads(line) for line in calls_path.read_text().splitlines()]
            writes = [call for call in calls if call["argv"][:2] in (["item", "create"], ["item", "edit"])]
            self.assertEqual([call["argv"][:2] for call in writes], [["item", "create"], ["item", "edit"]])
            joined_argv = json.dumps(calls)
            self.assertNotIn("first-secret", joined_argv)
            self.assertNotIn("second-secret", joined_argv)

    def test_batch_execution_reports_partial_write_without_values(self):
        tool = load_module()
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            entries = self._batch_registry()["entries"]
            entries[1]["canonical_item"] = "zz-second-production"
            entries[1]["canonical_id"] = "zz-second-production"
            document = self._batch_registry(entries=entries)
            document["canonical_items"].append(
                {"id": "zz-second-production", "vault": "Ken Deploy Production", "aliases": []}
            )
            registry_path = self._write_registry(root, document)
            fake_op = root / "op"
            fake_op.write_text(
                "#!/usr/bin/env python3\n"
                "import json, sys\n"
                "args = sys.argv[1:]; stdin = sys.stdin.read()\n"
                "if args == ['whoami', '--format=json']: result = {'type':'SERVICE_ACCOUNT'}\n"
                "elif args == ['vault', 'list', '--format=json']: result = [{'id':'vault-id','name':'Ken Deploy Production'}]\n"
                "elif args == ['item', 'list', '--vault', 'Ken Deploy Production', '--format=json']: result = []\n"
                "elif args[:2] == ['item', 'create']:\n"
                "    template = json.loads(stdin)\n"
                "    if template['title'] == 'zz-second-production': raise SystemExit(8)\n"
                "    result = {'id':'first-id','title':template['title'],'vault':{'id':'vault-id'},'fields':template['fields']}\n"
                "elif args[:2] == ['item', 'get']:\n"
                "    result = {'id':'first-id','title':'shared-production','vault':{'id':'vault-id'},'fields':[{'label':'FIRST_TOKEN','type':'CONCEALED'}]}\n"
                "else: raise SystemExit(8)\n"
                "print(json.dumps(result))\n"
            )
            fake_op.chmod(0o755)
            adapter = tool.MappingSourceAdapter(
                {
                    "op://Development/source/first": "first-secret",
                    "op://Development/source/second": "second-secret",
                }
            )
            plan = tool.plan_batch(registry_path=registry_path, source_adapter=adapter)
            report = tool.execute_batch(
                plan=plan,
                op_bin=fake_op,
                token="service-account-token",
                source_adapter=adapter,
            )
            self.assertEqual(report["status"], "partial-failure")
            self.assertEqual(report["completed_count"], 1)
            self.assertEqual(report["failed_count"], 1)
            output = json.dumps(report)
            self.assertNotIn("first-secret", output)
            self.assertNotIn("second-secret", output)
            self.assertNotIn("service-account-token", output)


if __name__ == "__main__":
    unittest.main()
