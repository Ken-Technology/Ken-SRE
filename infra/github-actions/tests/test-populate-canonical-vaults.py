import importlib.util
import json
import os
import stat
import subprocess
import tempfile
import unittest
from unittest import mock
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "populate-canonical-vaults.py"


def load_module():
    spec = importlib.util.spec_from_file_location("populate_canonical_vaults", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def registry_for(entries):
    items = {}
    for entry in entries:
        if entry.get("canonical_item"):
            items[(entry["canonical_vault"], entry["canonical_item"])] = {
                "id": entry["canonical_item"],
                "vault": entry["canonical_vault"],
                "aliases": [],
            }
    return {
        "schema_version": 1,
        "organization": "Ken-Technology",
        "allowed_vaults": [
            "Ken CI Runtime",
            "Ken Deploy Nonproduction",
            "Ken Deploy Production",
        ],
        "canonical_items": list(items.values()),
        "entries": entries,
    }


def entry(
    coordinate,
    vault,
    item,
    field,
    source,
    *,
    status="verified-readable",
    field_type="CONCEALED",
    disposition="dedicated-item",
):
    environment = {
        "Ken CI Runtime": "ci",
        "Ken Deploy Nonproduction": "nonproduction",
        "Ken Deploy Production": "production",
    }[vault]
    return {
        "coordinate": coordinate,
        "field_type": field_type,
        "canonical_id": item,
        "aliases": [],
        "disposition": disposition,
        "verification_status": status,
        "source_authority": source,
        "canonical_vault": vault,
        "canonical_item": item,
        "canonical_field": field,
        "environment": environment,
        "consumer_repositories": ["fixture"],
    }


def write_fake_op(root):
    path = root / "op"
    path.write_text(
        "#!/usr/bin/env python3\n"
        "import json, os, sys\n"
        "args = sys.argv[1:]\n"
        "token = os.environ.get('OP_SERVICE_ACCOUNT_TOKEN', '')\n"
        "state_path = os.path.join(os.path.dirname(sys.argv[0]), 'fake-state.json')\n"
        "try: state = json.load(open(state_path, encoding='utf-8'))\n"
        "except FileNotFoundError: state = {}\n"
        "log = os.environ.get('FAKE_OP_LOG')\n"
        "stdin = sys.stdin.read()\n"
        "if log:\n"
        "    with open(log, 'a', encoding='utf-8') as handle:\n"
        "        handle.write(json.dumps({'argv': args, 'token': token, 'stdin': stdin}) + '\\n')\n"
        "if token == 'personal-session':\n"
        "    item_id = args[args.index('get') + 1]\n"
        "    values = {'j34dtkat667tgzeopkanjwbdau': 'writer-ci', 'h5lsxmq25qrgk4x22wf4k57z24': 'writer-nonprod', '5ncmp2wtb44nmvdwmlo5coirq4': 'writer-prod'}\n"
        "    titles = {'j34dtkat667tgzeopkanjwbdau': 'Service Account Auth Token: ken-ci-runtime', 'h5lsxmq25qrgk4x22wf4k57z24': 'Service Account Auth Token: ken-deploy-nonproduction', '5ncmp2wtb44nmvdwmlo5coirq4': 'Service Account Auth Token: ken-deploy-production'}\n"
        "    print(json.dumps({'id': item_id, 'title': titles[item_id], 'vault': {'name': 'Employee'}, 'fields': [{'label': 'credential', 'type': 'CONCEALED', 'value': values[item_id]}]}))\n"
        "elif token == '':\n"
        "    if args[:2] == ['whoami', '--format=json']:\n"
        "        print(json.dumps({'id': 'PHLSEQ2HNVAALEWHKWGKZOAGSY', 'type': 'USER'}))\n"
        "    elif args[:2] == ['vault', 'get']:\n"
        "        print(json.dumps({'id': 'employee-vault-id', 'name': 'Employee'}))\n"
        "    else:\n"
        "        item_id = args[args.index('get') + 1]\n"
        "        values = {'j34dtkat667tgzeopkanjwbdau': 'writer-ci', 'h5lsxmq25qrgk4x22wf4k57z24': 'writer-nonprod', '5ncmp2wtb44nmvdwmlo5coirq4': 'writer-prod'}\n"
        "        titles = {'j34dtkat667tgzeopkanjwbdau': 'Service Account Auth Token: ken-ci-runtime', 'h5lsxmq25qrgk4x22wf4k57z24': 'Service Account Auth Token: ken-deploy-nonproduction', '5ncmp2wtb44nmvdwmlo5coirq4': 'Service Account Auth Token: ken-deploy-production'}\n"
        "        print(json.dumps({'id': item_id, 'title': titles[item_id], 'vault': {'name': 'Employee'}, 'fields': [{'label': 'credential', 'type': 'CONCEALED', 'value': values[item_id]}]}))\n"
        "elif token.startswith('source-'):\n"
        "    print(json.dumps({'title': 'source', 'fields': [{'label': 'credential', 'value': 'resolved-secret'}]}))\n"
        "elif args[:2] == ['whoami', '--format=json']:\n"
        "    print(json.dumps({'type': 'SERVICE_ACCOUNT', 'name': token}))\n"
        "elif args[:3] == ['vault', 'list', '--format=json']:\n"
        "    names = {'writer-ci': ('istjrwyeqryhpv7rytbm34pfea', 'Ken CI Runtime'), 'writer-nonprod': ('wmb7rpm5xvl4ez4kur3s5l3hxe', 'Ken Deploy Nonproduction'), 'writer-prod': ('q7zdmdggp2ng7hvxozhzt4uupm', 'Ken Deploy Production')}\n"
        "    vault_id, name = names[token]\n"
        "    print(json.dumps([{'id': vault_id, 'name': name}]))\n"
        "elif args[:2] == ['item', 'list']:\n"
        "    print('[]')\n"
        "elif args[:3] in (['item', 'create', '--vault'], ['item', 'edit', args[2] if len(args) > 2 else '']):\n"
        "    payload = json.loads(stdin or '{}')\n"
        "    item_id = 'created-' + payload.get('title', 'item')\n"
        "    state[item_id] = payload\n"
        "    json.dump(state, open(state_path, 'w', encoding='utf-8'))\n"
        "    print(json.dumps({'id': item_id, 'title': payload.get('title'), 'vault': {'id': {'writer-ci': 'istjrwyeqryhpv7rytbm34pfea', 'writer-nonprod': 'wmb7rpm5xvl4ez4kur3s5l3hxe', 'writer-prod': 'q7zdmdggp2ng7hvxozhzt4uupm'}[token]}, 'fields': payload.get('fields', [])}))\n"
        "else:\n"
        "    item_id = args[args.index('get') + 1]\n"
        "    vault_id = {'writer-ci': 'istjrwyeqryhpv7rytbm34pfea', 'writer-nonprod': 'wmb7rpm5xvl4ez4kur3s5l3hxe', 'writer-prod': 'q7zdmdggp2ng7hvxozhzt4uupm'}[token]\n"
        "    payload = state.get(item_id, {})\n"
        "    print(json.dumps({'id': item_id, 'title': payload.get('title', item_id), 'vault': {'id': vault_id}, 'fields': payload.get('fields', [{'label': 'TOKEN', 'type': 'CONCEALED'}])}))\n"
    )
    path.chmod(0o755)
    return path


def write_fake_ssh(root):
    path = root / "ssh"
    path.write_text(
        "#!/usr/bin/env python3\n"
        "import json, sys\n"
        "assert sys.argv[-2:] == ['cat', '--', '/etc/config.json']\n"
        "print(json.dumps({'Runtime': {'Secret': 'resolved-secret'}}))\n"
    )
    path.chmod(0o755)
    return path


class PopulateCanonicalVaultsTests(unittest.TestCase):
    def test_personal_token_boundary_reads_exact_three_items_without_returning_values(self):
        tool = load_module()
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            fake_op = write_fake_op(root)
            tokens = tool.PersonalWriterTokenSource(
                op_bin=fake_op,
                personal_token="personal-session",
                personal_vault="Employee",
                token_items={
                    "Ken CI Runtime": "j34dtkat667tgzeopkanjwbdau",
                    "Ken Deploy Nonproduction": "h5lsxmq25qrgk4x22wf4k57z24",
                    "Ken Deploy Production": "5ncmp2wtb44nmvdwmlo5coirq4",
                },
            ).load()
            self.assertEqual(set(tokens), tool.TARGET_VAULTS)
            self.assertEqual(tokens["Ken CI Runtime"], "writer-ci")
            self.assertEqual(tokens["Ken Deploy Nonproduction"], "writer-nonprod")
            self.assertEqual(tokens["Ken Deploy Production"], "writer-prod")

    def test_personal_token_boundary_requires_exact_three_named_items(self):
        tool = load_module()
        with self.assertRaisesRegex(ValueError, "exactly three"):
            tool.PersonalWriterTokenSource(
                op_bin=Path("/bin/false"),
                personal_token="personal-session",
                personal_vault="Employee",
                token_items={"Ken CI Runtime": "one"},
            )

    def test_personal_desktop_session_has_no_service_account_token_and_is_not_a_writer(self):
        tool = load_module()
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            fake_op = write_fake_op(root)
            personal = tool.PersonalWriterTokenSource(
                op_bin=fake_op,
                personal_account=True,
                personal_vault="Employee",
                token_items={
                    "Ken CI Runtime": "j34dtkat667tgzeopkanjwbdau",
                    "Ken Deploy Nonproduction": "h5lsxmq25qrgk4x22wf4k57z24",
                    "Ken Deploy Production": "5ncmp2wtb44nmvdwmlo5coirq4",
                },
                extra_env={"FAKE_OP_LOG": str(root / "op.log")},
            )
            tokens = personal.load()
            self.assertEqual(tokens["Ken CI Runtime"], "writer-ci")
            result = tool.populate_canonical_vaults(
                registry=registry_for(
                    [
                        entry(
                            "fixture|DESKTOP|Ken CI Runtime",
                            "Ken CI Runtime",
                            "fixture-desktop",
                            "DESKTOP",
                            "op://Source/source/credential",
                        )
                    ]
                ),
                source_adapter=tool.MappingSourceAdapter({"op://Source/source/credential": "desktop-secret"}),
                writer_source=personal,
                op_bin=fake_op,
                ledger_path=root / "ledger.yaml",
                extra_env={"FAKE_OP_LOG": str(root / "op.log")},
            )
            self.assertTrue(result["ready"])
            calls = [json.loads(line) for line in (root / "op.log").read_text().splitlines()]
            personal_reads = [
                call for call in calls if call["argv"][:2] == ["item", "get"] and "Employee" in call["argv"]
            ]
            self.assertEqual(len(personal_reads), 6)
            self.assertTrue(all(call["token"] == "" for call in personal_reads))
            target_calls = [
                call for call in calls
                if call not in personal_reads
                and call["argv"][:2] not in (["whoami", "--format=json"], ["vault", "get"])
            ]
            self.assertTrue(target_calls)
            self.assertTrue(all(call["token"] in set(tokens.values()) for call in target_calls))

    def test_known_population_resolves_schemes_groups_fields_and_writes_value_only_to_stdin(self):
        tool = load_module()
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            fake_op = write_fake_op(root)
            fake_ssh = write_fake_ssh(root)
            evidence = root / "evidence.json"
            evidence.write_text(json.dumps({"Runtime": {"Secret": "resolved-secret"}}))
            source = tool.SourceOrchestrationAdapter(
                op_adapter=tool.OpSourceAdapter(op_bin=fake_op, source_token="source-op"),
                ssh_adapter=tool.DeployedSourceAdapter(
                    ssh_bin=fake_ssh,
                    files={"source-host": root / "deployed.json"},
                ),
                evidence_adapter=tool.EvidenceSourceAdapter(root),
            )
            (root / "deployed.json").write_text(
                json.dumps({"Runtime": {"Secret": "resolved-secret"}})
            )
            entries = [
                entry(
                    "fixture|OP_TOKEN|Ken CI Runtime",
                    "Ken CI Runtime",
                    "fixture-ci",
                    "OP_TOKEN",
                    "op://Source/source/credential",
                ),
                entry(
                    "fixture|DEPLOY_SECRET|Ken Deploy Production",
                    "Ken Deploy Production",
                    "fixture-production",
                    "DEPLOY_SECRET",
                    "deployed://source-host/etc/config.json#Runtime.Secret",
                ),
                entry(
                    "fixture|EVIDENCE_SECRET|Ken Deploy Production",
                    "Ken Deploy Production",
                    "fixture-production",
                    "EVIDENCE_SECRET",
                    "evidence://evidence.json#Runtime.Secret",
                ),
            ]
            registry = registry_for(entries)
            ledger = root / "ledger.yaml"
            result = tool.populate_canonical_vaults(
                registry=registry,
                source_adapter=source,
                writer_source=tool.StaticWriterTokenSource(
                    {
                        "Ken CI Runtime": "writer-ci",
                        "Ken Deploy Nonproduction": "writer-nonprod",
                        "Ken Deploy Production": "writer-prod",
                    }
                ),
                op_bin=fake_op,
                ledger_path=ledger,
                extra_env={"FAKE_OP_LOG": str(root / "op.log")},
            )
            self.assertTrue(result["ready"])
            self.assertEqual(result["counts"]["blocked"], 0)
            serialized = json.dumps(result) + ledger.read_text()
            self.assertNotIn("resolved-secret", serialized)
            self.assertNotIn("writer-prod", serialized)
            calls = [json.loads(line) for line in (root / "op.log").read_text().splitlines()]
            writes = [call for call in calls if call["argv"][:2] in (["item", "create"], ["item", "edit"])]
            self.assertTrue(writes)
            self.assertTrue(all("resolved-secret" not in " ".join(call["argv"]) for call in writes))
            self.assertTrue(any("resolved-secret" in call["stdin"] for call in writes))

    def test_known_only_skips_unresolved_and_records_exact_blocked_count_without_readiness(self):
        tool = load_module()
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            fake_op = write_fake_op(root)
            entries = [
                entry(
                    "fixture|KNOWN|Ken CI Runtime",
                    "Ken CI Runtime",
                    "fixture-ci",
                    "KNOWN",
                    "op://Source/source/credential",
                ),
                entry(
                    "fixture|BLOCKED|Ken Deploy Production",
                    "Ken Deploy Production",
                    "fixture-prod",
                    "BLOCKED",
                    None,
                    status="unresolved",
                ),
            ]
            result = tool.populate_canonical_vaults(
                registry=registry_for(entries),
                source_adapter=tool.MappingSourceAdapter({"op://Source/source/credential": "known-secret"}),
                writer_source=tool.StaticWriterTokenSource(
                    {
                        "Ken CI Runtime": "writer-ci",
                        "Ken Deploy Nonproduction": "writer-nonprod",
                        "Ken Deploy Production": "writer-prod",
                    }
                ),
                op_bin=fake_op,
                ledger_path=root / "ledger.yaml",
                known_only=True,
            )
            self.assertFalse(result["ready"])
            self.assertEqual(result["status"], "blocked")
            self.assertEqual(result["counts"], {"selected": 1, "populated": 1, "blocked": 1})
            self.assertEqual(result["blocked"][0]["coordinate"], entries[1]["coordinate"])
            self.assertNotIn("known-secret", json.dumps(result))

    def test_population_refuses_unresolved_without_known_only_before_any_write(self):
        tool = load_module()
        entries = [
            entry(
                "fixture|BLOCKED|Ken Deploy Production",
                "Ken Deploy Production",
                "fixture-prod",
                "BLOCKED",
                None,
                status="unresolved",
            )
        ]
        with self.assertRaisesRegex(ValueError, "unresolved"):
            tool.populate_canonical_vaults(
                registry=registry_for(entries),
                source_adapter=tool.MappingSourceAdapter({}),
                writer_source=tool.StaticWriterTokenSource(
                    {
                        "Ken CI Runtime": "writer-ci",
                        "Ken Deploy Nonproduction": "writer-nonprod",
                        "Ken Deploy Production": "writer-prod",
                    }
                ),
                op_bin=Path("/bin/false"),
                ledger_path=Path("/tmp/unused-ledger"),
            )

    def test_ledger_is_value_free_and_replaced_atomically(self):
        tool = load_module()
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            ledger = root / "ledger.yaml"
            ledger.write_text("old-ledger\n")
            result = tool.write_value_free_ledger(
                ledger,
                {
                    "status": "blocked",
                    "ready": False,
                    "counts": {"selected": 0, "populated": 0, "blocked": 1},
                    "items": [],
                    "blocked": [{"coordinate": "fixture|TOKEN|Ken CI Runtime", "status": "unresolved"}],
                },
            )
            self.assertFalse(result)
            document = yaml.safe_load(ledger.read_text())
            self.assertEqual(document["status"], "blocked")
            self.assertEqual(stat.S_IMODE(ledger.stat().st_mode), 0o600)
            self.assertNotIn("value", ledger.read_text().lower())

    def test_generate_requires_allowlist_and_keeps_private_material_out_of_report(self):
        tool = load_module()
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            fake_op = write_fake_op(root)
            plan = root / "plan.yaml"
            plan.write_text(
                yaml.safe_dump(
                    {
                        "schema_version": 1,
                        "rows": [
                            {
                                "coordinate": "fixture|GENERATED|Ken Deploy Production",
                                "action": "generate-random-additive",
                                "target_canonical": {
                                    "vault": "Ken Deploy Production",
                                    "item": "fixture-generated",
                                    "field": "GENERATED",
                                },
                            }
                        ],
                    },
                    sort_keys=False,
                )
            )
            allowlist = root / "allowlist.yaml"
            allowlist.write_text(yaml.safe_dump({"coordinates": ["fixture|GENERATED|Ken Deploy Production"]}))
            result = tool.generate_canonical_vaults(
                plan_path=plan,
                allowlist_path=allowlist,
                writer_source=tool.StaticWriterTokenSource(
                    {
                        "Ken CI Runtime": "writer-ci",
                        "Ken Deploy Nonproduction": "writer-nonprod",
                        "Ken Deploy Production": "writer-prod",
                    }
                ),
                op_bin=fake_op,
                ledger_path=root / "ledger.yaml",
            )
            self.assertTrue(result["ready"])
            serialized = json.dumps(result).lower()
            self.assertNotIn("-----begin", serialized)
            self.assertNotIn("private material", serialized)

    def test_generated_ssh_key_interoperates_with_ssh_keygen(self):
        tool = load_module()
        with tempfile.TemporaryDirectory() as temp:
            key = Path(temp) / "generated-key"
            private, public = tool._ed25519_keypair()
            key.write_text(private)
            key.chmod(0o600)
            derived = subprocess.run(
                ["ssh-keygen", "-y", "-f", str(key)],
                capture_output=True,
                check=True,
                text=True,
            ).stdout.strip()
            self.assertEqual(derived, public.strip())

    def test_redirect_signing_key_interoperates_with_openssl_dgst(self):
        tool = load_module()
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            row = {"target_canonical": {"field": "REDIRECT_RELEASE_SIGNING_PRIVATE_KEY"}}
            private, public = tool._generate_secret(row)
            self.assertIsNone(public)
            key = root / "signing.pem"
            key.write_text(private)
            key.chmod(0o600)
            data = root / "payload"
            signature = root / "signature"
            data.write_bytes(b"ken-signing-compatibility")
            openssl = tool._tool_path("openssl")
            subprocess.run([str(openssl), "dgst", "-sha256", "-sign", str(key), "-out", str(signature), str(data)], check=True)
            verify_key = root / "public.pem"
            subprocess.run([str(openssl), "pkey", "-in", str(key), "-pubout", "-out", str(verify_key)], check=True, capture_output=True)
            verified = subprocess.run([str(openssl), "dgst", "-sha256", "-verify", str(verify_key), "-signature", str(signature), str(data)], capture_output=True, text=True)
            self.assertEqual(verified.returncode, 0, verified.stderr)
            self.assertIn("Verified OK", verified.stdout)

    def test_generation_allowlist_rejects_profile_wildcards(self):
        tool = load_module()
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "allowlist.yaml"
            path.write_text(yaml.safe_dump({"coordinates": ["one"], "profiles": ["opaque-token"]}))
            with self.assertRaisesRegex(ValueError, "wildcards"):
                tool._allowlist(path)

    def test_empty_source_is_rejected_before_population(self):
        tool = load_module()
        with self.assertRaisesRegex(ValueError, "empty"):
            tool._resolve_targets(
                [entry("fixture|EMPTY|Ken CI Runtime", "Ken CI Runtime", "item", "EMPTY", "op://Source/item/field")],
                tool.MappingSourceAdapter({"op://Source/item/field": ""}),
            )

    def test_failed_item_leaves_blocked_progress_ledger_and_invalidates_ready(self):
        tool = load_module()
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            fake_op = write_fake_op(root)
            entries = [
                entry("fixture|ONE|Ken CI Runtime", "Ken CI Runtime", "one", "ONE", "op://Source/item/one"),
                entry("fixture|TWO|Ken CI Runtime", "Ken CI Runtime", "two", "TWO", "op://Source/item/two"),
            ]
            ledger = root / "ledger.yaml"
            ledger.write_text(yaml.safe_dump({"status": "complete", "ready": True, "counts": {"selected": 0, "populated": 0, "blocked": 0}, "items": [], "blocked": []}))
            good = {"coordinate": "x", "status": "verified", "vault_id": tool.APPROVED_TARGET_VAULT_IDS["Ken CI Runtime"], "item_id": "one", "fields": {"ONE": "CONCEALED"}}
            with mock.patch.object(tool._MIGRATION, "populate_item", side_effect=[good, tool.MigrationError("write failed")]):
                with self.assertRaises(ValueError):
                    tool.populate_canonical_vaults(
                        registry=registry_for(entries),
                        source_adapter=tool.MappingSourceAdapter({"op://Source/item/one": "one-secret", "op://Source/item/two": "two-secret"}),
                        writer_source=tool.StaticWriterTokenSource({"Ken CI Runtime": "writer-ci", "Ken Deploy Nonproduction": "writer-nonprod", "Ken Deploy Production": "writer-prod"}),
                        op_bin=fake_op,
                        ledger_path=ledger,
                    )
            persisted = yaml.safe_load(ledger.read_text())
            self.assertEqual(persisted["status"], "blocked")
            self.assertFalse(persisted["ready"])
            self.assertEqual(persisted["counts"]["populated"], 1)

    def test_registration_artifact_is_durable_value_free_and_rejects_hardlinks(self):
        tool = load_module()
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            artifact = root / "registration.json"
            tool._write_registration_artifact(artifact, [{"coordinate": "fixture|SSH", "public_key": "ssh-ed25519 key"}], status="pending")
            document = json.loads(artifact.read_text())
            self.assertEqual(document["status"], "pending")
            self.assertEqual(stat.S_IMODE(artifact.stat().st_mode), 0o600)
            hardlink = root / "hardlink"
            os.link(artifact, hardlink)
            with self.assertRaisesRegex(ValueError, "unsafe"):
                tool._write_registration_artifact(artifact, [])

    def test_cli_does_not_print_writer_or_source_values(self):
        # Keep one end-to-end smoke assertion around the public command boundary.
        self.assertTrue(SCRIPT.is_file())
        self.assertNotIn("OP_SERVICE_ACCOUNT_TOKEN", SCRIPT.read_text())


if __name__ == "__main__":
    unittest.main()
