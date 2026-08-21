import copy
import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import yaml


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "production-secret-sources.py"
INTEGRATION_SCRIPT = ROOT / "scripts" / "integrate-production-secret-sources.py"
SOURCE_MAP = Path("/private/tmp/ken-production-secret-source-map.yaml")


def load_module():
    spec = importlib.util.spec_from_file_location("production_secret_sources", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def load_integration_module():
    spec = importlib.util.spec_from_file_location("integrate_production_secret_sources", INTEGRATION_SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class ProductionSecretSourcesTests(unittest.TestCase):
    def _source_map_document(self):
        return yaml.safe_load(SOURCE_MAP.read_text())

    def _load_document(self, document):
        tool = load_module()
        with tempfile.NamedTemporaryFile("w", suffix=".yaml") as stream:
            yaml.safe_dump(document, stream, sort_keys=False)
            stream.flush()
            return tool.ProductionSourceMap.load(Path(stream.name))

    def test_source_map_rejects_duplicate_keys_and_unknown_top_level_metadata(self):
        tool = load_module()
        with tempfile.NamedTemporaryFile("w", suffix=".yaml") as stream:
            stream.write("schema_version: 1\nschema_version: 1\n")
            stream.flush()
            with self.assertRaisesRegex(ValueError, "duplicate"):
                tool.ProductionSourceMap.load(Path(stream.name))

        unknown = self._source_map_document()
        unknown["status"] = "mapped"
        with self.assertRaisesRegex(ValueError, "schema"):
            self._load_document(unknown)

    def test_source_map_rejects_stale_counts_and_nested_schema_keys(self):
        tool = load_module()
        stale_counts = self._source_map_document()
        stale_counts["status_counts"]["partial"] = 4
        with self.assertRaisesRegex(ValueError, "status_counts"):
            self._load_document(stale_counts)

        extra_group_key = self._source_map_document()
        extra_group_key["mapped_groups"][0]["unexpected"] = True
        with self.assertRaisesRegex(ValueError, "schema"):
            self._load_document(extra_group_key)

        extra_authority_key = self._source_map_document()
        extra_authority_key["mapped_groups"][0]["authority"]["unexpected"] = True
        with self.assertRaisesRegex(ValueError, "schema"):
            self._load_document(extra_authority_key)

    def test_source_map_is_strict_and_maps_exactly_eighteen_coordinates(self):
        tool = load_module()
        source_map = tool.ProductionSourceMap.load(SOURCE_MAP)
        self.assertEqual(len(source_map.coordinates), 18)
        self.assertEqual(
            tool.authority_for_coordinate(
                "ken-cms|POSTGRES_PASSWORD|Ken Deploy Production"
            ),
            "ken-production://ken-cms/POSTGRES_PASSWORD/Ken%20Deploy%20Production",
        )
        with self.assertRaisesRegex(ValueError, "mapped"):
            source_map.group_for("ken-scraping|OVH_HOST_KEY|Ken Deploy Production")

    def test_registry_update_changes_only_mapped_rows(self):
        tool = load_module()
        source_map = tool.ProductionSourceMap.load(SOURCE_MAP)
        registry = yaml.safe_load(
            (ROOT / "inventory" / "canonical-credentials.yaml").read_text()
        )
        # The checked-out inventory is also the post-integration artifact. Normalize
        # only the mapped rows to the pre-integration shape for this unit fixture.
        mapped = set(source_map.coordinates)
        for entry in registry["entries"]:
            if entry["coordinate"] in mapped:
                entry["verification_status"] = "unresolved"
                entry["source_authority"] = None
        before = copy.deepcopy(registry)
        updated = tool.apply_registry_sources(registry, source_map)
        for old, new in zip(before["entries"], updated["entries"]):
            if old["coordinate"] in mapped:
                self.assertEqual(new["verification_status"], "verified-readable")
                self.assertEqual(
                    new["source_authority"], tool.authority_for_coordinate(old["coordinate"])
                )
            else:
                self.assertEqual(new, old)

    def test_adapter_derives_components_without_value_bearing_reports(self):
        tool = load_module()
        source_map = tool.ProductionSourceMap.load(SOURCE_MAP)

        files = {
            ("185.183.35.189", "/var/www/ken-agents/.env"): b"DATABASE_URL=postgres://u:p%40ss@db/ken\n",
            ("185.183.35.189", "/etc/ken-ai-mcp/ken-ai-mcp.env"): b"KEN_MYSQL_PORT=3307\n",
            ("185.183.35.189", "/etc/nginx/mtls/cloudflare-origin-pull-ca.pem"): b"ca-bytes",
            ("185.183.35.189", "/etc/ken/credentials/ken-redirect-client.pfx"): b"pfx-bytes",
            ("185.183.35.189", "/etc/nginx/redirect-sync-ingress/client-ca.pem"): b"client-ca",
            ("185.183.35.189", "/etc/nginx/redirect-sync-ingress/server.crt"): b"server-cert",
            ("185.183.35.189", "/etc/nginx/redirect-sync-ingress/server.key"): b"server-key",
            ("185.183.35.189", "/etc/nginx/redirect-sync-ingress/source-allowlist.conf"): b"allowlist",
            ("185.183.35.189", "/etc/letsencrypt/live/redirect-ingest.getken.dev/fullchain.pem"): b"fullchain",
            ("185.183.35.189", "/etc/letsencrypt/live/redirect-ingest.getken.dev/privkey.pem"): b"private-key",
            ("167.235.8.250", "/etc/elasticsearch/certs/http_ca.crt"): b"certificate",
        }

        def read_file(host, path):
            return files[(host, path)]

        def read_item(vault, item):
            self.assertEqual((vault, item), ("Development", "ken-cms-env"))
            return {"notesPlain": "DATABASE_URI=postgres://cms:cms-pass@db/cms\n"}

        adapter = tool.ProductionSourceAdapter(
            source_map, read_file=read_file, read_item=read_item, fingerprint=lambda _: "AA:BB"
        )
        self.assertEqual(
            adapter.resolve("ken-production://ken-ai-mcp/DB_PORT/Ken%20Deploy%20Production"),
            "3307",
        )
        self.assertEqual(
            adapter.resolve("ken-production://ken-cms/POSTGRES_PASSWORD/Ken%20Deploy%20Production"),
            "cms-pass",
        )
        self.assertEqual(
            adapter.resolve("ken-production://ken-backend/KEN_REDIRECT_CLIENT_PFX_BASE64/Ken%20Deploy%20Production"),
            "cGZ4LWJ5dGVz",
        )
        self.assertEqual(
            adapter.resolve("ken-production://ken-search/ELASTICSEARCH_CERT_FINGERPRINT/Ken%20Deploy%20Production"),
            "AABB",
        )
        report = tool.source_evidence(source_map)
        self.assertNotIn("hash", json.dumps(report).casefold())
        self.assertNotIn("cGZ4", json.dumps(report))

    def test_partial_and_unmapped_rows_cannot_be_selected(self):
        tool = load_module()
        raw = yaml.safe_load(SOURCE_MAP.read_text())
        raw["mapped_groups"][0]["status"] = "partial"
        with tempfile.NamedTemporaryFile("w", suffix=".yaml") as stream:
            yaml.safe_dump(raw, stream)
            stream.flush()
            with self.assertRaisesRegex(ValueError, "mapped"):
                tool.ProductionSourceMap.load(Path(stream.name))

    def test_integrate_is_hermetic_end_to_end_and_resumes_value_free_ledger(self):
        tool = load_module()
        integration = load_integration_module()
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            fake_op = root / "op"
            fake_op.write_text(
                "#!/usr/bin/env python3\n"
                "import json, os, sys\n"
                "args = sys.argv[1:]\n"
                "token = os.environ.get('OP_SERVICE_ACCOUNT_TOKEN', '')\n"
                "state_path = os.path.join(os.path.dirname(sys.argv[0]), 'state.json')\n"
                "log_path = os.path.join(os.path.dirname(sys.argv[0]), 'op-log.jsonl')\n"
                "try:\n"
                "    state = json.load(open(state_path, encoding='utf-8'))\n"
                "except FileNotFoundError:\n"
                "    state = {}\n"
                "kind = 'source' if token == 'source-token' else 'writer'\n"
                "with open(log_path, 'a', encoding='utf-8') as log:\n"
                "    log.write(json.dumps({'command': args[:2], 'kind': kind}) + '\\n')\n"
                "def emit(value):\n"
                "    print(json.dumps(value))\n"
                "if args[:2] == ['whoami', '--format=json']:\n"
                "    emit({'account_uuid': 'PHLSEQ2HNVAALEWHKWGKZOAGSY', 'user_uuid': 'writer-user', 'user_type': 'SERVICE_ACCOUNT', 'ServiceAccountType': 'SERVICE_ACCOUNT'})\n"
                "elif args[:3] == ['vault', 'list', '--format=json']:\n"
                "    vaults = {'writer-ci': ('istjrwyeqryhpv7rytbm34pfea', 'Ken CI Runtime'), 'writer-nonprod': ('wmb7rpm5xvl4ez4kur3s5l3hxe', 'Ken Deploy Nonproduction'), 'writer-prod': ('q7zdmdggp2ng7hvxozhzt4uupm', 'Ken Deploy Production')}\n"
                "    vault_id, name = vaults[token]\n"
                "    emit([{'id': vault_id, 'name': name}])\n"
                "elif args[:2] == ['item', 'get']:\n"
                "    item_id = args[2]\n"
                "    if kind == 'source':\n"
                "        emit({'id': item_id, 'title': 'ken-cms-env', 'notesPlain': 'DATABASE_URI=postgres://cms:fixture-pass@db/cms\\n'})\n"
                "    else:\n"
                "        emit(state[item_id])\n"
                "elif args[:2] == ['item', 'list']:\n"
                "    emit([])\n"
                "elif args[:2] == ['item', 'create']:\n"
                "    payload = json.loads(sys.stdin.read())\n"
                "    item_id = 'fixture-item-' + str(len(state) + 1)\n"
                "    record = {'id': item_id, 'title': payload['title'], 'vault': {'id': {'writer-ci': 'istjrwyeqryhpv7rytbm34pfea', 'writer-nonprod': 'wmb7rpm5xvl4ez4kur3s5l3hxe', 'writer-prod': 'q7zdmdggp2ng7hvxozhzt4uupm'}[token]}, 'fields': [{'label': f['label'], 'type': f['type']} for f in payload.get('fields', [])], 'sections': []}\n"
                "    state[item_id] = record\n"
                "    with open(state_path, 'w', encoding='utf-8') as stream: json.dump(state, stream)\n"
                "    emit(record)\n"
                "else:\n"
                "    raise SystemExit('unsupported fake op command')\n"
            )
            fake_op.chmod(0o755)
            fake_ssh = root / "ssh"
            fake_ssh.write_text(
                "#!/usr/bin/env python3\n"
                "import os, sys\n"
                "path = sys.argv[-1]\n"
                "if path.endswith('ken-agents/.env'):\n"
                "    sys.stdout.write('DATABASE_URL=postgres://agent:fixture-pass@db/ken\\n')\n"
                "elif path.endswith('ken-ai-mcp.env'):\n"
                "    sys.stdout.write('KEN_MYSQL_PORT=3307\\n')\n"
                "else:\n"
                "    sys.stdout.buffer.write(('fixture-' + os.path.basename(path)).encode())\n"
            )
            fake_ssh.chmod(0o755)
            ssh_key = root / "ssh-key"
            ssh_key.write_text("fixture ssh key placeholder")
            ssh_key.chmod(0o600)

            source_map_document = self._source_map_document()
            source_map_path = root / "source-map.yaml"
            source_map_path.write_text(yaml.safe_dump(source_map_document, sort_keys=False))
            source_map_path.chmod(0o600)
            registry = yaml.safe_load((ROOT / "inventory" / "canonical-credentials.yaml").read_text())
            mapped = {coordinate for group in source_map_document["mapped_groups"] for coordinate in group["coordinates"]}
            for entry in registry["entries"]:
                if entry["coordinate"] in mapped:
                    entry["verification_status"] = "unresolved"
                    entry["source_authority"] = None
            registry_path = root / "registry.yaml"
            registry_path.write_text(yaml.safe_dump(registry, sort_keys=False))
            evidence_path = root / "evidence.yaml"
            ledger_path = root / "ledger.yaml"
            token_items_path = root / "writer-token-items.yaml"
            token_items_path.write_text(yaml.safe_dump({vault: details["id"] for vault, details in integration._POPULATE.APPROVED_WRITER_ITEMS.items()}))
            token_paths = {}
            for vault, filename, token in (
                ("Ken CI Runtime", "ken-ci-runtime.token", "writer-ci"),
                ("Ken Deploy Nonproduction", "ken-deploy-nonproduction.token", "writer-nonprod"),
                ("Ken Deploy Production", "ken-deploy-production.token", "writer-prod"),
            ):
                path = root / filename
                path.write_text(token)
                path.chmod(0o600)
                token_paths[vault] = path

            first = registry["entries"][next(index for index, entry in enumerate(registry["entries"]) if entry["coordinate"] in mapped)]
            integration._POPULATE.write_value_free_ledger(
                ledger_path,
                {
                    "status": "in-progress",
                    "ready": False,
                    "counts": {"selected": 18, "populated": 1, "blocked": 0},
                    "items": [{
                        "vault": first["canonical_vault"],
                        "vault_id": "q7zdmdggp2ng7hvxozhzt4uupm",
                        "item": first["canonical_item"],
                        "item_id": "already-populated-item",
                        "status": "verified",
                        "fields": [{"label": first["canonical_field"], "type": first["field_type"], "status": "verified"}],
                    }],
                    "blocked": [],
                },
            )
            real_source_adapter = integration._SOURCES.ProductionSourceAdapter

            class FixtureSourceAdapter(real_source_adapter):
                def __init__(self, source_map, *, read_file, read_item):
                    super().__init__(source_map, read_file=read_file, read_item=read_item, fingerprint=lambda _: "AABB")

            with mock.patch.object(integration._SOURCES, "ProductionSourceAdapter", FixtureSourceAdapter):
                with mock.patch.dict(os.environ, {"OP_SERVICE_ACCOUNT_TOKEN": "source-token"}, clear=False):
                    result = integration.integrate(
                        source_map_path=source_map_path,
                        registry_path=registry_path,
                        ledger_path=ledger_path,
                        evidence_path=evidence_path,
                        writer_token_items_path=token_items_path,
                        op_bin=fake_op,
                        personal_op_bin=fake_op,
                        ssh_bin=fake_ssh,
                        ssh_key=ssh_key,
                        writer_token_dir=root,
                    )
            self.assertEqual(result["counts"], {"selected": 18, "populated": 18, "blocked": 0})
            ledger = yaml.safe_load(ledger_path.read_text())
            evidence = yaml.safe_load(evidence_path.read_text())
            self.assertEqual(ledger["counts"], {"selected": 18, "populated": 18, "blocked": 0})
            self.assertEqual(evidence["mapped_count"], 18)
            self.assertNotIn("value", ledger_path.read_text().casefold())
            self.assertNotIn("fixture-pass", evidence_path.read_text())
            calls = [json.loads(line) for line in (root / "op-log.jsonl").read_text().splitlines()]
            self.assertGreaterEqual(sum(call["command"] == ["whoami", "--format=json"] and call["kind"] == "writer" for call in calls), 3)
            self.assertEqual(sum(call["command"] == ["item", "create"] for call in calls), 17)

    def test_integrate_rejects_malformed_source_map_before_any_writer_call(self):
        tool = load_module()
        integration = load_integration_module()
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            bad_map = root / "bad-map.yaml"
            bad_map.write_text("schema_version: 1\nschema_version: 1\n")
            bad_map.chmod(0o600)
            fake_op = root / "op"
            fake_op.write_text("#!/bin/sh\nprintf 'writer call' >> \"$(dirname \"$0\")/called\"\nexit 1\n")
            fake_op.chmod(0o755)
            with self.assertRaisesRegex(ValueError, "source map"):
                integration.integrate(
                    source_map_path=bad_map,
                    registry_path=ROOT / "inventory" / "canonical-credentials.yaml",
                    ledger_path=root / "ledger.yaml",
                    evidence_path=root / "evidence.yaml",
                    writer_token_items_path=Path("/tmp/ken-writer-token-items.yaml"),
                    op_bin=fake_op,
                    personal_op_bin=fake_op,
                    ssh_bin=fake_op,
                    ssh_key=fake_op,
                    writer_token_dir=root,
                )
            self.assertFalse((root / "called").exists())

            partial_map = root / "partial-map.yaml"
            partial_document = self._source_map_document()
            partial_document["mapped_groups"][0]["status"] = "partial"
            partial_map.write_text(yaml.safe_dump(partial_document, sort_keys=False))
            partial_map.chmod(0o600)
            with self.assertRaisesRegex(ValueError, "mapped_groups"):
                integration.integrate(
                    source_map_path=partial_map,
                    registry_path=ROOT / "inventory" / "canonical-credentials.yaml",
                    ledger_path=root / "partial-ledger.yaml",
                    evidence_path=root / "partial-evidence.yaml",
                    writer_token_items_path=Path("/tmp/ken-writer-token-items.yaml"),
                    op_bin=fake_op,
                    personal_op_bin=fake_op,
                    ssh_bin=fake_op,
                    ssh_key=fake_op,
                    writer_token_dir=root,
                )
            self.assertFalse((root / "called").exists())


if __name__ == "__main__":
    unittest.main()
