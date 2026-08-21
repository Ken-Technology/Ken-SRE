import copy
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "production-secret-sources.py"
SOURCE_MAP = Path("/private/tmp/ken-production-secret-source-map.yaml")


def load_module():
    spec = importlib.util.spec_from_file_location("production_secret_sources", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class ProductionSecretSourcesTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
