#!/usr/bin/env python3
"""Integrate and populate only the approved mapped production coordinates."""

from __future__ import annotations

import argparse
import importlib.util
import os
import stat
import tempfile
from pathlib import Path
from typing import Any, Mapping, Sequence

import yaml


_ROOT = Path(__file__).resolve().parents[2]
_SOURCES_PATH = Path(__file__).with_name("production-secret-sources.py")
_POPULATE_PATH = Path(__file__).with_name("populate-canonical-vaults.py")


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"{name} could not be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_SOURCES = _load(_SOURCES_PATH, "production_secret_sources")
_POPULATE = _load(_POPULATE_PATH, "populate_canonical_vaults")
MigrationError = _POPULATE.MigrationError


def _write_yaml(path: Path, document: Mapping[str, Any], *, mode: int = 0o644) -> None:
    if path.is_symlink() or not path.parent.is_dir():
        raise MigrationError("artifact path is unsafe")
    payload = yaml.safe_dump(dict(document), sort_keys=False).encode("utf-8")
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except Exception:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def _rate_limit_preflight(op_bin: Path, writer_tokens: Mapping[str, str]) -> None:
    """Require a successful read-only API round trip before any item write.

    The CLI does not expose provider quota headers.  A failed identity/vault
    read is therefore treated as an unknown or exhausted rate-limit state and
    blocks the run before the first mutation.  Writes remain one item at a time.
    """
    for vault in sorted(writer_tokens):
        try:
            identity = _POPULATE._MIGRATION.run_op_json(
                op_bin=op_bin,
                argv=["whoami", "--format=json"],
                token=writer_tokens[vault],
            )
            visible = _POPULATE._MIGRATION.run_op_json(
                op_bin=op_bin,
                argv=["vault", "list", "--format=json"],
                token=writer_tokens[vault],
            )
        except MigrationError as exc:
            raise MigrationError("1Password rate-limit preflight failed") from exc
        if not isinstance(identity, Mapping) or not isinstance(visible, list):
            raise MigrationError("1Password rate-limit preflight response is invalid")


def integrate(
    *,
    source_map_path: Path,
    registry_path: Path,
    ledger_path: Path,
    evidence_path: Path,
    writer_token_items_path: Path,
    op_bin: Path,
    personal_op_bin: Path,
    ssh_bin: Path,
    ssh_key: Path,
    writer_token_dir: Path,
) -> Mapping[str, Any]:
    source_map = _SOURCES.ProductionSourceMap.load(source_map_path)
    registry = _POPULATE._registry_document(registry_path=registry_path, registry=None)
    updated_registry = _SOURCES.apply_registry_sources(registry, source_map)
    selected_registry = _SOURCES.population_registry(updated_registry, source_map)
    if len(selected_registry["entries"]) != 18:
        raise MigrationError("population selection is not exactly 18 mapped rows")

    source_token = os.environ.get("OP_SERVICE_ACCOUNT_TOKEN")
    if not isinstance(source_token, str) or not source_token:
        raise MigrationError("protected source reader is unavailable")
    op_adapter = _POPULATE.OpSourceAdapter(op_bin=personal_op_bin, source_token=source_token)
    ssh_adapter = _POPULATE.DeployedSourceAdapter(
        ssh_bin=ssh_bin, ssh_user="root", ssh_key=ssh_key
    )
    source_adapter = _SOURCES.ProductionSourceAdapter(
        source_map,
        read_file=ssh_adapter.read_bytes,
        read_item=op_adapter._get_item,
    )
    # Resolve the complete mapped set before loading writers or mutating a target.
    for coordinate in sorted(source_map.coordinates):
        source_adapter.resolve(_SOURCES.authority_for_coordinate(coordinate))

    token_items = _POPULATE._load_token_items(writer_token_items_path)
    expected_items = {vault: details["id"] for vault, details in _POPULATE.APPROVED_WRITER_ITEMS.items()}
    if dict(token_items) != expected_items:
        raise MigrationError("writer token item map does not match the reviewed three items")
    expected_paths = {
        vault: writer_token_dir / filename
        for vault, filename in {
            "Ken CI Runtime": "ken-ci-runtime.token",
            "Ken Deploy Nonproduction": "ken-deploy-nonproduction.token",
            "Ken Deploy Production": "ken-deploy-production.token",
        }.items()
    }
    writer_source = _POPULATE.FileWriterTokenSource(expected_paths)
    writer_tokens = writer_source.load()
    _rate_limit_preflight(op_bin, writer_tokens)
    result = _POPULATE.populate_canonical_vaults(
        registry=selected_registry,
        source_adapter=source_adapter,
        writer_source=_POPULATE.StaticWriterTokenSource(writer_tokens),
        op_bin=op_bin,
        ledger_path=ledger_path,
        known_only=False,
        resume_ledger=ledger_path if ledger_path.exists() else None,
    )
    if result.get("status") != "complete" or result.get("counts", {}).get("selected") != 18:
        raise MigrationError("mapped production population did not complete")
    _write_yaml(registry_path, updated_registry)
    _write_yaml(evidence_path, _SOURCES.source_evidence(source_map))
    return result


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-map", type=Path, required=True)
    parser.add_argument("--registry", type=Path, required=True)
    parser.add_argument("--ledger", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--writer-token-items", type=Path, required=True)
    parser.add_argument("--op-bin", type=Path, default=Path("/usr/local/bin/op"))
    parser.add_argument("--personal-op-bin", type=Path, default=Path("/usr/local/bin/op"))
    parser.add_argument("--ssh-bin", type=Path, default=Path("/usr/bin/ssh"))
    parser.add_argument("--ssh-key", type=Path, default=Path.home() / ".ssh/id_ed25519")
    parser.add_argument(
        "--writer-token-dir",
        type=Path,
        default=Path.home() / ".config/ken-actions/service-accounts",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    try:
        args = _parser().parse_args(argv)
        result = integrate(
            source_map_path=args.source_map,
            registry_path=args.registry,
            ledger_path=args.ledger,
            evidence_path=args.evidence,
            writer_token_items_path=args.writer_token_items,
            op_bin=args.op_bin,
            personal_op_bin=args.personal_op_bin,
            ssh_bin=args.ssh_bin,
            ssh_key=args.ssh_key,
            writer_token_dir=args.writer_token_dir,
        )
        print(f"population complete: {result['counts']['populated']} mapped items")
        return 0
    except (MigrationError, OSError, ValueError, yaml.YAMLError) as exc:
        print(f"production source integration refused: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
