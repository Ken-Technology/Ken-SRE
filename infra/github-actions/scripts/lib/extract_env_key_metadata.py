#!/usr/bin/env python3
"""Project an env file to left-hand key metadata without emitting values."""
from __future__ import annotations

import argparse
import json
import re
import sys
from typing import Any

from extract_op_env_metadata import extract_env_assignments


SAFE_SOURCE_RE = re.compile(r"^[A-Za-z0-9._/+-]+$")


def extract_env_metadata(content: str, *, source_file: str) -> dict[str, Any]:
    if not isinstance(content, str):
        raise ValueError("invalid env metadata input")
    if not isinstance(source_file, str) or not SAFE_SOURCE_RE.fullmatch(source_file):
        raise ValueError("invalid env metadata source")
    return {
        "schema_version": 1,
        "source_file": source_file,
        "keys": extract_env_assignments(content),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--source-file", required=True)
    try:
        args = parser.parse_args(argv)
        output = extract_env_metadata(sys.stdin.read(), source_file=args.source_file)
    except Exception:
        sys.stderr.write("env metadata extraction failed\n")
        return 2
    json.dump(output, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
