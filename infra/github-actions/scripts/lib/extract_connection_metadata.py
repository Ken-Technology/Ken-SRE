#!/usr/bin/env python3
"""Project connection-string structure without emitting connection values."""
from __future__ import annotations

import json
import re
import sys
from typing import Any
from urllib.parse import urlsplit


MYSQL_COMPONENTS = {
    "server": "server",
    "host": "server",
    "datasource": "server",
    "port": "port",
    "database": "database",
    "initialcatalog": "database",
    "userid": "user",
    "uid": "user",
    "user": "user",
    "username": "user",
    "password": "password",
    "pwd": "password",
}


def _split_mysql_segments(connection: str) -> list[str]:
    segments: list[str] = []
    current: list[str] = []
    quote: str | None = None
    brace_depth = 0
    escaped = False
    for character in connection:
        if escaped:
            current.append(character)
            escaped = False
            continue
        if quote is not None:
            current.append(character)
            if character == "\\":
                escaped = True
            elif character == quote:
                quote = None
            continue
        if character in {"'", '"'}:
            quote = character
            current.append(character)
        elif character == "{":
            brace_depth += 1
            current.append(character)
        elif character == "}" and brace_depth:
            brace_depth -= 1
            current.append(character)
        elif character == ";" and brace_depth == 0:
            segments.append("".join(current))
            current = []
        else:
            current.append(character)
    if quote is not None or brace_depth:
        raise ValueError("invalid connection metadata input")
    segments.append("".join(current))
    return segments


def _mysql_components(connection: str) -> list[str]:
    components: set[str] = set()
    assignments = 0
    for segment in _split_mysql_segments(connection):
        if not segment.strip():
            continue
        if "=" not in segment:
            raise ValueError("invalid connection metadata input")
        lhs, rhs = segment.split("=", 1)
        assignments += 1
        normalized = re.sub(r"[\s_-]+", "", lhs).lower()
        canonical = MYSQL_COMPONENTS.get(normalized)
        if canonical and rhs.strip():
            components.add(canonical)
    if not assignments or not components:
        raise ValueError("invalid connection metadata input")
    return sorted(components)


def extract_connection_metadata(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ValueError("invalid connection metadata envelope")
    mysql = payload.get("mysql")
    mongo = payload.get("mongo")
    if not isinstance(mysql, str) or not isinstance(mongo, str):
        raise ValueError("invalid connection metadata envelope")
    components = _mysql_components(mysql)
    mongo_present = bool(mongo.strip())
    mongo_database_present = False
    if mongo_present:
        try:
            parsed = urlsplit(mongo)
            if parsed.scheme not in {"mongodb", "mongodb+srv"} or not parsed.netloc:
                raise ValueError
            mongo_database_present = bool(parsed.path.strip("/"))
        except Exception as error:
            raise ValueError("invalid connection metadata input") from error
    return {
        "schema_version": 1,
        "mysql_components": components,
        "mongo_connection_present": mongo_present,
        "mongo_database_component_present": mongo_database_present,
    }


def main() -> int:
    try:
        payload = json.load(sys.stdin)
        output = extract_connection_metadata(payload)
    except Exception:
        sys.stderr.write("connection metadata extraction failed\n")
        return 2
    json.dump(output, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
