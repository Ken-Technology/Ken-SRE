#!/usr/bin/env python3
"""Extract environment key metadata from a 1Password item without emitting values."""
from __future__ import annotations

import json
import re
import sys
from typing import Any


ENV_ASSIGNMENT_RE = re.compile(
    r"^\s*(?:export\s+)?(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?P<rhs>.*)$"
)


def _quote_remains_open(text: str, quote: str) -> bool:
    escaped = False
    for character in text:
        if escaped:
            escaped = False
            continue
        if quote == '"' and character == "\\":
            escaped = True
            continue
        if character == quote:
            return False
    return True


def _has_unescaped_trailing_backslash(text: str) -> bool:
    count = 0
    for character in reversed(text.rstrip()):
        if character != "\\":
            break
        count += 1
    return count % 2 == 1


def extract_env_assignments(note: str) -> list[dict[str, Any]]:
    found: dict[str, bool] = {}
    open_quote: str | None = None
    continuation = False
    for line in note.splitlines():
        if open_quote is not None:
            if not _quote_remains_open(line, open_quote):
                open_quote = None
            continue
        if continuation:
            continuation = _has_unescaped_trailing_backslash(line)
            continue
        stripped = line.lstrip()
        if not stripped or stripped.startswith("#"):
            continue
        match = ENV_ASSIGNMENT_RE.match(line)
        if not match:
            continue
        name = match.group("name")
        if name in found:
            raise ValueError(f"duplicate environment assignment for {name}")
        rhs = match.group("rhs")
        rhs_trimmed = rhs.strip()
        found[name] = bool(rhs_trimmed)
        if rhs_trimmed[:1] in {"'", '"'}:
            quote = rhs_trimmed[0]
            if _quote_remains_open(rhs_trimmed[1:], quote):
                open_quote = quote
        elif _has_unescaped_trailing_backslash(rhs):
            continuation = True
    if open_quote is not None or continuation:
        raise ValueError("unterminated environment assignment")
    return [
        {
            "name": name,
            "declared_type": "environment-string",
            "value_present": found[name],
        }
        for name in sorted(found)
    ]


def extract_item_metadata(item: Any) -> dict[str, Any]:
    if not isinstance(item, dict):
        raise ValueError("invalid 1Password item metadata envelope")
    title = item.get("title")
    vault = item.get("vault")
    fields = item.get("fields")
    if (
        not isinstance(title, str)
        or not title.strip()
        or not isinstance(vault, dict)
        or not isinstance(vault.get("name"), str)
        or not vault["name"].strip()
        or not isinstance(fields, list)
    ):
        raise ValueError("invalid 1Password item metadata envelope")

    notes: list[str] = []
    for field in fields:
        if not isinstance(field, dict):
            continue
        if field.get("id") != "notesPlain" and field.get("purpose") != "NOTES":
            continue
        content = field.get("value")
        if not isinstance(content, str):
            raise ValueError("invalid 1Password notes field")
        notes.append(content)
    if not notes:
        raise ValueError("1Password item has no notes field")

    keys: list[dict[str, Any]] = []
    seen: set[str] = set()
    for note in notes:
        for key in extract_env_assignments(note):
            if key["name"] in seen:
                raise ValueError(
                    f"duplicate environment assignment for {key['name']}"
                )
            seen.add(key["name"])
            keys.append(key)

    return {
        "schema_version": 1,
        "vault": vault["name"],
        "item": title,
        "keys": sorted(keys, key=lambda key: key["name"]),
    }


def main() -> int:
    try:
        item = json.load(sys.stdin)
        output = extract_item_metadata(item)
    except Exception:
        sys.stderr.write("1Password item metadata extraction failed\n")
        return 2
    json.dump(output, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
