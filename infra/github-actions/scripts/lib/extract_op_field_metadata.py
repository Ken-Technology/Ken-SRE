#!/usr/bin/env python3
"""Project a 1Password item to labels, types, and presence without values."""
from __future__ import annotations

import json
import sys
from typing import Any


def extract_field_metadata(item: Any) -> dict[str, Any]:
    if not isinstance(item, dict):
        raise ValueError("invalid 1Password item metadata envelope")
    title = item.get("title")
    vault = item.get("vault")
    fields = item.get("fields")
    files = item.get("files") or []
    if (
        not isinstance(title, str)
        or not title.strip()
        or not isinstance(vault, dict)
        or not isinstance(vault.get("name"), str)
        or not isinstance(fields, list)
        or not isinstance(files, list)
    ):
        raise ValueError("invalid 1Password item metadata envelope")

    projected_fields: list[dict[str, Any]] = []
    for field in fields:
        if not isinstance(field, dict) or not isinstance(field.get("label"), str):
            raise ValueError("invalid 1Password field metadata")
        section = field.get("section")
        section_label = section.get("label") if isinstance(section, dict) else None
        projected_fields.append(
            {
                "label": field["label"],
                "field_type": field.get("type"),
                "purpose": field.get("purpose"),
                "section": section_label,
                "value_present": field.get("value") not in {None, ""},
            }
        )

    projected_files: list[dict[str, str]] = []
    for file in files:
        if not isinstance(file, dict) or not isinstance(file.get("name"), str):
            raise ValueError("invalid 1Password file metadata")
        projected_files.append({"name": file["name"]})

    return {
        "schema_version": 1,
        "vault": vault["name"],
        "item": title,
        "category": item.get("category"),
        "fields": projected_fields,
        "files": projected_files,
    }


def main() -> int:
    try:
        item = json.load(sys.stdin)
        output = extract_field_metadata(item)
    except Exception:
        sys.stderr.write("1Password field metadata extraction failed\n")
        return 2
    json.dump(output, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
