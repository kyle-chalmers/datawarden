#!/usr/bin/env python3
"""Deterministic classification hints for the datawarden data-classification skill.

Walks a target directory and emits, per file: validated-content indicator COUNTS (emails,
format-valid SSNs, Luhn-valid card numbers), matched PII column names (for delimited files),
matched filename patterns, and the resulting deterministic FLOOR tier per
reference/four-tier-framework.md.

The model may raise a file's tier above the floor, or argue Public with explicit justification;
it may never go below the floor. This script NEVER outputs data values — counts, column names,
and paths only. It never suggests Public.

Stdlib only. Read-only except the optional --emit-json path.
"""

import argparse
import json
import os
import re

PLUGIN_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
SCHEMA_VERSION = 1

TIER_ORDER = ["Internal", "Confidential", "Restricted"]  # floors only; Public is never automatic

FILENAME_PATTERNS = [
    (re.compile(r"(?i)(patient|medical|health|ssn|tax|payroll|card|payment)"), "Restricted"),
    (re.compile(r"(?i)(\.env|credential|secret|\.pem$|\.key$)"), "Restricted"),
    (re.compile(r"(?i)(customer|member|employee|user|contact|lead)"), "Confidential"),
]

COLUMN_PATTERNS = [
    (re.compile(r"(?i)^(ssn|social_security(_number)?|tax_id|national_id|passport(_number)?)$"), "Restricted"),
    (re.compile(r"(?i)^(card_number|pan|cvv|account_number|routing_number)$"), "Restricted"),
    (re.compile(r"(?i)^(dob|birth_date|date_of_birth|diagnosis|medical.*)$"), "Restricted"),
    (re.compile(r"(?i)^(email|phone|mobile|address|first_name|last_name|full_name|ip_address)$"), "Confidential"),
    (re.compile(r"(?i)^(salary|income|compensation)$"), "Confidential"),
]

EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
SSN = re.compile(r"\b(\d{3})-(\d{2})-(\d{4})\b")
PAN = re.compile(r"\b(?:\d[ -]?){13,19}\b")

MAX_BYTES = 1_000_000  # per-file content sample cap
SKIP_DIRS = {".git", "node_modules", ".venv", "__pycache__"}


def ssn_format_valid(match):
    area, group, serial = match.groups()
    if area in ("000", "666") or area >= "900":
        return False
    return group != "00" and serial != "0000"


def luhn_valid(digits):
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def looks_text(sample):
    return b"\x00" not in sample


def classify_file(path, relpath):
    indicators = {"emails": 0, "ssn_valid": 0, "pan_luhn_valid": 0}
    pii_columns = []
    filename_hits = []
    floor = "Internal"

    def raise_floor(tier):
        nonlocal floor
        if TIER_ORDER.index(tier) > TIER_ORDER.index(floor):
            floor = tier

    for pattern, tier in FILENAME_PATTERNS:
        if pattern.search(os.path.basename(relpath)):
            filename_hits.append(pattern.pattern)
            raise_floor(tier)

    try:
        with open(path, "rb") as f:
            raw = f.read(MAX_BYTES)
    except OSError:
        return None
    if not looks_text(raw):
        return {
            "path": relpath, "binary": True, "indicators": indicators,
            "pii_columns": pii_columns, "filename_hits": filename_hits, "floor": floor,
            "confidence": "possible",
        }
    text = raw.decode("utf-8", errors="replace")

    indicators["emails"] = len(EMAIL.findall(text))
    indicators["ssn_valid"] = sum(1 for m in SSN.finditer(text) if ssn_format_valid(m))
    indicators["pan_luhn_valid"] = sum(
        1 for m in PAN.finditer(text) if luhn_valid(re.sub(r"[ -]", "", m.group()))
    )

    # Header sniff for delimited files: match column names against the shared patterns.
    first_line = text.splitlines()[0] if text.splitlines() else ""
    if "," in first_line or "\t" in first_line:
        sep = "," if "," in first_line else "\t"
        for col in [c.strip().strip('"') for c in first_line.split(sep)]:
            for pattern, tier in COLUMN_PATTERNS:
                if pattern.match(col):
                    pii_columns.append(col)
                    raise_floor(tier)
                    break

    confidence = "probable"
    if indicators["ssn_valid"] or indicators["pan_luhn_valid"]:
        raise_floor("Restricted")
        confidence = "confirmed"
    elif indicators["emails"]:
        raise_floor("Confidential")
        confidence = "confirmed"
    elif not pii_columns and not filename_hits:
        confidence = "possible"

    return {
        "path": relpath, "binary": False, "indicators": indicators,
        "pii_columns": pii_columns, "filename_hits": filename_hits,
        "floor": floor, "confidence": confidence,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True)
    parser.add_argument("--emit-json", help="write JSON here instead of stdout")
    args = parser.parse_args()
    target = os.path.abspath(args.target)

    files = []
    for root, dirs, names in os.walk(target):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for name in sorted(names):
            path = os.path.join(root, name)
            rel = os.path.relpath(path, target)
            entry = classify_file(path, rel)
            if entry:
                files.append(entry)

    result = {
        "schema_version": SCHEMA_VERSION,
        "skill": "data-classification",
        "target": target,
        "tools": {"classify_hints": "1"},
        "files": files,
    }
    output = json.dumps(result, indent=2)
    if args.emit_json:
        with open(args.emit_json, "w", encoding="utf-8") as fh:
            fh.write(output + "\n")
    else:
        print(output)


if __name__ == "__main__":
    main()
