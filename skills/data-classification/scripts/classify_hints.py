#!/usr/bin/env python3
"""Deterministic classification verdicts for the datawarden data-classification skill.

Walks a target directory and emits:
- per-file hints: validated-content indicator COUNTS (emails, format-valid SSNs, Luhn-valid
  card numbers), matched PII column names, filename-pattern hits, and the deterministic
  FLOOR tier per reference/four-tier-framework.md;
- findings: DC-01 (Restricted-floor file) and DC-02 (Confidential-floor file), with
  citations, fingerprints, and .datawarden-ignore suppression applied;
- unknowns: DC-03 for every file that could not be read (fail-closed — an unreadable file
  is never silently omitted).

The model may raise a file's tier above the floor, or argue Public with explicit
justification; it may never go below the floor or alter these verdicts. This script NEVER
outputs data values — counts, column names, and paths only. It never suggests Public.

Stdlib only. Read-only except the optional --emit-json path.
"""

import argparse
import datetime
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
    except OSError as e:
        return {"path": relpath, "unreadable": True, "error": e.__class__.__name__}
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


def load_registry():
    with open(os.path.join(PLUGIN_ROOT, "reference", "citations.yml"), encoding="utf-8") as f:
        citations = json.load(f)["citations"]
    with open(os.path.join(PLUGIN_ROOT, "reference", "checks.yml"), encoding="utf-8") as f:
        checks = json.load(f)["checks"]
    return citations, checks


def load_suppressions(target):
    """Same .datawarden-ignore contract as the other evaluators (see finding-format.md).
    Fail closed: an unparseable expiry counts as expired."""
    path = os.path.join(target, ".datawarden-ignore")
    entries = {}
    if not os.path.exists(path):
        return entries
    today = datetime.date.today()
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            fingerprint = parts[0]
            expires, reason = None, ""
            for part in parts[1:]:
                if part.startswith("expires="):
                    expires = part.split("=", 1)[1]
                elif part.startswith("reason="):
                    reason = line.split("reason=", 1)[1]
            expired = False
            if expires:
                try:
                    expired = datetime.date.fromisoformat(expires) < today
                except ValueError:
                    expired = True
            entries[fingerprint] = {"expires": expires, "reason": reason, "expired": expired}
    return entries


def build_findings(files, citations, checks):
    findings = []
    for entry in files:
        floor = entry["floor"]
        if floor not in ("Restricted", "Confidential"):
            continue
        check_id = "DC-01" if floor == "Restricted" else "DC-02"
        severity = "HIGH" if floor == "Restricted" else "MEDIUM"
        confidence = entry["confidence"]
        if confidence == "possible" and severity == "HIGH":
            severity = "MEDIUM"  # confidence cap per finding-format.md
        ind = entry["indicators"]
        evidence_bits = []
        if ind["ssn_valid"]:
            evidence_bits.append(f"{ind['ssn_valid']} format-valid SSN(s)")
        if ind["pan_luhn_valid"]:
            evidence_bits.append(f"{ind['pan_luhn_valid']} Luhn-valid card number(s)")
        if ind["emails"]:
            evidence_bits.append(f"{ind['emails']} validated email(s)")
        if entry["pii_columns"]:
            evidence_bits.append(f"PII columns: {', '.join(entry['pii_columns'])}")
        if entry["filename_hits"]:
            evidence_bits.append("filename pattern match")
        findings.append({
            "check_id": check_id,
            "title": f"{floor}-tier content on disk: {entry['path']}",
            "severity": severity,
            "confidence": confidence,
            "file": entry["path"],
            "evidence": "; ".join(evidence_bits) + " (counts and column names only; no values sampled).",
            "remediation": (
                [
                    "Remove this file from AI-readable locations (working tree, agent-accessible dirs).",
                    "Serve any needed extract through a governed view that hashes/masks/omits the sensitive fields.",
                ]
                if floor == "Restricted"
                else ["Prefer masked or aggregated forms for person-identifying data at rest."]
            ),
            "rotate_first": False,
            "fingerprint": f"{check_id}:{entry['path']}:{floor}",
            "citations": [citations[k]["display"] for k in checks[check_id]["citations"]],
        })
    return findings


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True)
    parser.add_argument("--emit-json", help="write JSON here instead of stdout")
    args = parser.parse_args()
    target = os.path.abspath(args.target)
    citations, checks = load_registry()

    files, unknowns = [], []
    for root, dirs, names in os.walk(target):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for name in sorted(names):
            path = os.path.join(root, name)
            rel = os.path.relpath(path, target)
            entry = classify_file(path, rel)
            if entry is None:
                continue
            if entry.get("unreadable"):
                unknowns.append({
                    "check_id": "DC-03",
                    "reason": f"'{rel}' could not be read ({entry['error']}) — its tier is unverified.",
                    "action": "Fix permissions (or classify it manually) and re-run; do not treat "
                              "this file as a pass.",
                })
            else:
                files.append(entry)

    findings = build_findings(files, citations, checks)
    suppressions = load_suppressions(target)
    active, suppressed = [], []
    for f in findings:
        entry = suppressions.get(f["fingerprint"])
        if entry and not entry["expired"]:
            suppressed.append({
                "fingerprint": f["fingerprint"],
                "title": f["title"],
                "severity": f["severity"],
                "reason": entry["reason"],
                "expires": entry["expires"],
            })
        else:
            if entry and entry["expired"]:
                f["evidence"] += " (A suppression for this finding expired.)"
            active.append(f)

    result = {
        "schema_version": SCHEMA_VERSION,
        "skill": "data-classification",
        "target": target,
        "tools": {"classify_hints": "1"},
        "files": files,
        "findings": active,
        "unknowns": unknowns,
        "suppressed": suppressed,
    }
    output = json.dumps(result, indent=2)
    if args.emit_json:
        with open(args.emit_json, "w", encoding="utf-8") as fh:
            fh.write(output + "\n")
    else:
        print(output)


if __name__ == "__main__":
    main()
