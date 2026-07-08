#!/usr/bin/env python3
"""Unit tests for the deterministic matchers — locks the permission-glob semantics and the
fail-closed suppression-expiry behavior. Stdlib only; run by tests/run-fixture-checks.sh."""

import importlib.util
import os
import sys
import tempfile

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def load(name, rel):
    spec = importlib.util.spec_from_file_location(name, os.path.join(ROOT, rel))
    assert spec is not None and spec.loader is not None, rel
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


eval_secrets = load("eval_secrets", "skills/secrets-scanner/scripts/eval_secrets.py")

CASES = [
    # (pattern, relpath, expected deny_covers)
    ("./.env", ".env", True),
    ("./.env", "sub/.env", False),          # ./ anchors at project root
    (".env", ".env", True),
    (".env", "a/b/.env", True),             # bare name matches at any depth
    (".env", "prod.env", False),            # never a substring match
    ("**/.env", "a/b/.env", True),
    ("**/.env", ".env", True),              # zero segments allowed
    ("**/.env", "prod.env", False),         # the over-match bug this file locks against
    ("./secrets/**", "secrets/a/b.pem", True),
    ("./secrets/**", "notsecrets/a.pem", False),
    ("./.env.*", ".env.local", True),
    ("./.env.*", ".environment", False),
]

failures = []
for pattern, relpath, expected in CASES:
    got = eval_secrets.deny_covers(pattern, relpath)
    if got is not expected:
        failures.append(f"deny_covers({pattern!r}, {relpath!r}) = {got}, expected {expected}")

# Fail-closed expiry: an unparseable expires= must count as expired (finding resurfaces).
with tempfile.TemporaryDirectory() as tmp:
    with open(os.path.join(tmp, ".datawarden-ignore"), "w", encoding="utf-8") as f:
        f.write("SS-03:.env:github-pat expires=not-a-date reason=bad expiry\n")
        f.write("SS-01:x:y expires=2099-01-01 reason=valid future\n")
    entries = eval_secrets.load_suppressions(tmp)
    if not entries["SS-03:.env:github-pat"]["expired"]:
        failures.append("malformed expires= did not fail closed (should count as expired)")
    if entries["SS-01:x:y"]["expired"]:
        failures.append("valid future expires= incorrectly treated as expired")

if failures:
    print("MATCHER TESTS: FAIL")
    for f in failures:
        print("  " + f)
    sys.exit(1)
print(f"MATCHER TESTS: PASS ({len(CASES)} glob cases + expiry fail-closed)")
