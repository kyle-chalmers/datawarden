#!/usr/bin/env bash
# Deterministic baseline checks for datawarden. Run at session start and before every commit.
# Exits non-zero on any failure. No LLM calls.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1
fail=0
step() { echo; echo "==> $1"; }

step "JSON well-formed"
for f in .claude-plugin/plugin.json .claude-plugin/marketplace.json dev/feature_list.json; do
  if ! jq empty "$f" 2>/dev/null; then
    echo "FAIL: $f is not valid JSON"
    fail=1
  fi
done

step "structure: components at plugin root, only manifests inside .claude-plugin/"
[ -d skills ] || { echo "FAIL: skills/ missing at plugin root"; fail=1; }
for d in skills hooks commands agents; do
  if [ -e ".claude-plugin/$d" ]; then
    echo "FAIL: .claude-plugin/$d must not exist (components go at plugin root)"
    fail=1
  fi
done

step "plugin.json contract"
if [ "$(jq -r .name .claude-plugin/plugin.json)" != "datawarden" ]; then
  echo "FAIL: plugin.json name must be 'datawarden'"
  fail=1
fi
if ! jq -e 'has("version") | not' .claude-plugin/plugin.json >/dev/null; then
  echo "FAIL: plugin.json must omit 'version' until first public release (git-SHA versioning)"
  fail=1
fi

# Non-strict during dev: --strict escalates the intentional absence of a version field
# (git-SHA versioning until first public release) into an error. At public release,
# add semver to plugin.json and switch this to `claude plugin validate . --strict`.
step "claude plugin validate"
if command -v claude >/dev/null 2>&1; then
  if ! claude plugin validate .; then
    echo "FAIL: claude plugin validate"
    fail=1
  fi
else
  echo "SKIP: claude CLI not found (CI fallback: jq checks above)"
fi

step "shellcheck on dev/ and tests/ scripts"
if command -v shellcheck >/dev/null 2>&1; then
  while IFS= read -r -d '' f; do
    if ! shellcheck "$f"; then
      echo "FAIL: shellcheck $f"
      fail=1
    fi
  done < <(find dev tests -name '*.sh' -type f -print0 2>/dev/null)
else
  echo "SKIP: shellcheck not found"
fi

step "read-only SQL pack lint (no mutating statements)"
if compgen -G "skills/db-access-audit/sql/*/*.sql" >/dev/null 2>&1; then
  if grep -riEn '^[[:space:]]*(insert|update|delete|drop|alter|create|grant|revoke|truncate|merge|call|copy)\b' \
    skills/db-access-audit/sql/; then
    echo "FAIL: mutating SQL statement found in read-only audit pack"
    fail=1
  else
    echo "OK: SQL packs contain no mutating statements"
  fi
else
  echo "SKIP: no SQL packs yet"
fi

step "fixture checks"
if [ -x tests/run-fixture-checks.sh ]; then
  if ! tests/run-fixture-checks.sh; then
    echo "FAIL: fixture checks"
    fail=1
  fi
else
  echo "SKIP: no fixture checks yet"
fi

echo
if [ "$fail" -eq 0 ]; then
  echo "VALIDATE: PASS"
else
  echo "VALIDATE: FAIL"
  exit 1
fi
