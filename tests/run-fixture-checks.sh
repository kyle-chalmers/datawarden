#!/usr/bin/env bash
# Deterministic fixture assertions for datawarden. No LLM calls.
# Bidirectional: a missing expected finding is a false-negative regression;
# an unexpected finding on clean paths is a false-positive regression.
set -euo pipefail
cd "$(dirname "$0")/.." || exit 1
fail=0
step() { echo; echo "==> $1"; }

step "reference consistency: checks.yml -> citations.yml + fixtures"
if ! jq -e --slurpfile cites reference/citations.yml '
    [.checks | to_entries[]
     | select((.value.citations - ($cites[0].citations | keys)) != [] or (.value.fixtures | length) == 0)
     | .key] == []' reference/checks.yml >/dev/null; then
  echo "FAIL: a check in checks.yml cites an unknown citation key or has no fixture"
  jq -r --slurpfile cites reference/citations.yml '
    .checks | to_entries[]
    | select((.value.citations - ($cites[0].citations | keys)) != [] or (.value.fixtures | length) == 0)
    | "  offending check: \(.key)"' reference/checks.yml
  fail=1
else
  echo "OK: every check cites known citations and names at least one fixture"
fi

if ! command -v gitleaks >/dev/null 2>&1; then
  echo "SKIP: gitleaks not installed — secrets fixture assertions skipped (install: brew install gitleaks)"
  exit "$fail"
fi

EVAL="skills/secrets-scanner/scripts/eval_secrets.py"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

run_eval() { # $1 repo path -> writes $TMP/out.json
  local repo="$1"
  gitleaks git --no-banner --redact --report-format json --report-path "$TMP/hist.json" "$repo" >/dev/null 2>&1 || true
  gitleaks dir --no-banner --redact --report-format json --report-path "$TMP/dir.json" "$repo" >/dev/null 2>&1 || true
  python3 "$EVAL" --history-report "$TMP/hist.json" --dir-report "$TMP/dir.json" \
    --target "$repo" --gitleaks-version "test" --emit-json "$TMP/out.json"
}

assert() { # $1 description, $2 jq expression that must be true against $TMP/out.json
  if jq -e "$2" "$TMP/out.json" >/dev/null; then
    echo "OK: $1"
  else
    echo "FAIL: $1"
    echo "     (expression: $2)"
    fail=1
  fi
}

step "fixture secrets-generated: SS-01 history HIGH + SS-03 disk CRITICAL"
REPO="$(tests/fixtures/make-secrets-repo.sh | tail -1)"
run_eval "$REPO"
assert "exactly 2 findings" '.findings | length == 2'
assert "SS-01 present, severity HIGH, history-only exposure" \
  '.findings | any(.check_id == "SS-01" and .severity == "HIGH" and .exposure.in_history and (.exposure.on_disk | not) and (.exposure.vcs_remote | not))'
assert "SS-03 present on .env, severity CRITICAL, confirmed, agent-readable" \
  '.findings | any(.check_id == "SS-03" and .file == ".env" and .severity == "CRITICAL" and .confidence == "confirmed" and .exposure.agent_readable)'
assert "no secret values leak into the report (no ghp_ or AKIA strings)" \
  '[tostring | test("ghp_[A-Za-z0-9]{36}|AKIA[A-Z0-9]{16}")] == [false]'
assert "every finding carries at least one citation" \
  '[.findings[] | .citations | length > 0] | all'
assert "every finding carries a fingerprint" \
  '[.findings[] | .fingerprint | length > 0] | all'

step "fixture secrets-generated-denied: deny rule flips SS-03 to SS-02 HIGH"
REPO="$(tests/fixtures/make-secrets-repo.sh --with-deny-rule | tail -1)"
run_eval "$REPO"
assert "SS-02 present on .env, severity HIGH, not agent-readable" \
  '.findings | any(.check_id == "SS-02" and .file == ".env" and .severity == "HIGH" and (.exposure.agent_readable | not))'
assert "no SS-03 finding (false-positive guard)" \
  '[.findings[] | select(.check_id == "SS-03")] | length == 0'

step "fixture secrets-generated-remote: pushed history flips SS-01 to SS-04 rotate-first"
REPO="$(tests/fixtures/make-secrets-repo.sh --with-remote | tail -1)"
run_eval "$REPO"
assert "SS-04 present with rotate_first and vcs_remote exposure" \
  '.findings | any(.check_id == "SS-04" and .rotate_first and .exposure.vcs_remote)'
assert "no SS-01 finding (exposure upgraded, not duplicated)" \
  '[.findings[] | select(.check_id == "SS-01")] | length == 0'

step "false-positive guard: clean repo yields zero findings"
CLEAN="$(dirname "$(tests/fixtures/make-secrets-repo.sh | tail -1)")/clean-repo"
rm -rf "$CLEAN" && mkdir -p "$CLEAN"
git -C "$CLEAN" init -q -b main
git -C "$CLEAN" -c user.name=fixture -c user.email=f@example.invalid commit -q --allow-empty -m "empty"
echo "README" > "$CLEAN/README.md"
run_eval "$CLEAN"
assert "clean repo: zero findings" '.findings | length == 0'

step "suppression: .datawarden-ignore moves a finding to the appendix"
REPO="$(tests/fixtures/make-secrets-repo.sh | tail -1)"
FP="$(run_eval "$REPO"; jq -r '[.findings[] | select(.check_id == "SS-03")][0].fingerprint' "$TMP/out.json")"
printf '%s reason=fixture test\n' "$FP" > "$REPO/.datawarden-ignore"
run_eval "$REPO"
assert "suppressed finding is in the appendix, not findings" \
  '(.findings | map(.check_id) | index("SS-03")) == null and (.suppressed | length == 1)'

PERMEVAL="skills/ai-config-audit/scripts/permeval.py"

step "fixture ai-config: AC-01..AC-05 findings + AC-06 unknown"
python3 "$PERMEVAL" --target tests/fixtures/ai-config \
  --home tests/fixtures/ai-config/home --emit-json "$TMP/out.json"
assert "AC-01: all 3 recommended deny rules reported missing" \
  '.findings | any(.check_id == "AC-01" and (.title | test("Missing 3")) and .severity == "HIGH")'
assert "AC-02: Bash(npx *) flagged as env-runner allow" \
  '.findings | any(.check_id == "AC-02" and (.title | test("npx")) and .severity == "HIGH")'
assert "AC-02: colon-wildcard spelling Bash(uvx:*) also flagged" \
  '.findings | any(.check_id == "AC-02" and (.title | test("uvx")))'
assert "AC-03: credential-shaped MCP env key flagged by name" \
  '.findings | any(.check_id == "AC-03" and (.evidence | test("WAREHOUSE_PASSWORD")))'
assert "AC-03: the placeholder value itself never appears in output" \
  '[tostring | test("placeholder-not-a-real-value")] == [false]'
assert "AC-04: gemini trust:true flagged" \
  '.findings | any(.check_id == "AC-04" and (.file | test("gemini")))'
assert "AC-05: transcript INFO present" \
  '.findings | any(.check_id == "AC-05" and .severity == "INFO")'
assert "AC-06: retention always reported UNKNOWN with manual-check action" \
  '.unknowns | any(.check_id == "AC-06" and (.action | test("data-privacy-controls")))'
assert "every ai-config finding carries a citation and fingerprint" \
  '[.findings[] | (.citations | length > 0) and (.fingerprint | length > 0)] | all'

step "fixture ai-config-hardened: false-positive guard"
HARDHOME="$TMP/empty-home"
mkdir -p "$HARDHOME"
python3 "$PERMEVAL" --target tests/fixtures/ai-config-hardened \
  --home "$HARDHOME" --emit-json "$TMP/out.json"
assert "hardened config: zero findings" '.findings | length == 0'
assert "hardened config: AC-06 unknown still present (never a clean bill)" \
  '.unknowns | any(.check_id == "AC-06")'

CLASSIFY="skills/data-classification/scripts/classify_hints.py"

step "matcher unit tests (permission globs + fail-closed expiry)"
if ! python3 tests/test_matchers.py; then fail=1; fi

step "fixture classify-repo: deterministic floors, validators, no values in output"
python3 "$CLASSIFY" --target tests/fixtures/classify-repo --emit-json "$TMP/out.json"
assert "accounts.csv floors to Restricted, confirmed, via SSN + Luhn validators" \
  '.files | any(.path == "accounts.csv" and .floor == "Restricted" and .confidence == "confirmed" and .indicators.ssn_valid == 2 and .indicators.pan_luhn_valid >= 2)'
assert "customers.csv floors to Confidential via validated emails + PII columns" \
  '.files | any(.path == "customers.csv" and .floor == "Confidential" and .indicators.emails == 2 and (.pii_columns | length >= 2))'
assert "README.md and runbook.md floor to Internal (never auto-Public)" \
  '[.files[] | select(.path == "README.md" or .path == "runbook.md") | .floor == "Internal"] == [true, true]'
assert "no data values leak into hint output (no SSN/PAN/email strings)" \
  '[tostring | test("078-05-1120|4111111111111111|jane\\.doe@example\\.com")] == [false]'
assert "nothing is ever floored to Public" \
  '[.files[] | .floor != "Public"] | all'
assert "DC-01 finding emitted for accounts.csv (HIGH, confirmed, cited)" \
  '.findings | any(.check_id == "DC-01" and .file == "accounts.csv" and .severity == "HIGH" and .confidence == "confirmed" and (.citations | length > 0))'
assert "DC-02 finding emitted for customers.csv (MEDIUM)" \
  '.findings | any(.check_id == "DC-02" and .file == "customers.csv" and .severity == "MEDIUM")'

step "classification DC-03: unreadable file becomes an UNKNOWN, never a silent skip"
DCDIR="$TMP/dc-unreadable"
mkdir -p "$DCDIR"
echo "readable" > "$DCDIR/ok.txt"
echo "hidden" > "$DCDIR/locked.txt"
chmod 000 "$DCDIR/locked.txt"
if [ -r "$DCDIR/locked.txt" ]; then
  echo "SKIP: running as root (chmod 000 still readable) — DC-03 check skipped"
else
  python3 "$CLASSIFY" --target "$DCDIR" --emit-json "$TMP/out.json"
  assert "DC-03 unknown names the unreadable file" \
    '.unknowns | any(.check_id == "DC-03" and (.reason | test("locked.txt")))'
  assert "unreadable file absent from the classification table" \
    '[.files[] | .path] | index("locked.txt") == null'
fi
chmod 644 "$DCDIR/locked.txt" 2>/dev/null || true

step "classification suppression: .datawarden-ignore moves DC finding to appendix"
DCSUP="$TMP/dc-suppress"
mkdir -p "$DCSUP"
cp tests/fixtures/classify-repo/accounts.csv "$DCSUP/"
printf 'DC-01:accounts.csv:Restricted reason=fixture test\n' > "$DCSUP/.datawarden-ignore"
python3 "$CLASSIFY" --target "$DCSUP" --emit-json "$TMP/out.json"
assert "DC-01 suppressed into appendix" \
  '(.findings | map(.check_id) | index("DC-01")) == null and (.suppressed | length == 1)'

step "db-access-audit suppression via --ignore-dir (recorded CSVs, no docker)"
DBSUP="$TMP/db-suppress"
mkdir -p "$DBSUP"
printf 'DB-04:views:db reason=fixture test\n' > "$DBSUP/.datawarden-ignore"
python3 skills/db-access-audit/scripts/eval_grants.py \
  --grants tests/fixtures/postgres/expected/grants.csv \
  --pii tests/fixtures/postgres/expected/pii_columns.csv \
  --views tests/fixtures/postgres/expected/masked_views.csv \
  --settings tests/fixtures/postgres/expected/audit_logging.csv \
  --role ai_agent --principal-confirmed --ignore-dir "$DBSUP" --emit-json "$TMP/out.json"
assert "DB-04 suppressed into appendix; other findings intact" \
  '(.findings | map(.check_id) | index("DB-04")) == null and (.suppressed | length == 1) and (.findings | length >= 3)'

step "postgres pack (docker; self-skips when unavailable)"
if ! tests/postgres-fixture-check.sh; then
  echo "FAIL: postgres pack checks"
  fail=1
fi

echo
if [ "$fail" -eq 0 ]; then echo "FIXTURES: PASS"; else echo "FIXTURES: FAIL"; exit 1; fi
