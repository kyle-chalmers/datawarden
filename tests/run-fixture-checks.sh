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

echo
if [ "$fail" -eq 0 ]; then echo "FIXTURES: PASS"; else echo "FIXTURES: FAIL"; exit 1; fi
