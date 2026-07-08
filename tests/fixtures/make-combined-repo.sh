#!/usr/bin/env bash
# Generate the combined fixture repo for the security-audit orchestrator end-to-end check.
# Layers every finding class into one target:
#   - pushed history secret (SS-04, rotate-first) + gitignored .env secret (SS-03)  [generated]
#   - misconfigured .claude/settings.json + .mcp.json + .gemini/settings.json (AC-01/02/03/04)
#   - Confidential + Restricted data files (DC-01/DC-02)
# Prints the combined repo path on the last line of stdout.
set -euo pipefail
FIXTURES_DIR="$(cd "$(dirname "$0")" && pwd)"

SECRETS_REPO="$("$FIXTURES_DIR/make-secrets-repo.sh" --with-remote | tail -1)"
TARGET="$FIXTURES_DIR/generated/combined-repo"
rm -rf "$TARGET"
cp -R "$SECRETS_REPO" "$TARGET"

cp -R "$FIXTURES_DIR/ai-config/.claude" "$TARGET/.claude"
cp "$FIXTURES_DIR/ai-config/.mcp.json" "$TARGET/.mcp.json"
cp -R "$FIXTURES_DIR/ai-config/.gemini" "$TARGET/.gemini"
cp "$FIXTURES_DIR/classify-repo/customers.csv" "$TARGET/customers.csv"
cp "$FIXTURES_DIR/classify-repo/accounts.csv" "$TARGET/accounts.csv"

echo "$TARGET"
