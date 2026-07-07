# ai-config-audit reference

## What is auditable from disk, and what is not

| Concern | Locally auditable? | Check |
|---|---|---|
| Secret-file deny rules | Yes — `.claude/settings.json` / `.claude/settings.local.json` | AC-01 |
| Over-broad allow rules | Yes — same files | AC-02 |
| Credentials in MCP configs | Yes — config files below | AC-03 |
| Gemini `trust: true` | Yes — `.gemini/settings.json` | AC-04 |
| Plaintext transcripts | Yes — `~/.claude/projects/` | AC-05 |
| Consumer training/retention tier | **No** — account setting at claude.ai | AC-06 (always UNKNOWN) |

## MCP config path matrix (scanned by permeval.py)

| Tool | Project scope | User scope |
|---|---|---|
| Claude Code | `.mcp.json` | `~/.claude.json` (`mcpServers` key) |
| Claude Desktop | — | `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) |
| Cursor | `.cursor/mcp.json` | `~/.cursor/mcp.json` |
| Gemini CLI | `.gemini/settings.json` | `~/.gemini/settings.json` |
| Codex | — | `~/.codex/config.toml` (`[mcp_servers.*]` tables) + `~/.codex/auth.json` |

Codex TOML is parsed with `tomllib` on Python ≥3.11, else a line-based approximation that reads
key names only.

## Retention facts (verified against live Claude Code docs, 2026-07-07)

- **Consumer (Free/Pro/Max)**: the "Help improve Claude" toggle controls training; ON means
  5-year retention, OFF means 30 days. The Aug 2025 rollout presented it pre-set to ON.
  Check: https://claude.ai/settings/data-privacy-controls
- **Commercial (Team/Enterprise/API)**: not trained on by default; 30-day retention; Zero Data
  Retention is a per-organization option for qualified Enterprise accounts only.
- **Transcripts**: Claude Code stores session transcripts in plaintext under `~/.claude/projects/`
  for `cleanupPeriodDays` (default 30).

Re-verify these facts against https://code.claude.com/docs/en/data-usage when they matter — this
table has a compiled-on date, not an expiry warranty.

## Why AC-02 flags env-runners

`Bash(npx *)` reads as "allow npx" but means "allow anything npx can download and execute" — the
wildcard swallows the inner command. Same for uvx, pnpm dlx, docker run/exec, bare shells, etc.
The docs themselves call argument-constraining Bash patterns fragile; prefer exact commands and
PreToolUse hooks for anything broader.

## Deny rules vs. the OS (the AC-01 caveat)

`permissions.deny` `Read(...)` rules are enforced by Claude Code's tool layer. A subprocess the
agent legitimately runs (a Python script, a make target) reads files with the agent's OS
permissions and never consults deny rules. Deny rules are the right first step; OS-level
guarantees require sandboxing.

## Manual procedure — AC-06 (`manual-retention-check`)

1. Open https://claude.ai/settings/data-privacy-controls while logged into the account used by
   the AI tooling.
2. Record the state of "Help improve Claude" and the resulting retention window.
3. For Team/Enterprise: confirm the plan tier and any ZDR agreement in writing with the org admin.
4. Record the outcome next to the audit report; the report itself stays UNKNOWN by design.
