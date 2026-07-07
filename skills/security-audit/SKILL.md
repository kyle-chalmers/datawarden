---
description: Run the ~30-minute end-to-end data + AI security audit — orchestrates the datawarden audit skills into one prioritized, cited report. Read-only. (Slice-0 stub — slice 5 replaces this body.)
argument-hint: "[target-directory]"
---

# security-audit (slice-0 stub)

This is a slice-0 stub that exists only to prove plugin mechanics — specifically that this skill can
invoke another datawarden skill that runs in a forked context, and receive its return value.
Do NOT perform any audit.

Steps:

1. Invoke the `datawarden:ai-config-audit` skill via the Skill tool, with no arguments.
2. Capture the single line it returns.
3. Report EXACTLY these two lines and nothing else:

```
DATAWARDEN-STUB security-audit orchestration-ok
received: <the line returned by ai-config-audit>
```
