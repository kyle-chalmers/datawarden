# Contributing to DataWarden

## Ground rules (non-negotiable for a security repo)

1. **Never commit a secret-shaped string** — not even an obviously fake one. Fixture material
   that must look like a secret is *generated at test time* (`tests/fixtures/make-*.sh`) into
   the gitignored `tests/fixtures/generated/`. Committed fixtures may only contain
   vendor-documented examples, famous fakes (078-05-1120), or inert placeholders. CI gitleaks
   self-scans tree + full history on every push; a hit fails the build and, once pushed, lives
   in history forever.
2. **Citations are verified-only.** [reference/citations.yml](reference/citations.yml) is the
   single source of citation IDs; add an entry only after checking the live source, and never
   cite from memory. Every check in [reference/checks.yml](reference/checks.yml) must map to
   existing citation keys and at least one fixture id — CI enforces this.
3. **The model narrates; scripts decide.** Anything that determines severity, confidence, or
   exposure belongs in a deterministic stdlib-Python script with fixture assertions — not in
   SKILL.md prose.
4. **Read-only.** SQL packs must contain zero mutating statements (CI-linted). Skills never
   store credentials or print data values.

## Dev loop

```bash
claude --plugin-dir .        # load the plugin locally
./dev/validate.sh            # the deterministic baseline — must pass before every commit
./tests/postgres-fixture-check.sh   # docker-based DB pack check (self-skips without docker)
```

Python is stdlib-only by design (no requirements.txt to rot). Shell scripts must pass
shellcheck. JSON-in-`.yml` files under `reference/` are deliberate — jq validates them with
zero dependencies.

## Build discipline

`dev/feature_list.json` is the immutable feature list: sessions flip only `passes` (after
demonstrating the check, never asserting it) and append evidence to `dev/progress.txt`.
New work = new thin vertical slice with a runnable check, one atomic commit per feature.

## Releases

The `version` field is intentionally absent while pre-release (git-SHA versioning). First public
release adds synced semver + CHANGELOG + `claude plugin validate --strict`, and requires the
maintainer's explicit approval — this repo does not publish or submit to any marketplace without
it.
