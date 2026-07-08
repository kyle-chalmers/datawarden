# Expected findings — Snowflake recorded fixtures

The skill, given `--dialect snowflake --recorded tests/fixtures/snowflake --role AI_AGENT
--confirm`, must derive from the recorded outputs (interpretation rules in
`skills/db-access-audit/reference.md`):

| Check | Severity | Grounds (from the recorded outputs) |
|---|---|---|
| DB-01 | CRITICAL | `INSERT` and `UPDATE` on TABLE `ANALYTICS.APP.CUSTOMERS` granted to `AI_AGENT` |
| DB-02 | HIGH | `SELECT` with `granted_on = TABLE` on `ANALYTICS.APP.CUSTOMERS` and `ANALYTICS.APP.ORDERS` (no view grants at all) |
| DB-03 | HIGH | Restricted-floor columns `SSN`, `CARD_NUMBER` on `APP.CUSTOMERS`, a table the role can SELECT |
| DB-03 | MEDIUM | Confidential-floor columns `EMAIL`, `FULL_NAME` on the same readable table |
| DB-04 | MEDIUM | Zero masking policies in the account AND zero views in `ANALYTICS` |
| DB-05 | ≤ MEDIUM, confidence ≤ probable | Only `ACCOUNTADMIN` holds `IMPORTED PRIVILEGES` on the `SNOWFLAKE` database; no evidence anyone reviews the AI role's query history (partly organizational) |

Report requirements: header states **"Snowflake support: fixture-validated"** (or, for a real
run, that outputs were recorded, not live); every finding cites a `citations.yml` entry; no row
data appears (the fixtures contain none); severities respect the confidence caps in
`reference/finding-format.md`.

Without `--confirm` (principal unconfirmed), all severities must cap at MEDIUM/possible and a
DB-06 unknown must say why.
