-- audit_logging.sql — Snowflake always records QUERY_HISTORY; the auditable question is
-- whether anyone can and does review the AI role's queries. This lists who holds access to
-- the SNOWFLAKE database (ACCOUNT_USAGE lives there via imported privileges).
-- Read-only. Run with: snow sql -c <connection> -f audit_logging.sql
-- Interpretation: if no non-admin role holds IMPORTED PRIVILEGES here, or the user cannot
-- name who reviews AI query history, report DB-05 (confidence: probable at best — this check
-- is partly organizational).
SHOW GRANTS ON DATABASE SNOWFLAKE;
