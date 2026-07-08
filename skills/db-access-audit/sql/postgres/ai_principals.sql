-- ai_principals.sql — enumerate roles so the user can confirm which principal the AI uses.
-- Read-only. Run with: psql --csv -f ai_principals.sql
SELECT rolname,
       rolcanlogin,
       rolsuper,
       rolbypassrls
FROM pg_roles
WHERE rolname NOT LIKE 'pg\_%'
ORDER BY rolname;
