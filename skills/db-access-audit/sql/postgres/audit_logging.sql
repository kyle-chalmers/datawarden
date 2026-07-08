-- audit_logging.sql — is there any audit trail of the AI role's queries?
-- Checks pgaudit presence and statement logging settings.
-- Read-only. Run with: psql --csv -f audit_logging.sql
SELECT name, setting
FROM pg_settings
WHERE name IN ('shared_preload_libraries', 'log_statement',
               'log_min_duration_statement', 'logging_collector')
ORDER BY name;
