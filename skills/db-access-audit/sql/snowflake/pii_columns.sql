-- pii_columns.sql — PII-named columns in the target database (INFORMATION_SCHEMA is
-- per-database in Snowflake; run once per database of interest).
-- Read-only. Run with: snow sql -c <connection> -D "db=YOUR_DATABASE" -f pii_columns.sql
-- Patterns mirror reference/four-tier-framework.md.
SELECT table_schema,
       table_name,
       column_name,
       data_type,
       CASE
         WHEN REGEXP_LIKE(column_name,
              '^(ssn|social_security(_number)?|tax_id|national_id|passport(_number)?|card_number|pan|cvv|account_number|routing_number|dob|birth_date|date_of_birth|diagnosis)$', 'i')
           THEN 'Restricted'
         ELSE 'Confidential'
       END AS tier_floor
FROM &{ db }.INFORMATION_SCHEMA.COLUMNS
WHERE table_schema <> 'INFORMATION_SCHEMA'
  AND REGEXP_LIKE(column_name,
      '^(ssn|social_security(_number)?|tax_id|national_id|passport(_number)?|card_number|pan|cvv|account_number|routing_number|dob|birth_date|date_of_birth|diagnosis|email|phone|mobile|address|first_name|last_name|full_name|ip_address|salary|income)$', 'i')
ORDER BY table_schema, table_name, column_name;
