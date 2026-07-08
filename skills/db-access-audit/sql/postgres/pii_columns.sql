-- pii_columns.sql — columns whose names match the shared PII patterns
-- (reference/four-tier-framework.md), outside system schemas.
-- Read-only. Run with: psql --csv -f pii_columns.sql
SELECT c.table_schema,
       c.table_name,
       c.column_name,
       c.data_type,
       CASE
         WHEN c.column_name ~* '^(ssn|social_security(_number)?|tax_id|national_id|passport(_number)?|card_number|pan|cvv|account_number|routing_number|dob|birth_date|date_of_birth|diagnosis)$'
           THEN 'Restricted'
         ELSE 'Confidential'
       END AS tier_floor
FROM information_schema.columns c
WHERE c.table_schema NOT IN ('pg_catalog', 'information_schema')
  AND c.column_name ~* '^(ssn|social_security(_number)?|tax_id|national_id|passport(_number)?|card_number|pan|cvv|account_number|routing_number|dob|birth_date|date_of_birth|diagnosis|email|phone|mobile|address|first_name|last_name|full_name|ip_address|salary|income)$'
ORDER BY c.table_schema, c.table_name, c.column_name;
