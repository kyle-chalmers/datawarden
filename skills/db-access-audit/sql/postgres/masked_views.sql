-- masked_views.sql — does a masked/governed view layer exist?
-- Lists non-system views and whether their definitions show masking signals
-- (hashing, truncation, or explicit mask functions).
-- Read-only. Run with: psql --csv -f masked_views.sql
SELECT v.table_schema,
       v.table_name,
       (v.view_definition ~* '(md5|sha[0-9]*|digest|hash|mask|substr|left\(|right\(|overlay)') AS has_masking_signal
FROM information_schema.views v
WHERE v.table_schema NOT IN ('pg_catalog', 'information_schema')
ORDER BY v.table_schema, v.table_name;
