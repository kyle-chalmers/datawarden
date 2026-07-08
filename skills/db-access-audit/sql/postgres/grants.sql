-- grants.sql — table-level privileges held by the AI principal, split base table vs view.
-- Read-only. Run with: psql --csv -v ai_role='<role>' -f grants.sql
SELECT g.grantee,
       g.table_schema,
       g.table_name,
       g.privilege_type,
       CASE WHEN v.table_name IS NOT NULL THEN 'view' ELSE 'base table' END AS object_kind
FROM information_schema.role_table_grants g
LEFT JOIN information_schema.views v
  ON v.table_schema = g.table_schema
 AND v.table_name = g.table_name
WHERE g.grantee = :'ai_role'
ORDER BY g.table_schema, g.table_name, g.privilege_type;
