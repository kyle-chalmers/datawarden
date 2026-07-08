-- grants.sql — privileges granted to the AI role.
-- Read-only. Run with: snow sql -c <connection> -D "role=YOUR_AI_ROLE" -f grants.sql
-- Interpretation: privilege in {INSERT, UPDATE, DELETE, TRUNCATE, OWNERSHIP} on a TABLE -> DB-01;
-- privilege = SELECT with granted_on = TABLE (not VIEW) -> DB-02.
SHOW GRANTS TO ROLE &{ role };
