-- masked_views.sql — does a masked/governed layer exist? Two signals: dynamic masking
-- policies anywhere in the account, and the view inventory of the target database.
-- Read-only. Run with: snow sql -c <connection> -D "db=YOUR_DATABASE" -f masked_views.sql
SHOW MASKING POLICIES IN ACCOUNT;
SHOW VIEWS IN DATABASE &{ db };
