-- Unified Database Initialization
\c security_db;

-- Scope grants down to what the app actually needs at runtime: row-level
-- DML on tables, and sequence usage for SERIAL columns. The 'admin' role
-- is also the database owner (POSTGRES_USER) so it already has whatever
-- object-creation rights it needs for the app's own "CREATE TABLE IF NOT
-- EXISTS" calls (celery_tasks.py) via schema ownership - it does not also
-- need blanket ALL PRIVILEGES (including EXECUTE on functions, which the
-- app never calls) granted on top of that.
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO admin;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO admin;

-- Set default privileges for future objects
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO admin;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO admin;
