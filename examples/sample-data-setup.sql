-- Sample data setup for threat-hunting-sql repository.
-- Creates minimal schemas and inserts representative events demonstrating normal and suspicious behavior.
-- Run with: psql -h <HOST> -U <USER> -d <DATABASE> -f examples/sample-data-setup.sql

BEGIN;

-- Clean up existing objects for repeatability (comment out in production environments).
DROP TABLE IF EXISTS auth_logs CASCADE;
DROP TABLE IF EXISTS ip_geolocation CASCADE;
DROP TABLE IF EXISTS data_access_logs CASCADE;
DROP TABLE IF EXISTS user_permissions_audit CASCADE;
DROP TABLE IF EXISTS users CASCADE;

-- User directory for privilege context.
CREATE TABLE users (
    user_id TEXT PRIMARY KEY,
    display_name TEXT,
    department TEXT,
    role_name TEXT,
    privilege_level INTEGER CHECK (privilege_level >= 0)
);

INSERT INTO users (user_id, display_name, department, role_name, privilege_level) VALUES
    ('alice',  'Alice Anderson',  'Engineering', 'Engineer',          3),
    ('bob',    'Bob Brown',       'Finance',     'Analyst',            2),
    ('carol',  'Carol Chen',      'Security',    'Security Analyst',   6),
    ('dave',   'Dave Diaz',       'IT',          'Systems Admin',      7),
    ('eve',    'Evelyn Evans',    'IT',          'Helpdesk',           3),
    ('svc_ci', 'CI Service User', 'Engineering', 'Automation Account', 1);

-- Authentication logs.
CREATE TABLE auth_logs (
    ts TIMESTAMPTZ NOT NULL,
    user_id TEXT NOT NULL,
    source_ip TEXT NOT NULL,
    event_type TEXT NOT NULL CHECK (event_type IN ('LOGIN_FAILED', 'LOGIN_SUCCESS'))
);

CREATE INDEX ON auth_logs (ts);
CREATE INDEX ON auth_logs (user_id);
CREATE INDEX ON auth_logs (source_ip);

INSERT INTO auth_logs (ts, user_id, source_ip, event_type) VALUES
    (NOW() - INTERVAL '26 hours', 'alice', '203.0.113.5',  'LOGIN_SUCCESS'),
    (NOW() - INTERVAL '25 hours', 'alice', '203.0.113.5',  'LOGIN_SUCCESS'),
    (NOW() - INTERVAL '6 hours',  'bob',   '198.51.100.8', 'LOGIN_SUCCESS'),
    (NOW() - INTERVAL '5 hours',  'bob',   '198.51.100.8', 'LOGIN_FAILED'),
    (NOW() - INTERVAL '4 hours',  'bob',   '198.51.100.8', 'LOGIN_FAILED'),
    (NOW() - INTERVAL '3 hours',  'bob',   '198.51.100.8', 'LOGIN_FAILED'),
    (NOW() - INTERVAL '2 hours',  'bob',   '198.51.100.8', 'LOGIN_FAILED'),
    (NOW() - INTERVAL '95 minutes', 'bob', '198.51.100.8', 'LOGIN_FAILED'),
    (NOW() - INTERVAL '90 minutes', 'bob', '198.51.100.8', 'LOGIN_FAILED'),
    (NOW() - INTERVAL '2 hours',  'carol', '192.0.2.44',   'LOGIN_SUCCESS'),
    (NOW() - INTERVAL '90 minutes', 'alice', '192.0.2.55', 'LOGIN_SUCCESS'),
    (NOW() - INTERVAL '75 minutes', 'alice', '192.0.2.55', 'LOGIN_SUCCESS'),
    (NOW() - INTERVAL '70 minutes', 'alice', '198.51.100.200', 'LOGIN_SUCCESS'),
    (NOW() - INTERVAL '65 minutes', 'alice', '198.51.100.200', 'LOGIN_SUCCESS'),
    (NOW() - INTERVAL '10 minutes', 'alice', '198.51.100.200', 'LOGIN_SUCCESS');

-- IP to location mapping (representative data only).
CREATE TABLE ip_geolocation (
    ip TEXT PRIMARY KEY,
    country TEXT,
    region TEXT,
    city TEXT
);

INSERT INTO ip_geolocation (ip, country, region, city) VALUES
    ('203.0.113.5',    'US', 'California', 'San Francisco'),
    ('198.51.100.8',   'US', 'New York',   'New York'),
    ('192.0.2.44',     'US', 'Illinois',   'Chicago'),
    ('192.0.2.55',     'US', 'Texas',      'Austin'),
    ('198.51.100.200', 'DE', 'Berlin',     'Berlin');

-- Data access logs.
CREATE TABLE data_access_logs (
    ts TIMESTAMPTZ NOT NULL,
    user_id TEXT NOT NULL,
    resource TEXT NOT NULL,
    operation_type TEXT NOT NULL,
    bytes_transferred BIGINT NOT NULL,
    is_sensitive BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE INDEX ON data_access_logs (ts);
CREATE INDEX ON data_access_logs (user_id);
CREATE INDEX ON data_access_logs (resource);

INSERT INTO data_access_logs (ts, user_id, resource, operation_type, bytes_transferred, is_sensitive) VALUES
    (NOW() - INTERVAL '35 days', 'alice', 'repo/app',           'READ',   1048576, FALSE),
    (NOW() - INTERVAL '5 days',  'alice', 'repo/app',           'READ',   2097152, FALSE),
    (NOW() - INTERVAL '1 day',   'alice', 'repo/app',           'READ',   1048576, FALSE),
    (NOW() - INTERVAL '8 hours', 'alice', 'repo/app',           'READ',   10485760, FALSE),
    (NOW() - INTERVAL '4 hours', 'alice', 'repo/app',           'READ',   5242880, FALSE),
    (NOW() - INTERVAL '2 hours', 'alice', 'repo/app',           'READ',   5242880, FALSE),
    (NOW() - INTERVAL '1 hour',  'alice', 'repo/app',           'READ',   5242880, FALSE),
    (NOW() - INTERVAL '18 hours','bob',   'finance/reports',    'READ',   1048576, TRUE),
    (NOW() - INTERVAL '16 hours','bob',   'finance/reports',    'READ',   1048576, TRUE),
    (NOW() - INTERVAL '14 hours','bob',   'finance/reports',    'READ',   1048576, TRUE),
    (NOW() - INTERVAL '12 hours','bob',   'finance/reports',    'READ',   1048576, TRUE),
    (NOW() - INTERVAL '10 hours','bob',   'finance/reports',    'READ',   1048576, TRUE),
    (NOW() - INTERVAL '8 hours', 'bob',   'finance/reports',    'READ',   1048576, TRUE),
    (NOW() - INTERVAL '6 hours', 'bob',   'finance/reports',    'READ',   1048576, TRUE),
    (NOW() - INTERVAL '5 hours', 'bob',   'finance/reports',    'READ',   1048576, TRUE),
    (NOW() - INTERVAL '4 hours', 'bob',   'finance/reports',    'READ',   1048576, TRUE),
    (NOW() - INTERVAL '3 hours', 'bob',   'finance/reports',    'READ',   1048576, TRUE),
    (NOW() - INTERVAL '2 hours', 'bob',   'finance/reports',    'READ',   1048576, TRUE),
    (NOW() - INTERVAL '1 hour',  'bob',   'finance/reports',    'READ',   52428800, TRUE),
    (NOW() - INTERVAL '11 hours','carol', 'security/tools',     'ADMIN',  1048576, TRUE),
    (NOW() - INTERVAL '2 days',  'dave',  'infrastructure/vpn', 'ADMIN',  1048576, TRUE),
    (NOW() - INTERVAL '3 hours', 'eve',   'support/kb',         'READ',    524288, FALSE),
    (NOW() - INTERVAL '2 hours', 'svc_ci','build/artifacts',    'WRITE',  8388608, FALSE);

-- Permission audit log capturing grants and revokes.
CREATE TABLE user_permissions_audit (
    ts TIMESTAMPTZ NOT NULL,
    admin_user TEXT NOT NULL,
    target_user TEXT NOT NULL,
    action TEXT NOT NULL,
    object TEXT,
    details TEXT
);

CREATE INDEX ON user_permissions_audit (ts);
CREATE INDEX ON user_permissions_audit (target_user);

INSERT INTO user_permissions_audit (ts, admin_user, target_user, action, object, details) VALUES
    (NOW() - INTERVAL '10 days', 'dave',  'alice', 'GRANT ROLE', 'ENGINEER', 'Routine onboarding'),
    (NOW() - INTERVAL '8 days',  'dave',  'bob',   'GRANT ROLE', 'ANALYST',  'Finance assignment'),
    (NOW() - INTERVAL '3 days',  'dave',  'carol', 'GRANT ROLE', 'SECURITY_ADMIN', 'Access review approved'),
    (NOW() - INTERVAL '1 day',   'dave',  'eve',   'REVOKE ROLE', 'HELPDESK', 'Ticket closure'),
    (NOW() - INTERVAL '6 hours', 'dave',  'bob',   'GRANT ROLE', 'FINANCE_ADMIN', 'Emergency escalation'),
    (NOW() - INTERVAL '2 hours', 'dave',  'svc_ci','GRANT ROLE', 'DEPLOY_ADMIN', 'Pipeline update'),
    (NOW() - INTERVAL '30 minutes', 'dave', 'bob', 'ALTER ROLE', 'FINANCE_ADMIN', 'Promoted to admin rights');

COMMIT;

-- Suggested indexes for production scale:
-- CREATE INDEX CONCURRENTLY idx_auth_logs_ts_user ON auth_logs (ts, user_id);
-- CREATE INDEX CONCURRENTLY idx_data_access_sensitive ON data_access_logs (is_sensitive, ts);
-- CREATE INDEX CONCURRENTLY idx_permissions_target_ts ON user_permissions_audit (target_user, ts DESC);
