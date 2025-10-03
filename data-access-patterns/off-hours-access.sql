-- Purpose: Flag access to sensitive resources that occur outside configured business hours.
-- Assumptions: data_access_logs contains resource names and operation types, timestamps stored in UTC.
-- Parameters:
--   :off_hours_start_hour - start of business hours (0-23, default 8).
--   :off_hours_end_hour   - end of business hours (0-23, default 18).
--   :off_hours_timezone   - IANA timezone identifier for local business hours (default 'UTC').
-- Outputs: user_id, ts, resource, operation, local_hour, is_off_hours.
-- Tuning notes: Align timezone per user or office when possible. Consider rotating schedules for global teams.
-- False positives: On-call staff, maintenance windows, global workforce. Pair with HR schedules or approval workflows.
WITH params AS (
    SELECT
        COALESCE(NULLIF(:'off_hours_start_hour', '')::int, 8) AS start_hour,
        COALESCE(NULLIF(:'off_hours_end_hour', '')::int, 18) AS end_hour,
        COALESCE(NULLIF(:'off_hours_timezone', ''), 'UTC') AS tz_name
),
sensitive_access AS (
    SELECT
        dal.user_id,
        dal.ts,
        dal.resource,
        dal.operation_type,
        timezone(p.tz_name, dal.ts) AS local_ts,
        EXTRACT(HOUR FROM timezone(p.tz_name, dal.ts))::int AS local_hour
    FROM data_access_logs dal
    CROSS JOIN params p
    WHERE dal.ts >= NOW() - INTERVAL '7 days'
      AND dal.is_sensitive = TRUE
)
SELECT
    sa.user_id,
    sa.ts,
    sa.resource,
    sa.operation_type AS operation,
    sa.local_hour,
    (sa.local_hour < p.start_hour OR sa.local_hour >= p.end_hour) AS is_off_hours
FROM sensitive_access sa
CROSS JOIN params p
ORDER BY sa.ts DESC;
