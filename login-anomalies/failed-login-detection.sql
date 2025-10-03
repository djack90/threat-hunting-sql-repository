-- Purpose: Detect repeated failed login attempts by user and source IP within a configurable time window.
-- Assumptions: auth_logs contains login events with event_type in ('LOGIN_FAILED', 'LOGIN_SUCCESS'). Timestamps are UTC.
-- Parameters:
--   :failed_login_window_hours - rolling lookback window in hours (default 24).
--   :failed_login_threshold    - minimum failed attempts before alerting (default 5).
-- Outputs: user_id, source_ip, failed_count, first_failed_ts, last_failed_ts, recommended_severity.
-- Tuning notes: Increase the threshold for noisy service accounts or known brute-force scanning ranges. Consider adding IP reputation data.
-- False positives: Legitimate users mistyping passwords, password reset workflows, and load testing. Whitelist trusted automation accounts.
-- Severity guidance: Higher failed counts and shorter windows warrant higher severity (e.g., Critical beyond 20 attempts in 1 hour).
WITH params AS (
    SELECT
        COALESCE(NULLIF(:'failed_login_window_hours', '')::int, 24) AS window_hours,
        COALESCE(NULLIF(:'failed_login_threshold', '')::int, 5)        AS min_failures
),
recent_events AS (
    SELECT
        al.ts,
        al.user_id,
        al.source_ip,
        al.event_type
    FROM auth_logs al
    CROSS JOIN params p
    WHERE al.ts >= NOW() - (p.window_hours || ' hours')::interval
      AND al.event_type IN ('LOGIN_FAILED', 'LOGIN_SUCCESS')
),
failed_attempts AS (
    SELECT
        user_id,
        source_ip,
        COUNT(*) AS failed_count,
        MIN(ts) AS first_failed_ts,
        MAX(ts) AS last_failed_ts
    FROM recent_events
    WHERE event_type = 'LOGIN_FAILED'
    GROUP BY user_id, source_ip
),
severity_mapping AS (
    SELECT
        fa.user_id,
        fa.source_ip,
        fa.failed_count,
        fa.first_failed_ts,
        fa.last_failed_ts,
        CASE
            WHEN fa.failed_count >= 20 THEN 'Critical'
            WHEN fa.failed_count >= 10 THEN 'High'
            WHEN fa.failed_count >= 5  THEN 'Medium'
            ELSE 'Informational'
        END AS recommended_severity
    FROM failed_attempts fa
)
SELECT
    sm.user_id,
    sm.source_ip,
    sm.failed_count,
    sm.first_failed_ts,
    sm.last_failed_ts,
    sm.recommended_severity
FROM severity_mapping sm
CROSS JOIN params p
WHERE sm.failed_count >= p.min_failures
ORDER BY sm.failed_count DESC, sm.last_failed_ts DESC;
