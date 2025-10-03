-- Purpose: Detect users whose data transfer volume today greatly exceeds their historical baseline.
-- Assumptions: data_access_logs records per-operation byte counts with timestamps in UTC.
-- Parameters:
--   :data_volume_baseline_days - number of days to use for baseline averaging (default 30).
--   :data_volume_multiplier    - ratio above baseline that triggers an alert (default 10x).
-- Outputs: user_id, baseline_avg_daily_bytes, current_day_bytes, ratio, alert_flag.
-- Tuning notes: Adjust multiplier for high-volume teams; consider splitting by operation_type or resource sensitivity.
-- False positives: Backup jobs, ETL processes, service accounts. Implement allow lists or schedule-aware exclusions.
WITH params AS (
    SELECT
        COALESCE(NULLIF(:'data_volume_baseline_days', '')::int, 30) AS baseline_days,
        COALESCE(NULLIF(:'data_volume_multiplier', '')::numeric, 10.0) AS multiplier
),
baseline_daily AS (
    SELECT
        dal.user_id,
        DATE_TRUNC('day', dal.ts) AS activity_day,
        SUM(dal.bytes_transferred) AS day_total_bytes
    FROM data_access_logs dal
    CROSS JOIN params p
    WHERE dal.ts >= NOW() - (p.baseline_days || ' days')::interval
      AND dal.ts < DATE_TRUNC('day', NOW())
    GROUP BY dal.user_id, DATE_TRUNC('day', dal.ts)
),
baseline AS (
    SELECT
        bd.user_id,
        AVG(bd.day_total_bytes) AS baseline_avg_daily_bytes
    FROM baseline_daily bd
    GROUP BY bd.user_id
),
current_day AS (
    SELECT
        dal.user_id,
        SUM(dal.bytes_transferred) AS current_day_bytes
    FROM data_access_logs dal
    WHERE dal.ts >= DATE_TRUNC('day', NOW())
      AND dal.ts < DATE_TRUNC('day', NOW()) + INTERVAL '1 day'
    GROUP BY dal.user_id
)
SELECT
    COALESCE(cd.user_id, b.user_id) AS user_id,
    COALESCE(b.baseline_avg_daily_bytes, 0) AS baseline_avg_daily_bytes,
    COALESCE(cd.current_day_bytes, 0) AS current_day_bytes,
    CASE
        WHEN COALESCE(b.baseline_avg_daily_bytes, 0) = 0 THEN NULL
        ELSE ROUND(cd.current_day_bytes / NULLIF(b.baseline_avg_daily_bytes, 0), 2)
    END AS ratio,
    CASE
        WHEN COALESCE(b.baseline_avg_daily_bytes, 0) = 0 THEN (cd.current_day_bytes > 0)
        ELSE cd.current_day_bytes > b.baseline_avg_daily_bytes * p.multiplier
    END AS alert_flag
FROM baseline b
FULL OUTER JOIN current_day cd ON cd.user_id = b.user_id
CROSS JOIN params p
ORDER BY alert_flag DESC, ratio DESC NULLS LAST, user_id;
