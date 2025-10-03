-- Purpose: Identify successful logins from IP locations not seen for the user during the historical lookback window.
-- Assumptions: auth_logs records login events, and ip_geolocation maps IPs to country/region/city. Timestamps stored in UTC.
-- Parameters:
--   :new_login_lookback_days - number of days to treat as historical baseline (default 90).
-- Outputs: user_id, login_ts, source_ip, country, city, is_new_country, is_new_city, historical_count.
-- Tuning notes: Shorten the lookback for frequent travelers or VPN-heavy users. Extend for high-sensitivity accounts.
-- False positives: VPNs, CDNs, and mobile carriers may rotate IPs frequently. Consider region-level fuzziness or ASN whitelists.
-- Recommended: For region fuzziness, treat neighboring cities within the same metro area as known via additional enrichment.
WITH params AS (
    SELECT
        COALESCE(NULLIF(:'new_login_lookback_days', '')::int, 90) AS lookback_days
),
successful_logins AS (
    SELECT
        al.ts,
        al.user_id,
        al.source_ip,
        geo.country,
        geo.region,
        geo.city
    FROM auth_logs al
    INNER JOIN ip_geolocation geo ON geo.ip = al.source_ip
    WHERE al.event_type = 'LOGIN_SUCCESS'
),
historical_locations AS (
    SELECT
        sl.user_id,
        sl.country,
        sl.region,
        sl.city,
        COUNT(DISTINCT sl.source_ip) AS historical_count
    FROM successful_logins sl
    CROSS JOIN params p
    WHERE sl.ts >= NOW() - (p.lookback_days || ' days')::interval
      AND sl.ts < NOW() - INTERVAL '1 day'
    GROUP BY sl.user_id, sl.country, sl.region, sl.city
),
current_successes AS (
    SELECT
        sl.ts,
        sl.user_id,
        sl.source_ip,
        sl.country,
        sl.region,
        sl.city
    FROM successful_logins sl
    WHERE sl.ts >= NOW() - INTERVAL '7 days'
)
SELECT
    cs.user_id,
    cs.ts AS login_ts,
    cs.source_ip,
    cs.country,
    cs.city,
    NOT EXISTS (
        SELECT 1
        FROM historical_locations hl
        WHERE hl.user_id = cs.user_id
          AND hl.country = cs.country
    ) AS is_new_country,
    NOT EXISTS (
        SELECT 1
        FROM historical_locations hl
        WHERE hl.user_id = cs.user_id
          AND hl.country = cs.country
          AND hl.city = cs.city
    ) AS is_new_city,
    COALESCE((
        SELECT hl.historical_count
        FROM historical_locations hl
        WHERE hl.user_id = cs.user_id
          AND hl.country = cs.country
          AND hl.city = cs.city
        LIMIT 1
    ), 0) AS historical_count
FROM current_successes cs
ORDER BY cs.ts DESC;
