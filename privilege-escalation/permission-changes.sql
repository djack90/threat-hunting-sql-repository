-- Purpose: Review permission changes and highlight potential privilege escalations for follow-up investigation.
-- Assumptions: user_permissions_audit logs GRANT/REVOKE/ALTER actions with admin_user and target_user fields.
-- Parameters:
--   :permission_change_lookback_days - number of days to review (default 14).
--   :admin_role_keyword              - keyword that indicates high privilege in the action/object fields (default 'ADMIN').
-- Outputs: target_user, action, object, admin_user, ts, recommended_investigation_steps.
-- Tuning notes: Align :admin_role_keyword with your naming (e.g., 'SUPERUSER', 'DBA'). Add joins to HR or identity data to enrich context.
-- False positives: Bulk provisioning, automated role sync jobs. Correlate with change tickets before alerting.
WITH params AS (
    SELECT
        COALESCE(NULLIF(:'permission_change_lookback_days', '')::int, 14) AS lookback_days,
        COALESCE(NULLIF(:'admin_role_keyword', ''), 'ADMIN') AS admin_keyword
),
recent_changes AS (
    SELECT
        upa.ts,
        upa.admin_user,
        upa.target_user,
        upa.action,
        upa.object,
        upa.details
    FROM user_permissions_audit upa
    CROSS JOIN params p
    WHERE upa.ts >= NOW() - (p.lookback_days || ' days')::interval
),
user_baseline AS (
    SELECT
        u.user_id,
        u.role_name,
        u.privilege_level
    FROM users u
),
escalation_candidates AS (
    SELECT
        rc.*,
        ub.privilege_level AS target_privilege_level,
        CASE
            WHEN rc.action ILIKE '%' || p.admin_keyword || '%'
              OR rc.object ILIKE '%' || p.admin_keyword || '%'
              OR rc.details ILIKE '%' || p.admin_keyword || '%'
            THEN TRUE
            ELSE FALSE
        END AS matches_admin_keyword
    FROM recent_changes rc
    LEFT JOIN user_baseline ub ON ub.user_id = rc.target_user
    CROSS JOIN params p
),
unusual_escalations AS (
    SELECT
        ec.ts,
        ec.admin_user,
        ec.target_user,
        ec.action,
        ec.object,
        ec.details,
        ec.matches_admin_keyword,
        COALESCE(ec.target_privilege_level, 0) < 5 AS low_privilege_user
    FROM escalation_candidates ec
    WHERE ec.matches_admin_keyword = TRUE
)
SELECT
    ue.target_user,
    ue.action,
    ue.object,
    ue.admin_user,
    ue.ts,
    CASE
        WHEN ue.low_privilege_user THEN 'Confirm business justification, validate approval chain, and review admin user session logs.'
        ELSE 'Review change ticket and ensure the admin action aligns with scheduled maintenance.'
    END AS recommended_investigation_steps
FROM unusual_escalations ue
UNION ALL
SELECT
    rc.target_user,
    rc.action,
    rc.object,
    rc.admin_user,
    rc.ts,
    'Documented change: verify against provisioning records and correlate with authentication logs.' AS recommended_investigation_steps
FROM recent_changes rc
WHERE NOT EXISTS (
    SELECT 1 FROM unusual_escalations ue
    WHERE ue.ts = rc.ts
      AND ue.admin_user = rc.admin_user
      AND ue.target_user = rc.target_user
      AND ue.action = rc.action
      AND ue.object = rc.object
)
ORDER BY ts DESC, target_user;
