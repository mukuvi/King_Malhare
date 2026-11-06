-- Data retention cleanup. Run as a scheduled job with psql.
-- Findings are preserved; raw scanner output and operational history are pruned.
-- Object storage cleanup must be handled by the deployment (the rows below are
-- deliberately limited to data that has no external artefact dependency).

BEGIN;

-- Raw normalized results older than the organization's retention policy.
DELETE FROM scan_results sr
USING scans sc, organizations o
WHERE sr.scan_id = sc.id
  AND sc.org_id = o.id
  AND sr.created_at < now() - (o.retention_days || ' days')::interval;

-- Scanner stdout/stderr excerpts.
UPDATE scanner_executions e
SET output_excerpt = ''
FROM organizations o
WHERE e.org_id = o.id
  AND e.started_at < now() - (o.retention_days || ' days')::interval
  AND e.output_excerpt <> '';

-- Audit history older than retention (minimum 30 days enforced by schema).
DELETE FROM audit_events a
USING organizations o
WHERE a.org_id = o.id
  AND a.created_at < now() - (o.retention_days || ' days')::interval;

-- Read notifications older than 90 days.
DELETE FROM notifications
WHERE read_at IS NOT NULL AND created_at < now() - interval '90 days';

COMMIT;

-- Evidence and reports are NOT deleted automatically because their rows own
-- object-store keys. Use the report/evidence delete endpoints or a documented
-- object lifecycle policy; deleting rows first would orphan storage objects.
