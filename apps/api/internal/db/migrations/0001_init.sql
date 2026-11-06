-- King Malhare core schema
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE OR REPLACE FUNCTION set_updated_at() RETURNS trigger AS $$
BEGIN
  NEW.updated_at = now();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- ---------------------------------------------------------------------------
-- Tenancy, identity, RBAC
-- ---------------------------------------------------------------------------

CREATE TABLE organizations (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name TEXT NOT NULL CHECK (char_length(name) BETWEEN 2 AND 120),
  slug TEXT NOT NULL UNIQUE CHECK (slug ~ '^[a-z0-9][a-z0-9-]{1,60}$'),
  emergency_stop BOOLEAN NOT NULL DEFAULT false,
  retention_days INTEGER NOT NULL DEFAULT 365 CHECK (retention_days BETWEEN 30 AND 3650),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email TEXT NOT NULL,
  name TEXT NOT NULL CHECK (char_length(name) BETWEEN 1 AND 120),
  password_hash TEXT NOT NULL,
  avatar_color TEXT NOT NULL DEFAULT '#f5a524',
  is_active BOOLEAN NOT NULL DEFAULT true,
  last_login_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX users_email_lower_uidx ON users (lower(email));

CREATE TABLE roles (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  description TEXT NOT NULL,
  rank INTEGER NOT NULL
);

CREATE TABLE permissions (
  id TEXT PRIMARY KEY,
  description TEXT NOT NULL
);

CREATE TABLE role_permissions (
  role_id TEXT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
  permission_id TEXT NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
  PRIMARY KEY (role_id, permission_id)
);

CREATE TABLE memberships (
  org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role_id TEXT NOT NULL REFERENCES roles(id),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (org_id, user_id)
);
CREATE INDEX memberships_user_idx ON memberships (user_id);

CREATE TABLE sessions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  token_hash BYTEA NOT NULL UNIQUE,
  csrf_token TEXT NOT NULL,
  ip TEXT,
  user_agent TEXT,
  expires_at TIMESTAMPTZ NOT NULL,
  revoked_at TIMESTAMPTZ,
  last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX sessions_user_idx ON sessions (user_id) WHERE revoked_at IS NULL;

-- ---------------------------------------------------------------------------
-- Assets, ownership, authorization
-- ---------------------------------------------------------------------------

CREATE TABLE assets (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  name TEXT NOT NULL CHECK (char_length(name) BETWEEN 2 AND 160),
  type TEXT NOT NULL CHECK (type IN ('website','web_app','api','graphql_api','ip','network','cloud','server','container','internal')),
  target TEXT NOT NULL CHECK (char_length(target) BETWEEN 3 AND 2048),
  description TEXT NOT NULL DEFAULT '',
  environment TEXT NOT NULL DEFAULT 'production' CHECK (environment IN ('production','staging','development','lab','internal')),
  owner_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
  tags TEXT[] NOT NULL DEFAULT '{}',
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','archived')),
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  last_assessed_at TIMESTAMPTZ,
  created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (org_id, target)
);
CREATE INDEX assets_org_status_idx ON assets (org_id, status, created_at DESC);
CREATE INDEX assets_org_type_idx ON assets (org_id, type);
CREATE INDEX assets_tags_gin ON assets USING gin (tags);
CREATE INDEX assets_search_idx ON assets USING gin (to_tsvector('english', name || ' ' || target || ' ' || description));

CREATE TABLE asset_ownerships (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  asset_id UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
  user_id UUID REFERENCES users(id) ON DELETE SET NULL,
  contact TEXT NOT NULL DEFAULT '',
  relationship TEXT NOT NULL DEFAULT 'owner' CHECK (relationship IN ('owner','technical','business','approver')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX asset_ownerships_asset_idx ON asset_ownerships (asset_id);

CREATE TABLE authorizations (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  asset_id UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
  reference TEXT NOT NULL CHECK (char_length(reference) BETWEEN 3 AND 240),
  approved_by_name TEXT NOT NULL,
  approved_by_email TEXT NOT NULL DEFAULT '',
  scope_notes TEXT NOT NULL DEFAULT '',
  intrusive_allowed BOOLEAN NOT NULL DEFAULT false,
  allow_private BOOLEAN NOT NULL DEFAULT false,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','revoked')),
  valid_from TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at TIMESTAMPTZ NOT NULL,
  evidence_key TEXT,
  created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  revoked_at TIMESTAMPTZ,
  revoked_by UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  CHECK (expires_at > valid_from)
);
CREATE INDEX authorizations_asset_idx ON authorizations (asset_id, status, expires_at DESC);
CREATE INDEX authorizations_org_idx ON authorizations (org_id, status);

-- ---------------------------------------------------------------------------
-- Profiles and scans
-- ---------------------------------------------------------------------------

CREATE TABLE scan_profiles (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
  key TEXT NOT NULL,
  name TEXT NOT NULL,
  category TEXT NOT NULL CHECK (category IN ('web','network','cloud','authentication','infrastructure')),
  scanner TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  config JSONB NOT NULL DEFAULT '{}'::jsonb,
  intrusive BOOLEAN NOT NULL DEFAULT false,
  is_system BOOLEAN NOT NULL DEFAULT false,
  created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (org_id, key)
);
CREATE UNIQUE INDEX scan_profiles_system_key_uidx ON scan_profiles (key) WHERE org_id IS NULL;

CREATE TABLE scans (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  asset_id UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
  authorization_id UUID NOT NULL REFERENCES authorizations(id),
  profile_id UUID REFERENCES scan_profiles(id) ON DELETE SET NULL,
  category TEXT NOT NULL CHECK (category IN ('web','network','cloud','authentication','infrastructure')),
  scanner TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'queued' CHECK (status IN ('pending','queued','initializing','running','completed','failed','cancelled')),
  target_snapshot TEXT NOT NULL,
  config JSONB NOT NULL DEFAULT '{}'::jsonb,
  scope_snapshot JSONB NOT NULL DEFAULT '{}'::jsonb,
  progress INTEGER NOT NULL DEFAULT 0 CHECK (progress BETWEEN 0 AND 100),
  phase TEXT NOT NULL DEFAULT 'queued',
  summary JSONB NOT NULL DEFAULT '{}'::jsonb,
  error TEXT,
  cancel_requested BOOLEAN NOT NULL DEFAULT false,
  attempt INTEGER NOT NULL DEFAULT 0,
  created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  queued_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  started_at TIMESTAMPTZ,
  finished_at TIMESTAMPTZ,
  last_heartbeat_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX scans_org_created_idx ON scans (org_id, created_at DESC);
CREATE INDEX scans_org_status_idx ON scans (org_id, status);
CREATE INDEX scans_asset_idx ON scans (asset_id, created_at DESC);
CREATE INDEX scans_active_idx ON scans (status) WHERE status IN ('pending','queued','initializing','running');

CREATE TABLE scanner_executions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  scanner TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('running','completed','failed','cancelled','unavailable')),
  command_summary TEXT NOT NULL DEFAULT '',
  started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  finished_at TIMESTAMPTZ,
  exit_code INTEGER,
  output_excerpt TEXT NOT NULL DEFAULT '',
  error TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX scanner_executions_scan_idx ON scanner_executions (scan_id, started_at);

CREATE TABLE scan_results (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  asset_id UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
  scanner TEXT NOT NULL,
  fingerprint TEXT NOT NULL,
  title TEXT NOT NULL,
  severity TEXT NOT NULL CHECK (severity IN ('critical','high','medium','low','info')),
  confidence TEXT NOT NULL DEFAULT 'firm' CHECK (confidence IN ('certain','firm','tentative')),
  cve TEXT,
  cwe TEXT,
  cvss NUMERIC(3,1) CHECK (cvss IS NULL OR (cvss >= 0 AND cvss <= 10)),
  endpoint TEXT NOT NULL DEFAULT '',
  description TEXT NOT NULL DEFAULT '',
  remediation TEXT NOT NULL DEFAULT '',
  evidence JSONB NOT NULL DEFAULT '{}'::jsonb,
  raw JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX scan_results_scan_idx ON scan_results (scan_id, severity);
CREATE INDEX scan_results_fingerprint_idx ON scan_results (org_id, fingerprint);

-- ---------------------------------------------------------------------------
-- Findings and evidence
-- ---------------------------------------------------------------------------

CREATE TABLE findings (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  asset_id UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
  scan_id UUID REFERENCES scans(id) ON DELETE SET NULL,
  fingerprint TEXT NOT NULL,
  title TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  severity TEXT NOT NULL CHECK (severity IN ('critical','high','medium','low','info')),
  confidence TEXT NOT NULL DEFAULT 'firm' CHECK (confidence IN ('certain','firm','tentative')),
  cve TEXT,
  cwe TEXT,
  cvss NUMERIC(3,1) CHECK (cvss IS NULL OR (cvss >= 0 AND cvss <= 10)),
  endpoint TEXT NOT NULL DEFAULT '',
  evidence JSONB NOT NULL DEFAULT '{}'::jsonb,
  reproduction TEXT NOT NULL DEFAULT '',
  business_impact TEXT NOT NULL DEFAULT '',
  technical_impact TEXT NOT NULL DEFAULT '',
  remediation TEXT NOT NULL DEFAULT '',
  "references" JSONB NOT NULL DEFAULT '[]'::jsonb,
  assigned_to UUID REFERENCES users(id) ON DELETE SET NULL,
  status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','confirmed','in_progress','fixed','retest_required','accepted_risk','false_positive')),
  first_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
  verified_at TIMESTAMPTZ,
  verified_by UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (org_id, fingerprint)
);
CREATE INDEX findings_org_severity_idx ON findings (org_id, severity, status);
CREATE INDEX findings_org_status_idx ON findings (org_id, status, last_seen DESC);
CREATE INDEX findings_org_asset_idx ON findings (org_id, asset_id);
CREATE INDEX findings_org_lastseen_idx ON findings (org_id, last_seen DESC);
CREATE INDEX findings_assigned_idx ON findings (assigned_to) WHERE assigned_to IS NOT NULL;
CREATE INDEX findings_search_idx ON findings USING gin (to_tsvector('english', title || ' ' || description));

CREATE TABLE finding_events (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  finding_id UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
  actor_id UUID REFERENCES users(id) ON DELETE SET NULL,
  type TEXT NOT NULL CHECK (type IN ('created','status_changed','severity_changed','assigned','verified','remediation','comment')),
  from_value TEXT,
  to_value TEXT,
  note TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX finding_events_finding_idx ON finding_events (finding_id, created_at DESC);

CREATE TABLE remediation_records (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  finding_id UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
  action TEXT NOT NULL,
  notes TEXT NOT NULL DEFAULT '',
  performed_by UUID REFERENCES users(id) ON DELETE SET NULL,
  performed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  deadline TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE evidence (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  finding_id UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
  filename TEXT NOT NULL,
  content_type TEXT NOT NULL,
  size_bytes BIGINT NOT NULL CHECK (size_bytes > 0 AND size_bytes <= 26214400),
  storage_key TEXT NOT NULL UNIQUE,
  sha256 TEXT NOT NULL,
  uploaded_by UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX evidence_finding_idx ON evidence (finding_id);

-- ---------------------------------------------------------------------------
-- Reports, notifications, audit
-- ---------------------------------------------------------------------------

CREATE TABLE reports (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  scan_id UUID REFERENCES scans(id) ON DELETE SET NULL,
  title TEXT NOT NULL,
  client_name TEXT NOT NULL DEFAULT '',
  assessor_name TEXT NOT NULL DEFAULT '',
  period_start TIMESTAMPTZ,
  period_end TIMESTAMPTZ,
  status TEXT NOT NULL DEFAULT 'generating' CHECK (status IN ('generating','ready','failed')),
  summary JSONB NOT NULL DEFAULT '{}'::jsonb,
  html_key TEXT,
  pdf_key TEXT,
  error TEXT,
  created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX reports_org_idx ON reports (org_id, created_at DESC);

CREATE TABLE notifications (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  user_id UUID REFERENCES users(id) ON DELETE CASCADE,
  type TEXT NOT NULL CHECK (type IN ('scan','finding','report','system','authorization')),
  title TEXT NOT NULL,
  body TEXT NOT NULL DEFAULT '',
  link TEXT NOT NULL DEFAULT '',
  read_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX notifications_user_idx ON notifications (user_id, read_at, created_at DESC);
CREATE INDEX notifications_org_idx ON notifications (org_id, created_at DESC);

CREATE TABLE audit_events (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id UUID REFERENCES organizations(id) ON DELETE SET NULL,
  actor_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
  action TEXT NOT NULL,
  resource_type TEXT NOT NULL,
  resource_id TEXT,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  ip TEXT,
  user_agent TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX audit_org_created_idx ON audit_events (org_id, created_at DESC);
CREATE INDEX audit_action_idx ON audit_events (action, created_at DESC);

-- ---------------------------------------------------------------------------
-- Integrations and automation
-- ---------------------------------------------------------------------------

CREATE TABLE cloud_connections (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  provider TEXT NOT NULL CHECK (provider IN ('aws','azure','gcp')),
  name TEXT NOT NULL,
  account_id TEXT NOT NULL DEFAULT '',
  encrypted_credentials BYTEA NOT NULL,
  nonce BYTEA NOT NULL,
  key_version INTEGER NOT NULL DEFAULT 1,
  status TEXT NOT NULL DEFAULT 'unverified' CHECK (status IN ('unverified','verified','error','disabled')),
  last_verified_at TIMESTAMPTZ,
  last_error TEXT,
  created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX cloud_connections_org_idx ON cloud_connections (org_id);

CREATE TABLE api_credentials (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  token_prefix TEXT NOT NULL,
  token_hash BYTEA NOT NULL UNIQUE,
  scopes TEXT[] NOT NULL DEFAULT '{}',
  last_used_at TIMESTAMPTZ,
  expires_at TIMESTAMPTZ,
  revoked_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX api_credentials_org_idx ON api_credentials (org_id, created_at DESC);

CREATE TABLE scan_schedules (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  asset_id UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
  authorization_id UUID NOT NULL REFERENCES authorizations(id) ON DELETE CASCADE,
  scanner TEXT NOT NULL,
  category TEXT NOT NULL CHECK (category IN ('web','network','cloud','authentication','infrastructure')),
  profile_id UUID REFERENCES scan_profiles(id) ON DELETE SET NULL,
  config JSONB NOT NULL DEFAULT '{}'::jsonb,
  cron TEXT NOT NULL,
  enabled BOOLEAN NOT NULL DEFAULT true,
  next_run_at TIMESTAMPTZ,
  last_run_at TIMESTAMPTZ,
  created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX scan_schedules_due_idx ON scan_schedules (next_run_at) WHERE enabled;

CREATE TABLE cve_cache (
  cve_id TEXT PRIMARY KEY,
  payload JSONB NOT NULL,
  fetched_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE cwe_catalog (
  cwe_id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  description TEXT NOT NULL,
  category TEXT NOT NULL DEFAULT 'general'
);

-- updated_at triggers
CREATE TRIGGER organizations_updated BEFORE UPDATE ON organizations FOR EACH ROW EXECUTE FUNCTION set_updated_at();
CREATE TRIGGER users_updated BEFORE UPDATE ON users FOR EACH ROW EXECUTE FUNCTION set_updated_at();
CREATE TRIGGER assets_updated BEFORE UPDATE ON assets FOR EACH ROW EXECUTE FUNCTION set_updated_at();
CREATE TRIGGER scan_profiles_updated BEFORE UPDATE ON scan_profiles FOR EACH ROW EXECUTE FUNCTION set_updated_at();
CREATE TRIGGER findings_updated BEFORE UPDATE ON findings FOR EACH ROW EXECUTE FUNCTION set_updated_at();
CREATE TRIGGER cloud_connections_updated BEFORE UPDATE ON cloud_connections FOR EACH ROW EXECUTE FUNCTION set_updated_at();
