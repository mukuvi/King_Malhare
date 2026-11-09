export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type FindingStatus =
  | "open"
  | "confirmed"
  | "in_progress"
  | "fixed"
  | "retest_required"
  | "accepted_risk"
  | "false_positive";
export type ScanStatus =
  | "pending"
  | "queued"
  | "initializing"
  | "running"
  | "completed"
  | "failed"
  | "cancelled";
export type AssetType =
  | "website"
  | "web_app"
  | "api"
  | "graphql_api"
  | "ip"
  | "network"
  | "cloud"
  | "server"
  | "container"
  | "internal";
export type Environment = "production" | "staging" | "development" | "lab" | "internal";
export type Category = "web" | "network" | "cloud" | "authentication" | "infrastructure";

export interface Paginated<T> {
  items: T[];
  page: number;
  per_page: number;
  total: number;
}

export interface User {
  id: string;
  name: string;
  email: string;
  avatar_color: string;
  last_login_at?: string;
  created_at: string;
}

export interface Organization {
  id: string;
  name: string;
  slug: string;
  emergency_stop: boolean;
  retention_days: number;
  created_at: string;
  member_count?: number;
  asset_count?: number;
}

export interface Me {
  user: User;
  org: Organization;
  role: string;
  permissions: string[];
  platform_admin: boolean;
  csrf_token?: string;
}

export interface PlatformOverview {
  organizations: number;
  users: number;
  active_users: number;
  platform_admins: number;
  assets: number;
  scans: number;
  running_scans: number;
  findings: number;
  high_risk_findings: number;
}

export interface PlatformOrganization {
  id: string;
  name: string;
  slug: string;
  created_at: string;
  member_count: number;
  asset_count: number;
  scan_count: number;
  open_findings: number;
  owner_name: string;
  owner_email: string;
}

export interface PlatformMembership {
  org_id: string;
  org_name: string;
  role_id: string;
  role_name: string;
}

export interface PlatformUser {
  id: string;
  name: string;
  email: string;
  is_active: boolean;
  is_platform_admin: boolean;
  last_login_at?: string;
  created_at: string;
  memberships: PlatformMembership[];
}

export interface PlatformActivity {
  id: string;
  org_id?: string;
  org_name?: string;
  action: string;
  resource_type: string;
  resource_id?: string;
  metadata?: Record<string, unknown>;
  created_at: string;
  actor?: string;
  actor_email?: string;
}

export interface Asset {
  id: string;
  name: string;
  type: AssetType;
  target: string;
  description: string;
  environment: Environment;
  owner_user_id?: string;
  owner_name?: string;
  tags: string[];
  status: "active" | "archived";
  metadata: Record<string, unknown>;
  last_assessed_at?: string;
  created_at: string;
  updated_at: string;
  active_authorizations: number;
  open_findings: number;
  critical_findings: number;
  high_findings: number;
  scan_count: number;
  posture_score: number;
  owners?: AssetOwner[];
}

export interface AssetOwner {
  id: string;
  user_id?: string;
  name?: string;
  email?: string;
  contact: string;
  relationship: string;
}

export interface Authorization {
  id: string;
  asset_id: string;
  reference: string;
  approved_by_name: string;
  approved_by_email: string;
  scope_notes: string;
  intrusive_allowed: boolean;
  allow_private: boolean;
  status: "active" | "revoked";
  effective_status: "active" | "expired" | "scheduled" | "revoked";
  valid_from: string;
  expires_at: string;
  created_at: string;
  created_by_name?: string;
}

export interface ParamSchema {
  type: string;
  enum?: string[];
  min?: number;
  max?: number;
  max_items?: number;
  description: string;
}

export interface ScannerInfo {
  name: string;
  label: string;
  category: Category;
  description: string;
  intrusive: boolean;
  binary?: string;
  params: Record<string, ParamSchema>;
  default_params: Record<string, unknown>;
  status: "available" | "unavailable" | "offline";
  version: string;
  detail: string;
}

export interface ScanProfile {
  id: string;
  org_id?: string;
  key: string;
  name: string;
  category: Category;
  scanner: string;
  description: string;
  config: Record<string, unknown>;
  intrusive: boolean;
  is_system: boolean;
  created_at: string;
}

export interface Scan {
  id: string;
  asset_id: string;
  asset_name: string;
  asset_target: string;
  category: Category;
  scanner: string;
  status: ScanStatus;
  progress: number;
  phase: string;
  target: string;
  created_at: string;
  started_at?: string;
  finished_at?: string;
  error?: string;
  findings: number;
  critical: number;
  high: number;
  created_by_name?: string;
  intrusive: boolean;
}

export interface ScanExecution {
  id: string;
  scanner: string;
  status: string;
  command: string;
  started_at: string;
  finished_at?: string;
  exit_code?: number;
  output_excerpt: string;
  error?: string;
}

export interface ScanDetail extends Scan {
  config: Record<string, unknown>;
  scope: {
    reference: string;
    approved_by: string;
    expires_at: string;
    intrusive_allowed: boolean;
    allow_private: boolean;
    scope_notes: string;
    resolved_ips: string[];
    asset_environment: string;
  };
  summary: Record<string, unknown>;
  authorization: {
    id: string;
    reference: string;
    approved_by_name: string;
    expires_at: string;
    intrusive_allowed: boolean;
    allow_private: boolean;
  };
  executions: ScanExecution[];
  severity_counts: Record<Severity, number>;
  result_count: number;
}

export interface ScanResult {
  id: string;
  title: string;
  severity: Severity;
  confidence: string;
  cve?: string;
  cwe?: string;
  cvss?: number;
  endpoint: string;
  description: string;
  evidence: Record<string, unknown>;
  created_at: string;
}

export interface Finding {
  id: string;
  title: string;
  severity: Severity;
  status: FindingStatus;
  confidence: string;
  asset_id: string;
  asset_name: string;
  endpoint: string;
  cve?: string;
  cwe?: string;
  cvss?: number;
  assigned_to?: string;
  assignee_name?: string;
  scan_id?: string;
  first_seen: string;
  last_seen: string;
  verified_at?: string;
  evidence_count: number;
}

export interface EvidenceFile {
  id: string;
  filename: string;
  content_type: string;
  size_bytes: number;
  sha256: string;
  uploaded_by?: string;
  created_at: string;
}

export interface FindingDetail extends Finding {
  asset_target: string;
  description: string;
  reproduction: string;
  business_impact: string;
  technical_impact: string;
  remediation: string;
  references: string[];
  evidence: Record<string, unknown>;
  verified_by?: string;
  events: FindingEvent[];
  remediation_records: RemediationRecord[];
  evidence_files: EvidenceFile[];
}

export interface FindingEvent {
  id: string;
  type: string;
  from?: string;
  to?: string;
  note: string;
  actor?: string;
  created_at: string;
}

export interface RemediationRecord {
  id: string;
  action: string;
  notes: string;
  performed_by?: string;
  performed_at: string;
  deadline?: string;
}

export interface Report {
  id: string;
  title: string;
  client_name: string;
  assessor_name: string;
  scan_id?: string;
  status: "generating" | "ready" | "failed";
  summary?: {
    counts?: Record<string, number>;
    posture_score?: number;
    findings?: number;
    scope?: number;
    html_sha256?: string;
    pdf_sha256?: string;
  };
  created_at: string;
  created_by?: string;
  scanner?: string;
  asset_name?: string;
  asset_id?: string;
  period_start?: string;
  period_end?: string;
  error?: string;
  has_html?: boolean;
  has_pdf?: boolean;
}

export interface Notification {
  id: string;
  type: "scan" | "finding" | "report" | "system" | "authorization";
  title: string;
  body: string;
  link: string;
  read: boolean;
  created_at: string;
  read_at?: string;
}

export interface AuditEvent {
  id: string;
  action: string;
  resource_type: string;
  resource_id?: string;
  metadata: Record<string, unknown>;
  ip?: string;
  actor?: string;
  actor_email?: string;
  created_at: string;
}

export interface Overview {
  assets: { active: number; archived: number; without_authorization: number };
  scans: { active: number; last_24h: number; failed_24h: number; completed: number; last_at?: string };
  findings: Record<Severity | "open" | "total", number>;
  reports: number;
  posture_score: number;
  emergency_stop: boolean;
  recent_scans: Array<{
    id: string;
    scanner: string;
    category: Category;
    status: ScanStatus;
    progress: number;
    created_at: string;
    asset_name: string;
    findings: number;
  }>;
  activity: AuditEvent[];
}

export interface TrendPoint {
  date: string;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  total: number;
  scans: number;
  failed_scans: number;
}

export type CVE = CVERecord;

export interface CVERecord {
  id: string;
  summary: string;
  cvss?: number;
  cvss_vector?: string;
  cvss_version?: string;
  severity: string;
  cwe: string[];
  references: string[];
  published?: string;
  modified?: string;
  affected: string[];
  known_exploited: boolean;
  source: string;
  cached: boolean;
  stale: boolean;
  fetched_at?: string;
}

export interface CWE {
  id: string;
  name: string;
  description: string;
  category: string;
}

export interface CloudConnection {
  id: string;
  provider: "aws" | "azure" | "gcp";
  name: string;
  account_id: string;
  status: "unverified" | "verified" | "error" | "disabled";
  last_verified_at?: string;
  last_error?: string;
  created_at: string;
}

export interface ApiKey {
  id: string;
  name: string;
  token_prefix: string;
  scopes: string[];
  last_used_at?: string;
  expires_at?: string;
  revoked: boolean;
  created_at: string;
}

export interface Schedule {
  id: string;
  asset_id: string;
  asset_name: string;
  authorization_id: string;
  scanner: string;
  category: Category;
  profile_id?: string;
  config: Record<string, unknown>;
  cron: string;
  enabled: boolean;
  next_run_at?: string;
  last_run_at?: string;
  created_at: string;
}

export interface Member {
  user_id: string;
  name: string;
  email: string;
  role: string;
  role_name: string;
  avatar_color: string;
  is_active: boolean;
  last_login_at?: string;
  joined_at: string;
  open_findings: number;
}

export interface IntegrationStatus {
  scanners: Array<{
    name: string;
    label: string;
    category: Category;
    intrusive: boolean;
    status: "available" | "unavailable" | "offline";
    version: string;
    detail: string;
  }>;
  workers: Array<Record<string, unknown>>;
  worker_online: boolean;
  queue_depth: number;
  cloud_connections: CloudConnection[];
  storage_driver: string;
  environment: string;
}

export interface ApiErrorShape {
  error: {
    code: string;
    message: string;
    details?: Record<string, unknown>;
  };
}
