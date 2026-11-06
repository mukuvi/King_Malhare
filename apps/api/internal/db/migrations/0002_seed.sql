-- Seed RBAC, system scan profiles and CWE reference catalogue.
INSERT INTO roles (id, name, description, rank) VALUES
  ('owner',  'Owner',  'Full control including organization deletion and billing', 100),
  ('admin',  'Admin',  'Manages members, assets, integrations and all assessments', 80),
  ('analyst','Analyst','Runs assessments and manages findings and reports', 50),
  ('viewer', 'Viewer', 'Read-only access to assets, findings and reports', 10)
ON CONFLICT (id) DO NOTHING;

INSERT INTO permissions (id, description) VALUES
  ('org:manage','Manage organization settings and emergency stop'),
  ('members:manage','Invite, update and remove members'),
  ('assets:read','View assets and authorization records'),
  ('assets:write','Create and update assets and authorizations'),
  ('auth:manage','Create and revoke authorization records'),
  ('scans:read','View scans, executions and live progress'),
  ('scans:write','Start and cancel assessments'),
  ('scans:intrusive','Approve and run intrusive assessments'),
  ('findings:read','View findings and evidence'),
  ('findings:write','Triage findings and manage remediation'),
  ('reports:read','View and download reports'),
  ('reports:write','Generate and delete reports'),
  ('audit:read','Read audit events'),
  ('integrations:manage','Manage cloud connections, schedules and scanners'),
  ('api_keys:manage','Issue and revoke API credentials')
ON CONFLICT (id) DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT 'owner', id FROM permissions
ON CONFLICT DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT 'admin', id FROM permissions WHERE id <> 'org:manage'
ON CONFLICT DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id) VALUES
  ('analyst','assets:read'),('analyst','assets:write'),('analyst','auth:manage'),
  ('analyst','scans:read'),('analyst','scans:write'),('analyst','findings:read'),
  ('analyst','findings:write'),('analyst','reports:read'),('analyst','reports:write')
ON CONFLICT DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id) VALUES
  ('viewer','assets:read'),('viewer','scans:read'),('viewer','findings:read'),('viewer','reports:read')
ON CONFLICT DO NOTHING;

INSERT INTO scan_profiles (org_id, key, name, category, scanner, description, config, intrusive, is_system) VALUES
  (NULL,'web-baseline','Web baseline','web','http-baseline',
   'Non-intrusive HTTP assessment: security headers, cookies, CORS, TLS, server disclosure, common exposed paths.',
   '{"exposure_check":true,"tls_check":true,"cors_check":true,"max_requests":120}', false, true),
  (NULL,'web-nuclei-safe','Nuclei safe','web','nuclei',
   'Template-based detection limited to low-impact templates (exposures, misconfigurations, default logins).',
   '{"severity":["low","medium","high","critical"],"rate_limit":40,"tags":["exposure","misconfig","panel"],"timeout":10}', false, true),
  (NULL,'web-nuclei-cve','Nuclei CVE detection','web','nuclei',
   'CVE and exposure templates with conservative rate limits.',
   '{"severity":["medium","high","critical"],"rate_limit":50,"tags":["cve","exposure"],"timeout":10}', false, true),
  (NULL,'web-zap-spider','ZAP spider + passive','web','zap',
   'Crawl the target and analyse responses without active attack requests.',
   '{"mode":"spider","max_duration_minutes":5}', false, true),
  (NULL,'web-zap-active','ZAP active scan','web','zap',
   'Active attack scan. Requires intrusive approval.',
   '{"mode":"active","max_duration_minutes":10}', true, true),
  (NULL,'web-nikto','Nikto server audit','web','nikto',
   'Server misconfiguration and dangerous file checks using Nikto.',
   '{"tuning":"123bde","max_time":"5m"}', false, true),
  (NULL,'web-gobuster','Content discovery','web','gobuster',
   'Bounded directory and file discovery using a curated wordlist.',
   '{"wordlist":"common","threads":10,"status_codes":["200","204","301","302","401","403"]}', false, true),
  (NULL,'web-sqlmap','SQL injection verification','web','sqlmap',
   'Guarded SQL injection verification on a single parameter. Requires intrusive approval; no shell, no data dump.',
   '{"level":1,"risk":1,"technique":"B","dump":false,"os_shell":false}', true, true),
  (NULL,'network-discovery','Network discovery','network','nmap',
   'Host discovery and top-port scan of an authorized CIDR or host.',
   '{"profile":"discovery","ports":"top-1000","os_detection":false}', false, true),
  (NULL,'network-service','Service enumeration','network','nmap',
   'Service and version detection with default scripts on common ports.',
   '{"profile":"service","ports":"top-1000","service_detection":true,"os_detection":false}', false, true),
  (NULL,'network-full','Full TCP assessment','network','nmap',
   'Service detection, default safe scripts and OS fingerprint hints on all TCP ports.',
   '{"profile":"full","ports":"all","service_detection":true,"os_detection":true}', false, true),
  (NULL,'network-tls','TLS configuration','network','testssl',
   'Protocol, cipher and certificate assessment for a TLS endpoint.',
   '{"mode":"--quiet","protocols":true}', false, true),
  (NULL,'cloud-aws','AWS posture baseline','cloud','aws-posture',
   'Read-only AWS checks: root MFA, CloudTrail, S3 public access, password policy, open security groups, stale keys.',
   '{"regions":["us-east-1"],"checks":["root_mfa","cloudtrail","s3_public_access","password_policy","open_security_groups","stale_keys"]}', false, true),
  (NULL,'cloud-prowler-aws','Prowler AWS','cloud','prowler',
   'Run the Prowler AWS provider with read-only credentials (requires Prowler installed).',
   '{"provider":"aws","severity":["critical","high","medium"]}', false, true),
  (NULL,'cloud-scoutsuite','ScoutSuite','cloud','scoutsuite',
   'Multi-cloud configuration assessment with ScoutSuite (requires ScoutSuite installed).',
   '{"provider":"aws","report_dir":"scoutsuite"}', false, true),
  (NULL,'auth-baseline','Authentication baseline','authentication','auth-baseline',
   'Rate-limit, lockout and session behaviour checks using an explicit test account. Requires intrusive approval.',
   '{"attempts":5,"delay_ms":500,"max_attempts":10}', true, true),
  (NULL,'container-trivy','Container image scan','infrastructure','trivy',
   'Vulnerability and misconfiguration scan of an allowlisted container image.',
   '{"scan_type":"image","severity":["CRITICAL","HIGH","MEDIUM"]}', false, true),
  (NULL,'iac-checkov','IaC configuration scan','infrastructure','checkov',
   'Static analysis of an allowlisted repository path.',
   '{"framework":"all","compact":true}', false, true)
ON CONFLICT DO NOTHING;

INSERT INTO cwe_catalog (cwe_id, name, description, category) VALUES
  ('CWE-79','Improper Neutralization of Input During Web Page Generation (XSS)','User-controlled data reaches HTML output without context-appropriate encoding, allowing script execution in a victim browser.','web'),
  ('CWE-89','Improper Neutralization of Special Elements used in an SQL Command (SQL Injection)','Untrusted input is concatenated into SQL, changing query semantics and potentially exposing or modifying data.','web'),
  ('CWE-352','Cross-Site Request Forgery (CSRF)','State-changing requests are accepted without a verifiable anti-CSRF token or equivalent origin control.','web'),
  ('CWE-918','Server-Side Request Forgery (SSRF)','The server fetches a URL supplied by a user without validating destination scheme, host or resolved address.','web'),
  ('CWE-639','Authorization Bypass Through User-Controlled Key (IDOR)','An object identifier supplied by the user is used without verifying that the caller is authorized for that object.','web'),
  ('CWE-287','Improper Authentication','Authentication logic can be bypassed or does not robustly verify identity.','authentication'),
  ('CWE-307','Improper Restriction of Excessive Authentication Attempts','Login or verification endpoints allow unlimited attempts, enabling password guessing.','authentication'),
  ('CWE-384','Session Fixation','A session identifier is not rotated after authentication, allowing an attacker to reuse a known identifier.','authentication'),
  ('CWE-613','Insufficient Session Expiration','Sessions or credentials remain valid longer than necessary, increasing the impact of theft.','authentication'),
  ('CWE-521','Weak Password Requirements','Password policy permits trivially guessable credentials or lacks length and breach checks.','authentication'),
  ('CWE-319','Cleartext Transmission of Sensitive Information','Sensitive data is transmitted without transport encryption.','network'),
  ('CWE-327','Use of a Broken or Risky Cryptographic Algorithm','Weak ciphers, hashes or protocol versions are used to protect data.','crypto'),
  ('CWE-326','Inadequate Encryption Strength','Key sizes or parameters are insufficient for the protection claimed.','crypto'),
  ('CWE-295','Improper Certificate Validation','TLS certificates are not validated, or certificate configuration is insecure.','crypto'),
  ('CWE-942','Permissive Cross-domain Policy with Untrusted Domains','CORS or cross-domain policy trusts arbitrary origins, including credentialed requests.','web'),
  ('CWE-693','Protection Mechanism Failure','Security headers or defensive controls are missing or ineffective.','web'),
  ('CWE-1021','Improper Restriction of Rendered UI Layers (Clickjacking)','The application can be framed by third parties, enabling clickjacking.','web'),
  ('CWE-200','Exposure of Sensitive Information to an Unauthorized Actor','Sensitive data such as stack traces, credentials or internal metadata is exposed.','web'),
  ('CWE-538','Insertion of Sensitive Information into Externally-Accessible File or Directory','Files such as .git, backups or environment files are served publicly.','web'),
  ('CWE-434','Unrestricted Upload of File with Dangerous Type','File uploads allow executable or script content to be stored and served.','web'),
  ('CWE-22','Improper Limitation of a Pathname to a Restricted Directory (Path Traversal)','User-controlled paths escape the intended directory.','web'),
  ('CWE-611','Improper Restriction of XML External Entity Reference (XXE)','XML parsers resolve external entities supplied by attackers.','web'),
  ('CWE-502','Deserialization of Untrusted Data','Untrusted serialized objects are deserialized, potentially enabling code execution.','appsec'),
  ('CWE-798','Use of Hard-coded Credentials','Credentials are embedded in source or configuration and can be extracted.','appsec'),
  ('CWE-250','Execution with Unnecessary Privileges','Processes or users run with more privilege than required.','infrastructure'),
  ('CWE-284','Improper Access Control','Access control is missing or applied inconsistently across resources.','appsec'),
  ('CWE-601','URL Redirection to Untrusted Site (Open Redirect)','User-controlled redirect targets allow phishing or token leakage.','web'),
  ('CWE-1321','Improperly Controlled Modification of Object Prototype Attributes (Prototype Pollution)','Untrusted object merge operations modify prototype attributes.','appsec'),
  ('CWE-532','Insertion of Sensitive Information into Log File','Secrets or personal data are written to logs.','operations'),
  ('CWE-778','Insufficient Logging','Security-relevant events are not recorded, preventing detection and investigation.','operations'),
  ('CWE-1104','Use of Unmaintained Third Party Components','Dependencies are no longer maintained and receive no security fixes.','supply-chain'),
  ('CWE-1395','Dependency on Vulnerable Third-Party Component','A dependency contains known vulnerabilities that are reachable.','supply-chain')
ON CONFLICT (cwe_id) DO NOTHING;
