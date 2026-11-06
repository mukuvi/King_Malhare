package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/kingmalhare/api/internal/scanner"
	"github.com/kingmalhare/api/internal/security"
)

type scanInput struct {
	AssetID             string         `json:"asset_id"`
	AuthorizationID     string         `json:"authorization_id"`
	Scanner             string         `json:"scanner"`
	Category            string         `json:"category"`
	ProfileID           *string        `json:"profile_id"`
	Params              map[string]any `json:"params"`
	ConfirmIntrusive    bool           `json:"confirm_intrusive"`
	CloudConnectionID   string         `json:"cloud_connection_id"`
	TestAccountPassword string         `json:"test_account_password"`
	IdempotencyKey      string         `json:"idempotency_key"`
}

type scanRequestError struct {
	Status  int
	Code    string
	Message string
}

func (e *scanRequestError) Error() string { return e.Message }

func scanErr(status int, code, msg string) error {
	return &scanRequestError{Status: status, Code: code, Message: msg}
}

func (s *Server) handleCreateScan(w http.ResponseWriter, r *http.Request) {
	var req scanInput
	if !decodeJSON(w, r, &req) {
		return
	}
	if key := strings.TrimSpace(r.Header.Get("Idempotency-Key")); key != "" {
		if len(key) > 200 {
			s.writeValidation(w, "Idempotency-Key is too long.")
			return
		}
		req.IdempotencyKey = key
	}
	ac := actor(r)
	scanID, err := s.createScan(r.Context(), ac, req, "manual")
	if err != nil {
		var se *scanRequestError
		if errors.As(err, &se) {
			writeError(w, se.Status, se.Code, se.Message, nil)
			return
		}
		s.log.Error("scan creation failed", "error", err)
		writeError(w, http.StatusInternalServerError, "scan_create_failed", "The assessment could not be queued.", nil)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"id": scanID, "status": "queued"})
}

func (s *Server) createScan(ctx context.Context, ac *AuthContext, input scanInput, source string) (string, error) {
	if !validUUID(input.AssetID) || !validUUID(input.AuthorizationID) {
		return "", scanErr(http.StatusUnprocessableEntity, "validation_error", "A valid asset and authorization are required.")
	}
	if len(input.IdempotencyKey) > 200 {
		return "", scanErr(http.StatusUnprocessableEntity, "validation_error", "Idempotency key is too long.")
	}
	if input.IdempotencyKey != "" {
		var existing string
		err := s.db.QueryRow(ctx, `
			SELECT id::text FROM scans
			WHERE org_id=$1 AND asset_id=$2 AND scope_snapshot->>'idempotency_key'=$3
			  AND created_at > now() - interval '10 minutes'
			ORDER BY created_at DESC LIMIT 1`, ac.OrgID, input.AssetID, input.IdempotencyKey).Scan(&existing)
		if err == nil {
			return existing, nil
		}
		if !isNotFound(err) {
			return "", err
		}
	}
	asset, err := s.loadAsset(ctx, ac.OrgID, input.AssetID)
	if isNotFound(err) {
		return "", scanErr(http.StatusNotFound, "asset_not_found", "Asset not found.")
	}
	if err != nil {
		return "", err
	}
	if asset.Status != "active" {
		return "", scanErr(http.StatusConflict, "asset_archived", "Archived assets cannot be assessed.")
	}

	emergency, err := s.queue.EmergencyStop(ctx, ac.OrgID)
	if err != nil {
		return "", fmt.Errorf("check emergency stop: %w", err)
	}
	if emergency {
		return "", scanErr(http.StatusLocked, "emergency_stop_active", "The organization emergency stop is active. Clear it before starting assessments.")
	}

	var authRef, authApprover, authScope string
	var authExpires time.Time
	var authValidFrom time.Time
	var intrusiveAllowed, allowPrivate bool
	err = s.db.QueryRow(ctx, `
		SELECT reference, approved_by_name, scope_notes, expires_at, valid_from, intrusive_allowed, allow_private
		FROM authorizations
		WHERE id=$1 AND org_id=$2 AND asset_id=$3 AND status='active'`, input.AuthorizationID, ac.OrgID, input.AssetID).
		Scan(&authRef, &authApprover, &authScope, &authExpires, &authValidFrom, &intrusiveAllowed, &allowPrivate)
	if isNotFound(err) {
		return "", scanErr(http.StatusForbidden, "authorization_required", "A valid, active authorization record is required for this asset.")
	}
	if err != nil {
		return "", err
	}
	now := time.Now()
	if authExpires.Before(now) || authValidFrom.After(now) {
		return "", scanErr(http.StatusForbidden, "authorization_expired", "The authorization record is not valid at this time.")
	}

	meta, ok := scanner.Find(input.Scanner)
	if !ok {
		return "", scanErr(http.StatusUnprocessableEntity, "unknown_scanner", "Unknown scanner.")
	}
	category := input.Category
	if category == "" {
		category = meta.Category
	}
	if category != meta.Category {
		return "", scanErr(http.StatusUnprocessableEntity, "category_mismatch", "Scanner category does not match the requested assessment category.")
	}
	if !assetSupportsScanner(asset.Type, input.Scanner) {
		return "", scanErr(http.StatusUnprocessableEntity, "unsupported_scanner", "This scanner cannot assess this asset type.")
	}

	config := map[string]any{}
	if input.ProfileID != nil && *input.ProfileID != "" {
		var profileScanner string
		var profileConfig []byte
		err := s.db.QueryRow(ctx, `
			SELECT scanner, config FROM scan_profiles
			WHERE id=$1 AND (org_id=$2 OR org_id IS NULL)`, *input.ProfileID, ac.OrgID).Scan(&profileScanner, &profileConfig)
		if isNotFound(err) {
			return "", scanErr(http.StatusUnprocessableEntity, "profile_not_found", "Scan profile not found.")
		}
		if err != nil {
			return "", err
		}
		if profileScanner != input.Scanner {
			return "", scanErr(http.StatusUnprocessableEntity, "profile_mismatch", "The selected profile belongs to a different scanner.")
		}
		_ = json.Unmarshal(profileConfig, &config)
	}
	for k, v := range input.Params {
		config[k] = v
	}
	config, err = scanner.ValidateParams(input.Scanner, config)
	if err != nil {
		return "", scanErr(http.StatusUnprocessableEntity, "invalid_parameters", err.Error())
	}
	intrusive := scanner.IsIntrusive(input.Scanner, config)
	if intrusive {
		if !ac.Can("scans:intrusive") {
			return "", scanErr(http.StatusForbidden, "intrusive_permission_required", "Intrusive assessments require the scans:intrusive permission.")
		}
		if !intrusiveAllowed {
			return "", scanErr(http.StatusForbidden, "intrusive_not_authorized", "The authorization record does not permit intrusive testing.")
		}
		if !input.ConfirmIntrusive {
			return "", scanErr(http.StatusUnprocessableEntity, "intrusive_confirmation_required", "Explicit approval is required for disruptive testing.")
		}
	}

	var credentials *scanner.CloudCredential
	jobTarget := asset.Target
	if meta.Category == "cloud" {
		if input.CloudConnectionID == "" {
			return "", scanErr(http.StatusUnprocessableEntity, "cloud_connection_required", "Select a cloud connection for cloud assessments.")
		}
		cred, prov, account, err := s.decryptCloudConnection(ctx, ac.OrgID, input.CloudConnectionID)
		if err != nil {
			return "", err
		}
		if input.Scanner == "prowler" || input.Scanner == "scoutsuite" {
			if p, _ := config["provider"].(string); p != prov {
				return "", scanErr(http.StatusUnprocessableEntity, "provider_mismatch", "Profile provider does not match the cloud connection.")
			}
		}
		if prov != "aws" && (input.Scanner == "aws-posture") {
			return "", scanErr(http.StatusUnprocessableEntity, "provider_unsupported", "The native posture scanner currently supports AWS only.")
		}
		if input.Scanner == "aws-posture" && prov != "aws" {
			return "", scanErr(http.StatusUnprocessableEntity, "provider_mismatch", "Select an AWS connection for the AWS posture scanner.")
		}
		credentials = &scanner.CloudCredential{Provider: prov, Fields: cred}
		jobTarget = account
	}
	if input.Scanner == "auth-baseline" {
		testUser, _ := config["test_username"].(string)
		if strings.TrimSpace(testUser) == "" || len(input.TestAccountPassword) < 1 {
			return "", scanErr(http.StatusUnprocessableEntity, "test_account_required", "Provide the username and password of an explicitly authorized test account.")
		}
		if len(input.TestAccountPassword) > 256 {
			return "", scanErr(http.StatusUnprocessableEntity, "test_account_invalid", "Test account password is too long.")
		}
		credentials = &scanner.CloudCredential{Provider: "test-account", Fields: map[string]string{
			"username": strings.TrimSpace(testUser), "password": input.TestAccountPassword,
		}}
	}

	resolvedIPs := []string{}
	switch asset.Type {
	case "network":
		if err := validateNetworkTarget(asset.Target, allowPrivate); err != nil {
			return "", scanErr(http.StatusForbidden, "target_not_authorized", err.Error())
		}
		if !s.cfg.AllowPrivateTargets && targetIsPrivateLiteral(asset.Target) {
			return "", scanErr(http.StatusForbidden, "private_targets_disabled", "This deployment is not configured to assess private targets. Enable ALLOW_PRIVATE_TARGETS only inside an isolated assessment environment.")
		}
	case "ip":
		if err := validateIPTarget(asset.Target, allowPrivate); err != nil {
			return "", scanErr(http.StatusForbidden, "target_not_authorized", err.Error())
		}
		if !s.cfg.AllowPrivateTargets && targetIsPrivateLiteral(asset.Target) {
			return "", scanErr(http.StatusForbidden, "private_targets_disabled", "This deployment is not configured to assess private targets. Enable ALLOW_PRIVATE_TARGETS only inside an isolated assessment environment.")
		}
	case "website", "web_app", "api", "graphql_api", "server", "internal":
		ips, err := scanner.ResolveAndAuthorize(ctx, asset.Type, asset.Target, allowPrivate)
		if err != nil {
			return "", scanErr(http.StatusForbidden, "target_not_authorized", err.Error())
		}
		for _, ip := range ips {
			resolvedIPs = append(resolvedIPs, ip.String())
			if !s.cfg.AllowPrivateTargets && isPrivateAddress(ip) {
				return "", scanErr(http.StatusForbidden, "private_targets_disabled", "This deployment is not configured to assess private targets. Enable ALLOW_PRIVATE_TARGETS only inside an isolated assessment environment.")
			}
		}
	}

	// Concurrency and abuse limits.
	var active int
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM scans WHERE org_id=$1 AND status IN ('queued','initializing','running')`, ac.OrgID).Scan(&active); err != nil {
		return "", err
	}
	if active >= 5 {
		return "", scanErr(http.StatusTooManyRequests, "concurrency_limit", "Five assessments are already active. Wait for one to finish or cancel it.")
	}
	allowed, _, rlErr := s.queue.RateLimit(ctx, "km:rl:scan:"+ac.OrgID, 30, time.Hour)
	if rlErr == nil && !allowed {
		return "", scanErr(http.StatusTooManyRequests, "scan_quota_exceeded", "The hourly assessment limit has been reached.")
	}
	if depth, err := s.queue.QueueDepth(ctx); err == nil && depth > 2000 {
		return "", scanErr(http.StatusServiceUnavailable, "queue_saturated", "The scan queue is saturated. Try again shortly.")
	}

	scopeBody, _ := json.Marshal(map[string]any{
		"authorization_id": input.AuthorizationID, "reference": authRef, "approved_by": authApprover,
		"expires_at": authExpires.UTC().Format(time.RFC3339), "intrusive_allowed": intrusiveAllowed,
		"allow_private": allowPrivate, "asset_environment": asset.Environment, "scope_notes": authScope,
		"idempotency_key": input.IdempotencyKey, "resolved_ips": resolvedIPs, "source": source, "intrusive": intrusive,
	})
	configBody, _ := json.Marshal(config)

	tx, err := s.db.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var scanID string
	err = tx.QueryRow(ctx, `
		INSERT INTO scans (org_id, asset_id, authorization_id, profile_id, category, scanner, status, target_snapshot,
			config, scope_snapshot, created_by, phase)
		VALUES ($1,$2,$3,$4,$5,$6,'queued',$7,$8,$9,$10,'queued') RETURNING id::text`,
		ac.OrgID, input.AssetID, input.AuthorizationID, input.ProfileID, category, input.Scanner,
		asset.Target, configBody, scopeBody, ac.UserID).Scan(&scanID)
	if err != nil {
		return "", err
	}
	if err := tx.Commit(ctx); err != nil {
		return "", err
	}

	host := targetHost(asset.Type, asset.Target)
	job := scanner.Job{
		ScanID: scanID, OrgID: ac.OrgID, Scanner: input.Scanner, Category: category,
		Target: jobTarget, TargetType: asset.Type, Config: config,
		Scope: scanner.Scope{
			AssetID: input.AssetID, AuthorizationID: input.AuthorizationID, AllowPrivate: allowPrivate,
			IntrusiveAllowed: intrusiveAllowed, ExpiresAt: authExpires.UTC().Format(time.RFC3339),
			AuthorizedHost: host, AssetEnvironment: asset.Environment, Reference: authRef,
			ApprovedTargets: []string{host},
		},
		Credentials: credentials, CreatedBy: ac.UserID, QueuedAt: time.Now().UTC().Format(time.RFC3339),
	}
	if err := s.queue.Enqueue(ctx, job); err != nil {
		_, _ = s.db.Exec(ctx, `UPDATE scans SET status='failed', error='Queue unavailable', finished_at=now() WHERE id=$1`, scanID)
		return "", err
	}
	s.queue.Publish(ctx, scanner.Event{Type: "status", ScanID: scanID, Status: "queued", Phase: "queued", Progress: 0, Message: "Assessment queued", At: time.Now().UTC()})
	s.auditSystem(ctx, ac.OrgID, "scan.created", "scan", scanID, map[string]any{
		"scanner": input.Scanner, "asset_id": input.AssetID, "intrusive": intrusive, "source": source, "actor_id": ac.UserID,
	})
	s.notify(ctx, ac.OrgID, nil, "scan", "Assessment queued", meta.Label+" started against "+asset.Name+".", "/scans/"+scanID)
	return scanID, nil
}

func targetHost(assetType, target string) string {
	switch assetType {
	case "website", "web_app", "api", "graphql_api":
		if i := strings.Index(target, "://"); i >= 0 {
			rest := target[i+3:]
			if j := strings.IndexAny(rest, "/?#"); j >= 0 {
				rest = rest[:j]
			}
			if h, _, err := net.SplitHostPort(rest); err == nil {
				return h
			}
			return rest
		}
	}
	return target
}

func validateNetworkTarget(target string, allowPrivate bool) error {
	_, cidr, err := net.ParseCIDR(target)
	if err != nil {
		ip := net.ParseIP(target)
		if ip == nil {
			return scanner.ErrInvalidTarget
		}
		return validateIPTarget(target, allowPrivate)
	}
	for _, m := range []string{"169.254.169.254", "100.100.100.200", "fd00:ec2::254"} {
		if ip := net.ParseIP(m); ip != nil && cidr.Contains(ip) {
			return scanner.ErrMetadataTarget
		}
	}
	for _, blocked := range []string{"169.254.0.0/16", "fe80::/10"} {
		if _, bnet, err := net.ParseCIDR(blocked); err == nil && cidrOverlaps(cidr, bnet) {
			return scanner.ErrMetadataTarget
		}
	}
	if (cidr.IP.IsPrivate() || cidr.IP.IsLoopback() || cidr.IP.IsLinkLocalUnicast()) && !allowPrivate {
		return scanner.ErrPrivateTarget
	}
	return nil
}

func cidrOverlaps(a, b *net.IPNet) bool {
	return a.Contains(b.IP) || b.Contains(a.IP)
}

func targetIsPrivateLiteral(target string) bool {
	if ip := net.ParseIP(target); ip != nil {
		return isPrivateAddress(ip)
	}
	if _, cidr, err := net.ParseCIDR(target); err == nil {
		return isPrivateAddress(cidr.IP)
	}
	return false
}

func isPrivateAddress(ip net.IP) bool {
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified()
}

func validateIPTarget(target string, allowPrivate bool) error {
	ip := net.ParseIP(target)
	if ip == nil {
		return scanner.ErrInvalidTarget
	}
	for _, m := range []string{"169.254.169.254", "169.254.170.2", "100.100.100.200", "fd00:ec2::254"} {
		if mip := net.ParseIP(m); mip != nil && mip.Equal(ip) {
			return scanner.ErrMetadataTarget
		}
	}
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return scanner.ErrMetadataTarget
	}
	if (ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast()) && !allowPrivate {
		return scanner.ErrPrivateTarget
	}
	return nil
}

func assetSupportsScanner(assetType, sc string) bool {
	web := assetType == "website" || assetType == "web_app" || assetType == "api" || assetType == "graphql_api"
	switch sc {
	case "http-baseline", "nuclei", "nikto", "gobuster", "zap", "sqlmap":
		return web
	case "nmap":
		return assetType == "ip" || assetType == "network" || assetType == "server" || assetType == "internal"
	case "testssl":
		return web || assetType == "server" || assetType == "internal"
	case "aws-posture", "prowler", "scoutsuite":
		return assetType == "cloud"
	case "trivy":
		return assetType == "container" || assetType == "server"
	case "checkov":
		return assetType == "internal" || assetType == "container"
	case "auth-baseline":
		return web
	}
	return false
}

func (s *Server) decryptCloudConnection(ctx context.Context, orgID, connectionID string) (map[string]string, string, string, error) {
	var provider, account string
	var enc, nonce []byte
	err := s.db.QueryRow(ctx, `
		SELECT provider, account_id, encrypted_credentials, nonce FROM cloud_connections
		WHERE id=$1 AND org_id=$2 AND status <> 'disabled'`, connectionID, orgID).Scan(&provider, &account, &enc, &nonce)
	if isNotFound(err) {
		return nil, "", "", scanErr(http.StatusNotFound, "cloud_connection_not_found", "Cloud connection not found.")
	}
	if err != nil {
		return nil, "", "", err
	}
	plain, err := s.cipher.Decrypt(enc, nonce, orgID+":"+connectionID)
	if err != nil {
		return nil, "", "", scanErr(http.StatusUnprocessableEntity, "cloud_credentials_unreadable", "Cloud credentials could not be decrypted. Re-enter the connection.")
	}
	var fields map[string]string
	if err := json.Unmarshal(plain, &fields); err != nil {
		return nil, "", "", scanErr(http.StatusUnprocessableEntity, "cloud_credentials_invalid", "Cloud credentials are malformed.")
	}
	return fields, provider, account, nil
}

type scanListItem struct {
	ID          string  `json:"id"`
	AssetID     string  `json:"asset_id"`
	AssetName   string  `json:"asset_name"`
	AssetTarget string  `json:"asset_target"`
	Category    string  `json:"category"`
	Scanner     string  `json:"scanner"`
	Status      string  `json:"status"`
	Progress    int     `json:"progress"`
	Phase       string  `json:"phase"`
	Target      string  `json:"target"`
	CreatedAt   string  `json:"created_at"`
	StartedAt   *string `json:"started_at,omitempty"`
	FinishedAt  *string `json:"finished_at,omitempty"`
	Error       *string `json:"error,omitempty"`
	Findings    int     `json:"findings"`
	Critical    int     `json:"critical"`
	High        int     `json:"high"`
	CreatedBy   *string `json:"created_by_name,omitempty"`
	Intrusive   bool    `json:"intrusive"`
}

func (s *Server) handleListScans(w http.ResponseWriter, r *http.Request) {
	ac := actor(r)
	pageNo, perPage := pagination(r)
	status := r.URL.Query().Get("status")
	if status != "" && status != "active" && !validScanStatus(status) {
		s.writeValidation(w, "Unknown scan status.")
		return
	}
	category := r.URL.Query().Get("category")
	scannerName := r.URL.Query().Get("scanner")
	assetID := r.URL.Query().Get("asset_id")
	search := strings.TrimSpace(r.URL.Query().Get("search"))
	sort := sortClause(r, map[string]string{"created_at": "sc.created_at", "status": "sc.status", "started_at": "sc.started_at"}, "sc.created_at desc")
	where := `sc.org_id=$1 AND (
			$2='' OR
			($2='active' AND sc.status IN ('pending','queued','initializing','running')) OR
			($2<>'active' AND sc.status=$2)
		) AND ($3='' OR sc.category=$3) AND ($4='' OR sc.scanner=$4)
		AND ($5='' OR sc.asset_id::text=$5) AND ($6='' OR a.name ILIKE '%'||$6||'%' OR sc.target_snapshot ILIKE '%'||$6||'%')`
	var total int
	if err := s.db.QueryRow(r.Context(), `SELECT count(*) FROM scans sc JOIN assets a ON a.id=sc.asset_id WHERE `+where, ac.OrgID, status, category, scannerName, assetID, search).Scan(&total); err != nil {
		s.dbError(w, err, "scans")
		return
	}
	rows, err := s.db.Query(r.Context(), `
		SELECT sc.id::text, sc.asset_id::text, a.name, a.target, sc.category, sc.scanner, sc.status, sc.progress,
		       sc.phase, sc.target_snapshot, sc.created_at, sc.started_at, sc.finished_at, sc.error,
		       (SELECT count(DISTINCT fingerprint) FROM scan_results sr WHERE sr.scan_id=sc.id),
		       (SELECT count(DISTINCT fingerprint) FROM scan_results sr WHERE sr.scan_id=sc.id AND sr.severity='critical'),
		       (SELECT count(DISTINCT fingerprint) FROM scan_results sr WHERE sr.scan_id=sc.id AND sr.severity='high'),
		       u.name, COALESCE((sc.scope_snapshot->>'intrusive')::boolean,false)
		FROM scans sc JOIN assets a ON a.id=sc.asset_id LEFT JOIN users u ON u.id=sc.created_by
		WHERE `+where+` ORDER BY `+sort+` LIMIT $7 OFFSET $8`,
		ac.OrgID, status, category, scannerName, assetID, search, perPage, (pageNo-1)*perPage)
	if err != nil {
		s.dbError(w, err, "scans")
		return
	}
	defer rows.Close()
	items := []scanListItem{}
	for rows.Next() {
		var x scanListItem
		var created time.Time
		var started, finished *time.Time
		var createdBy *string
		if err := rows.Scan(&x.ID, &x.AssetID, &x.AssetName, &x.AssetTarget, &x.Category, &x.Scanner, &x.Status, &x.Progress,
			&x.Phase, &x.Target, &created, &started, &finished, &x.Error, &x.Findings, &x.Critical, &x.High, &createdBy, &x.Intrusive); err != nil {
			s.dbError(w, err, "scan")
			return
		}
		x.CreatedAt = created.UTC().Format(time.RFC3339)
		if started != nil {
			v := started.UTC().Format(time.RFC3339)
			x.StartedAt = &v
		}
		if finished != nil {
			v := finished.UTC().Format(time.RFC3339)
			x.FinishedAt = &v
		}
		x.CreatedBy = createdBy
		items = append(items, x)
	}
	writeJSON(w, http.StatusOK, page{Items: items, Page: pageNo, PerPage: perPage, Total: total})
}

type scanDetail struct {
	scanListItem
	Config        any              `json:"config"`
	Scope         any              `json:"scope"`
	Summary       any              `json:"summary"`
	Authorization map[string]any   `json:"authorization"`
	Executions    []map[string]any `json:"executions"`
	Severity      map[string]int   `json:"severity_counts"`
	ResultCount   int              `json:"result_count"`
}

func (s *Server) handleGetScan(w http.ResponseWriter, r *http.Request) {
	ac := actor(r)
	scanID := chiURLParam(r, "scanID")
	if !validUUID(scanID) {
		writeError(w, http.StatusBadRequest, "invalid_id", "Invalid scan id.", nil)
		return
	}
	var x scanDetail
	var created time.Time
	var started, finished *time.Time
	var config, scope, summary []byte
	var authID, authRef, approver string
	var authExpires time.Time
	var intrusiveAllowed, allowPrivate bool
	var createdBy *string
	err := s.db.QueryRow(r.Context(), `
		SELECT sc.id::text, sc.asset_id::text, a.name, a.target, sc.category, sc.scanner, sc.status, sc.progress,
		       sc.phase, sc.target_snapshot, sc.created_at, sc.started_at, sc.finished_at, sc.error,
		       (SELECT count(DISTINCT fingerprint) FROM scan_results sr WHERE sr.scan_id=sc.id),
		       (SELECT count(DISTINCT fingerprint) FROM scan_results sr WHERE sr.scan_id=sc.id AND sr.severity='critical'),
		       (SELECT count(DISTINCT fingerprint) FROM scan_results sr WHERE sr.scan_id=sc.id AND sr.severity='high'),
		       u.name, COALESCE((sc.scope_snapshot->>'intrusive')::boolean,false),
		       sc.config, sc.scope_snapshot, sc.summary,
		       sc.authorization_id::text, au.reference, au.approved_by_name, au.expires_at, au.intrusive_allowed, au.allow_private
		FROM scans sc JOIN assets a ON a.id=sc.asset_id
		LEFT JOIN users u ON u.id=sc.created_by
		JOIN authorizations au ON au.id=sc.authorization_id
		WHERE sc.id=$1 AND sc.org_id=$2`, scanID, ac.OrgID).
		Scan(&x.ID, &x.AssetID, &x.AssetName, &x.AssetTarget, &x.Category, &x.Scanner, &x.Status, &x.Progress,
			&x.Phase, &x.Target, &created, &started, &finished, &x.Error, &x.Findings, &x.Critical, &x.High,
			&createdBy, &x.Intrusive, &config, &scope, &summary,
			&authID, &authRef, &approver, &authExpires, &intrusiveAllowed, &allowPrivate)
	if isNotFound(err) {
		writeError(w, http.StatusNotFound, "not_found", "Assessment not found.", nil)
		return
	}
	if err != nil {
		s.dbError(w, err, "scan")
		return
	}
	x.CreatedAt = created.UTC().Format(time.RFC3339)
	if started != nil {
		v := started.UTC().Format(time.RFC3339)
		x.StartedAt = &v
	}
	if finished != nil {
		v := finished.UTC().Format(time.RFC3339)
		x.FinishedAt = &v
	}
	x.CreatedBy = createdBy
	x.Config = json.RawMessage(config)
	x.Scope = json.RawMessage(scope)
	x.Summary = json.RawMessage(summary)
	x.Authorization = map[string]any{
		"id": authID, "reference": authRef, "approved_by_name": approver,
		"expires_at":        authExpires.UTC().Format(time.RFC3339),
		"intrusive_allowed": intrusiveAllowed, "allow_private": allowPrivate,
	}
	x.Executions = []map[string]any{}
	execRows, err := s.db.Query(r.Context(), `
		SELECT id::text, scanner, status, command_summary, started_at, finished_at, exit_code, output_excerpt, error
		FROM scanner_executions WHERE scan_id=$1 ORDER BY started_at`, scanID)
	if err == nil {
		defer execRows.Close()
		for execRows.Next() {
			var id, sc, status, cmd, output string
			var st time.Time
			var fin *time.Time
			var code *int
			var execErr *string
			if execRows.Scan(&id, &sc, &status, &cmd, &st, &fin, &code, &output, &execErr) == nil {
				m := map[string]any{"id": id, "scanner": sc, "status": status, "command": cmd,
					"started_at": st.UTC().Format(time.RFC3339), "exit_code": code, "output_excerpt": output, "error": execErr}
				if fin != nil {
					m["finished_at"] = fin.UTC().Format(time.RFC3339)
				}
				x.Executions = append(x.Executions, m)
			}
		}
	}
	x.Severity = map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
	sevRows, err := s.db.Query(r.Context(), `SELECT severity, count(*) FROM scan_results WHERE scan_id=$1 GROUP BY severity`, scanID)
	if err == nil {
		defer sevRows.Close()
		for sevRows.Next() {
			var sev string
			var n int
			if sevRows.Scan(&sev, &n) == nil {
				x.Severity[sev] = n
				x.ResultCount += n
			}
		}
	}
	writeJSON(w, http.StatusOK, x)
}

func (s *Server) handleCancelScan(w http.ResponseWriter, r *http.Request) {
	ac := actor(r)
	scanID := chiURLParam(r, "scanID")
	var status string
	var cancel bool
	err := s.db.QueryRow(r.Context(), `SELECT status, cancel_requested FROM scans WHERE id=$1 AND org_id=$2`, scanID, ac.OrgID).Scan(&status, &cancel)
	if isNotFound(err) {
		writeError(w, http.StatusNotFound, "not_found", "Assessment not found.", nil)
		return
	}
	if err != nil {
		s.dbError(w, err, "scan")
		return
	}
	if status == "completed" || status == "failed" || status == "cancelled" {
		writeError(w, http.StatusConflict, "not_cancellable", "This assessment has already finished.", nil)
		return
	}
	if status == "queued" || status == "pending" {
		_, err = s.db.Exec(r.Context(), `UPDATE scans SET status='cancelled', cancel_requested=true, finished_at=now(), error='Cancelled before execution' WHERE id=$1 AND org_id=$2`, scanID, ac.OrgID)
	} else {
		_, err = s.db.Exec(r.Context(), `UPDATE scans SET cancel_requested=true WHERE id=$1 AND org_id=$2`, scanID, ac.OrgID)
	}
	if err != nil {
		s.dbError(w, err, "scan")
		return
	}
	_ = s.queue.SetCancel(r.Context(), scanID)
	s.queue.Publish(r.Context(), scanner.Event{Type: "status", ScanID: scanID, Status: "cancelled", Message: "Cancellation requested", At: time.Now().UTC()})
	s.audit(r, "scan.cancelled", "scan", scanID, nil)
	writeJSON(w, http.StatusAccepted, map[string]any{"ok": true})
}

func (s *Server) handleScanEvents(w http.ResponseWriter, r *http.Request) {
	ac := actor(r)
	scanID := chiURLParam(r, "scanID")
	var status, phase string
	var progress int
	var errMsg *string
	var summary []byte
	err := s.db.QueryRow(r.Context(), `SELECT status, phase, progress, error, summary FROM scans WHERE id=$1 AND org_id=$2`, scanID, ac.OrgID).
		Scan(&status, &phase, &progress, &errMsg, &summary)
	if isNotFound(err) {
		writeError(w, http.StatusNotFound, "not_found", "Assessment not found.", nil)
		return
	}
	if err != nil {
		s.dbError(w, err, "scan")
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "stream_unsupported", "Streaming is not supported by this connection.", nil)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	initial, _ := json.Marshal(map[string]any{"type": "snapshot", "scan_id": scanID, "status": status, "phase": phase, "progress": progress, "message": errMsg, "summary": json.RawMessage(summary)})
	fmt.Fprintf(w, "retry: 3000\nevent: update\ndata: %s\n\n", initial)
	flusher.Flush()

	pubsub := s.rdb.Subscribe(r.Context(), s.cfg.EventsChan+":"+scanID)
	defer pubsub.Close()
	ch := pubsub.Channel()
	keepalive := time.NewTicker(20 * time.Second)
	defer keepalive.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-keepalive.C:
			fmt.Fprint(w, ": keepalive\n\n")
			flusher.Flush()
		case msg, ok := <-ch:
			if !ok {
				return
			}
			fmt.Fprintf(w, "event: update\ndata: %s\n\n", msg.Payload)
			flusher.Flush()
			var ev scanner.Event
			if json.Unmarshal([]byte(msg.Payload), &ev) == nil {
				if ev.Status == "completed" || ev.Status == "failed" || ev.Status == "cancelled" {
					return
				}
			}
		}
	}
}

func (s *Server) handleScanExecutions(w http.ResponseWriter, r *http.Request) {
	ac := actor(r)
	scanID := chiURLParam(r, "scanID")
	rows, err := s.db.Query(r.Context(), `
		SELECT e.id::text, e.scanner, e.status, e.command_summary, e.started_at, e.finished_at, e.exit_code,
		       e.output_excerpt, e.error
		FROM scanner_executions e JOIN scans sc ON sc.id=e.scan_id
		WHERE e.scan_id=$1 AND sc.org_id=$2 ORDER BY e.started_at`, scanID, ac.OrgID)
	if err != nil {
		s.dbError(w, err, "executions")
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id, sc, status, cmd, output string
		var started time.Time
		var finished *time.Time
		var code *int
		var execErr *string
		if err := rows.Scan(&id, &sc, &status, &cmd, &started, &finished, &code, &output, &execErr); err != nil {
			s.dbError(w, err, "execution")
			return
		}
		m := map[string]any{"id": id, "scanner": sc, "status": status, "command": cmd,
			"started_at": started.UTC().Format(time.RFC3339), "exit_code": code, "output_excerpt": output, "error": execErr}
		if finished != nil {
			m["finished_at"] = finished.UTC().Format(time.RFC3339)
		}
		out = append(out, m)
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": out})
}

func (s *Server) handleScanResults(w http.ResponseWriter, r *http.Request) {
	ac := actor(r)
	scanID := chiURLParam(r, "scanID")
	pageNo, perPage := pagination(r)
	rows, err := s.db.Query(r.Context(), `
		SELECT id::text, title, severity, confidence, cve, cwe, cvss, endpoint, description, evidence, created_at
		FROM scan_results WHERE scan_id=$1 AND org_id=$2
		ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END,
		created_at LIMIT $3 OFFSET $4`, scanID, ac.OrgID, perPage, (pageNo-1)*perPage)
	if err != nil {
		s.dbError(w, err, "results")
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id, title, sev, conf, endpoint, desc string
		var cve, cwe *string
		var cvss *float64
		var evidence []byte
		var created time.Time
		if err := rows.Scan(&id, &title, &sev, &conf, &cve, &cwe, &cvss, &endpoint, &desc, &evidence, &created); err != nil {
			s.dbError(w, err, "result")
			return
		}
		out = append(out, map[string]any{"id": id, "title": title, "severity": sev, "confidence": conf,
			"cve": cve, "cwe": cwe, "cvss": cvss, "endpoint": endpoint, "description": desc,
			"evidence": json.RawMessage(evidence), "created_at": created.UTC().Format(time.RFC3339)})
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": out})
}

func (s *Server) handleScanFindings(w http.ResponseWriter, r *http.Request) {
	ac := actor(r)
	scanID := chiURLParam(r, "scanID")
	rows, err := s.db.Query(r.Context(), `
		SELECT f.id::text, f.title, f.severity, f.status, f.endpoint, f.cve, f.cwe, f.cvss, f.first_seen, f.last_seen
		FROM findings f
		JOIN (SELECT DISTINCT fingerprint FROM scan_results WHERE scan_id=$1 AND org_id=$2) sr
		  ON sr.fingerprint = f.fingerprint
		WHERE f.org_id=$2 ORDER BY last_seen DESC`, scanID, ac.OrgID)
	if err != nil {
		s.dbError(w, err, "findings")
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id, title, sev, status, endpoint string
		var cve, cwe *string
		var cvss *float64
		var first, last time.Time
		if err := rows.Scan(&id, &title, &sev, &status, &endpoint, &cve, &cwe, &cvss, &first, &last); err != nil {
			s.dbError(w, err, "finding")
			return
		}
		out = append(out, map[string]any{"id": id, "title": title, "severity": sev, "status": status, "endpoint": endpoint,
			"cve": cve, "cwe": cwe, "cvss": cvss, "first_seen": first.UTC().Format(time.RFC3339), "last_seen": last.UTC().Format(time.RFC3339)})
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": out})
}

func (s *Server) handleCompareScans(w http.ResponseWriter, r *http.Request) {
	ac := actor(r)
	baseID := r.URL.Query().Get("base")
	compareID := r.URL.Query().Get("compare")
	if !validUUID(baseID) || !validUUID(compareID) {
		s.writeValidation(w, "base and compare scan ids are required.")
		return
	}
	var count int
	_ = s.db.QueryRow(r.Context(), `SELECT count(*) FROM scans WHERE org_id=$1 AND id IN ($2,$3)`, ac.OrgID, baseID, compareID).Scan(&count)
	if count != 2 {
		writeError(w, http.StatusNotFound, "not_found", "One or both assessments were not found.", nil)
		return
	}
	rows, err := s.db.Query(r.Context(), `
		SELECT scan_id::text, fingerprint, title, severity, endpoint, cve FROM scan_results WHERE scan_id IN ($1,$2)`, baseID, compareID)
	if err != nil {
		s.dbError(w, err, "compare")
		return
	}
	defer rows.Close()
	type row struct {
		title, sev, endpoint string
		cve                  *string
	}
	base := map[string]row{}
	comp := map[string]row{}
	for rows.Next() {
		var scanID, fp, title, sev, endpoint string
		var cve *string
		if err := rows.Scan(&scanID, &fp, &title, &sev, &endpoint, &cve); err != nil {
			continue
		}
		if scanID == baseID {
			base[fp] = row{title, sev, endpoint, cve}
		} else {
			comp[fp] = row{title, sev, endpoint, cve}
		}
	}
	newFindings := []map[string]any{}
	fixed := []map[string]any{}
	persisting := []map[string]any{}
	for fp, c := range comp {
		if _, ok := base[fp]; !ok {
			newFindings = append(newFindings, map[string]any{"fingerprint": fp, "title": c.title, "severity": c.sev, "endpoint": c.endpoint, "cve": c.cve})
		} else {
			persisting = append(persisting, map[string]any{"fingerprint": fp, "title": c.title, "severity": c.sev, "endpoint": c.endpoint, "cve": c.cve})
		}
	}
	for fp, b := range base {
		if _, ok := comp[fp]; !ok {
			fixed = append(fixed, map[string]any{"fingerprint": fp, "title": b.title, "severity": b.sev, "endpoint": b.endpoint, "cve": b.cve})
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"base": baseID, "compare": compareID, "new": newFindings, "resolved": fixed, "persisting": persisting,
	})
}

func (s *Server) handleEmergencyStop(w http.ResponseWriter, r *http.Request) {
	ac := actor(r)
	tx, err := s.db.Begin(r.Context())
	if err != nil {
		s.dbError(w, err, "organization")
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()
	if _, err := tx.Exec(r.Context(), `UPDATE organizations SET emergency_stop=true WHERE id=$1`, ac.OrgID); err != nil {
		s.dbError(w, err, "organization")
		return
	}
	rows, err := tx.Query(r.Context(), `
		UPDATE scans SET status='cancelled', cancel_requested=true, finished_at=now(), error='Cancelled by emergency stop'
		WHERE org_id=$1 AND status IN ('pending','queued','initializing','running') RETURNING id::text`, ac.OrgID)
	if err != nil {
		s.dbError(w, err, "scan")
		return
	}
	ids := []string{}
	for rows.Next() {
		var id string
		if rows.Scan(&id) == nil {
			ids = append(ids, id)
		}
	}
	rows.Close()
	if err := tx.Commit(r.Context()); err != nil {
		s.dbError(w, err, "organization")
		return
	}
	_ = s.queue.SetEmergencyStop(r.Context(), ac.OrgID, true)
	for _, id := range ids {
		_ = s.queue.SetCancel(r.Context(), id)
		s.queue.Publish(r.Context(), scanner.Event{Type: "status", ScanID: id, Status: "cancelled", Message: "Emergency stop activated", At: time.Now().UTC()})
	}
	s.audit(r, "org.emergency_stop", "organization", ac.OrgID, map[string]any{"cancelled_scans": len(ids)})
	s.notify(r.Context(), ac.OrgID, nil, "system", "Emergency stop activated", fmt.Sprintf("%d active assessments were cancelled.", len(ids)), "/scans")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "cancelled": len(ids)})
}

func (s *Server) handleClearEmergencyStop(w http.ResponseWriter, r *http.Request) {
	ac := actor(r)
	if _, err := s.db.Exec(r.Context(), `UPDATE organizations SET emergency_stop=false WHERE id=$1`, ac.OrgID); err != nil {
		s.dbError(w, err, "organization")
		return
	}
	_ = s.queue.SetEmergencyStop(r.Context(), ac.OrgID, false)
	s.audit(r, "org.emergency_stop_cleared", "organization", ac.OrgID, nil)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// --- Profiles and scanner availability ---

func (s *Server) handleListProfiles(w http.ResponseWriter, r *http.Request) {
	ac := actor(r)
	rows, err := s.db.Query(r.Context(), `
		SELECT id::text, org_id::text, key, name, category, scanner, description, config, intrusive, is_system, created_at
		FROM scan_profiles WHERE org_id=$1 OR org_id IS NULL ORDER BY is_system DESC, category, name`, ac.OrgID)
	if err != nil {
		s.dbError(w, err, "profiles")
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id, key, name, category, sc, desc string
		var orgID *string
		var config []byte
		var intrusive, system bool
		var created time.Time
		if err := rows.Scan(&id, &orgID, &key, &name, &category, &sc, &desc, &config, &intrusive, &system, &created); err != nil {
			s.dbError(w, err, "profile")
			return
		}
		out = append(out, map[string]any{"id": id, "org_id": orgID, "key": key, "name": name, "category": category,
			"scanner": sc, "description": desc, "config": json.RawMessage(config), "intrusive": intrusive,
			"is_system": system, "created_at": created.UTC().Format(time.RFC3339)})
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": out})
}

type createProfileRequest struct {
	Name        string         `json:"name"`
	Category    string         `json:"category"`
	Scanner     string         `json:"scanner"`
	Description string         `json:"description"`
	Config      map[string]any `json:"config"`
	Key         string         `json:"key"`
}

func (s *Server) handleCreateProfile(w http.ResponseWriter, r *http.Request) {
	var req createProfileRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	ac := actor(r)
	meta, ok := scanner.Find(req.Scanner)
	if !ok {
		s.writeValidation(w, "Unknown scanner.")
		return
	}
	if req.Category == "" {
		req.Category = meta.Category
	}
	if req.Category != meta.Category {
		s.writeValidation(w, "Category does not match scanner.")
		return
	}
	config, err := scanner.ValidateParams(req.Scanner, req.Config)
	if err != nil {
		s.writeValidation(w, err.Error())
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if len(req.Name) < 2 || len(req.Name) > 120 {
		s.writeValidation(w, "Profile name must be between 2 and 120 characters.")
		return
	}
	key := strings.TrimSpace(req.Key)
	if key == "" {
		key = security.Slugify(req.Name)
	}
	if len(key) < 2 || len(key) > 60 {
		s.writeValidation(w, "Profile key is invalid.")
		return
	}
	body, _ := json.Marshal(config)
	var id string
	err = s.db.QueryRow(r.Context(), `
		INSERT INTO scan_profiles (org_id, key, name, category, scanner, description, config, intrusive, is_system, created_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,false,$9) RETURNING id::text`,
		ac.OrgID, key, req.Name, req.Category, req.Scanner, strings.TrimSpace(req.Description), body,
		scanner.IsIntrusive(req.Scanner, config), ac.UserID).Scan(&id)
	if err != nil {
		if strings.Contains(err.Error(), "scan_profiles_org_id_key_key") || strings.Contains(err.Error(), "duplicate key") {
			writeError(w, http.StatusConflict, "profile_exists", "A profile with this key already exists.", nil)
			return
		}
		s.dbError(w, err, "profile")
		return
	}
	s.audit(r, "profile.created", "scan_profile", id, map[string]any{"scanner": req.Scanner})
	writeJSON(w, http.StatusCreated, map[string]any{"id": id})
}

func (s *Server) handleUpdateProfile(w http.ResponseWriter, r *http.Request) {
	var req createProfileRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	ac := actor(r)
	id := chiURLParam(r, "profileID")
	var system bool
	err := s.db.QueryRow(r.Context(), `SELECT is_system FROM scan_profiles WHERE id=$1 AND (org_id=$2 OR org_id IS NULL)`, id, ac.OrgID).Scan(&system)
	if isNotFound(err) {
		writeError(w, http.StatusNotFound, "not_found", "Profile not found.", nil)
		return
	}
	if system {
		writeError(w, http.StatusForbidden, "system_profile", "System profiles cannot be modified. Duplicate one to customize it.", nil)
		return
	}
	meta, ok := scanner.Find(req.Scanner)
	if !ok || req.Category != meta.Category {
		s.writeValidation(w, "Scanner and category do not match.")
		return
	}
	config, err := scanner.ValidateParams(req.Scanner, req.Config)
	if err != nil {
		s.writeValidation(w, err.Error())
		return
	}
	body, _ := json.Marshal(config)
	_, err = s.db.Exec(r.Context(), `
		UPDATE scan_profiles SET name=$1, category=$2, scanner=$3, description=$4, config=$5, intrusive=$6
		WHERE id=$7 AND org_id=$8`, strings.TrimSpace(req.Name), req.Category, req.Scanner, strings.TrimSpace(req.Description),
		body, scanner.IsIntrusive(req.Scanner, config), id, ac.OrgID)
	if err != nil {
		s.dbError(w, err, "profile")
		return
	}
	s.audit(r, "profile.updated", "scan_profile", id, nil)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleDeleteProfile(w http.ResponseWriter, r *http.Request) {
	ac := actor(r)
	id := chiURLParam(r, "profileID")
	tag, err := s.db.Exec(r.Context(), `DELETE FROM scan_profiles WHERE id=$1 AND org_id=$2 AND is_system=false`, id, ac.OrgID)
	if err != nil {
		s.dbError(w, err, "profile")
		return
	}
	if tag.RowsAffected() == 0 {
		writeError(w, http.StatusNotFound, "not_found", "Custom profile not found.", nil)
		return
	}
	s.audit(r, "profile.deleted", "scan_profile", id, nil)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleScanners(w http.ResponseWriter, r *http.Request) {
	ac := actor(r)
	heartbeats, _ := s.queue.Heartbeats(r.Context())
	availability := map[string]map[string]any{}
	var latest time.Time
	workers := []map[string]any{}
	for _, hb := range heartbeats {
		workers = append(workers, hb)
		if t, ok := hb["at"].(string); ok {
			if parsed, err := time.Parse(time.RFC3339, t); err == nil && parsed.After(latest) {
				latest = parsed
			}
		}
		if scanners, ok := hb["scanners"].(map[string]any); ok {
			for name, raw := range scanners {
				if m, ok := raw.(map[string]any); ok {
					availability[name] = m
				}
			}
		}
	}
	online := !latest.IsZero() && time.Since(latest) < 90*time.Second
	items := []map[string]any{}
	for _, meta := range scanner.Catalog {
		av, ok := availability[meta.Name]
		status := "unavailable"
		version := ""
		detail := "No worker has reported this scanner. Start a scanner worker."
		if ok {
			if available, _ := av["available"].(bool); available {
				status = "available"
				detail = "Scanner detected by worker."
			} else {
				detail = "Worker could not find the required binary or service."
			}
			if v, ok := av["version"].(string); ok {
				version = v
			}
			if e, ok := av["error"].(string); ok && e != "" {
				detail = e
			}
		}
		if !online {
			status = "offline"
			detail = "No scanner worker heartbeat in the last 90 seconds."
		}
		items = append(items, map[string]any{
			"name": meta.Name, "label": meta.Label, "category": meta.Category, "description": meta.Description,
			"intrusive": meta.Intrusive, "binary": meta.Binary, "params": meta.Params,
			"default_params": meta.DefaultParams, "status": status, "version": version, "detail": detail,
		})
	}
	depth, _ := s.queue.QueueDepth(r.Context())
	emergency, _ := s.queue.EmergencyStop(r.Context(), ac.OrgID)
	writeJSON(w, http.StatusOK, map[string]any{
		"items": items, "workers": workers, "worker_online": online, "queue_depth": depth,
		"emergency_stop": emergency, "last_heartbeat": emptyTime(latest),
	})
}

func emptyTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}
