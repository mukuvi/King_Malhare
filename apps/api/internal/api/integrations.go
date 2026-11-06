package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/kingmalhare/api/internal/scanner"
	"github.com/kingmalhare/api/internal/security"
)

// --- Cloud connections ---

type cloudRequest struct {
	Provider    string            `json:"provider"`
	Name        string            `json:"name"`
	AccountID   string            `json:"account_id"`
	Credentials map[string]string `json:"credentials"`
}

var cloudRequired = map[string][]string{
	"aws":   {"access_key_id", "secret_access_key", "region"},
	"azure": {"tenant_id", "client_id", "client_secret", "subscription_id"},
	"gcp":   {"service_account_json"},
}

func (s *Server) handleListCloud(w http.ResponseWriter, r *http.Request) {
	ac := actor(r)
	rows, err := s.db.Query(r.Context(), `
		SELECT id::text, provider, name, account_id, status, last_verified_at, last_error, created_at
		FROM cloud_connections WHERE org_id=$1 AND status <> 'disabled' ORDER BY created_at DESC`, ac.OrgID)
	if err != nil {
		s.dbError(w, err, "cloud connections")
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id, provider, name, account, status string
		var verified *time.Time
		var lastErr *string
		var created time.Time
		if err := rows.Scan(&id, &provider, &name, &account, &status, &verified, &lastErr, &created); err != nil {
			s.dbError(w, err, "cloud connection")
			return
		}
		m := map[string]any{"id": id, "provider": provider, "name": name, "account_id": account,
			"status": status, "last_error": lastErr, "created_at": created.UTC().Format(time.RFC3339)}
		if verified != nil {
			m["last_verified_at"] = verified.UTC().Format(time.RFC3339)
		}
		out = append(out, m)
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": out})
}

func (s *Server) handleCreateCloud(w http.ResponseWriter, r *http.Request) {
	var req cloudRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	ac := actor(r)
	req.Provider = strings.ToLower(strings.TrimSpace(req.Provider))
	req.Name = strings.TrimSpace(req.Name)
	if req.Provider != "aws" && req.Provider != "azure" && req.Provider != "gcp" {
		s.writeValidation(w, "Provider must be aws, azure or gcp.")
		return
	}
	if len(req.Name) < 2 || len(req.Name) > 120 {
		s.writeValidation(w, "Connection name must be between 2 and 120 characters.")
		return
	}
	for _, field := range cloudRequired[req.Provider] {
		if strings.TrimSpace(req.Credentials[field]) == "" {
			s.writeValidation(w, "Missing credential field: "+field)
			return
		}
	}
	if req.Provider == "gcp" {
		var blob map[string]any
		if err := json.Unmarshal([]byte(req.Credentials["service_account_json"]), &blob); err != nil {
			s.writeValidation(w, "Service account JSON is not valid JSON.")
			return
		}
	}
	allowed := map[string]bool{"region": true, "session_token": true, "role_arn": true, "external_id": true}
	for k := range req.Credentials {
		ok := allowed[k]
		for _, f := range cloudRequired[req.Provider] {
			if k == f {
				ok = true
			}
		}
		if !ok {
			s.writeValidation(w, "Unexpected credential field: "+k)
			return
		}
	}
	var id string
	if err := s.db.QueryRow(r.Context(), `SELECT gen_random_uuid()::text`).Scan(&id); err != nil {
		s.dbError(w, err, "cloud connection")
		return
	}
	plain, _ := json.Marshal(req.Credentials)
	enc, nonce, err := s.cipher.Encrypt(plain, ac.OrgID+":"+id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "encryption_failed", "Credentials could not be encrypted.", nil)
		return
	}
	_, err = s.db.Exec(r.Context(), `
		INSERT INTO cloud_connections (id, org_id, provider, name, account_id, encrypted_credentials, nonce, status, created_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7,'unverified',$8)`,
		id, ac.OrgID, req.Provider, req.Name, strings.TrimSpace(req.AccountID), enc, nonce, ac.UserID)
	if err != nil {
		s.dbError(w, err, "cloud connection")
		return
	}
	s.audit(r, "cloud.connection_created", "cloud_connection", id, map[string]any{"provider": req.Provider, "name": req.Name})
	writeJSON(w, http.StatusCreated, map[string]any{"id": id, "status": "unverified"})
}

func (s *Server) handleDeleteCloud(w http.ResponseWriter, r *http.Request) {
	ac := actor(r)
	id := chiURLParam(r, "connectionID")
	tag, err := s.db.Exec(r.Context(), `DELETE FROM cloud_connections WHERE id=$1 AND org_id=$2`, id, ac.OrgID)
	if err != nil {
		s.dbError(w, err, "cloud connection")
		return
	}
	if tag.RowsAffected() == 0 {
		writeError(w, http.StatusNotFound, "not_found", "Cloud connection not found.", nil)
		return
	}
	s.audit(r, "cloud.connection_deleted", "cloud_connection", id, nil)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleValidateCloud(w http.ResponseWriter, r *http.Request) {
	ac := actor(r)
	id := chiURLParam(r, "connectionID")
	fields, provider, _, err := s.decryptCloudConnection(r.Context(), ac.OrgID, id)
	if err != nil {
		if se, ok := err.(*scanRequestError); ok {
			writeError(w, se.Status, se.Code, se.Message, nil)
			return
		}
		s.dbError(w, err, "cloud connection")
		return
	}
	if _, err := s.db.Exec(r.Context(), `UPDATE cloud_connections SET status='unverified', last_error=NULL WHERE id=$1 AND org_id=$2`, id, ac.OrgID); err != nil {
		s.dbError(w, err, "cloud connection")
		return
	}
	s.audit(r, "cloud.connection_validated", "cloud_connection", id, map[string]any{"provider": provider})
	writeJSON(w, http.StatusOK, map[string]any{
		"decryptable": true, "live_verified": false,
		"message":        "Credentials decrypt correctly and the required fields are present. Live permissions are verified by running a read-only posture assessment.",
		"fields_present": len(fields),
	})
}

// --- API keys ---

type createAPIKeyRequest struct {
	Name      string   `json:"name"`
	Scopes    []string `json:"scopes"`
	ExpiresIn int      `json:"expires_in_days"`
}

func (s *Server) handleListAPIKeys(w http.ResponseWriter, r *http.Request) {
	ac := actor(r)
	rows, err := s.db.Query(r.Context(), `
		SELECT id::text, name, token_prefix, scopes, last_used_at, expires_at, revoked_at, created_at
		FROM api_credentials WHERE org_id=$1 ORDER BY created_at DESC`, ac.OrgID)
	if err != nil {
		s.dbError(w, err, "api keys")
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id, name, prefix string
		var scopes []string
		var lastUsed, expires, revoked *time.Time
		var created time.Time
		if err := rows.Scan(&id, &name, &prefix, &scopes, &lastUsed, &expires, &revoked, &created); err != nil {
			s.dbError(w, err, "api key")
			return
		}
		m := map[string]any{"id": id, "name": name, "token_prefix": prefix, "scopes": scopes,
			"created_at": created.UTC().Format(time.RFC3339), "revoked": revoked != nil}
		if lastUsed != nil {
			m["last_used_at"] = lastUsed.UTC().Format(time.RFC3339)
		}
		if expires != nil {
			m["expires_at"] = expires.UTC().Format(time.RFC3339)
		}
		out = append(out, m)
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": out})
}

func (s *Server) handleCreateAPIKey(w http.ResponseWriter, r *http.Request) {
	var req createAPIKeyRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	ac := actor(r)
	req.Name = strings.TrimSpace(req.Name)
	if len(req.Name) < 2 || len(req.Name) > 120 {
		s.writeValidation(w, "Key name must be between 2 and 120 characters.")
		return
	}
	if len(req.Scopes) == 0 {
		for p := range ac.Permissions {
			req.Scopes = append(req.Scopes, p)
		}
	}
	if len(req.Scopes) > 30 {
		s.writeValidation(w, "Too many scopes.")
		return
	}
	for _, scope := range req.Scopes {
		if !ac.Can(scope) {
			writeError(w, http.StatusForbidden, "scope_not_granted", "You cannot issue a key with a permission you do not hold.", map[string]any{"scope": scope})
			return
		}
	}
	prefix, _ := security.RandomHex(4)
	secret, err := security.RandomToken(32)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "key_generation_failed", "Could not generate the key.", nil)
		return
	}
	token := "km_" + prefix + "_" + secret
	var expires *time.Time
	if req.ExpiresIn > 0 {
		if req.ExpiresIn > 730 {
			s.writeValidation(w, "Key lifetime cannot exceed two years.")
			return
		}
		t := time.Now().AddDate(0, 0, req.ExpiresIn)
		expires = &t
	}
	var id string
	err = s.db.QueryRow(r.Context(), `
		INSERT INTO api_credentials (org_id, user_id, name, token_prefix, token_hash, scopes, expires_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING id::text`,
		ac.OrgID, ac.UserID, req.Name, "km_"+prefix, security.HashToken(s.cfg.SessionPepper, token), req.Scopes, expires).Scan(&id)
	if err != nil {
		s.dbError(w, err, "api key")
		return
	}
	s.audit(r, "api_key.created", "api_credential", id, map[string]any{"scopes": req.Scopes})
	writeJSON(w, http.StatusCreated, map[string]any{
		"id": id, "token": token, "prefix": "km_" + prefix, "scopes": req.Scopes,
		"message": "Copy this token now. It is not shown again.",
	})
}

func (s *Server) handleRevokeAPIKey(w http.ResponseWriter, r *http.Request) {
	ac := actor(r)
	id := chiURLParam(r, "keyID")
	tag, err := s.db.Exec(r.Context(), `UPDATE api_credentials SET revoked_at=now() WHERE id=$1 AND org_id=$2 AND revoked_at IS NULL`, id, ac.OrgID)
	if err != nil {
		s.dbError(w, err, "api key")
		return
	}
	if tag.RowsAffected() == 0 {
		writeError(w, http.StatusNotFound, "not_found", "API key not found or already revoked.", nil)
		return
	}
	s.audit(r, "api_key.revoked", "api_credential", id, nil)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// --- Schedules ---

type scheduleRequest struct {
	AssetID         string         `json:"asset_id"`
	AuthorizationID string         `json:"authorization_id"`
	Scanner         string         `json:"scanner"`
	Category        string         `json:"category"`
	ProfileID       *string        `json:"profile_id"`
	Config          map[string]any `json:"config"`
	Cron            string         `json:"cron"`
	Enabled         *bool          `json:"enabled"`
}

func (s *Server) handleListSchedules(w http.ResponseWriter, r *http.Request) {
	ac := actor(r)
	rows, err := s.db.Query(r.Context(), `
		SELECT s.id::text, s.asset_id::text, a.name, s.authorization_id::text, s.scanner, s.category,
		       s.profile_id::text, s.config, s.cron, s.enabled, s.next_run_at, s.last_run_at, s.created_at
		FROM scan_schedules s JOIN assets a ON a.id=s.asset_id
		WHERE s.org_id=$1 ORDER BY s.created_at DESC`, ac.OrgID)
	if err != nil {
		s.dbError(w, err, "schedules")
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id, assetID, assetName, authID, sc, category, cronExpr string
		var profileID *string
		var cfg []byte
		var enabled bool
		var next, last, created *time.Time
		if err := rows.Scan(&id, &assetID, &assetName, &authID, &sc, &category, &profileID, &cfg, &cronExpr, &enabled, &next, &last, &created); err != nil {
			s.dbError(w, err, "schedule")
			return
		}
		m := map[string]any{"id": id, "asset_id": assetID, "asset_name": assetName, "authorization_id": authID,
			"scanner": sc, "category": category, "profile_id": profileID, "config": json.RawMessage(cfg),
			"cron": cronExpr, "enabled": enabled, "next_run_at": timeOrNil(next), "last_run_at": timeOrNil(last), "created_at": maybeTime(created)}
		out = append(out, m)
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": out})
}

func maybeTime(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func (s *Server) handleCreateSchedule(w http.ResponseWriter, r *http.Request) {
	var req scheduleRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	ac := actor(r)
	meta, ok := scanner.Find(req.Scanner)
	if !ok {
		s.writeValidation(w, "Unknown scanner.")
		return
	}
	if meta.Intrusive || req.Scanner == "sqlmap" || req.Scanner == "auth-baseline" {
		s.writeValidation(w, "Intrusive scanners cannot be scheduled. Run them manually with explicit approval.")
		return
	}
	if meta.Category == "cloud" {
		s.writeValidation(w, "Cloud assessments cannot be scheduled yet. Run them manually after selecting a connection.")
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
	next, err := nextCron(req.Cron, time.Now())
	if err != nil {
		s.writeValidation(w, "Cron expression is invalid: "+err.Error())
		return
	}
	var valid bool
	_ = s.db.QueryRow(r.Context(), `
		SELECT EXISTS(SELECT 1 FROM assets a JOIN authorizations au ON au.asset_id=a.id
		WHERE a.id=$1 AND a.org_id=$2 AND au.id=$3 AND au.org_id=$2 AND au.status='active' AND au.expires_at>now())`,
		req.AssetID, ac.OrgID, req.AuthorizationID).Scan(&valid)
	if !valid {
		s.writeValidation(w, "Asset and active authorization do not match.")
		return
	}
	body, _ := json.Marshal(config)
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	var id string
	err = s.db.QueryRow(r.Context(), `
		INSERT INTO scan_schedules (org_id, asset_id, authorization_id, scanner, category, profile_id, config, cron, enabled, next_run_at, created_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING id::text`,
		ac.OrgID, req.AssetID, req.AuthorizationID, req.Scanner, req.Category, req.ProfileID, body, req.Cron, enabled, next, ac.UserID).Scan(&id)
	if err != nil {
		s.dbError(w, err, "schedule")
		return
	}
	s.audit(r, "schedule.created", "scan_schedule", id, map[string]any{"cron": req.Cron, "scanner": req.Scanner})
	writeJSON(w, http.StatusCreated, map[string]any{"id": id, "next_run_at": next.UTC().Format(time.RFC3339)})
}

type updateScheduleRequest struct {
	Cron    *string `json:"cron"`
	Enabled *bool   `json:"enabled"`
}

func (s *Server) handleUpdateSchedule(w http.ResponseWriter, r *http.Request) {
	var req updateScheduleRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	ac := actor(r)
	id := chiURLParam(r, "scheduleID")
	if req.Cron != nil {
		next, err := nextCron(*req.Cron, time.Now())
		if err != nil {
			s.writeValidation(w, "Cron expression is invalid: "+err.Error())
			return
		}
		_, err = s.db.Exec(r.Context(), `UPDATE scan_schedules SET cron=$1, next_run_at=$2 WHERE id=$3 AND org_id=$4`, *req.Cron, next, id, ac.OrgID)
		if err != nil {
			s.dbError(w, err, "schedule")
			return
		}
	}
	if req.Enabled != nil {
		_, err := s.db.Exec(r.Context(), `UPDATE scan_schedules SET enabled=$1 WHERE id=$2 AND org_id=$3`, *req.Enabled, id, ac.OrgID)
		if err != nil {
			s.dbError(w, err, "schedule")
			return
		}
	}
	s.audit(r, "schedule.updated", "scan_schedule", id, nil)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleDeleteSchedule(w http.ResponseWriter, r *http.Request) {
	ac := actor(r)
	id := chiURLParam(r, "scheduleID")
	tag, err := s.db.Exec(r.Context(), `DELETE FROM scan_schedules WHERE id=$1 AND org_id=$2`, id, ac.OrgID)
	if err != nil {
		s.dbError(w, err, "schedule")
		return
	}
	if tag.RowsAffected() == 0 {
		writeError(w, http.StatusNotFound, "not_found", "Schedule not found.", nil)
		return
	}
	s.audit(r, "schedule.deleted", "scan_schedule", id, nil)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) StartScheduler(ctx context.Context) {
	ticker := time.NewTicker(45 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.runDueSchedules(ctx)
		}
	}
}

func (s *Server) runDueSchedules(ctx context.Context) {
	rows, err := s.db.Query(ctx, `
		UPDATE scan_schedules SET last_run_at=now(), next_run_at=now()+interval '1 hour'
		WHERE id IN (
		  SELECT id FROM scan_schedules WHERE enabled AND next_run_at <= now() ORDER BY next_run_at LIMIT 5 FOR UPDATE SKIP LOCKED
		) RETURNING id::text, org_id::text, asset_id::text, authorization_id::text, scanner, category, profile_id::text, config, cron, created_by::text`)
	if err != nil {
		s.log.Error("scheduler query failed", "error", err)
		return
	}
	type due struct {
		id, orgID, assetID, authID, scannerName, category string
		profileID                                         *string
		config                                            []byte
		cronExpr, createdBy                               string
	}
	var jobs []due
	for rows.Next() {
		var d due
		if err := rows.Scan(&d.id, &d.orgID, &d.assetID, &d.authID, &d.scannerName, &d.category, &d.profileID, &d.config, &d.cronExpr, &d.createdBy); err != nil {
			s.log.Error("scheduler row scan failed", "error", err)
			continue
		}
		jobs = append(jobs, d)
	}
	rows.Close()
	for _, d := range jobs {
		next, cronErr := nextCron(d.cronExpr, time.Now())
		if cronErr != nil {
			_, _ = s.db.Exec(ctx, `UPDATE scan_schedules SET enabled=false WHERE id=$1`, d.id)
			s.notify(ctx, d.orgID, nil, "system", "Schedule disabled", "A schedule was disabled because its cron expression is invalid.", "/integrations")
			continue
		}
		_, _ = s.db.Exec(ctx, `UPDATE scan_schedules SET next_run_at=$1 WHERE id=$2`, next, d.id)
		ac := s.systemActor(ctx, d.orgID, d.createdBy)
		if ac == nil {
			continue
		}
		var params map[string]any
		_ = json.Unmarshal(d.config, &params)
		_, err := s.createScan(ctx, ac, scanInput{
			AssetID: d.assetID, AuthorizationID: d.authID, Scanner: d.scannerName, Category: d.category,
			ProfileID: d.profileID, Params: params, ConfirmIntrusive: false, IdempotencyKey: "schedule:" + d.id + ":" + next.Format(time.RFC3339),
		}, "schedule")
		if err != nil {
			s.log.Warn("scheduled scan failed", "schedule", d.id, "error", err)
			s.notify(ctx, d.orgID, nil, "system", "Scheduled assessment skipped", "A scheduled scan could not start: "+err.Error(), "/integrations")
		}
	}
}

func (s *Server) systemActor(ctx context.Context, orgID, userID string) *AuthContext {
	if userID == "" {
		return nil
	}
	ac := &AuthContext{OrgID: orgID, UserID: userID, Permissions: map[string]bool{}}
	var perms []string
	err := s.db.QueryRow(ctx, `
		SELECT u.email, u.name, o.name, m.role_id,
		       COALESCE(array_agg(rp.permission_id) FILTER (WHERE rp.permission_id IS NOT NULL), '{}')
		FROM memberships m JOIN users u ON u.id=m.user_id JOIN organizations o ON o.id=m.org_id
		LEFT JOIN role_permissions rp ON rp.role_id=m.role_id
		WHERE m.org_id=$1 AND m.user_id=$2 GROUP BY u.id, o.id, m.role_id`, orgID, userID).
		Scan(&ac.Email, &ac.Name, &ac.OrgName, &ac.Role, &perms)
	if err != nil {
		return nil
	}
	for _, p := range perms {
		ac.Permissions[p] = true
	}
	return ac
}

// --- Integrations ---

func (s *Server) handleIntegrations(w http.ResponseWriter, r *http.Request) {
	ac := actor(r)
	heartbeats, _ := s.queue.Heartbeats(r.Context())
	availability := map[string]map[string]any{}
	var latest time.Time
	for _, hb := range heartbeats {
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
	scanners := []map[string]any{}
	for _, meta := range scanner.Catalog {
		status := "unavailable"
		detail := "No worker has reported this scanner."
		version := ""
		if online {
			if av, ok := availability[meta.Name]; ok {
				if v, _ := av["available"].(bool); v {
					status = "available"
					detail = "Detected by worker."
				} else {
					detail = "Required binary or service not found."
				}
				if v, _ := av["version"].(string); v != "" {
					version = v
				}
				if e, _ := av["error"].(string); e != "" {
					detail = e
				}
			}
		} else {
			status = "offline"
			detail = "No worker heartbeat in the last 90 seconds."
		}
		scanners = append(scanners, map[string]any{"name": meta.Name, "label": meta.Label, "category": meta.Category,
			"intrusive": meta.Intrusive, "status": status, "version": version, "detail": detail})
	}
	type conn struct {
		ID       string `json:"id"`
		Provider string `json:"provider"`
		Name     string `json:"name"`
		Status   string `json:"status"`
		Account  string `json:"account_id"`
	}
	var connections []conn
	rows, err := s.db.Query(r.Context(), `SELECT id::text, provider, name, status, account_id FROM cloud_connections WHERE org_id=$1`, ac.OrgID)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var c conn
			if rows.Scan(&c.ID, &c.Provider, &c.Name, &c.Status, &c.Account) == nil {
				connections = append(connections, c)
			}
		}
	}
	depth, _ := s.queue.QueueDepth(r.Context())
	writeJSON(w, http.StatusOK, map[string]any{
		"scanners": scanners, "workers": heartbeats, "worker_online": online,
		"queue_depth": depth, "cloud_connections": connections,
		"storage_driver": s.cfg.StorageDriver, "environment": s.cfg.Env,
	})
}
