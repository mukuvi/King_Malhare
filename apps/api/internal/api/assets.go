package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/kingmalhare/api/internal/scanner"
)

var assetTypes = map[string]bool{
	"website": true, "web_app": true, "api": true, "graphql_api": true, "ip": true,
	"network": true, "cloud": true, "server": true, "container": true, "internal": true,
}
var environments = map[string]bool{"production": true, "staging": true, "development": true, "lab": true, "internal": true}

type assetDTO struct {
	ID               string   `json:"id"`
	Name             string   `json:"name"`
	Type             string   `json:"type"`
	Target           string   `json:"target"`
	Description      string   `json:"description"`
	Environment      string   `json:"environment"`
	OwnerUserID      *string  `json:"owner_user_id,omitempty"`
	OwnerName        *string  `json:"owner_name,omitempty"`
	Tags             []string `json:"tags"`
	Status           string   `json:"status"`
	Metadata         any      `json:"metadata"`
	LastAssessedAt   *string  `json:"last_assessed_at,omitempty"`
	CreatedAt        string   `json:"created_at"`
	UpdatedAt        string   `json:"updated_at"`
	ActiveAuths      int      `json:"active_authorizations"`
	OpenFindings     int      `json:"open_findings"`
	CriticalFindings int      `json:"critical_findings"`
	HighFindings     int      `json:"high_findings"`
	ScanCount        int      `json:"scan_count"`
	PostureScore     int      `json:"posture_score"`
}

func (s *Server) handleListAssets(w http.ResponseWriter, r *http.Request) {
	ac := actor(r)
	pageNo, perPage := pagination(r)
	search := strings.TrimSpace(r.URL.Query().Get("search"))
	typ := r.URL.Query().Get("type")
	env := r.URL.Query().Get("environment")
	status := r.URL.Query().Get("status")
	if status == "" {
		status = "active"
	}
	if typ != "" && !assetTypes[typ] {
		s.writeValidation(w, "Unknown asset type.")
		return
	}
	if env != "" && !environments[env] {
		s.writeValidation(w, "Unknown environment.")
		return
	}
	sort := sortClause(r, map[string]string{
		"name": "a.name", "created_at": "a.created_at", "last_assessed_at": "a.last_assessed_at",
		"risk": "risk_units", "type": "a.type",
	}, "a.created_at desc")

	where := `a.org_id=$1 AND ($2='' OR a.status=$2) AND ($3='' OR a.type=$3) AND ($4='' OR a.environment=$4)
		AND ($5='' OR a.name ILIKE '%'||$5||'%' OR a.target ILIKE '%'||$5||'%')`
	var total int
	if err := s.db.QueryRow(r.Context(), `SELECT count(*) FROM assets a WHERE `+where, ac.OrgID, status, typ, env, search).Scan(&total); err != nil {
		s.dbError(w, err, "assets")
		return
	}
	query := `
		SELECT a.id::text, a.name, a.type, a.target, a.description, a.environment, a.owner_user_id::text, u.name,
		       a.tags, a.status, a.metadata, a.last_assessed_at, a.created_at, a.updated_at,
		       (SELECT count(*) FROM authorizations au WHERE au.asset_id=a.id AND au.status='active' AND au.expires_at>now()),
		       (SELECT count(*) FROM findings f WHERE f.asset_id=a.id AND f.status NOT IN ('fixed','false_positive','accepted_risk')),
		       (SELECT count(*) FROM findings f WHERE f.asset_id=a.id AND f.severity='critical' AND f.status NOT IN ('fixed','false_positive','accepted_risk')),
		       (SELECT count(*) FROM findings f WHERE f.asset_id=a.id AND f.severity='high' AND f.status NOT IN ('fixed','false_positive','accepted_risk')),
		       (SELECT count(*) FROM scans sc WHERE sc.asset_id=a.id),
		       COALESCE((SELECT sum(CASE f.severity WHEN 'critical' THEN 12 WHEN 'high' THEN 6 WHEN 'medium' THEN 3 WHEN 'low' THEN 1 ELSE 0.2 END)
		                 FROM findings f WHERE f.asset_id=a.id AND f.status NOT IN ('fixed','false_positive','accepted_risk')),0) AS risk_units
		FROM assets a LEFT JOIN users u ON u.id=a.owner_user_id
		WHERE ` + where + ` ORDER BY ` + sort + ` LIMIT $6 OFFSET $7`
	rows, err := s.db.Query(r.Context(), query, ac.OrgID, status, typ, env, search, perPage, (pageNo-1)*perPage)
	if err != nil {
		s.dbError(w, err, "assets")
		return
	}
	defer rows.Close()
	items := []assetDTO{}
	for rows.Next() {
		a, risk, err := scanAssetRow(rows)
		if err != nil {
			s.dbError(w, err, "asset")
			return
		}
		a.PostureScore = assetScore(risk)
		items = append(items, a)
	}
	writeJSON(w, http.StatusOK, page{Items: items, Page: pageNo, PerPage: perPage, Total: total})
}

func scanAssetRow(rows interface {
	Scan(dest ...any) error
}) (assetDTO, float64, error) {
	var a assetDTO
	var ownerID, ownerName *string
	var lastAssessed *time.Time
	var created, updated time.Time
	var metadata []byte
	var risk float64
	err := rows.Scan(&a.ID, &a.Name, &a.Type, &a.Target, &a.Description, &a.Environment, &ownerID, &ownerName,
		&a.Tags, &a.Status, &metadata, &lastAssessed, &created, &updated,
		&a.ActiveAuths, &a.OpenFindings, &a.CriticalFindings, &a.HighFindings, &a.ScanCount, &risk)
	if err != nil {
		return a, 0, err
	}
	if ownerID != nil && *ownerID != "" {
		a.OwnerUserID = ownerID
		a.OwnerName = ownerName
	}
	if lastAssessed != nil {
		v := lastAssessed.UTC().Format(time.RFC3339)
		a.LastAssessedAt = &v
	}
	a.CreatedAt = created.UTC().Format(time.RFC3339)
	a.UpdatedAt = updated.UTC().Format(time.RFC3339)
	a.Metadata = json.RawMessage(metadata)
	if len(metadata) == 0 {
		a.Metadata = map[string]any{}
	}
	if a.Tags == nil {
		a.Tags = []string{}
	}
	return a, risk, nil
}

func assetScore(risk float64) int {
	score := 100 - risk
	if score < 0 {
		return 0
	}
	return int(score)
}

type createAssetRequest struct {
	Name        string         `json:"name"`
	Type        string         `json:"type"`
	Target      string         `json:"target"`
	Description string         `json:"description"`
	Environment string         `json:"environment"`
	OwnerUserID *string        `json:"owner_user_id"`
	Tags        []string       `json:"tags"`
	Metadata    map[string]any `json:"metadata"`
}

func (s *Server) handleCreateAsset(w http.ResponseWriter, r *http.Request) {
	var req createAssetRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	ac := actor(r)
	req.Name = strings.TrimSpace(req.Name)
	req.Target = strings.TrimSpace(req.Target)
	req.Description = strings.TrimSpace(req.Description)
	if len(req.Name) < 2 || len(req.Name) > 160 {
		s.writeValidation(w, "Asset name must be between 2 and 160 characters.")
		return
	}
	if !assetTypes[req.Type] {
		s.writeValidation(w, "Choose a valid asset type.")
		return
	}
	if req.Environment == "" {
		req.Environment = "production"
	}
	if !environments[req.Environment] {
		s.writeValidation(w, "Choose a valid environment.")
		return
	}
	normalized, err := scanner.NormalizeTarget(req.Type, req.Target)
	if err != nil {
		s.writeValidation(w, "Target is not valid for this asset type: "+err.Error())
		return
	}
	tags, err := cleanTags(req.Tags)
	if err != nil {
		s.writeValidation(w, err.Error())
		return
	}
	meta := req.Metadata
	if meta == nil {
		meta = map[string]any{}
	}
	metaBody, _ := json.Marshal(meta)
	if len(metaBody) > 4096 {
		s.writeValidation(w, "Metadata must be smaller than 4 KB.")
		return
	}
	ownerID := ac.UserID
	if req.OwnerUserID != nil && *req.OwnerUserID != "" {
		var exists bool
		if err := s.db.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM memberships WHERE org_id=$1 AND user_id=$2)`, ac.OrgID, *req.OwnerUserID).Scan(&exists); err != nil || !exists {
			s.writeValidation(w, "Owner must be a member of this organization.")
			return
		}
		ownerID = *req.OwnerUserID
	}
	var assetID string
	err = s.db.QueryRow(r.Context(), `
		INSERT INTO assets (org_id, name, type, target, description, environment, owner_user_id, tags, metadata, created_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING id::text`,
		ac.OrgID, req.Name, req.Type, normalized, req.Description, req.Environment, ownerID, tags, metaBody, ac.UserID).Scan(&assetID)
	if err != nil {
		if strings.Contains(err.Error(), "assets_org_id_target_key") {
			writeError(w, http.StatusConflict, "asset_exists", "An asset with this target already exists in the organization.", nil)
			return
		}
		s.dbError(w, err, "asset")
		return
	}
	_, _ = s.db.Exec(r.Context(), `INSERT INTO asset_ownerships (asset_id, user_id, relationship) VALUES ($1,$2,'owner')`, assetID, ownerID)
	s.audit(r, "asset.created", "asset", assetID, map[string]any{"name": req.Name, "target": normalized, "type": req.Type})
	writeJSON(w, http.StatusCreated, map[string]any{"id": assetID, "target": normalized})
}

func cleanTags(tags []string) ([]string, error) {
	if len(tags) > 20 {
		return nil, fmt.Errorf("at most 20 tags are allowed")
	}
	out := make([]string, 0, len(tags))
	seen := map[string]bool{}
	re := regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._:\-]{0,31}$`)
	for _, tag := range tags {
		tag = strings.TrimSpace(tag)
		if tag == "" {
			continue
		}
		if !re.MatchString(tag) {
			return nil, fmt.Errorf("tag %q is invalid (letters, numbers, dot, colon, dash; max 32 chars)", tag)
		}
		if !seen[tag] {
			seen[tag] = true
			out = append(out, tag)
		}
	}
	return out, nil
}

func (s *Server) loadAsset(ctx context.Context, orgID, assetID string) (assetDTO, error) {
	row := s.db.QueryRow(ctx, `
		SELECT a.id::text, a.name, a.type, a.target, a.description, a.environment, a.owner_user_id::text, u.name,
		       a.tags, a.status, a.metadata, a.last_assessed_at, a.created_at, a.updated_at,
		       (SELECT count(*) FROM authorizations au WHERE au.asset_id=a.id AND au.status='active' AND au.expires_at>now()),
		       (SELECT count(*) FROM findings f WHERE f.asset_id=a.id AND f.status NOT IN ('fixed','false_positive','accepted_risk')),
		       (SELECT count(*) FROM findings f WHERE f.asset_id=a.id AND f.severity='critical' AND f.status NOT IN ('fixed','false_positive','accepted_risk')),
		       (SELECT count(*) FROM findings f WHERE f.asset_id=a.id AND f.severity='high' AND f.status NOT IN ('fixed','false_positive','accepted_risk')),
		       (SELECT count(*) FROM scans sc WHERE sc.asset_id=a.id),
		       COALESCE((SELECT sum(CASE f.severity WHEN 'critical' THEN 12 WHEN 'high' THEN 6 WHEN 'medium' THEN 3 WHEN 'low' THEN 1 ELSE 0.2 END)
		                 FROM findings f WHERE f.asset_id=a.id AND f.status NOT IN ('fixed','false_positive','accepted_risk')),0)
		FROM assets a LEFT JOIN users u ON u.id=a.owner_user_id
		WHERE a.org_id=$1 AND a.id=$2`, orgID, assetID)
	a, risk, err := scanAssetRow(row)
	if err != nil {
		return a, err
	}
	a.PostureScore = assetScore(risk)
	return a, nil
}

type assetDetail struct {
	assetDTO
	Owners []map[string]any `json:"owners"`
}

func (s *Server) handleGetAsset(w http.ResponseWriter, r *http.Request) {
	ac := actor(r)
	assetID := chiURLParam(r, "assetID")
	if !validUUID(assetID) {
		writeError(w, http.StatusBadRequest, "invalid_id", "Invalid asset id.", nil)
		return
	}
	a, err := s.loadAsset(r.Context(), ac.OrgID, assetID)
	if isNotFound(err) {
		writeError(w, http.StatusNotFound, "not_found", "Asset not found.", nil)
		return
	}
	if err != nil {
		s.dbError(w, err, "asset")
		return
	}
	detail := assetDetail{assetDTO: a, Owners: []map[string]any{}}
	rows, err := s.db.Query(r.Context(), `
		SELECT ao.id::text, ao.user_id::text, u.name, u.email, ao.contact, ao.relationship
		FROM asset_ownerships ao LEFT JOIN users u ON u.id=ao.user_id
		WHERE ao.asset_id=$1 ORDER BY ao.created_at`, assetID)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var id string
			var uid, name, email *string
			var contact, rel string
			if rows.Scan(&id, &uid, &name, &email, &contact, &rel) == nil {
				detail.Owners = append(detail.Owners, map[string]any{
					"id": id, "user_id": uid, "name": name, "email": email, "contact": contact, "relationship": rel,
				})
			}
		}
	}
	writeJSON(w, http.StatusOK, detail)
}

type updateAssetRequest struct {
	Name        *string   `json:"name"`
	Description *string   `json:"description"`
	Environment *string   `json:"environment"`
	OwnerUserID *string   `json:"owner_user_id"`
	Tags        *[]string `json:"tags"`
	Status      *string   `json:"status"`
	Target      *string   `json:"target"`
}

func (s *Server) handleUpdateAsset(w http.ResponseWriter, r *http.Request) {
	var req updateAssetRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	ac := actor(r)
	assetID := chiURLParam(r, "assetID")
	if !validUUID(assetID) {
		writeError(w, http.StatusBadRequest, "invalid_id", "Invalid asset id.", nil)
		return
	}
	a, err := s.loadAsset(r.Context(), ac.OrgID, assetID)
	if isNotFound(err) {
		writeError(w, http.StatusNotFound, "not_found", "Asset not found.", nil)
		return
	}
	if err != nil {
		s.dbError(w, err, "asset")
		return
	}
	if req.Name != nil {
		name := strings.TrimSpace(*req.Name)
		if len(name) < 2 || len(name) > 160 {
			s.writeValidation(w, "Asset name must be between 2 and 160 characters.")
			return
		}
		if _, err := s.db.Exec(r.Context(), `UPDATE assets SET name=$1 WHERE id=$2 AND org_id=$3`, name, assetID, ac.OrgID); err != nil {
			s.dbError(w, err, "asset")
			return
		}
	}
	if req.Description != nil {
		desc := strings.TrimSpace(*req.Description)
		if len(desc) > 4000 {
			s.writeValidation(w, "Description is too long.")
			return
		}
		_, _ = s.db.Exec(r.Context(), `UPDATE assets SET description=$1 WHERE id=$2 AND org_id=$3`, desc, assetID, ac.OrgID)
	}
	if req.Environment != nil {
		if !environments[*req.Environment] {
			s.writeValidation(w, "Unknown environment.")
			return
		}
		_, _ = s.db.Exec(r.Context(), `UPDATE assets SET environment=$1 WHERE id=$2 AND org_id=$3`, *req.Environment, assetID, ac.OrgID)
	}
	if req.OwnerUserID != nil {
		var exists bool
		_ = s.db.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM memberships WHERE org_id=$1 AND user_id=$2)`, ac.OrgID, *req.OwnerUserID).Scan(&exists)
		if !exists {
			s.writeValidation(w, "Owner must be a member of this organization.")
			return
		}
		_, _ = s.db.Exec(r.Context(), `UPDATE assets SET owner_user_id=$1 WHERE id=$2 AND org_id=$3`, *req.OwnerUserID, assetID, ac.OrgID)
	}
	if req.Tags != nil {
		tags, err := cleanTags(*req.Tags)
		if err != nil {
			s.writeValidation(w, err.Error())
			return
		}
		_, _ = s.db.Exec(r.Context(), `UPDATE assets SET tags=$1 WHERE id=$2 AND org_id=$3`, tags, assetID, ac.OrgID)
	}
	if req.Status != nil {
		if *req.Status != "active" && *req.Status != "archived" {
			s.writeValidation(w, "Status must be active or archived.")
			return
		}
		_, _ = s.db.Exec(r.Context(), `UPDATE assets SET status=$1 WHERE id=$2 AND org_id=$3`, *req.Status, assetID, ac.OrgID)
	}
	if req.Target != nil && *req.Target != a.Target {
		normalized, err := scanner.NormalizeTarget(a.Type, *req.Target)
		if err != nil {
			s.writeValidation(w, "Target is not valid: "+err.Error())
			return
		}
		_, err = s.db.Exec(r.Context(), `UPDATE assets SET target=$1 WHERE id=$2 AND org_id=$3`, normalized, assetID, ac.OrgID)
		if err != nil {
			if strings.Contains(err.Error(), "assets_org_id_target_key") {
				writeError(w, http.StatusConflict, "asset_exists", "Another asset already uses this target.", nil)
				return
			}
			s.dbError(w, err, "asset")
			return
		}
	}
	s.audit(r, "asset.updated", "asset", assetID, nil)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleArchiveAsset(w http.ResponseWriter, r *http.Request) {
	ac := actor(r)
	assetID := chiURLParam(r, "assetID")
	if _, err := s.db.Exec(r.Context(), `UPDATE assets SET status='archived' WHERE id=$1 AND org_id=$2`, assetID, ac.OrgID); err != nil {
		s.dbError(w, err, "asset")
		return
	}
	s.audit(r, "asset.archived", "asset", assetID, nil)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

type authorizationDTO struct {
	ID               string  `json:"id"`
	AssetID          string  `json:"asset_id"`
	Reference        string  `json:"reference"`
	ApprovedByName   string  `json:"approved_by_name"`
	ApprovedByEmail  string  `json:"approved_by_email"`
	ScopeNotes       string  `json:"scope_notes"`
	IntrusiveAllowed bool    `json:"intrusive_allowed"`
	AllowPrivate     bool    `json:"allow_private"`
	Status           string  `json:"status"`
	EffectiveStatus  string  `json:"effective_status"`
	ValidFrom        string  `json:"valid_from"`
	ExpiresAt        string  `json:"expires_at"`
	CreatedAt        string  `json:"created_at"`
	CreatedBy        *string `json:"created_by,omitempty"`
	CreatedByName    *string `json:"created_by_name,omitempty"`
}

func (s *Server) handleListAuthorizations(w http.ResponseWriter, r *http.Request) {
	ac := actor(r)
	assetID := chiURLParam(r, "assetID")
	rows, err := s.db.Query(r.Context(), `
		SELECT a.id::text, a.asset_id::text, a.reference, a.approved_by_name, a.approved_by_email, a.scope_notes,
		       a.intrusive_allowed, a.allow_private, a.status, a.valid_from, a.expires_at, a.created_at,
		       a.created_by::text, u.name,
		       CASE WHEN a.status='revoked' THEN 'revoked' WHEN a.expires_at <= now() THEN 'expired' WHEN a.valid_from > now() THEN 'scheduled' ELSE 'active' END
		FROM authorizations a LEFT JOIN users u ON u.id=a.created_by
		WHERE a.org_id=$1 AND a.asset_id=$2 ORDER BY a.created_at DESC`, ac.OrgID, assetID)
	if err != nil {
		s.dbError(w, err, "authorizations")
		return
	}
	defer rows.Close()
	out := []authorizationDTO{}
	for rows.Next() {
		var a authorizationDTO
		var validFrom, expires, created time.Time
		var createdBy, createdName *string
		if err := rows.Scan(&a.ID, &a.AssetID, &a.Reference, &a.ApprovedByName, &a.ApprovedByEmail, &a.ScopeNotes,
			&a.IntrusiveAllowed, &a.AllowPrivate, &a.Status, &validFrom, &expires, &created, &createdBy, &createdName, &a.EffectiveStatus); err != nil {
			s.dbError(w, err, "authorization")
			return
		}
		a.ValidFrom = validFrom.UTC().Format(time.RFC3339)
		a.ExpiresAt = expires.UTC().Format(time.RFC3339)
		a.CreatedAt = created.UTC().Format(time.RFC3339)
		a.CreatedBy = createdBy
		a.CreatedByName = createdName
		out = append(out, a)
	}
	writeJSON(w, http.StatusOK, out)
}

type createAuthorizationRequest struct {
	Reference        string `json:"reference"`
	ApprovedByName   string `json:"approved_by_name"`
	ApprovedByEmail  string `json:"approved_by_email"`
	ScopeNotes       string `json:"scope_notes"`
	IntrusiveAllowed bool   `json:"intrusive_allowed"`
	AllowPrivate     bool   `json:"allow_private"`
	ValidFrom        string `json:"valid_from"`
	ExpiresAt        string `json:"expires_at"`
}

func (s *Server) handleCreateAuthorization(w http.ResponseWriter, r *http.Request) {
	var req createAuthorizationRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	ac := actor(r)
	assetID := chiURLParam(r, "assetID")
	asset, err := s.loadAsset(r.Context(), ac.OrgID, assetID)
	if isNotFound(err) {
		writeError(w, http.StatusNotFound, "not_found", "Asset not found.", nil)
		return
	}
	if err != nil {
		s.dbError(w, err, "asset")
		return
	}
	req.Reference = strings.TrimSpace(req.Reference)
	req.ApprovedByName = strings.TrimSpace(req.ApprovedByName)
	if len(req.Reference) < 3 || len(req.Reference) > 240 || len(req.ApprovedByName) < 2 {
		s.writeValidation(w, "Provide an authorization reference and the approving person's name.")
		return
	}
	if req.ApprovedByEmail != "" && !validEmailLoose(req.ApprovedByEmail) {
		s.writeValidation(w, "Approver email is not valid.")
		return
	}
	validFrom := time.Now()
	if req.ValidFrom != "" {
		t, err := time.Parse(time.RFC3339, req.ValidFrom)
		if err != nil {
			s.writeValidation(w, "valid_from must be an RFC 3339 timestamp.")
			return
		}
		validFrom = t
	}
	expires, err := time.Parse(time.RFC3339, req.ExpiresAt)
	if err != nil {
		s.writeValidation(w, "expires_at must be an RFC 3339 timestamp.")
		return
	}
	now := time.Now()
	if !expires.After(now) {
		s.writeValidation(w, "Authorization expiry must be in the future.")
		return
	}
	if expires.After(now.AddDate(2, 0, 0)) {
		s.writeValidation(w, "Authorization duration cannot exceed two years.")
		return
	}
	if !validFrom.Before(expires) {
		s.writeValidation(w, "Authorization start must be before expiry.")
		return
	}
	if req.AllowPrivate && asset.Environment == "production" {
		// Allowed, but explicit: the operator is authorizing internal testing of a production asset.
		s.log.Warn("private-range authorization created for production asset", "asset_id", assetID, "org_id", ac.OrgID)
	}
	var id string
	err = s.db.QueryRow(r.Context(), `
		INSERT INTO authorizations (org_id, asset_id, reference, approved_by_name, approved_by_email, scope_notes,
			intrusive_allowed, allow_private, valid_from, expires_at, created_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING id::text`,
		ac.OrgID, assetID, req.Reference, req.ApprovedByName, strings.TrimSpace(req.ApprovedByEmail), strings.TrimSpace(req.ScopeNotes),
		req.IntrusiveAllowed, req.AllowPrivate, validFrom, expires, ac.UserID).Scan(&id)
	if err != nil {
		s.dbError(w, err, "authorization")
		return
	}
	s.audit(r, "authorization.created", "authorization", id, map[string]any{
		"asset_id": assetID, "expires_at": expires.UTC().Format(time.RFC3339), "intrusive": req.IntrusiveAllowed, "private": req.AllowPrivate,
	})
	s.notify(r.Context(), ac.OrgID, nil, "authorization", "Authorization recorded", "Scope approval for "+asset.Name+" is valid until "+expires.UTC().Format("2 Jan 2006")+".", "/assets/"+assetID)
	writeJSON(w, http.StatusCreated, map[string]any{"id": id})
}

type revokeAuthorizationRequest struct {
	Status string `json:"status"`
	Reason string `json:"reason"`
}

func (s *Server) handleRevokeAuthorization(w http.ResponseWriter, r *http.Request) {
	var req revokeAuthorizationRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Status != "revoked" {
		s.writeValidation(w, "Only revocation is supported.")
		return
	}
	ac := actor(r)
	id := chiURLParam(r, "authorizationID")
	tag, err := s.db.Exec(r.Context(), `
		UPDATE authorizations SET status='revoked', revoked_at=now(), revoked_by=$1
		WHERE id=$2 AND org_id=$3 AND status='active'`, ac.UserID, id, ac.OrgID)
	if err != nil {
		s.dbError(w, err, "authorization")
		return
	}
	if tag.RowsAffected() == 0 {
		writeError(w, http.StatusNotFound, "not_found", "Active authorization not found.", nil)
		return
	}
	// Revocation is immediate: queued scans are cancelled and running workers are
	// told to stop via the cancellation key.
	rows, err := s.db.Query(r.Context(), `
		UPDATE scans SET status='cancelled', cancel_requested=true, finished_at=now(), error='Authorization revoked'
		WHERE org_id=$1 AND authorization_id=$2 AND status IN ('pending','queued','initializing','running')
		RETURNING id::text`, ac.OrgID, id)
	if err == nil {
		ids := []string{}
		for rows.Next() {
			var scanID string
			if rows.Scan(&scanID) == nil {
				ids = append(ids, scanID)
			}
		}
		rows.Close()
		for _, scanID := range ids {
			_ = s.queue.SetCancel(r.Context(), scanID)
			s.queue.Publish(r.Context(), scanner.Event{Type: "status", ScanID: scanID, Status: "cancelled", Message: "Authorization revoked", At: time.Now().UTC()})
		}
	}
	s.audit(r, "authorization.revoked", "authorization", id, map[string]any{"reason": truncate(req.Reason, 500)})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleAssetScans(w http.ResponseWriter, r *http.Request) {
	ac := actor(r)
	assetID := chiURLParam(r, "assetID")
	pageNo, perPage := pagination(r)
	rows, err := s.db.Query(r.Context(), `
		SELECT id::text, category, scanner, status, progress, phase, target_snapshot, created_at, started_at, finished_at, error
		FROM scans WHERE org_id=$1 AND asset_id=$2 ORDER BY created_at DESC LIMIT $3 OFFSET $4`,
		ac.OrgID, assetID, perPage, (pageNo-1)*perPage)
	if err != nil {
		s.dbError(w, err, "scans")
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var id, category, sc, status, phase, target string
		var progress int
		var created time.Time
		var started, finished *time.Time
		var scanErr *string
		if err := rows.Scan(&id, &category, &sc, &status, &progress, &phase, &target, &created, &started, &finished, &scanErr); err != nil {
			s.dbError(w, err, "scan")
			return
		}
		item := map[string]any{"id": id, "category": category, "scanner": sc, "status": status, "progress": progress,
			"phase": phase, "target": target, "created_at": created.UTC().Format(time.RFC3339), "error": scanErr}
		if started != nil {
			item["started_at"] = started.UTC().Format(time.RFC3339)
		}
		if finished != nil {
			item["finished_at"] = finished.UTC().Format(time.RFC3339)
		}
		items = append(items, item)
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) handleAssetFindings(w http.ResponseWriter, r *http.Request) {
	ac := actor(r)
	assetID := chiURLParam(r, "assetID")
	pageNo, perPage := pagination(r)
	rows, err := s.db.Query(r.Context(), `
		SELECT id::text, title, severity, status, endpoint, cve, cwe, cvss, first_seen, last_seen
		FROM findings WHERE org_id=$1 AND asset_id=$2 ORDER BY
		CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END,
		last_seen DESC LIMIT $3 OFFSET $4`, ac.OrgID, assetID, perPage, (pageNo-1)*perPage)
	if err != nil {
		s.dbError(w, err, "findings")
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var id, title, severity, status, endpoint string
		var cve, cwe *string
		var cvss *float64
		var first, last time.Time
		if err := rows.Scan(&id, &title, &severity, &status, &endpoint, &cve, &cwe, &cvss, &first, &last); err != nil {
			s.dbError(w, err, "finding")
			return
		}
		items = append(items, map[string]any{"id": id, "title": title, "severity": severity, "status": status,
			"endpoint": endpoint, "cve": cve, "cwe": cwe, "cvss": cvss,
			"first_seen": first.UTC().Format(time.RFC3339), "last_seen": last.UTC().Format(time.RFC3339)})
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func validEmailLoose(s string) bool {
	return strings.Contains(s, "@") && !strings.ContainsAny(s, " \n\r\t")
}
