package api

import (
	"context"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/kingmalhare/api/internal/security"
)

type orgDetail struct {
	orgDTO
	MemberCount int `json:"member_count"`
	AssetCount  int `json:"asset_count"`
}

func (s *Server) handleGetOrg(w http.ResponseWriter, r *http.Request) {
	ac := actor(r)
	var o orgDetail
	var created time.Time
	err := s.db.QueryRow(r.Context(), `SELECT id::text, name, slug, emergency_stop, retention_days, created_at FROM organizations WHERE id=$1`, ac.OrgID).
		Scan(&o.ID, &o.Name, &o.Slug, &o.EmergencyStop, &o.RetentionDays, &created)
	if err != nil {
		s.dbError(w, err, "organization")
		return
	}
	o.CreatedAt = created.UTC().Format(time.RFC3339)
	_ = s.db.QueryRow(r.Context(), `SELECT count(*) FROM memberships WHERE org_id=$1`, ac.OrgID).Scan(&o.MemberCount)
	_ = s.db.QueryRow(r.Context(), `SELECT count(*) FROM assets WHERE org_id=$1 AND status='active'`, ac.OrgID).Scan(&o.AssetCount)
	writeJSON(w, http.StatusOK, o)
}

type updateOrgRequest struct {
	Name          *string `json:"name"`
	RetentionDays *int    `json:"retention_days"`
}

func (s *Server) handleUpdateOrg(w http.ResponseWriter, r *http.Request) {
	var req updateOrgRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	ac := actor(r)
	if req.Name == nil && req.RetentionDays == nil {
		s.writeValidation(w, "Provide at least one field to update.")
		return
	}
	if req.Name != nil {
		name := strings.TrimSpace(*req.Name)
		if utf8.RuneCountInString(name) < 2 || len(name) > 120 {
			s.writeValidation(w, "Organization name must be between 2 and 120 characters.")
			return
		}
		if _, err := s.db.Exec(r.Context(), `UPDATE organizations SET name=$1 WHERE id=$2`, name, ac.OrgID); err != nil {
			s.dbError(w, err, "organization")
			return
		}
	}
	if req.RetentionDays != nil {
		days := *req.RetentionDays
		if days < 30 || days > 3650 {
			s.writeValidation(w, "Retention must be between 30 and 3650 days.")
			return
		}
		if _, err := s.db.Exec(r.Context(), `UPDATE organizations SET retention_days=$1 WHERE id=$2`, days, ac.OrgID); err != nil {
			s.dbError(w, err, "organization")
			return
		}
	}
	s.audit(r, "org.updated", "organization", ac.OrgID, nil)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

type memberDTO struct {
	UserID       string  `json:"user_id"`
	Name         string  `json:"name"`
	Email        string  `json:"email"`
	Role         string  `json:"role"`
	RoleName     string  `json:"role_name"`
	AvatarColor  string  `json:"avatar_color"`
	IsActive     bool    `json:"is_active"`
	LastLoginAt  *string `json:"last_login_at,omitempty"`
	JoinedAt     string  `json:"joined_at"`
	OpenFindings int     `json:"open_findings"`
}

func (s *Server) handleListMembers(w http.ResponseWriter, r *http.Request) {
	ac := actor(r)
	rows, err := s.db.Query(r.Context(), `
		SELECT u.id::text, u.name, u.email, m.role_id, ro.name, u.avatar_color, u.is_active, u.last_login_at, m.created_at,
		       (SELECT count(*) FROM findings f WHERE f.org_id=$1 AND f.assigned_to=u.id AND f.status NOT IN ('fixed','false_positive','accepted_risk'))
		FROM memberships m
		JOIN users u ON u.id=m.user_id
		JOIN roles ro ON ro.id=m.role_id
		WHERE m.org_id=$1
		ORDER BY ro.rank DESC, u.name ASC`, ac.OrgID)
	if err != nil {
		s.dbError(w, err, "members")
		return
	}
	defer rows.Close()
	out := []memberDTO{}
	for rows.Next() {
		var m memberDTO
		var lastLogin *time.Time
		var joined time.Time
		if err := rows.Scan(&m.UserID, &m.Name, &m.Email, &m.Role, &m.RoleName, &m.AvatarColor, &m.IsActive, &lastLogin, &joined, &m.OpenFindings); err != nil {
			s.dbError(w, err, "members")
			return
		}
		if lastLogin != nil {
			v := lastLogin.UTC().Format(time.RFC3339)
			m.LastLoginAt = &v
		}
		m.JoinedAt = joined.UTC().Format(time.RFC3339)
		out = append(out, m)
	}
	writeJSON(w, http.StatusOK, out)
}

type createMemberRequest struct {
	Name   string `json:"name"`
	Email  string `json:"email"`
	RoleID string `json:"role_id"`
}

func (s *Server) handleCreateMember(w http.ResponseWriter, r *http.Request) {
	var req createMemberRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	ac := actor(r)
	req.Email = strings.ToLower(strings.TrimSpace(req.Email))
	req.Name = strings.TrimSpace(req.Name)
	req.RoleID = strings.TrimSpace(req.RoleID)
	if !security.ValidEmail(req.Email) || len(req.Name) < 2 {
		s.writeValidation(w, "Provide a valid name and email address.")
		return
	}
	if req.RoleID == "" {
		req.RoleID = "analyst"
	}
	if req.RoleID == "owner" {
		s.writeValidation(w, "Ownership transfer is not available through member invitations.")
		return
	}
	if !s.canAssignRole(r, ac.Role, req.RoleID) {
		writeError(w, http.StatusForbidden, "role_too_high", "You cannot grant a role at or above your own level.", nil)
		return
	}
	var userID string
	var created bool
	var tempPassword string
	err := s.db.QueryRow(r.Context(), `SELECT id::text FROM users WHERE lower(email)=lower($1)`, req.Email).Scan(&userID)
	if isNotFound(err) {
		tempPassword = "Km1!" + mustToken(16)
		hash, herr := security.HashPassword(tempPassword)
		if herr != nil {
			writeError(w, http.StatusInternalServerError, "hash_failed", "Could not create the member.", nil)
			return
		}
		err = s.db.QueryRow(r.Context(), `
			INSERT INTO users (email, name, password_hash) VALUES ($1,$2,$3) RETURNING id::text`,
			req.Email, req.Name, hash).Scan(&userID)
		if err != nil {
			s.dbError(w, err, "user")
			return
		}
		created = true
	} else if err != nil {
		s.dbError(w, err, "user")
		return
	}
	var count int
	_ = s.db.QueryRow(r.Context(), `SELECT count(*) FROM memberships WHERE org_id=$1 AND user_id=$2`, ac.OrgID, userID).Scan(&count)
	if count > 0 {
		writeError(w, http.StatusConflict, "already_member", "This person is already a member of the organization.", nil)
		return
	}
	if _, err := s.db.Exec(r.Context(), `INSERT INTO memberships (org_id,user_id,role_id) VALUES ($1,$2,$3)`, ac.OrgID, userID, req.RoleID); err != nil {
		s.dbError(w, err, "membership")
		return
	}
	s.audit(r, "member.added", "user", userID, map[string]any{"role": req.RoleID, "email": req.Email, "invited": created})
	s.notify(r.Context(), ac.OrgID, nil, "system", "New team member", req.Name+" joined as "+req.RoleID+".", "/settings")
	var orgName string
	_ = s.db.QueryRow(r.Context(), `SELECT name FROM organizations WHERE id=$1`, ac.OrgID).Scan(&orgName)
	s.notifyPlatformAdmins(r.Context(), ac.UserID, "Member added", req.Email+" was added to "+orgName+" as "+req.RoleID+".", "/platform?tab=users")
	resp := map[string]any{"user_id": userID, "created": created}
	if created {
		resp["temporary_password"] = tempPassword
	}
	writeJSON(w, http.StatusCreated, resp)
}

type updateMemberRequest struct {
	RoleID string `json:"role_id"`
}

func (s *Server) handleUpdateMember(w http.ResponseWriter, r *http.Request) {
	var req updateMemberRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	ac := actor(r)
	targetID := chiURLParam(r, "userID")
	if !validUUID(targetID) {
		writeError(w, http.StatusBadRequest, "invalid_id", "Invalid member id.", nil)
		return
	}
	if targetID == ac.UserID {
		s.writeValidation(w, "You cannot change your own role.")
		return
	}
	var currentRole string
	err := s.db.QueryRow(r.Context(), `SELECT role_id FROM memberships WHERE org_id=$1 AND user_id=$2`, ac.OrgID, targetID).Scan(&currentRole)
	if isNotFound(err) {
		writeError(w, http.StatusNotFound, "not_found", "Member not found.", nil)
		return
	}
	if err != nil {
		s.dbError(w, err, "member")
		return
	}
	if currentRole == "owner" || req.RoleID == "owner" {
		s.writeValidation(w, "The owner role cannot be changed through this endpoint.")
		return
	}
	if !validRole(req.RoleID) {
		s.writeValidation(w, "Unknown role.")
		return
	}
	if !s.outranks(r.Context(), ac.Role, currentRole) || !s.canAssignRole(r, ac.Role, req.RoleID) {
		writeError(w, http.StatusForbidden, "role_too_high", "You cannot modify a member at or above your own level.", nil)
		return
	}
	if _, err := s.db.Exec(r.Context(), `UPDATE memberships SET role_id=$1 WHERE org_id=$2 AND user_id=$3`, req.RoleID, ac.OrgID, targetID); err != nil {
		s.dbError(w, err, "member")
		return
	}
	s.audit(r, "member.role_changed", "user", targetID, map[string]any{"from": currentRole, "to": req.RoleID})
	var email, orgName string
	_ = s.db.QueryRow(r.Context(), `SELECT email FROM users WHERE id=$1`, targetID).Scan(&email)
	_ = s.db.QueryRow(r.Context(), `SELECT name FROM organizations WHERE id=$1`, ac.OrgID).Scan(&orgName)
	s.notifyPlatformAdmins(r.Context(), ac.UserID, "Member role changed", email+" changed from "+currentRole+" to "+req.RoleID+" in "+orgName+".", "/platform?tab=users")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleRemoveMember(w http.ResponseWriter, r *http.Request) {
	ac := actor(r)
	targetID := chiURLParam(r, "userID")
	if targetID == ac.UserID {
		s.writeValidation(w, "You cannot remove yourself from the organization.")
		return
	}
	var currentRole string
	err := s.db.QueryRow(r.Context(), `SELECT role_id FROM memberships WHERE org_id=$1 AND user_id=$2`, ac.OrgID, targetID).Scan(&currentRole)
	if isNotFound(err) {
		writeError(w, http.StatusNotFound, "not_found", "Member not found.", nil)
		return
	}
	if err != nil {
		s.dbError(w, err, "member")
		return
	}
	if currentRole == "owner" || !s.outranks(r.Context(), ac.Role, currentRole) {
		writeError(w, http.StatusForbidden, "role_too_high", "You cannot remove this member.", nil)
		return
	}
	if _, err := s.db.Exec(r.Context(), `DELETE FROM memberships WHERE org_id=$1 AND user_id=$2`, ac.OrgID, targetID); err != nil {
		s.dbError(w, err, "member")
		return
	}
	s.audit(r, "member.removed", "user", targetID, nil)
	var email, orgName string
	_ = s.db.QueryRow(r.Context(), `SELECT email FROM users WHERE id=$1`, targetID).Scan(&email)
	_ = s.db.QueryRow(r.Context(), `SELECT name FROM organizations WHERE id=$1`, ac.OrgID).Scan(&orgName)
	s.notifyPlatformAdmins(r.Context(), ac.UserID, "Member removed", email+" was removed from "+orgName+".", "/platform?tab=users")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) canAssignRole(r *http.Request, actorRole, targetRole string) bool {
	if !validRole(targetRole) {
		return false
	}
	var actorRank, targetRank int
	_ = s.db.QueryRow(r.Context(), `SELECT rank FROM roles WHERE id=$1`, actorRole).Scan(&actorRank)
	_ = s.db.QueryRow(r.Context(), `SELECT rank FROM roles WHERE id=$1`, targetRole).Scan(&targetRank)
	if actorRole == "owner" {
		return targetRole != "owner" && targetRank < actorRank
	}
	return targetRank < actorRank
}

func (s *Server) outranks(ctx context.Context, actorRole, targetRole string) bool {
	var a, t int
	_ = s.db.QueryRow(ctx, `SELECT rank FROM roles WHERE id=$1`, actorRole).Scan(&a)
	_ = s.db.QueryRow(ctx, `SELECT rank FROM roles WHERE id=$1`, targetRole).Scan(&t)
	return a > t
}

func validRole(r string) bool {
	return r == "owner" || r == "admin" || r == "analyst" || r == "viewer"
}

func mustToken(n int) string {
	t, err := security.RandomToken(n)
	if err != nil {
		return "ChangeMeNow1"
	}
	// RandomToken uses URL-safe base64; replace characters that are awkward to type.
	out := strings.NewReplacer("-", "x", "_", "y").Replace(t)
	if len(out) > 18 {
		out = out[:18]
	}
	return out
}
