package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/kingmalhare/api/internal/security"
)

func (s *Server) handlePlatformOverview(w http.ResponseWriter, r *http.Request) {
	count := func(sql string) int {
		var n int
		_ = s.db.QueryRow(r.Context(), sql).Scan(&n)
		return n
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"organizations":      count(`SELECT count(*) FROM organizations`),
		"users":              count(`SELECT count(*) FROM users`),
		"active_users":       count(`SELECT count(*) FROM users WHERE is_active`),
		"platform_admins":    count(`SELECT count(*) FROM users WHERE is_platform_admin`),
		"assets":             count(`SELECT count(*) FROM assets WHERE status='active'`),
		"scans":              count(`SELECT count(*) FROM scans`),
		"running_scans":      count(`SELECT count(*) FROM scans WHERE status IN ('queued','initializing','running')`),
		"findings":           count(`SELECT count(*) FROM findings WHERE status NOT IN ('fixed','false_positive','accepted_risk')`),
		"high_risk_findings": count(`SELECT count(*) FROM findings WHERE severity IN ('critical','high') AND status NOT IN ('fixed','false_positive','accepted_risk')`),
		"active_sessions":    count(`SELECT count(*) FROM sessions WHERE revoked_at IS NULL AND expires_at > now()`),
	})
}

func (s *Server) handlePlatformOrganizations(w http.ResponseWriter, r *http.Request) {
	rows, err := s.db.Query(r.Context(), `
		SELECT o.id::text, o.name, o.slug, o.created_at, o.emergency_stop, o.retention_days,
		       (SELECT count(*) FROM memberships m WHERE m.org_id=o.id),
		       (SELECT count(*) FROM assets a WHERE a.org_id=o.id AND a.status='active'),
		       (SELECT count(*) FROM scans s WHERE s.org_id=o.id),
		       (SELECT count(*) FROM findings f WHERE f.org_id=o.id AND f.status NOT IN ('fixed','false_positive','accepted_risk')),
		       COALESCE((SELECT u.name FROM memberships m JOIN users u ON u.id=m.user_id
		                 WHERE m.org_id=o.id AND m.role_id='owner' ORDER BY m.created_at LIMIT 1),''),
		       COALESCE((SELECT u.email FROM memberships m JOIN users u ON u.id=m.user_id
		                 WHERE m.org_id=o.id AND m.role_id='owner' ORDER BY m.created_at LIMIT 1),'')
		FROM organizations o
		ORDER BY o.created_at ASC`)
	if err != nil {
		s.dbError(w, err, "organizations")
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var id, name, slug, ownerName, ownerEmail string
		var created time.Time
		var emergencyStop bool
		var retention, members, assets, scans, findings int
		if err := rows.Scan(&id, &name, &slug, &created, &emergencyStop, &retention, &members, &assets, &scans, &findings, &ownerName, &ownerEmail); err != nil {
			s.dbError(w, err, "organization")
			return
		}
		items = append(items, map[string]any{
			"id": id, "name": name, "slug": slug, "created_at": created.UTC().Format(time.RFC3339),
			"emergency_stop": emergencyStop, "retention_days": retention,
			"member_count": members, "asset_count": assets, "scan_count": scans, "open_findings": findings,
			"owner_name": ownerName, "owner_email": ownerEmail,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) handlePlatformOrganization(w http.ResponseWriter, r *http.Request) {
	orgID := chiURLParam(r, "orgID")
	if !validUUID(orgID) {
		writeError(w, http.StatusBadRequest, "invalid_id", "Invalid organization id.", nil)
		return
	}
	var id, name, slug string
	var created time.Time
	var emergencyStop bool
	var retention, members, assets, scans, findings int
	err := s.db.QueryRow(r.Context(), `
		SELECT o.id::text, o.name, o.slug, o.emergency_stop, o.retention_days, o.created_at,
		       (SELECT count(*) FROM memberships m WHERE m.org_id=o.id),
		       (SELECT count(*) FROM assets a WHERE a.org_id=o.id AND a.status='active'),
		       (SELECT count(*) FROM scans s WHERE s.org_id=o.id),
		       (SELECT count(*) FROM findings f WHERE f.org_id=o.id AND f.status NOT IN ('fixed','false_positive','accepted_risk'))
		FROM organizations o WHERE o.id=$1`, orgID).
		Scan(&id, &name, &slug, &emergencyStop, &retention, &created, &members, &assets, &scans, &findings)
	if isNotFound(err) {
		writeError(w, http.StatusNotFound, "not_found", "Organization not found.", nil)
		return
	}
	if err != nil {
		s.dbError(w, err, "organization")
		return
	}

	memberRows, err := s.db.Query(r.Context(), `
		SELECT u.id::text, u.name, u.email, m.role_id, ro.name, u.avatar_color, u.is_active, u.last_login_at, m.created_at,
		       (SELECT count(*) FROM findings f WHERE f.org_id=$1 AND f.assigned_to=u.id AND f.status NOT IN ('fixed','false_positive','accepted_risk'))
		FROM memberships m
		JOIN users u ON u.id=m.user_id
		JOIN roles ro ON ro.id=m.role_id
		WHERE m.org_id=$1
		ORDER BY ro.rank DESC, u.name ASC`, orgID)
	if err != nil {
		s.dbError(w, err, "members")
		return
	}
	defer memberRows.Close()
	memberList := []memberDTO{}
	for memberRows.Next() {
		var m memberDTO
		var lastLogin *time.Time
		var joined time.Time
		if err := memberRows.Scan(&m.UserID, &m.Name, &m.Email, &m.Role, &m.RoleName, &m.AvatarColor, &m.IsActive, &lastLogin, &joined, &m.OpenFindings); err != nil {
			s.dbError(w, err, "member")
			return
		}
		if lastLogin != nil {
			v := lastLogin.UTC().Format(time.RFC3339)
			m.LastLoginAt = &v
		}
		m.JoinedAt = joined.UTC().Format(time.RFC3339)
		memberList = append(memberList, m)
	}

	scanRows, err := s.db.Query(r.Context(), `
		SELECT id::text, category, scanner, status, progress, created_at
		FROM scans WHERE org_id=$1 ORDER BY created_at DESC LIMIT 10`, orgID)
	if err != nil {
		s.dbError(w, err, "scans")
		return
	}
	defer scanRows.Close()
	recentScans := []map[string]any{}
	for scanRows.Next() {
		var sid, category, scanner, status string
		var progress int
		var scanCreated time.Time
		if err := scanRows.Scan(&sid, &category, &scanner, &status, &progress, &scanCreated); err != nil {
			s.dbError(w, err, "scan")
			return
		}
		recentScans = append(recentScans, map[string]any{
			"id": sid, "category": category, "scanner": scanner, "status": status,
			"progress": progress, "created_at": scanCreated.UTC().Format(time.RFC3339),
		})
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"organization": map[string]any{
			"id": id, "name": name, "slug": slug, "emergency_stop": emergencyStop,
			"retention_days": retention, "created_at": created.UTC().Format(time.RFC3339),
			"member_count": members, "asset_count": assets, "scan_count": scans, "open_findings": findings,
		},
		"members":      memberList,
		"recent_scans": recentScans,
	})
}

func (s *Server) handlePlatformUpdateOrganization(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name          *string `json:"name"`
		Slug          *string `json:"slug"`
		RetentionDays *int    `json:"retention_days"`
		EmergencyStop *bool   `json:"emergency_stop"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	orgID := chiURLParam(r, "orgID")
	if !validUUID(orgID) {
		writeError(w, http.StatusBadRequest, "invalid_id", "Invalid organization id.", nil)
		return
	}
	if req.Name == nil && req.Slug == nil && req.RetentionDays == nil && req.EmergencyStop == nil {
		s.writeValidation(w, "Provide at least one field to update.")
		return
	}
	var exists bool
	_ = s.db.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM organizations WHERE id=$1)`, orgID).Scan(&exists)
	if !exists {
		writeError(w, http.StatusNotFound, "not_found", "Organization not found.", nil)
		return
	}
	changed := map[string]any{}
	if req.Name != nil {
		name := strings.TrimSpace(*req.Name)
		if utf8.RuneCountInString(name) < 2 || len(name) > 120 {
			s.writeValidation(w, "Organization name must be between 2 and 120 characters.")
			return
		}
		if _, err := s.db.Exec(r.Context(), `UPDATE organizations SET name=$1 WHERE id=$2`, name, orgID); err != nil {
			s.dbError(w, err, "organization")
			return
		}
		changed["name"] = name
	}
	if req.Slug != nil {
		slug := strings.TrimSpace(strings.ToLower(*req.Slug))
		if slug != security.Slugify(slug) || len(slug) < 2 || len(slug) > 80 {
			s.writeValidation(w, "Slug must use lowercase letters, numbers and hyphens.")
			return
		}
		var taken bool
		_ = s.db.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM organizations WHERE slug=$1 AND id<>$2)`, slug, orgID).Scan(&taken)
		if taken {
			writeError(w, http.StatusConflict, "slug_in_use", "Another organization already uses this slug.", nil)
			return
		}
		if _, err := s.db.Exec(r.Context(), `UPDATE organizations SET slug=$1 WHERE id=$2`, slug, orgID); err != nil {
			s.dbError(w, err, "organization")
			return
		}
		changed["slug"] = slug
	}
	if req.RetentionDays != nil {
		if *req.RetentionDays < 30 || *req.RetentionDays > 3650 {
			s.writeValidation(w, "Retention must be between 30 and 3650 days.")
			return
		}
		if _, err := s.db.Exec(r.Context(), `UPDATE organizations SET retention_days=$1 WHERE id=$2`, *req.RetentionDays, orgID); err != nil {
			s.dbError(w, err, "organization")
			return
		}
		changed["retention_days"] = *req.RetentionDays
	}
	if req.EmergencyStop != nil {
		if _, err := s.db.Exec(r.Context(), `UPDATE organizations SET emergency_stop=$1 WHERE id=$2`, *req.EmergencyStop, orgID); err != nil {
			s.dbError(w, err, "organization")
			return
		}
		changed["emergency_stop"] = *req.EmergencyStop
	}
	s.auditSystem(r.Context(), orgID, "platform.organization_updated", "organization", orgID, changed)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handlePlatformUpdateMember(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RoleID string `json:"role_id"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	orgID := chiURLParam(r, "orgID")
	userID := chiURLParam(r, "userID")
	if !validUUID(orgID) || !validUUID(userID) {
		writeError(w, http.StatusBadRequest, "invalid_id", "Invalid organization or user id.", nil)
		return
	}
	roleID := strings.TrimSpace(req.RoleID)
	if !validRole(roleID) {
		s.writeValidation(w, "Unknown role.")
		return
	}
	var current string
	err := s.db.QueryRow(r.Context(), `SELECT role_id FROM memberships WHERE org_id=$1 AND user_id=$2`, orgID, userID).Scan(&current)
	if isNotFound(err) {
		writeError(w, http.StatusNotFound, "not_found", "Member not found.", nil)
		return
	}
	if err != nil {
		s.dbError(w, err, "member")
		return
	}
	if current == "owner" && roleID != "owner" {
		var owners int
		_ = s.db.QueryRow(r.Context(), `SELECT count(*) FROM memberships WHERE org_id=$1 AND role_id='owner' AND user_id<>$2`, orgID, userID).Scan(&owners)
		if owners == 0 {
			s.writeValidation(w, "The organization must keep at least one owner.")
			return
		}
	}
	if _, err := s.db.Exec(r.Context(), `UPDATE memberships SET role_id=$1 WHERE org_id=$2 AND user_id=$3`, roleID, orgID, userID); err != nil {
		s.dbError(w, err, "member")
		return
	}
	s.auditSystem(r.Context(), orgID, "platform.member_role_changed", "user", userID, map[string]any{"from": current, "to": roleID})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handlePlatformRemoveMember(w http.ResponseWriter, r *http.Request) {
	orgID := chiURLParam(r, "orgID")
	userID := chiURLParam(r, "userID")
	if !validUUID(orgID) || !validUUID(userID) {
		writeError(w, http.StatusBadRequest, "invalid_id", "Invalid organization or user id.", nil)
		return
	}
	var current string
	err := s.db.QueryRow(r.Context(), `SELECT role_id FROM memberships WHERE org_id=$1 AND user_id=$2`, orgID, userID).Scan(&current)
	if isNotFound(err) {
		writeError(w, http.StatusNotFound, "not_found", "Member not found.", nil)
		return
	}
	if err != nil {
		s.dbError(w, err, "member")
		return
	}
	if current == "owner" {
		var owners int
		_ = s.db.QueryRow(r.Context(), `SELECT count(*) FROM memberships WHERE org_id=$1 AND role_id='owner' AND user_id<>$2`, orgID, userID).Scan(&owners)
		if owners == 0 {
			s.writeValidation(w, "The organization must keep at least one owner.")
			return
		}
	}
	if _, err := s.db.Exec(r.Context(), `DELETE FROM memberships WHERE org_id=$1 AND user_id=$2`, orgID, userID); err != nil {
		s.dbError(w, err, "member")
		return
	}
	s.auditSystem(r.Context(), orgID, "platform.member_removed", "user", userID, map[string]any{"role": current})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handlePlatformUsers(w http.ResponseWriter, r *http.Request) {
	rows, err := s.db.Query(r.Context(), `
		SELECT u.id::text, u.name, u.email, u.is_active, u.is_platform_admin, u.last_login_at, u.created_at,
		       COALESCE(json_agg(json_build_object(
		         'org_id', o.id::text, 'org_name', o.name,
		         'role_id', m.role_id, 'role_name', ro.name
		       )) FILTER (WHERE m.org_id IS NOT NULL), '[]'::json)
		FROM users u
		LEFT JOIN memberships m ON m.user_id=u.id
		LEFT JOIN organizations o ON o.id=m.org_id
		LEFT JOIN roles ro ON ro.id=m.role_id
		GROUP BY u.id
		ORDER BY u.created_at ASC`)
	if err != nil {
		s.dbError(w, err, "users")
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var id, name, email string
		var active, platformAdmin bool
		var lastLogin *time.Time
		var created time.Time
		var memberships []byte
		if err := rows.Scan(&id, &name, &email, &active, &platformAdmin, &lastLogin, &created, &memberships); err != nil {
			s.dbError(w, err, "user")
			return
		}
		item := map[string]any{
			"id": id, "name": name, "email": email, "is_active": active,
			"is_platform_admin": platformAdmin, "created_at": created.UTC().Format(time.RFC3339),
			"memberships": json.RawMessage(memberships),
		}
		if lastLogin != nil {
			item["last_login_at"] = lastLogin.UTC().Format(time.RFC3339)
		}
		items = append(items, item)
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) handlePlatformUserDetail(w http.ResponseWriter, r *http.Request) {
	userID := chiURLParam(r, "userID")
	if !validUUID(userID) {
		writeError(w, http.StatusBadRequest, "invalid_id", "Invalid user id.", nil)
		return
	}
	var id, name, email, avatar string
	var active, platformAdmin bool
	var lastLogin *time.Time
	var created time.Time
	err := s.db.QueryRow(r.Context(), `
		SELECT id::text, name, email, avatar_color, is_active, is_platform_admin, last_login_at, created_at
		FROM users WHERE id=$1`, userID).
		Scan(&id, &name, &email, &avatar, &active, &platformAdmin, &lastLogin, &created)
	if isNotFound(err) {
		writeError(w, http.StatusNotFound, "not_found", "User not found.", nil)
		return
	}
	if err != nil {
		s.dbError(w, err, "user")
		return
	}
	user := map[string]any{
		"id": id, "name": name, "email": email, "avatar_color": avatar,
		"is_active": active, "is_platform_admin": platformAdmin,
		"created_at": created.UTC().Format(time.RFC3339),
	}
	if lastLogin != nil {
		user["last_login_at"] = lastLogin.UTC().Format(time.RFC3339)
	}

	memberRows, err := s.db.Query(r.Context(), `
		SELECT o.id::text, o.name, m.role_id, ro.name, m.created_at
		FROM memberships m
		JOIN organizations o ON o.id=m.org_id
		JOIN roles ro ON ro.id=m.role_id
		WHERE m.user_id=$1
		ORDER BY o.name ASC`, userID)
	if err != nil {
		s.dbError(w, err, "memberships")
		return
	}
	defer memberRows.Close()
	memberships := []map[string]any{}
	for memberRows.Next() {
		var orgID, orgName, roleID, roleName string
		var joined time.Time
		if err := memberRows.Scan(&orgID, &orgName, &roleID, &roleName, &joined); err != nil {
			s.dbError(w, err, "membership")
			return
		}
		memberships = append(memberships, map[string]any{
			"org_id": orgID, "org_name": orgName, "role_id": roleID,
			"role_name": roleName, "joined_at": joined.UTC().Format(time.RFC3339),
		})
	}

	count := func(sql string) int {
		var n int
		_ = s.db.QueryRow(r.Context(), sql, userID).Scan(&n)
		return n
	}
	counts := map[string]any{
		"assets_owned":      count(`SELECT count(*) FROM assets WHERE owner_user_id=$1 AND status='active'`),
		"findings_assigned": count(`SELECT count(*) FROM findings WHERE assigned_to=$1 AND status NOT IN ('fixed','false_positive','accepted_risk')`),
		"scans_started":     count(`SELECT count(*) FROM scans WHERE created_by=$1`),
		"reports_created":   count(`SELECT count(*) FROM reports WHERE created_by=$1`),
	}

	sessionRows, err := s.db.Query(r.Context(), `
		SELECT s.id::text, s.org_id::text, o.name, COALESCE(s.ip,''), COALESCE(s.user_agent,''),
		       s.created_at, s.last_seen_at, s.expires_at
		FROM sessions s
		JOIN organizations o ON o.id=s.org_id
		WHERE s.user_id=$1 AND s.revoked_at IS NULL AND s.expires_at > now()
		ORDER BY s.last_seen_at DESC`, userID)
	if err != nil {
		s.dbError(w, err, "sessions")
		return
	}
	defer sessionRows.Close()
	sessions := []map[string]any{}
	for sessionRows.Next() {
		var sid, orgID, orgName, ip, ua string
		var sessionCreated, lastSeen, expires time.Time
		if err := sessionRows.Scan(&sid, &orgID, &orgName, &ip, &ua, &sessionCreated, &lastSeen, &expires); err != nil {
			s.dbError(w, err, "session")
			return
		}
		sessions = append(sessions, map[string]any{
			"id": sid, "user_id": id, "user_name": name, "user_email": email,
			"org_id": orgID, "org_name": orgName, "ip": ip, "user_agent": ua,
			"created_at": sessionCreated.UTC().Format(time.RFC3339),
			"last_seen_at": lastSeen.UTC().Format(time.RFC3339),
			"expires_at": expires.UTC().Format(time.RFC3339),
		})
	}

	activityRows, err := s.db.Query(r.Context(), `
		SELECT e.id::text, COALESCE(o.name,''), e.action, e.resource_type, COALESCE(e.resource_id,''),
		       e.metadata, COALESCE(e.ip,''), e.created_at
		FROM audit_events e
		LEFT JOIN organizations o ON o.id=e.org_id
		WHERE e.actor_user_id=$1
		ORDER BY e.created_at DESC LIMIT 30`, userID)
	if err != nil {
		s.dbError(w, err, "activity")
		return
	}
	defer activityRows.Close()
	activity := []map[string]any{}
	for activityRows.Next() {
		var eventID, orgName, action, resourceType, resourceID, ip string
		var metadata []byte
		var eventCreated time.Time
		if err := activityRows.Scan(&eventID, &orgName, &action, &resourceType, &resourceID, &metadata, &ip, &eventCreated); err != nil {
			s.dbError(w, err, "activity")
			return
		}
		activity = append(activity, map[string]any{
			"id": eventID, "org_name": orgName, "action": action, "resource_type": resourceType,
			"resource_id": resourceID, "metadata": json.RawMessage(metadata), "ip": ip,
			"created_at": eventCreated.UTC().Format(time.RFC3339),
		})
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"user": user, "memberships": memberships, "counts": counts,
		"sessions": sessions, "activity": activity,
	})
}

func (s *Server) handlePlatformUpdateUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name          *string `json:"name"`
		Email         *string `json:"email"`
		IsActive      *bool   `json:"is_active"`
		PlatformAdmin *bool   `json:"is_platform_admin"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	targetID := chiURLParam(r, "userID")
	if !validUUID(targetID) {
		writeError(w, http.StatusBadRequest, "invalid_id", "Invalid user id.", nil)
		return
	}
	ac := actor(r)
	if req.Name == nil && req.Email == nil && req.IsActive == nil && req.PlatformAdmin == nil {
		s.writeValidation(w, "Provide at least one field to update.")
		return
	}
	if targetID == ac.UserID {
		if req.IsActive != nil && !*req.IsActive {
			s.writeValidation(w, "You cannot suspend your own account.")
			return
		}
		if req.PlatformAdmin != nil && !*req.PlatformAdmin {
			s.writeValidation(w, "You cannot remove your own platform admin access.")
			return
		}
	}
	var exists bool
	_ = s.db.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM users WHERE id=$1)`, targetID).Scan(&exists)
	if !exists {
		writeError(w, http.StatusNotFound, "not_found", "User not found.", nil)
		return
	}
	changed := map[string]any{}
	if req.Name != nil {
		name := strings.TrimSpace(*req.Name)
		if utf8.RuneCountInString(name) < 2 || len(name) > 120 {
			s.writeValidation(w, "Name must be between 2 and 120 characters.")
			return
		}
		if _, err := s.db.Exec(r.Context(), `UPDATE users SET name=$1, updated_at=now() WHERE id=$2`, name, targetID); err != nil {
			s.dbError(w, err, "user")
			return
		}
		changed["name"] = name
	}
	if req.Email != nil {
		email := strings.ToLower(strings.TrimSpace(*req.Email))
		if !security.ValidEmail(email) {
			s.writeValidation(w, "Provide a valid email address.")
			return
		}
		var taken bool
		_ = s.db.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM users WHERE lower(email)=lower($1) AND id<>$2)`, email, targetID).Scan(&taken)
		if taken {
			writeError(w, http.StatusConflict, "email_in_use", "Another account already uses this email.", nil)
			return
		}
		if _, err := s.db.Exec(r.Context(), `UPDATE users SET email=$1, updated_at=now() WHERE id=$2`, email, targetID); err != nil {
			s.dbError(w, err, "user")
			return
		}
		changed["email"] = email
	}
	if req.IsActive != nil {
		if _, err := s.db.Exec(r.Context(), `UPDATE users SET is_active=$1, updated_at=now() WHERE id=$2`, *req.IsActive, targetID); err != nil {
			s.dbError(w, err, "user")
			return
		}
		if !*req.IsActive {
			_, _ = s.db.Exec(r.Context(), `UPDATE sessions SET revoked_at=now() WHERE user_id=$1 AND revoked_at IS NULL`, targetID)
		}
		changed["is_active"] = *req.IsActive
	}
	if req.PlatformAdmin != nil {
		if _, err := s.db.Exec(r.Context(), `UPDATE users SET is_platform_admin=$1, updated_at=now() WHERE id=$2`, *req.PlatformAdmin, targetID); err != nil {
			s.dbError(w, err, "user")
			return
		}
		changed["is_platform_admin"] = *req.PlatformAdmin
	}
	s.auditSystem(r.Context(), "", "platform.user_updated", "user", targetID, changed)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handlePlatformResetPassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Password string `json:"password"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	targetID := chiURLParam(r, "userID")
	if !validUUID(targetID) {
		writeError(w, http.StatusBadRequest, "invalid_id", "Invalid user id.", nil)
		return
	}
	var exists bool
	_ = s.db.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM users WHERE id=$1)`, targetID).Scan(&exists)
	if !exists {
		writeError(w, http.StatusNotFound, "not_found", "User not found.", nil)
		return
	}
	password := strings.TrimSpace(req.Password)
	generated := false
	if password == "" {
		token, err := security.RandomToken(18)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "password_generation_failed", "Could not generate a password.", nil)
			return
		}
		password = "Km1!" + token
		generated = true
	}
	if err := security.ValidatePassword(password); err != nil {
		s.writeValidation(w, err.Error())
		return
	}
	hash, err := security.HashPassword(password)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "hash_failed", "Could not reset the password.", nil)
		return
	}
	if _, err := s.db.Exec(r.Context(), `UPDATE users SET password_hash=$1, updated_at=now() WHERE id=$2`, hash, targetID); err != nil {
		s.dbError(w, err, "user")
		return
	}
	tag, _ := s.db.Exec(r.Context(), `UPDATE sessions SET revoked_at=now() WHERE user_id=$1 AND revoked_at IS NULL`, targetID)
	s.auditSystem(r.Context(), "", "platform.password_reset", "user", targetID, map[string]any{"generated": generated, "sessions_revoked": tag.RowsAffected()})
	writeJSON(w, http.StatusOK, map[string]any{
		"temporary_password": password,
		"generated":          generated,
		"sessions_revoked":   tag.RowsAffected(),
	})
}

func (s *Server) handlePlatformSignOutUser(w http.ResponseWriter, r *http.Request) {
	targetID := chiURLParam(r, "userID")
	if !validUUID(targetID) {
		writeError(w, http.StatusBadRequest, "invalid_id", "Invalid user id.", nil)
		return
	}
	tag, err := s.db.Exec(r.Context(), `UPDATE sessions SET revoked_at=now() WHERE user_id=$1 AND revoked_at IS NULL`, targetID)
	if err != nil {
		s.dbError(w, err, "sessions")
		return
	}
	s.auditSystem(r.Context(), "", "platform.user_signed_out", "user", targetID, map[string]any{"sessions_revoked": tag.RowsAffected()})
	writeJSON(w, http.StatusOK, map[string]any{"revoked": tag.RowsAffected()})
}

func (s *Server) handlePlatformSessions(w http.ResponseWriter, r *http.Request) {
	rows, err := s.db.Query(r.Context(), `
		SELECT s.id::text, s.user_id::text, u.name, u.email, s.org_id::text, o.name,
		       COALESCE(s.ip,''), COALESCE(s.user_agent,''), s.created_at, s.last_seen_at, s.expires_at
		FROM sessions s
		JOIN users u ON u.id=s.user_id
		JOIN organizations o ON o.id=s.org_id
		WHERE s.revoked_at IS NULL AND s.expires_at > now()
		ORDER BY s.last_seen_at DESC LIMIT 200`)
	if err != nil {
		s.dbError(w, err, "sessions")
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var id, userID, userName, userEmail, orgID, orgName, ip, ua string
		var created, lastSeen, expires time.Time
		if err := rows.Scan(&id, &userID, &userName, &userEmail, &orgID, &orgName, &ip, &ua, &created, &lastSeen, &expires); err != nil {
			s.dbError(w, err, "session")
			return
		}
		items = append(items, map[string]any{
			"id": id, "user_id": userID, "user_name": userName, "user_email": userEmail,
			"org_id": orgID, "org_name": orgName, "ip": ip, "user_agent": ua,
			"created_at": created.UTC().Format(time.RFC3339),
			"last_seen_at": lastSeen.UTC().Format(time.RFC3339),
			"expires_at": expires.UTC().Format(time.RFC3339),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) handlePlatformRevokeSession(w http.ResponseWriter, r *http.Request) {
	sessionID := chiURLParam(r, "sessionID")
	if !validUUID(sessionID) {
		writeError(w, http.StatusBadRequest, "invalid_id", "Invalid session id.", nil)
		return
	}
	tag, err := s.db.Exec(r.Context(), `UPDATE sessions SET revoked_at=now() WHERE id=$1 AND revoked_at IS NULL`, sessionID)
	if err != nil {
		s.dbError(w, err, "session")
		return
	}
	if tag.RowsAffected() == 0 {
		writeError(w, http.StatusNotFound, "not_found", "Session not found or already revoked.", nil)
		return
	}
	s.auditSystem(r.Context(), "", "platform.session_revoked", "session", sessionID, nil)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handlePlatformActivity(w http.ResponseWriter, r *http.Request) {
	pageNo, perPage := pagination(r)
	orgID := strings.TrimSpace(r.URL.Query().Get("org_id"))
	userID := strings.TrimSpace(r.URL.Query().Get("user_id"))
	action := strings.TrimSpace(r.URL.Query().Get("action"))
	search := strings.TrimSpace(r.URL.Query().Get("search"))
	where := `($1='' OR e.org_id::text=$1)
		AND ($2='' OR e.actor_user_id::text=$2)
		AND ($3='' OR e.action ILIKE '%'||$3||'%')
		AND ($4='' OR e.action ILIKE '%'||$4||'%' OR COALESCE(u.name,'') ILIKE '%'||$4||'%'
		     OR COALESCE(u.email,'') ILIKE '%'||$4||'%' OR COALESCE(o.name,'') ILIKE '%'||$4||'%'
		     OR COALESCE(e.resource_id,'') ILIKE '%'||$4||'%')`
	var total int
	if err := s.db.QueryRow(r.Context(), `
		SELECT count(*) FROM audit_events e
		LEFT JOIN organizations o ON o.id=e.org_id
		LEFT JOIN users u ON u.id=e.actor_user_id
		WHERE `+where, orgID, userID, action, search).Scan(&total); err != nil {
		s.dbError(w, err, "activity")
		return
	}
	rows, err := s.db.Query(r.Context(), `
		SELECT e.id::text, COALESCE(e.org_id::text,''), COALESCE(o.name,''), e.action, e.resource_type,
		       COALESCE(e.resource_id,''), e.metadata, COALESCE(e.ip,''), e.created_at,
		       COALESCE(u.name,''), COALESCE(u.email,'')
		FROM audit_events e
		LEFT JOIN organizations o ON o.id=e.org_id
		LEFT JOIN users u ON u.id=e.actor_user_id
		WHERE `+where+`
		ORDER BY e.created_at DESC LIMIT $5 OFFSET $6`,
		orgID, userID, action, search, perPage, (pageNo-1)*perPage)
	if err != nil {
		s.dbError(w, err, "activity")
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var id, eventOrgID, orgName, eventAction, resourceType, resourceID, ip, actorName, actorEmail string
		var metadata []byte
		var created time.Time
		if err := rows.Scan(&id, &eventOrgID, &orgName, &eventAction, &resourceType, &resourceID, &metadata, &ip, &created, &actorName, &actorEmail); err != nil {
			s.dbError(w, err, "activity")
			return
		}
		items = append(items, map[string]any{
			"id": id, "org_id": eventOrgID, "org_name": orgName, "action": eventAction,
			"resource_type": resourceType, "resource_id": resourceID,
			"metadata": json.RawMessage(metadata), "ip": ip,
			"created_at": created.UTC().Format(time.RFC3339),
			"actor": actorName, "actor_email": actorEmail,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "total": total, "page": pageNo, "per_page": perPage})
}
