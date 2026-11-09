package api

import (
	"encoding/json"
	"net/http"
	"time"
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
	})
}

func (s *Server) handlePlatformOrganizations(w http.ResponseWriter, r *http.Request) {
	rows, err := s.db.Query(r.Context(), `
		SELECT o.id::text, o.name, o.slug, o.created_at,
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
		var members, assets, scans, findings int
		if err := rows.Scan(&id, &name, &slug, &created, &members, &assets, &scans, &findings, &ownerName, &ownerEmail); err != nil {
			s.dbError(w, err, "organization")
			return
		}
		items = append(items, map[string]any{
			"id": id, "name": name, "slug": slug, "created_at": created.UTC().Format(time.RFC3339),
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

func (s *Server) handlePlatformUpdateUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IsActive      *bool `json:"is_active"`
		PlatformAdmin *bool `json:"is_platform_admin"`
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
	if req.IsActive == nil && req.PlatformAdmin == nil {
		s.writeValidation(w, "Provide is_active or is_platform_admin.")
		return
	}
	if targetID == ac.UserID {
		if req.IsActive != nil && !*req.IsActive {
			s.writeValidation(w, "You cannot deactivate your own account.")
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
	if req.IsActive != nil {
		if _, err := s.db.Exec(r.Context(), `UPDATE users SET is_active=$1 WHERE id=$2`, *req.IsActive, targetID); err != nil {
			s.dbError(w, err, "user")
			return
		}
	}
	if req.PlatformAdmin != nil {
		if _, err := s.db.Exec(r.Context(), `UPDATE users SET is_platform_admin=$1 WHERE id=$2`, *req.PlatformAdmin, targetID); err != nil {
			s.dbError(w, err, "user")
			return
		}
	}
	s.auditSystem(r.Context(), "", "platform.user_updated", "user", targetID, map[string]any{
		"is_active": req.IsActive, "is_platform_admin": req.PlatformAdmin,
	})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handlePlatformActivity(w http.ResponseWriter, r *http.Request) {
	rows, err := s.db.Query(r.Context(), `
		SELECT e.id::text, COALESCE(e.org_id::text,''), COALESCE(o.name,''), e.action, e.resource_type,
		       COALESCE(e.resource_id,''), e.metadata, e.created_at, COALESCE(u.name,''), COALESCE(u.email,'')
		FROM audit_events e
		LEFT JOIN organizations o ON o.id=e.org_id
		LEFT JOIN users u ON u.id=e.actor_user_id
		ORDER BY e.created_at DESC LIMIT 100`)
	if err != nil {
		s.dbError(w, err, "activity")
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var id, orgID, orgName, action, resourceType, resourceID, actorName, actorEmail string
		var metadata []byte
		var created time.Time
		if err := rows.Scan(&id, &orgID, &orgName, &action, &resourceType, &resourceID, &metadata, &created, &actorName, &actorEmail); err != nil {
			s.dbError(w, err, "activity")
			return
		}
		items = append(items, map[string]any{
			"id": id, "org_id": orgID, "org_name": orgName, "action": action,
			"resource_type": resourceType, "resource_id": resourceID,
			"metadata": json.RawMessage(metadata), "created_at": created.UTC().Format(time.RFC3339),
			"actor": actorName, "actor_email": actorEmail,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}
