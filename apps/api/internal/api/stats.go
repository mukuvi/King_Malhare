package api

import (
	"context"
	"encoding/json"
	"net/http"
	"time"
)

func (s *Server) handleOverview(w http.ResponseWriter, r *http.Request) {
	ac := actor(r)
	ctx := r.Context()
	type counts struct {
		AssetsActive, AssetsArchived, AuthMissing, ScansActive, Scans24h, ScansFailed24h, ScansCompleted int
		FindingsOpen, FindingsTotal, Critical, High, Medium, Low, Info, Reports                          int
	}
	var c counts
	queries := []struct {
		dest *int
		sql  string
	}{
		{&c.AssetsActive, `SELECT count(*) FROM assets WHERE org_id=$1 AND status='active'`},
		{&c.AssetsArchived, `SELECT count(*) FROM assets WHERE org_id=$1 AND status='archived'`},
		{&c.AuthMissing, `SELECT count(*) FROM assets a WHERE a.org_id=$1 AND a.status='active' AND NOT EXISTS (SELECT 1 FROM authorizations au WHERE au.asset_id=a.id AND au.status='active' AND au.expires_at>now())`},
		{&c.ScansActive, `SELECT count(*) FROM scans WHERE org_id=$1 AND status IN ('pending','queued','initializing','running')`},
		{&c.Scans24h, `SELECT count(*) FROM scans WHERE org_id=$1 AND created_at>now()-interval '24 hours'`},
		{&c.ScansFailed24h, `SELECT count(*) FROM scans WHERE org_id=$1 AND status='failed' AND created_at>now()-interval '24 hours'`},
		{&c.ScansCompleted, `SELECT count(*) FROM scans WHERE org_id=$1 AND status='completed'`},
		{&c.FindingsOpen, `SELECT count(*) FROM findings WHERE org_id=$1 AND status NOT IN ('fixed','false_positive','accepted_risk')`},
		{&c.FindingsTotal, `SELECT count(*) FROM findings WHERE org_id=$1`},
		{&c.Critical, `SELECT count(*) FROM findings WHERE org_id=$1 AND severity='critical' AND status NOT IN ('fixed','false_positive','accepted_risk')`},
		{&c.High, `SELECT count(*) FROM findings WHERE org_id=$1 AND severity='high' AND status NOT IN ('fixed','false_positive','accepted_risk')`},
		{&c.Medium, `SELECT count(*) FROM findings WHERE org_id=$1 AND severity='medium' AND status NOT IN ('fixed','false_positive','accepted_risk')`},
		{&c.Low, `SELECT count(*) FROM findings WHERE org_id=$1 AND severity='low' AND status NOT IN ('fixed','false_positive','accepted_risk')`},
		{&c.Info, `SELECT count(*) FROM findings WHERE org_id=$1 AND severity='info' AND status NOT IN ('fixed','false_positive','accepted_risk')`},
		{&c.Reports, `SELECT count(*) FROM reports WHERE org_id=$1`},
	}
	for _, q := range queries {
		if err := s.db.QueryRow(ctx, q.sql, ac.OrgID).Scan(q.dest); err != nil {
			s.dbError(w, err, "overview")
			return
		}
	}
	severity := map[string]int{"critical": c.Critical, "high": c.High, "medium": c.Medium, "low": c.Low, "info": c.Info}
	score := postureScore(severity, max(c.AssetsActive, 1))

	emergency, _, _ := s.orgSetting(ctx, ac.OrgID)
	var lastScan *time.Time
	_ = s.db.QueryRow(ctx, `SELECT max(created_at) FROM scans WHERE org_id=$1`, ac.OrgID).Scan(&lastScan)

	recentScans := []map[string]any{}
	rows, err := s.db.Query(ctx, `
		SELECT sc.id::text, sc.scanner, sc.category, sc.status, sc.progress, sc.created_at, a.name,
		       (SELECT count(DISTINCT fingerprint) FROM scan_results sr WHERE sr.scan_id=sc.id)
		FROM scans sc JOIN assets a ON a.id=sc.asset_id
		WHERE sc.org_id=$1 ORDER BY sc.created_at DESC LIMIT 6`, ac.OrgID)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var id, sc, cat, status, asset string
			var progress, findings int
			var created time.Time
			if rows.Scan(&id, &sc, &cat, &status, &progress, &created, &asset, &findings) == nil {
				recentScans = append(recentScans, map[string]any{"id": id, "scanner": sc, "category": cat, "status": status,
					"progress": progress, "created_at": created.UTC().Format(time.RFC3339), "asset_name": asset, "findings": findings})
			}
		}
	}
	activity, _ := s.activityRows(ctx, ac.OrgID, 8)
	resp := map[string]any{
		"assets": map[string]any{"active": c.AssetsActive, "archived": c.AssetsArchived, "without_authorization": c.AuthMissing},
		"scans":  map[string]any{"active": c.ScansActive, "last_24h": c.Scans24h, "failed_24h": c.ScansFailed24h, "completed": c.ScansCompleted, "last_at": timeOrNil(lastScan)},
		"findings": map[string]any{"open": c.FindingsOpen, "total": c.FindingsTotal, "critical": c.Critical, "high": c.High,
			"medium": c.Medium, "low": c.Low, "info": c.Info},
		"reports":        c.Reports,
		"posture_score":  score,
		"emergency_stop": emergency,
		"recent_scans":   recentScans,
		"activity":       activity,
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleTrends(w http.ResponseWriter, r *http.Request) {
	ac := actor(r)
	days := queryInt(r, "days", 30)
	if days < 7 || days > 180 {
		days = 30
	}
	start := time.Now().UTC().AddDate(0, 0, -(days - 1)).Truncate(24 * time.Hour)
	rows, err := s.db.Query(r.Context(), `
		WITH days AS (
		  SELECT generate_series($2::date, current_date, '1 day')::date AS d
		),
		f AS (
		  SELECT first_seen::date AS d,
		    count(*) FILTER (WHERE severity='critical') AS critical,
		    count(*) FILTER (WHERE severity='high') AS high,
		    count(*) FILTER (WHERE severity='medium') AS medium,
		    count(*) FILTER (WHERE severity='low') AS low,
		    count(*) FILTER (WHERE severity='info') AS info,
		    count(*) AS total
		  FROM findings WHERE org_id=$1 AND first_seen >= $2 GROUP BY 1
		),
		s AS (
		  SELECT created_at::date AS d, count(*) AS scans, count(*) FILTER (WHERE status='failed') AS failed
		  FROM scans WHERE org_id=$1 AND created_at >= $2 GROUP BY 1
		)
		SELECT to_char(days.d,'YYYY-MM-DD'), COALESCE(f.critical,0), COALESCE(f.high,0), COALESCE(f.medium,0),
		       COALESCE(f.low,0), COALESCE(f.info,0), COALESCE(f.total,0), COALESCE(s.scans,0), COALESCE(s.failed,0)
		FROM days LEFT JOIN f ON f.d=days.d LEFT JOIN s ON s.d=days.d ORDER BY days.d`, ac.OrgID, start)
	if err != nil {
		s.dbError(w, err, "trends")
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var d string
		var critical, high, medium, low, info, total, scans, failed int
		if err := rows.Scan(&d, &critical, &high, &medium, &low, &info, &total, &scans, &failed); err != nil {
			s.dbError(w, err, "trend")
			return
		}
		out = append(out, map[string]any{"date": d, "critical": critical, "high": high, "medium": medium,
			"low": low, "info": info, "total": total, "scans": scans, "failed_scans": failed})
	}
	writeJSON(w, http.StatusOK, map[string]any{"days": days, "items": out})
}

func (s *Server) handleActivity(w http.ResponseWriter, r *http.Request) {
	ac := actor(r)
	items, err := s.activityRows(r.Context(), ac.OrgID, 30)
	if err != nil {
		s.dbError(w, err, "activity")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) activityRows(rctx context.Context, orgID string, limit int) ([]map[string]any, error) {
	rows, err := s.db.Query(rctx, `
		SELECT e.id::text, e.action, e.resource_type, e.resource_id, e.metadata, e.created_at, u.name
		FROM audit_events e LEFT JOIN users u ON u.id=e.actor_user_id
		WHERE e.org_id=$1 ORDER BY e.created_at DESC LIMIT $2`, orgID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id, action, rtype string
		var rid *string
		var meta []byte
		var created time.Time
		var actor *string
		if err := rows.Scan(&id, &action, &rtype, &rid, &meta, &created, &actor); err != nil {
			return nil, err
		}
		out = append(out, map[string]any{"id": id, "action": action, "resource_type": rtype, "resource_id": rid,
			"metadata": json.RawMessage(meta), "created_at": created.UTC().Format(time.RFC3339), "actor": actor})
	}
	return out, nil
}

func timeOrNil(t *time.Time) any {
	if t == nil {
		return nil
	}
	return t.UTC().Format(time.RFC3339)
}

func (s *Server) handleListNotifications(w http.ResponseWriter, r *http.Request) {
	ac := actor(r)
	pageNo, perPage := pagination(r)
	unreadOnly := r.URL.Query().Get("unread") == "true"
	visible := `n.org_id=$1 AND (n.user_id=$2 OR n.user_id IS NULL)
		AND NOT EXISTS (SELECT 1 FROM notification_dismissals d WHERE d.notification_id=n.id AND d.user_id=$2)`
	var total, unread int
	_ = s.db.QueryRow(r.Context(), `SELECT count(*) FROM notifications n WHERE `+visible, ac.OrgID, ac.UserID).Scan(&total)
	_ = s.db.QueryRow(r.Context(), `SELECT count(*) FROM notifications n WHERE `+visible+` AND n.read_at IS NULL`, ac.OrgID, ac.UserID).Scan(&unread)
	rows, err := s.db.Query(r.Context(), `
		SELECT n.id::text, n.type, n.title, n.body, n.link, n.read_at, n.created_at
		FROM notifications n WHERE `+visible+` AND ($3=false OR n.read_at IS NULL)
		ORDER BY n.created_at DESC LIMIT $4 OFFSET $5`, ac.OrgID, ac.UserID, unreadOnly, perPage, (pageNo-1)*perPage)
	if err != nil {
		s.dbError(w, err, "notifications")
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var id, typ, title, body, link string
		var readAt *time.Time
		var created time.Time
		if err := rows.Scan(&id, &typ, &title, &body, &link, &readAt, &created); err != nil {
			s.dbError(w, err, "notification")
			return
		}
		item := map[string]any{"id": id, "type": typ, "title": title, "body": body, "link": link,
			"read": readAt != nil, "created_at": created.UTC().Format(time.RFC3339)}
		if readAt != nil {
			item["read_at"] = readAt.UTC().Format(time.RFC3339)
		}
		items = append(items, item)
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "total": total, "unread": unread, "page": pageNo, "per_page": perPage})
}

type readNotificationsRequest struct {
	IDs []string `json:"ids"`
	All bool     `json:"all"`
}

func (s *Server) handleReadNotifications(w http.ResponseWriter, r *http.Request) {
	var req readNotificationsRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	ac := actor(r)
	if req.All {
		_, err := s.db.Exec(r.Context(), `UPDATE notifications SET read_at=now() WHERE org_id=$1 AND (user_id=$2 OR user_id IS NULL) AND read_at IS NULL`, ac.OrgID, ac.UserID)
		if err != nil {
			s.dbError(w, err, "notifications")
			return
		}
	} else {
		if len(req.IDs) == 0 || len(req.IDs) > 200 {
			s.writeValidation(w, "Provide notification ids or set all=true.")
			return
		}
		_, err := s.db.Exec(r.Context(), `UPDATE notifications SET read_at=now() WHERE org_id=$1 AND (user_id=$2 OR user_id IS NULL) AND id = ANY($3::uuid[])`, ac.OrgID, ac.UserID, req.IDs)
		if err != nil {
			s.dbError(w, err, "notifications")
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleClearNotifications(w http.ResponseWriter, r *http.Request) {
	ac := actor(r)
	tx, err := s.db.Begin(r.Context())
	if err != nil {
		s.dbError(w, err, "notifications")
		return
	}
	defer tx.Rollback(r.Context())
	// Organization-wide notifications are shared, so clear them for this user by
	// recording a dismissal instead of deleting the row for every member.
	if _, err := tx.Exec(r.Context(), `
		INSERT INTO notification_dismissals (notification_id, user_id)
		SELECT n.id, $2 FROM notifications n WHERE n.org_id=$1 AND n.user_id IS NULL
		ON CONFLICT DO NOTHING`, ac.OrgID, ac.UserID); err != nil {
		s.dbError(w, err, "notifications")
		return
	}
	if _, err := tx.Exec(r.Context(), `DELETE FROM notifications WHERE org_id=$1 AND user_id=$2`, ac.OrgID, ac.UserID); err != nil {
		s.dbError(w, err, "notifications")
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		s.dbError(w, err, "notifications")
		return
	}
	s.audit(r, "notifications.cleared", "notification", "", nil)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleAuditEvents(w http.ResponseWriter, r *http.Request) {
	ac := actor(r)
	pageNo, perPage := pagination(r)
	action := r.URL.Query().Get("action")
	resourceType := r.URL.Query().Get("resource_type")
	search := r.URL.Query().Get("search")
	where := `e.org_id=$1 AND ($2='' OR e.action ILIKE '%'||$2||'%') AND ($3='' OR e.resource_type=$3)
		AND ($4='' OR e.resource_id=$4 OR u.name ILIKE '%'||$4||'%')`
	var total int
	if err := s.db.QueryRow(r.Context(), `SELECT count(*) FROM audit_events e LEFT JOIN users u ON u.id=e.actor_user_id WHERE `+where, ac.OrgID, action, resourceType, search).Scan(&total); err != nil {
		s.dbError(w, err, "audit")
		return
	}
	rows, err := s.db.Query(r.Context(), `
		SELECT e.id::text, e.action, e.resource_type, e.resource_id, e.metadata, e.ip, e.created_at, u.name, u.email
		FROM audit_events e LEFT JOIN users u ON u.id=e.actor_user_id
		WHERE `+where+` ORDER BY e.created_at DESC LIMIT $5 OFFSET $6`, ac.OrgID, action, resourceType, search, perPage, (pageNo-1)*perPage)
	if err != nil {
		s.dbError(w, err, "audit")
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var id, act, rt string
		var rid *string
		var meta []byte
		var ip, actorName, actorEmail *string
		var created time.Time
		if err := rows.Scan(&id, &act, &rt, &rid, &meta, &ip, &created, &actorName, &actorEmail); err != nil {
			s.dbError(w, err, "audit")
			return
		}
		items = append(items, map[string]any{"id": id, "action": act, "resource_type": rt, "resource_id": rid,
			"metadata": json.RawMessage(meta), "ip": ip, "actor": actorName, "actor_email": actorEmail,
			"created_at": created.UTC().Format(time.RFC3339)})
	}
	writeJSON(w, http.StatusOK, page{Items: items, Page: pageNo, PerPage: perPage, Total: total})
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
