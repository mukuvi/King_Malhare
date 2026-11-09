package api

import (
	"context"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/kingmalhare/api/internal/security"
)

type registerRequest struct {
	OrgName  string `json:"org_name"`
	Name     string `json:"name"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type meResponse struct {
	User          userDTO  `json:"user"`
	Org           orgDTO   `json:"org"`
	Role          string   `json:"role"`
	Permissions   []string `json:"permissions"`
	PlatformAdmin bool     `json:"platform_admin"`
	CSRFToken     string   `json:"csrf_token,omitempty"`
}

type userDTO struct {
	ID          string  `json:"id"`
	Name        string  `json:"name"`
	Email       string  `json:"email"`
	AvatarColor string  `json:"avatar_color"`
	LastLoginAt *string `json:"last_login_at,omitempty"`
	CreatedAt   string  `json:"created_at"`
}

type orgDTO struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Slug          string `json:"slug"`
	EmergencyStop bool   `json:"emergency_stop"`
	RetentionDays int    `json:"retention_days"`
	CreatedAt     string `json:"created_at"`
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "ok", "service": "king-malhare-api", "version": "1.0.0",
		"uptime_seconds": int(time.Since(s.start).Seconds()),
	})
}

func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	if err := s.db.Ping(ctx); err != nil {
		writeError(w, http.StatusServiceUnavailable, "database_unavailable", "Database is not reachable.", nil)
		return
	}
	if err := s.rdb.Ping(ctx).Err(); err != nil {
		writeError(w, http.StatusServiceUnavailable, "redis_unavailable", "Queue backend is not reachable.", nil)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ready", "checks": map[string]string{"postgres": "ok", "redis": "ok"}})
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	allowed, _, _ := s.queue.RateLimit(r.Context(), "km:rl:register:"+clientIP(r), 5, time.Hour)
	if !allowed {
		writeError(w, http.StatusTooManyRequests, "rate_limited", "Too many registration attempts.", nil)
		return
	}
	var req registerRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	req.Email = strings.ToLower(strings.TrimSpace(req.Email))
	req.Name = strings.TrimSpace(req.Name)
	req.OrgName = strings.TrimSpace(req.OrgName)
	if !security.ValidEmail(req.Email) || len(req.Name) < 2 || len(req.OrgName) < 2 {
		s.writeValidation(w, "Provide a valid organization name, your name and email address.")
		return
	}
	if security.IsFreeEmailDomain(req.Email) {
		writeError(w, http.StatusUnprocessableEntity, "organization_email_required", "Use your organization email address. Free email providers cannot create an organization. Team members are invited by their organization.", nil)
		return
	}
	if err := security.ValidatePassword(req.Password); err != nil {
		s.writeValidation(w, err.Error())
		return
	}
	if !s.cfg.RegistrationEnabled {
		var count int
		_ = s.db.QueryRow(r.Context(), `SELECT count(*) FROM users`).Scan(&count)
		if count > 0 {
			writeError(w, http.StatusForbidden, "registration_disabled", "Self-registration is disabled. Ask your organization owner to invite you.", nil)
			return
		}
	}
	hash, err := security.HashPassword(req.Password)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, "weak_password", err.Error(), nil)
		return
	}
	slug := security.Slugify(req.OrgName)
	tx, err := s.db.Begin(r.Context())
	if err != nil {
		s.dbError(w, err, "organization")
		return
	}
	defer func() { _ = tx.Rollback(r.Context()) }()
	var orgID, userID, createdAt string
	err = tx.QueryRow(r.Context(), `SELECT gen_random_uuid()::text, gen_random_uuid()::text`).Scan(&orgID, &userID)
	if err != nil {
		s.dbError(w, err, "organization")
		return
	}
	err = tx.QueryRow(r.Context(), `
		INSERT INTO organizations (id, name, slug) VALUES ($1,$2,$3)
		ON CONFLICT (slug) DO NOTHING RETURNING id::text, created_at::text`, orgID, req.OrgName, slug).Scan(&orgID, &createdAt)
	if err != nil {
		// Slug collision: retry with a suffix.
		suffix, _ := security.RandomHex(3)
		slug = slug + "-" + suffix
		err = tx.QueryRow(r.Context(), `
			INSERT INTO organizations (id, name, slug) VALUES ($1,$2,$3) RETURNING id::text, created_at::text`,
			orgID, req.OrgName, slug).Scan(&orgID, &createdAt)
		if err != nil {
			s.dbError(w, err, "organization")
			return
		}
	}
	_, err = tx.Exec(r.Context(), `
		INSERT INTO users (id, email, name, password_hash) VALUES ($1,$2,$3,$4)`,
		userID, req.Email, req.Name, hash)
	if err != nil {
		if strings.Contains(err.Error(), "users_email_lower_uidx") {
			writeError(w, http.StatusConflict, "email_in_use", "An account with this email already exists.", nil)
			return
		}
		s.dbError(w, err, "user")
		return
	}
	if _, err := tx.Exec(r.Context(), `INSERT INTO memberships (org_id, user_id, role_id) VALUES ($1,$2,'owner')`, orgID, userID); err != nil {
		s.dbError(w, err, "membership")
		return
	}
	if err := tx.Commit(r.Context()); err != nil {
		s.dbError(w, err, "organization")
		return
	}

	ac, err := s.createSession(w, r, userID, orgID)
	if err != nil {
		s.dbError(w, err, "session")
		return
	}
	s.auditSystem(r.Context(), orgID, "auth.register", "user", userID, map[string]any{"email": req.Email})
	s.notify(r.Context(), orgID, nil, "system", "Welcome to King Malhare", "Add your first asset and authorization record to begin an assessment.", "/assets")
	s.meResponse(w, r, ac)
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	req.Email = strings.ToLower(strings.TrimSpace(req.Email))
	rlKey := "km:rl:login:" + clientIP(r) + ":" + req.Email
	allowed, _, _ := s.queue.RateLimit(r.Context(), rlKey, 10, 15*time.Minute)
	if !allowed {
		writeError(w, http.StatusTooManyRequests, "rate_limited", "Too many sign-in attempts. Try again in a few minutes.", nil)
		return
	}
	var userID, hash, orgID string
	err := s.db.QueryRow(r.Context(), `
		SELECT u.id::text, u.password_hash, m.org_id::text
		FROM users u JOIN memberships m ON m.user_id = u.id
		WHERE lower(u.email)=lower($1) AND u.is_active
		ORDER BY (SELECT rank FROM roles WHERE id=m.role_id) DESC LIMIT 1`, req.Email).
		Scan(&userID, &hash, &orgID)
	if err != nil || !security.VerifyPassword(req.Password, hash) {
		s.auditSystem(r.Context(), orgID, "auth.login_failed", "user", "", map[string]any{"email": req.Email, "ip": clientIP(r)})
		writeError(w, http.StatusUnauthorized, "invalid_credentials", "Email or password is incorrect.", nil)
		return
	}
	if _, err := s.db.Exec(r.Context(), `UPDATE users SET last_login_at=now() WHERE id=$1`, userID); err != nil {
		s.log.Warn("last login update failed", "error", err)
	}
	ac, err := s.createSession(w, r, userID, orgID)
	if err != nil {
		s.dbError(w, err, "session")
		return
	}
	s.auditSystem(r.Context(), orgID, "auth.login", "user", userID, map[string]any{"ip": clientIP(r)})
	var orgName string
	_ = s.db.QueryRow(r.Context(), `SELECT name FROM organizations WHERE id=$1`, orgID).Scan(&orgName)
	s.notifyPlatformAdmins(r.Context(), userID, "Member signed in", req.Email+" signed in from "+clientIP(r)+" in "+orgName+".", "/platform?tab=activity")
	s.meResponse(w, r, ac)
}

func (s *Server) createSession(w http.ResponseWriter, r *http.Request, userID, orgID string) (*AuthContext, error) {
	token, err := security.RandomToken(32)
	if err != nil {
		return nil, err
	}
	csrf, err := security.RandomToken(24)
	if err != nil {
		return nil, err
	}
	expires := time.Now().Add(s.cfg.SessionTTL)
	_, err = s.db.Exec(r.Context(), `
		INSERT INTO sessions (user_id, org_id, token_hash, csrf_token, ip, user_agent, expires_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		userID, orgID, security.HashToken(s.cfg.SessionPepper, token), csrf, clientIP(r), truncate(r.UserAgent(), 400), expires)
	if err != nil {
		return nil, err
	}
	http.SetCookie(w, &http.Cookie{
		Name: "km_session", Value: token, Path: "/", HttpOnly: true,
		Secure: s.cfg.CookieSecure, SameSite: http.SameSiteLaxMode,
		Domain: s.cfg.CookieDomain, Expires: expires, MaxAge: int(s.cfg.SessionTTL.Seconds()),
	})
	http.SetCookie(w, &http.Cookie{
		Name: "km_csrf", Value: csrf, Path: "/", HttpOnly: false,
		Secure: s.cfg.CookieSecure, SameSite: http.SameSiteLaxMode,
		Domain: s.cfg.CookieDomain, Expires: expires, MaxAge: int(s.cfg.SessionTTL.Seconds()),
	})
	ac, err := s.loadSessionAuth(r.Context(), security.HashToken(s.cfg.SessionPepper, token))
	if err != nil {
		return nil, err
	}
	return ac, nil
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie("km_session"); err == nil && cookie.Value != "" {
		hash := security.HashToken(s.cfg.SessionPepper, cookie.Value)
		_, _ = s.db.Exec(r.Context(), `UPDATE sessions SET revoked_at=now() WHERE token_hash=$1`, hash)
	}
	clearCookie(w, "km_session", s.cfg.CookieDomain)
	clearCookie(w, "km_csrf", s.cfg.CookieDomain)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func clearCookie(w http.ResponseWriter, name, domain string) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: "", Path: "/", Domain: domain, MaxAge: -1, HttpOnly: name == "km_session", SameSite: http.SameSiteLaxMode})
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	s.meResponse(w, r, actor(r))
}

func (s *Server) meResponse(w http.ResponseWriter, r *http.Request, ac *AuthContext) {
	var u userDTO
	var lastLogin *time.Time
	var created time.Time
	err := s.db.QueryRow(r.Context(), `SELECT id::text, name, email, avatar_color, last_login_at, created_at FROM users WHERE id=$1`, ac.UserID).
		Scan(&u.ID, &u.Name, &u.Email, &u.AvatarColor, &lastLogin, &created)
	if err != nil {
		s.dbError(w, err, "user")
		return
	}
	if lastLogin != nil {
		v := lastLogin.UTC().Format(time.RFC3339)
		u.LastLoginAt = &v
	}
	u.CreatedAt = created.UTC().Format(time.RFC3339)
	var o orgDTO
	var orgCreated time.Time
	if err := s.db.QueryRow(r.Context(), `SELECT id::text, name, slug, emergency_stop, retention_days, created_at FROM organizations WHERE id=$1`, ac.OrgID).
		Scan(&o.ID, &o.Name, &o.Slug, &o.EmergencyStop, &o.RetentionDays, &orgCreated); err != nil {
		s.dbError(w, err, "organization")
		return
	}
	o.CreatedAt = orgCreated.UTC().Format(time.RFC3339)
	perms := make([]string, 0, len(ac.Permissions))
	for p := range ac.Permissions {
		perms = append(perms, p)
	}
	writeJSON(w, http.StatusOK, meResponse{User: u, Org: o, Role: ac.Role, Permissions: perms, PlatformAdmin: ac.PlatformAdmin, CSRFToken: ac.CSRF})
}

type changePasswordRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	var req changePasswordRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	ac := actor(r)
	if ac.ViaAPIKey {
		writeError(w, http.StatusForbidden, "session_required", "Password changes require a browser session.", nil)
		return
	}
	var hash string
	if err := s.db.QueryRow(r.Context(), `SELECT password_hash FROM users WHERE id=$1`, ac.UserID).Scan(&hash); err != nil {
		s.dbError(w, err, "user")
		return
	}
	if !security.VerifyPassword(req.CurrentPassword, hash) {
		writeError(w, http.StatusForbidden, "invalid_password", "Your current password is incorrect.", nil)
		return
	}
	newHash, err := security.HashPassword(req.NewPassword)
	if err != nil {
		s.writeValidation(w, err.Error())
		return
	}
	if _, err := s.db.Exec(r.Context(), `UPDATE users SET password_hash=$1 WHERE id=$2`, newHash, ac.UserID); err != nil {
		s.dbError(w, err, "user")
		return
	}
	_, _ = s.db.Exec(r.Context(), `UPDATE sessions SET revoked_at=now() WHERE user_id=$1 AND id<>$2`, ac.UserID, ac.SessionID)
	s.audit(r, "user.password_changed", "user", ac.UserID, nil)
	s.notify(r.Context(), ac.OrgID, &ac.UserID, "system", "Password changed", "Your password was updated and other sessions were signed out.", "/settings")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

type updateMeRequest struct {
	Name string `json:"name"`
}

func (s *Server) handleUpdateMe(w http.ResponseWriter, r *http.Request) {
	var req updateMeRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if utf8.RuneCountInString(req.Name) < 2 || len(req.Name) > 120 {
		s.writeValidation(w, "Name must be between 2 and 120 characters.")
		return
	}
	ac := actor(r)
	if _, err := s.db.Exec(r.Context(), `UPDATE users SET name=$1 WHERE id=$2`, req.Name, ac.UserID); err != nil {
		s.dbError(w, err, "user")
		return
	}
	s.audit(r, "user.updated", "user", ac.UserID, nil)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func clientIP(r *http.Request) string {
	if ip := r.Header.Get("X-Real-IP"); ip != "" {
		return ip
	}
	return strings.Split(r.RemoteAddr, ":")[0]
}
