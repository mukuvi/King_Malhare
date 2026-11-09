package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"runtime/debug"
	"strings"
	"time"

	"github.com/kingmalhare/api/internal/security"
	"github.com/redis/go-redis/v9"
)

type ctxKey string

const (
	ctxAuth ctxKey = "auth"
)

type AuthContext struct {
	UserID      string
	Email       string
	Name        string
	OrgID       string
	OrgName     string
	Role          string
	Permissions   map[string]bool
	PlatformAdmin bool
	SessionID     string
	CSRF          string
	ViaAPIKey     bool
}

func (a *AuthContext) Can(perm string) bool { return a != nil && a.Permissions[perm] }

func actor(r *http.Request) *AuthContext {
	a, _ := r.Context().Value(ctxAuth).(*AuthContext)
	return a
}

func (s *Server) recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				s.log.Error("panic recovered", "error", rec, "path", r.URL.Path, "stack", string(debug.Stack()))
				writeError(w, http.StatusInternalServerError, "internal_error", "An unexpected error occurred.", nil)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}
func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = 200
	}
	n, err := w.ResponseWriter.Write(b)
	w.bytes += n
	return n, err
}
func (w *statusWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (s *Server) requestLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w}
		next.ServeHTTP(sw, r)
		status := sw.status
		if status == 0 {
			status = 200
		}
		level := slog.LevelInfo
		if status >= 500 {
			level = slog.LevelError
		} else if status >= 400 {
			level = slog.LevelWarn
		}
		s.log.Log(r.Context(), level, "request",
			"method", r.Method, "path", r.URL.Path, "status", status,
			"duration_ms", time.Since(start).Milliseconds(), "request_id", r.Header.Get("X-Request-Id"))
	})
}

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'")
		if s.cfg.Env == "production" {
			h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) cors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" && s.cfg.AllowsOrigin(origin) {
			h := w.Header()
			h.Set("Access-Control-Allow-Origin", origin)
			h.Set("Access-Control-Allow-Credentials", "true")
			h.Set("Access-Control-Allow-Methods", "GET, POST, PATCH, PUT, DELETE, OPTIONS")
			h.Set("Access-Control-Allow-Headers", "Content-Type, X-CSRF-Token, Authorization, X-Requested-With")
			h.Set("Access-Control-Max-Age", "600")
			h.Add("Vary", "Origin")
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var ac *AuthContext
		var tokenHash []byte
		var err error

		authHeader := r.Header.Get("Authorization")
		if strings.HasPrefix(authHeader, "Bearer km_") {
			token := strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))
			tokenHash = security.HashToken(s.cfg.SessionPepper, token)
			ac, err = s.loadAPIKeyAuth(r.Context(), tokenHash)
			if err != nil {
				s.log.Debug("api key auth failed", "error", err)
			}
		} else {
			cookie, cerr := r.Cookie("km_session")
			if cerr == nil && cookie.Value != "" {
				tokenHash = security.HashToken(s.cfg.SessionPepper, cookie.Value)
				ac, err = s.loadSessionAuth(r.Context(), tokenHash)
				if err != nil {
					s.log.Debug("session auth failed", "error", err)
				}
			}
		}
		if ac == nil {
			writeError(w, http.StatusUnauthorized, "unauthenticated", "Sign in to continue.", nil)
			return
		}

		if !ac.ViaAPIKey && isMutating(r.Method) {
			csrf := r.Header.Get("X-CSRF-Token")
			if ac.CSRF == "" || !security.ConstantTimeEqual(csrf, ac.CSRF) {
				writeError(w, http.StatusForbidden, "csrf_failed", "The request could not be verified. Refresh the page and try again.", nil)
				return
			}
			if origin := r.Header.Get("Origin"); origin != "" && !s.cfg.AllowsOrigin(origin) {
				writeError(w, http.StatusForbidden, "origin_rejected", "Request origin is not allowed.", nil)
				return
			}
		}

		ctx := context.WithValue(r.Context(), ctxAuth, ac)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (s *Server) loadSessionAuth(ctx context.Context, tokenHash []byte) (*AuthContext, error) {
	var ac AuthContext
	var perms []string
	err := s.db.QueryRow(ctx, `
		SELECT s.id::text, s.csrf_token, u.id::text, u.email, u.name, u.is_platform_admin,
		       s.org_id::text, o.name, m.role_id,
		       COALESCE(array_agg(rp.permission_id) FILTER (WHERE rp.permission_id IS NOT NULL), '{}')
		FROM sessions s
		JOIN users u ON u.id = s.user_id AND u.is_active
		JOIN organizations o ON o.id = s.org_id
		JOIN memberships m ON m.user_id = u.id AND m.org_id = s.org_id
		LEFT JOIN role_permissions rp ON rp.role_id = m.role_id
		WHERE s.token_hash = $1 AND s.revoked_at IS NULL AND s.expires_at > now()
		GROUP BY s.id, u.id, o.id, m.role_id`, tokenHash).
		Scan(&ac.SessionID, &ac.CSRF, &ac.UserID, &ac.Email, &ac.Name, &ac.PlatformAdmin, &ac.OrgID, &ac.OrgName, &ac.Role, &perms)
	if err != nil {
		return nil, err
	}
	ac.Permissions = map[string]bool{}
	for _, p := range perms {
		ac.Permissions[p] = true
	}
	ac.ViaAPIKey = false
	_, _ = s.db.Exec(ctx, `UPDATE sessions SET last_seen_at = now() WHERE id = $1 AND last_seen_at < now() - interval '5 minutes'`, ac.SessionID)
	return &ac, nil
}

func (s *Server) loadAPIKeyAuth(ctx context.Context, tokenHash []byte) (*AuthContext, error) {
	var ac AuthContext
	var scopes []string
	err := s.db.QueryRow(ctx, `
		SELECT c.id::text, c.user_id::text, u.email, u.name, u.is_platform_admin, c.org_id::text, o.name, c.scopes
		FROM api_credentials c
		JOIN users u ON u.id = c.user_id AND u.is_active
		JOIN organizations o ON o.id = c.org_id
		WHERE c.token_hash = $1 AND c.revoked_at IS NULL
		  AND (c.expires_at IS NULL OR c.expires_at > now())`, tokenHash).
		Scan(&ac.SessionID, &ac.UserID, &ac.Email, &ac.Name, &ac.PlatformAdmin, &ac.OrgID, &ac.OrgName, &scopes)
	if err != nil {
		return nil, err
	}
	ac.Role = "api"
	ac.Permissions = map[string]bool{}
	for _, p := range scopes {
		ac.Permissions[p] = true
	}
	ac.ViaAPIKey = true
	_, _ = s.db.Exec(ctx, `UPDATE api_credentials SET last_used_at = now() WHERE id = $1`, ac.SessionID)
	return &ac, nil
}

func (s *Server) internalAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" || r.URL.Path == "/metrics" {
			next.ServeHTTP(w, r)
			return
		}
		if s.cfg.WorkerToken == "" {
			writeError(w, http.StatusServiceUnavailable, "worker_auth_unconfigured", "Worker service token is not configured.", nil)
			return
		}
		if !security.ConstantTimeEqual(r.Header.Get("X-Service-Token"), s.cfg.WorkerToken) {
			writeError(w, http.StatusUnauthorized, "invalid_service_token", "Invalid service token.", nil)
			return
		}
		if strings.TrimSpace(r.Header.Get("X-Worker-Id")) == "" {
			writeError(w, http.StatusBadRequest, "worker_id_required", "X-Worker-Id header is required.", nil)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) requirePerm(perm string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ac := actor(r)
		if ac == nil || !ac.Can(perm) {
			writeError(w, http.StatusForbidden, "forbidden", "You do not have permission to perform this action.", map[string]any{"required": perm})
			return
		}
		next(w, r)
	}
}

func (s *Server) requirePlatformAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ac := actor(r)
		if ac == nil || !ac.PlatformAdmin {
			writeError(w, http.StatusForbidden, "platform_admin_required", "This area is restricted to platform administrators.", nil)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) rateLimit(limit int, window time.Duration, prefix string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ac := actor(r)
			if ac == nil {
				next.ServeHTTP(w, r)
				return
			}
			key := fmt.Sprintf("km:rl:%s:%s", prefix, ac.UserID)
			allowed, remaining, err := s.queue.RateLimit(r.Context(), key, limit, window)
			if err != nil && err != redis.Nil {
				s.log.Warn("rate limiter unavailable", "error", err)
			}
			w.Header().Set("X-RateLimit-Remaining", fmt.Sprintf("%d", remaining))
			if !allowed {
				w.Header().Set("Retry-After", fmt.Sprintf("%d", int(window.Seconds())))
				writeError(w, http.StatusTooManyRequests, "rate_limited", "Too many requests. Slow down and try again.", nil)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func isMutating(m string) bool {
	switch m {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	}
	return false
}

func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	defer r.Body.Close()
	r.Body = http.MaxBytesReader(w, r.Body, 2<<20)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json", "Request body is not valid JSON.", map[string]any{"detail": err.Error()})
		return false
	}
	return true
}

func requireID(w http.ResponseWriter, r *http.Request, key string) (string, bool) {
	v := chiURLParam(r, key)
	if v == "" {
		writeError(w, http.StatusBadRequest, "missing_id", "Missing resource identifier.", nil)
		return "", false
	}
	return v, true
}
