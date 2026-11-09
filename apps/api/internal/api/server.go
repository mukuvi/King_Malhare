package api

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/kingmalhare/api/internal/config"
	"github.com/kingmalhare/api/internal/scanner"
	"github.com/kingmalhare/api/internal/security"
	"github.com/kingmalhare/api/internal/storage"
	"github.com/redis/go-redis/v9"
)

type Server struct {
	cfg    *config.Config
	db     *pgxpool.Pool
	rdb    *redis.Client
	queue  *scanner.Queue
	store  storage.Store
	cipher *security.CredentialCipher
	log    *slog.Logger
	start  time.Time
}

func NewServer(cfg *config.Config, db *pgxpool.Pool, rdb *redis.Client, q *scanner.Queue, store storage.Store, cipher *security.CredentialCipher, log *slog.Logger) *Server {
	return &Server{cfg: cfg, db: db, rdb: rdb, queue: q, store: store, cipher: cipher, log: log, start: time.Now()}
}

func (s *Server) PublicRouter() http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(s.recoverer)
	r.Use(s.requestLogger)
	r.Use(s.securityHeaders)
	r.Use(s.cors)
	r.Use(middleware.Timeout(90 * time.Second))

	r.Route("/api/v1", func(r chi.Router) {
		r.Get("/health", s.handleHealth)
		r.Get("/ready", s.handleReady)
		r.Get("/openapi.yaml", s.handleOpenAPI)
		r.Get("/docs", s.handleDocs)

		r.Post("/auth/register", s.handleRegister)
		r.Post("/auth/login", s.handleLogin)
		r.Post("/auth/logout", s.handleLogout)

		r.Group(func(r chi.Router) {
			r.Use(s.authenticate)
			r.Use(s.rateLimit(600, time.Minute, "api"))
			r.Get("/auth/me", s.handleMe)
			r.Post("/auth/change-password", s.handleChangePassword)

			r.Get("/stats/overview", s.handleOverview)
			r.Get("/stats/trends", s.handleTrends)
			r.Get("/stats/activity", s.handleActivity)

			r.Get("/org", s.handleGetOrg)
			r.Patch("/org", s.requirePerm("org:manage", s.handleUpdateOrg))
			r.Get("/org/members", s.requirePerm("assets:read", s.handleListMembers))
			r.Post("/org/members", s.requirePerm("members:manage", s.handleCreateMember))
			r.Patch("/org/members/{userID}", s.requirePerm("members:manage", s.handleUpdateMember))
			r.Delete("/org/members/{userID}", s.requirePerm("members:manage", s.handleRemoveMember))

			r.Get("/assets", s.requirePerm("assets:read", s.handleListAssets))
			r.Post("/assets", s.requirePerm("assets:write", s.handleCreateAsset))
			r.Get("/assets/{assetID}", s.requirePerm("assets:read", s.handleGetAsset))
			r.Patch("/assets/{assetID}", s.requirePerm("assets:write", s.handleUpdateAsset))
			r.Delete("/assets/{assetID}", s.requirePerm("assets:write", s.handleArchiveAsset))
			r.Get("/assets/{assetID}/authorizations", s.requirePerm("assets:read", s.handleListAuthorizations))
			r.Post("/assets/{assetID}/authorizations", s.requirePerm("auth:manage", s.handleCreateAuthorization))
			r.Patch("/authorizations/{authorizationID}", s.requirePerm("auth:manage", s.handleRevokeAuthorization))
			r.Get("/assets/{assetID}/scans", s.requirePerm("scans:read", s.handleAssetScans))
			r.Get("/assets/{assetID}/findings", s.requirePerm("findings:read", s.handleAssetFindings))

			r.Get("/scan-profiles", s.requirePerm("scans:read", s.handleListProfiles))
			r.Post("/scan-profiles", s.requirePerm("scans:write", s.handleCreateProfile))
			r.Patch("/scan-profiles/{profileID}", s.requirePerm("scans:write", s.handleUpdateProfile))
			r.Delete("/scan-profiles/{profileID}", s.requirePerm("scans:write", s.handleDeleteProfile))
			r.Get("/scanners", s.requirePerm("scans:read", s.handleScanners))

			r.Get("/scans", s.requirePerm("scans:read", s.handleListScans))
			r.Post("/scans", s.requirePerm("scans:write", s.handleCreateScan))
			r.Get("/scans/compare", s.requirePerm("scans:read", s.handleCompareScans))
			r.Get("/scans/{scanID}", s.requirePerm("scans:read", s.handleGetScan))
			r.Post("/scans/{scanID}/cancel", s.requirePerm("scans:write", s.handleCancelScan))
			r.Get("/scans/{scanID}/events", s.requirePerm("scans:read", s.handleScanEvents))
			r.Get("/scans/{scanID}/executions", s.requirePerm("scans:read", s.handleScanExecutions))
			r.Get("/scans/{scanID}/results", s.requirePerm("scans:read", s.handleScanResults))
			r.Get("/scans/{scanID}/findings", s.requirePerm("findings:read", s.handleScanFindings))
			r.Post("/scans/emergency-stop", s.requirePerm("org:manage", s.handleEmergencyStop))
			r.Delete("/emergency-stop", s.requirePerm("org:manage", s.handleClearEmergencyStop))

			r.Get("/findings", s.requirePerm("findings:read", s.handleListFindings))
			r.Get("/findings/{findingID}", s.requirePerm("findings:read", s.handleGetFinding))
			r.Patch("/findings/{findingID}", s.requirePerm("findings:write", s.handleUpdateFinding))
			r.Post("/findings/{findingID}/verify", s.requirePerm("findings:write", s.handleVerifyFinding))
			r.Post("/findings/{findingID}/remediation", s.requirePerm("findings:write", s.handleCreateRemediation))
			r.Get("/findings/{findingID}/evidence", s.requirePerm("findings:read", s.handleListEvidence))
			r.Post("/findings/{findingID}/evidence", s.requirePerm("findings:write", s.handleUploadEvidence))
			r.Get("/evidence/{evidenceID}/download", s.requirePerm("findings:read", s.handleDownloadEvidence))

			r.Get("/intel/cve/{cveID}", s.requirePerm("findings:read", s.handleCVE))
			r.Get("/intel/cwes", s.requirePerm("findings:read", s.handleCWEs))
			r.Get("/intel/recent", s.requirePerm("findings:read", s.handleRecentIntel))

			r.Get("/reports", s.requirePerm("reports:read", s.handleListReports))
			r.Post("/reports", s.requirePerm("reports:write", s.handleCreateReport))
			r.Get("/reports/{reportID}", s.requirePerm("reports:read", s.handleGetReport))
			r.Get("/reports/{reportID}/html", s.requirePerm("reports:read", s.handleReportHTML))
			r.Get("/reports/{reportID}/pdf", s.requirePerm("reports:read", s.handleReportPDF))
			r.Delete("/reports/{reportID}", s.requirePerm("reports:write", s.handleDeleteReport))

			r.Get("/notifications", s.handleListNotifications)
			r.Post("/notifications/read", s.handleReadNotifications)
			r.Delete("/notifications", s.handleClearNotifications)
			r.Get("/audit-events", s.requirePerm("audit:read", s.handleAuditEvents))
			r.Delete("/audit-events", s.requirePerm("org:manage", s.handleClearAuditEvents))

			r.Get("/cloud-connections", s.requirePerm("integrations:manage", s.handleListCloud))
			r.Post("/cloud-connections", s.requirePerm("integrations:manage", s.handleCreateCloud))
			r.Delete("/cloud-connections/{connectionID}", s.requirePerm("integrations:manage", s.handleDeleteCloud))
			r.Post("/cloud-connections/{connectionID}/validate", s.requirePerm("integrations:manage", s.handleValidateCloud))
			r.Get("/integrations", s.requirePerm("integrations:manage", s.handleIntegrations))

			r.Get("/api-keys", s.requirePerm("api_keys:manage", s.handleListAPIKeys))
			r.Post("/api-keys", s.requirePerm("api_keys:manage", s.handleCreateAPIKey))
			r.Delete("/api-keys/{keyID}", s.requirePerm("api_keys:manage", s.handleRevokeAPIKey))

			r.Get("/schedules", s.requirePerm("integrations:manage", s.handleListSchedules))
			r.Post("/schedules", s.requirePerm("integrations:manage", s.handleCreateSchedule))
			r.Patch("/schedules/{scheduleID}", s.requirePerm("integrations:manage", s.handleUpdateSchedule))
			r.Delete("/schedules/{scheduleID}", s.requirePerm("integrations:manage", s.handleDeleteSchedule))

			r.Patch("/me", s.handleUpdateMe)

			r.Route("/platform", func(r chi.Router) {
				r.Use(s.requirePlatformAdmin)
				r.Get("/overview", s.handlePlatformOverview)
				r.Get("/organizations", s.handlePlatformOrganizations)
				r.Get("/organizations/{orgID}", s.handlePlatformOrganization)
				r.Patch("/organizations/{orgID}", s.handlePlatformUpdateOrganization)
				r.Patch("/organizations/{orgID}/members/{userID}", s.handlePlatformUpdateMember)
				r.Delete("/organizations/{orgID}/members/{userID}", s.handlePlatformRemoveMember)
				r.Get("/users", s.handlePlatformUsers)
				r.Get("/users/{userID}", s.handlePlatformUserDetail)
				r.Patch("/users/{userID}", s.handlePlatformUpdateUser)
				r.Post("/users/{userID}/reset-password", s.handlePlatformResetPassword)
				r.Post("/users/{userID}/sign-out", s.handlePlatformSignOutUser)
				r.Get("/sessions", s.handlePlatformSessions)
				r.Delete("/sessions", s.handlePlatformRevokeAllSessions)
				r.Delete("/sessions/{sessionID}", s.handlePlatformRevokeSession)
				r.Get("/activity", s.handlePlatformActivity)
				r.Delete("/activity", s.handlePlatformClearActivity)
			})
		})
	})
	r.NotFound(func(w http.ResponseWriter, r *http.Request) {
		writeError(w, http.StatusNotFound, "not_found", "The requested endpoint does not exist.", nil)
	})
	r.MethodNotAllowed(func(w http.ResponseWriter, r *http.Request) {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed for this endpoint.", nil)
	})
	return r
}

func (s *Server) InternalRouter() http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(s.recoverer)
	r.Use(s.internalAuth)
	r.Route("/internal/worker", func(r chi.Router) {
		r.Post("/jobs/{scanID}/claim", s.handleWorkerClaim)
		r.Post("/jobs/{scanID}/progress", s.handleWorkerProgress)
		r.Post("/jobs/{scanID}/executions", s.handleWorkerExecution)
		r.Post("/jobs/{scanID}/results", s.handleWorkerResults)
		r.Post("/jobs/{scanID}/complete", s.handleWorkerComplete)
		r.Get("/jobs/{scanID}/cancel-state", s.handleWorkerCancelState)
		r.Get("/config/{orgID}", s.handleWorkerConfig)
	})
	r.Get("/health", s.handleHealth)
	r.Get("/metrics", s.handleMetrics)
	return r
}

func (s *Server) StartReaper(ctx context.Context) {
	ticker := time.NewTicker(2 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.reapStaleScans(ctx)
			s.expireSessions(ctx)
		}
	}
}

func (s *Server) reapStaleScans(ctx context.Context) {
	cutoff := time.Now().Add(-s.cfg.ScanStale)
	rows, err := s.db.Query(ctx, `
		SELECT id, org_id, attempt FROM scans
		WHERE status IN ('initializing','running') AND COALESCE(last_heartbeat_at, started_at, queued_at) < $1`, cutoff)
	if err != nil {
		s.log.Error("reaper query failed", "error", err)
		return
	}
	type stale struct {
		id, orgID string
		attempt   int
	}
	var staleScans []stale
	for rows.Next() {
		var x stale
		if rows.Scan(&x.id, &x.orgID, &x.attempt) == nil {
			staleScans = append(staleScans, x)
		}
	}
	rows.Close()
	for _, x := range staleScans {
		_, err := s.db.Exec(ctx, `UPDATE scans SET status='failed', error=$2, finished_at=now()
			WHERE id=$1 AND status IN ('initializing','running')`,
			x.id, "Worker heartbeat lost. The scan was stopped by the reaper and can be retried.")
		if err == nil {
			s.queue.Publish(ctx, scanner.Event{Type: "status", ScanID: x.id, Status: "failed", Message: "Worker heartbeat lost", At: time.Now().UTC()})
			s.auditSystem(ctx, x.orgID, "scan.reaped", "scan", x.id, map[string]any{"attempt": x.attempt})
		}
	}
	if len(staleScans) > 0 {
		s.log.Warn("reaped stale scans", "count", len(staleScans))
	}
}

func (s *Server) expireSessions(ctx context.Context) {
	_, _ = s.db.Exec(ctx, `DELETE FROM sessions WHERE expires_at < now() - interval '7 days' OR revoked_at < now() - interval '7 days'`)
}
