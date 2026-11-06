package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/kingmalhare/api/internal/api"
	"github.com/kingmalhare/api/internal/config"
	"github.com/kingmalhare/api/internal/db"
	"github.com/kingmalhare/api/internal/scanner"
	"github.com/kingmalhare/api/internal/security"
	"github.com/kingmalhare/api/internal/storage"
	"github.com/redis/go-redis/v9"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintln(os.Stderr, "configuration error:", err)
		os.Exit(1)
	}
	level := slog.LevelInfo
	switch strings.ToLower(cfg.LogLevel) {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}
	var handler slog.Handler
	if cfg.Env == "production" {
		handler = slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level})
	} else {
		handler = slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: level})
	}
	logger := slog.New(handler)
	slog.SetDefault(logger)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pool, err := db.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		logger.Error("database connection failed", "error", err)
		os.Exit(1)
	}
	defer pool.Close()
	if err := db.Migrate(ctx, pool, logger); err != nil {
		logger.Error("migration failed", "error", err)
		os.Exit(1)
	}

	opt, err := redis.ParseURL(cfg.RedisURL)
	if err != nil {
		logger.Error("redis url invalid", "error", err)
		os.Exit(1)
	}
	rdb := redis.NewClient(opt)
	defer rdb.Close()
	pingCtx, pingCancel := context.WithTimeout(ctx, 5*time.Second)
	if err := rdb.Ping(pingCtx).Err(); err != nil {
		pingCancel()
		logger.Error("redis unavailable", "error", err)
		os.Exit(1)
	}
	pingCancel()

	cipher, err := security.NewCredentialCipher(cfg.CredentialKey)
	if err != nil {
		logger.Error("credential cipher failed", "error", err)
		os.Exit(1)
	}
	store, err := storage.New(cfg.StorageDriver, cfg.StoragePath, cfg.S3Endpoint, cfg.S3Bucket, cfg.S3AccessKey, cfg.S3SecretKey, cfg.S3UseSSL)
	if err != nil {
		logger.Error("storage initialisation failed", "error", err)
		os.Exit(1)
	}
	queue := scanner.NewQueue(rdb, cfg.QueueKey, cfg.EventsChan)
	srv := api.NewServer(cfg, pool, rdb, queue, store, cipher, logger)

	go srv.StartReaper(ctx)
	go srv.StartScheduler(ctx)

	public := &http.Server{
		Addr:              cfg.APIAddr,
		Handler:           srv.PublicRouter(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       45 * time.Second,
		WriteTimeout:      0, // SSE streams do not have a fixed write deadline
		IdleTimeout:       120 * time.Second,
	}
	internal := &http.Server{
		Addr:              cfg.InternalAddr,
		Handler:           srv.InternalRouter(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	errCh := make(chan error, 2)
	go func() {
		logger.Info("public API listening", "addr", cfg.APIAddr, "env", cfg.Env, "origin", cfg.AppOrigin)
		if err := public.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()
	go func() {
		logger.Info("internal worker API listening", "addr", cfg.InternalAddr)
		if err := internal.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	select {
	case sig := <-stop:
		logger.Info("shutdown signal received", "signal", sig.String())
	case err := <-errCh:
		logger.Error("server error", "error", err)
	}

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer shutdownCancel()
	_ = public.Shutdown(shutdownCtx)
	_ = internal.Shutdown(shutdownCtx)
	cancel()
	logger.Info("shutdown complete")
}
