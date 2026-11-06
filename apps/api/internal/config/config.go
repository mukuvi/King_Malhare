package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Env                 string
	AppOrigin           string
	PublicAPIURL        string
	APIAddr             string
	InternalAddr        string
	LogLevel            string
	RegistrationEnabled bool
	AllowPrivateTargets bool

	DatabaseURL string
	RedisURL    string
	QueueKey    string
	EventsChan  string

	SessionPepper string
	SessionTTL    time.Duration
	CookieSecure  bool
	CookieDomain  string
	CredentialKey string
	WorkerToken   string

	StorageDriver string
	StoragePath   string
	S3Endpoint    string
	S3Bucket      string
	S3AccessKey   string
	S3SecretKey   string
	S3UseSSL      bool

	VulnIntelURL  string
	ScanStale     time.Duration
	DataRetention int
}

func Load() (*Config, error) {
	LoadDotEnv()
	c := &Config{
		Env:                 env("APP_ENV", "development"),
		AppOrigin:           strings.TrimRight(env("APP_ORIGIN", "http://localhost:5173"), "/"),
		PublicAPIURL:        env("PUBLIC_API_URL", "http://localhost:8080"),
		APIAddr:             env("API_ADDR", ":"+env("API_PORT", "8080")),
		InternalAddr:        env("INTERNAL_LISTEN_ADDR", ":8081"),
		LogLevel:            env("LOG_LEVEL", "info"),
		RegistrationEnabled: envBool("REGISTRATION_ENABLED", true),
		AllowPrivateTargets: envBool("ALLOW_PRIVATE_TARGETS", false),
		DatabaseURL:         env("DATABASE_URL", ""),
		RedisURL:            env("REDIS_URL", "redis://localhost:6379/0"),
		QueueKey:            env("SCAN_QUEUE", "km:scan:jobs"),
		EventsChan:          env("SCAN_EVENTS_CHANNEL", "km:scan:events"),
		SessionPepper:       env("SESSION_PEPPER", ""),
		CookieSecure:        envBool("COOKIE_SECURE", false),
		CookieDomain:        env("COOKIE_DOMAIN", ""),
		CredentialKey:       env("CREDENTIAL_ENCRYPTION_KEY", ""),
		WorkerToken:         env("WORKER_SERVICE_TOKEN", ""),
		StorageDriver:       env("STORAGE_DRIVER", "local"),
		StoragePath:         env("STORAGE_LOCAL_PATH", "./data/storage"),
		S3Endpoint:          env("S3_ENDPOINT", ""),
		S3Bucket:            env("S3_BUCKET", "king-malhare"),
		S3AccessKey:         env("S3_ACCESS_KEY", ""),
		S3SecretKey:         env("S3_SECRET_KEY", ""),
		S3UseSSL:            envBool("S3_USE_SSL", false),
		VulnIntelURL:        env("VULN_INTEL_URL", "https://cve.circl.lu"),
		ScanStale:           envDuration("SCAN_STALE_MINUTES", 30*time.Minute),
		DataRetention:       envInt("DATA_RETENTION_DAYS", 365),
	}
	if d, err := time.ParseDuration(env("SESSION_TTL_HOURS", "12") + "h"); err == nil {
		c.SessionTTL = d
	} else {
		c.SessionTTL = 12 * time.Hour
	}
	if c.DatabaseURL == "" {
		return nil, fmt.Errorf("DATABASE_URL is required")
	}
	if c.SessionPepper == "" {
		return nil, fmt.Errorf("SESSION_PEPPER is required")
	}
	if len(c.CredentialKey) != 64 {
		return nil, fmt.Errorf("CREDENTIAL_ENCRYPTION_KEY must be 64 hex characters (32 bytes)")
	}
	if c.Env == "production" {
		if !c.CookieSecure {
			return nil, fmt.Errorf("COOKIE_SECURE=true is required in production")
		}
		if c.WorkerToken == "" || strings.HasPrefix(c.WorkerToken, "replace-") || strings.HasPrefix(c.WorkerToken, "dev0") {
			return nil, fmt.Errorf("WORKER_SERVICE_TOKEN must be set in production")
		}
		if strings.Contains(c.AppOrigin, "localhost") {
			return nil, fmt.Errorf("APP_ORIGIN must be the public HTTPS origin in production")
		}
		if strings.HasPrefix(c.CredentialKey, "fedcba98") || strings.HasPrefix(c.SessionPepper, "0123456789abcdef") {
			return nil, fmt.Errorf("development secrets detected; replace SESSION_PEPPER and CREDENTIAL_ENCRYPTION_KEY in production")
		}
	}
	return c, nil
}

func IsProduction(c *Config) bool { return c.Env == "production" }

func env(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}

func envBool(k string, def bool) bool {
	v := strings.TrimSpace(os.Getenv(k))
	if v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return def
	}
	return b
}

func envInt(k string, def int) int {
	v := strings.TrimSpace(os.Getenv(k))
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}

func envDuration(k string, def time.Duration) time.Duration {
	v := strings.TrimSpace(os.Getenv(k))
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return def
	}
	return d
}
