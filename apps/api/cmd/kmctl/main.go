package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/kingmalhare/api/internal/config"
	"github.com/kingmalhare/api/internal/db"
	"github.com/kingmalhare/api/internal/security"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}
	command := os.Args[1]
	switch command {
	case "migrate":
		withDB(func(ctx context.Context, cfg *config.Config, pool *pgxpool.Pool) {
			fmt.Println("Migrations are up to date.")
		})
	case "seed":
		withDB(func(ctx context.Context, cfg *config.Config, pool *pgxpool.Pool) {
			var roles, perms, profiles, cwes int
			_ = pool.QueryRow(ctx, `SELECT count(*) FROM roles`).Scan(&roles)
			_ = pool.QueryRow(ctx, `SELECT count(*) FROM permissions`).Scan(&perms)
			_ = pool.QueryRow(ctx, `SELECT count(*) FROM scan_profiles WHERE is_system`).Scan(&profiles)
			_ = pool.QueryRow(ctx, `SELECT count(*) FROM cwe_catalog`).Scan(&cwes)
			fmt.Printf("Seed data present: %d roles, %d permissions, %d system profiles, %d CWE records.\n", roles, perms, profiles, cwes)
		})
	case "create-admin":
		createAdmin()
	case "platform-admin":
		setPlatformAdmin()
	case "version":
		fmt.Println("King Malhare API 1.0.0")
	default:
		usage()
		os.Exit(1)
	}
}

func withDB(fn func(context.Context, *config.Config, *pgxpool.Pool)) {
	fmt.Println("Loading configuration…")
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintln(os.Stderr, "configuration error:", err)
		os.Exit(1)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	pool, err := db.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		fmt.Fprintln(os.Stderr, "database error:", err)
		os.Exit(1)
	}
	defer pool.Close()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	if err := db.Migrate(ctx, pool, logger); err != nil {
		fmt.Fprintln(os.Stderr, "migration error:", err)
		os.Exit(1)
	}
	fn(ctx, cfg, pool)
}

func createAdmin() {
	fs := flag.NewFlagSet("create-admin", flag.ExitOnError)
	email := fs.String("email", "", "owner email address")
	password := fs.String("password", "", "password (omit to generate one)")
	name := fs.String("name", "Security Owner", "display name")
	orgName := fs.String("org", "", "organization name")
	_ = fs.Parse(os.Args[2:])
	if *email == "" || *orgName == "" {
		fmt.Fprintln(os.Stderr, "--email and --org are required")
		os.Exit(1)
	}
	*email = strings.ToLower(strings.TrimSpace(*email))
	if !security.ValidEmail(*email) {
		fmt.Fprintln(os.Stderr, "invalid email")
		os.Exit(1)
	}
	generated := false
	if *password == "" {
		tok, err := security.RandomToken(18)
		if err != nil {
			fmt.Fprintln(os.Stderr, "could not generate password")
			os.Exit(1)
		}
		*password = "Km1!" + tok
		generated = true
	}
	if err := security.ValidatePassword(*password); err != nil {
		fmt.Fprintln(os.Stderr, "password policy:", err)
		os.Exit(1)
	}
	hash, err := security.HashPassword(*password)
	if err != nil {
		fmt.Fprintln(os.Stderr, "hash error:", err)
		os.Exit(1)
	}
	withDB(func(ctx context.Context, cfg *config.Config, p *pgxpool.Pool) {
		var orgID, userID string
		err := p.QueryRow(ctx, `SELECT id::text FROM organizations WHERE lower(name)=lower($1) LIMIT 1`, *orgName).Scan(&orgID)
		if err != nil {
			slug := security.Slugify(*orgName)
			if err := p.QueryRow(ctx, `INSERT INTO organizations (name, slug) VALUES ($1,$2) RETURNING id::text`, *orgName, slug).Scan(&orgID); err != nil {
				suffix, _ := security.RandomHex(2)
				err = p.QueryRow(ctx, `INSERT INTO organizations (name, slug) VALUES ($1,$2) RETURNING id::text`, *orgName, slug+"-"+suffix).Scan(&orgID)
				if err != nil {
					fmt.Fprintln(os.Stderr, "create organization:", err)
					os.Exit(1)
				}
			}
		}
		err = p.QueryRow(ctx, `SELECT id::text FROM users WHERE lower(email)=lower($1)`, *email).Scan(&userID)
		if err != nil {
			if err := p.QueryRow(ctx, `INSERT INTO users (email, name, password_hash) VALUES ($1,$2,$3) RETURNING id::text`, *email, *name, hash).Scan(&userID); err != nil {
				fmt.Fprintln(os.Stderr, "create user:", err)
				os.Exit(1)
			}
		} else if *password != "" {
			_, _ = p.Exec(ctx, `UPDATE users SET password_hash=$1 WHERE id=$2`, hash, userID)
		}
		_, _ = p.Exec(ctx, `INSERT INTO memberships (org_id,user_id,role_id) VALUES ($1,$2,'owner')
			ON CONFLICT (org_id,user_id) DO UPDATE SET role_id='owner'`, orgID, userID)
		fmt.Println("Owner account ready.")
		fmt.Println("  email:", *email)
		if generated {
			fmt.Println("  password:", *password)
		} else {
			fmt.Println("  password: (the one you supplied)")
		}
		fmt.Println("  organization:", *orgName)
		fmt.Println("Sign in at the web console. Change the generated password after first login.")
	})
}

func setPlatformAdmin() {
	fs := flag.NewFlagSet("platform-admin", flag.ExitOnError)
	email := fs.String("email", "", "user email address")
	revoke := fs.Bool("revoke", false, "remove platform admin access instead of granting it")
	_ = fs.Parse(os.Args[2:])
	if *email == "" {
		fmt.Fprintln(os.Stderr, "--email is required")
		os.Exit(1)
	}
	*email = strings.ToLower(strings.TrimSpace(*email))
	if !security.ValidEmail(*email) {
		fmt.Fprintln(os.Stderr, "invalid email")
		os.Exit(1)
	}
	withDB(func(ctx context.Context, cfg *config.Config, p *pgxpool.Pool) {
		var userID string
		if err := p.QueryRow(ctx, `SELECT id::text FROM users WHERE lower(email)=lower($1)`, *email).Scan(&userID); err != nil {
			fmt.Fprintln(os.Stderr, "user not found:", err)
			os.Exit(1)
		}
		if _, err := p.Exec(ctx, `UPDATE users SET is_platform_admin=$1 WHERE id=$2`, !*revoke, userID); err != nil {
			fmt.Fprintln(os.Stderr, "update platform admin:", err)
			os.Exit(1)
		}
		if *revoke {
			fmt.Println("Platform admin access revoked for", *email)
		} else {
			fmt.Println("Platform admin access granted to", *email)
		}
	})
}

func usage() {
	fmt.Println(`King Malhare control utility

Usage:
  kmctl migrate
  kmctl seed
  kmctl create-admin --email you@example.com --org "Your Org" [--password ...] [--name ...]
  kmctl platform-admin --email you@example.com [--revoke]
  kmctl version`)
}
