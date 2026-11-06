SHELL := /bin/bash
.DEFAULT_GOAL := help

help: ## Show available targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[33m%-22s\033[0m %s\n", $$1, $$2}'

env: ## Create .env from example if missing
	@test -f .env || cp .env.example .env

up: ## Start infrastructure dependencies
	docker compose up -d postgres redis

down: ## Stop all compose services
	docker compose down

migrate: ## Apply database migrations
	cd apps/api && go run ./cmd/kmctl migrate

seed: ## Seed roles, permissions, scan profiles, CWE catalog
	cd apps/api && go run ./cmd/kmctl seed

admin: ## Create an owner account (EMAIL=... PASSWORD=... ORG=...)
	cd apps/api && go run ./cmd/kmctl create-admin --email "$(EMAIL)" --password "$(PASSWORD)" --org "$(ORG)"

dev-api: ## Run API with hot reload disabled
	cd apps/api && go run ./cmd/server

dev-web: ## Run Vite dev server
	cd apps/web && npm run dev

dev-worker: ## Run one scanner worker on the host
	cd apps/scanner-workers && python3 -m venv .venv 2>/dev/null || true; \
	.venv/bin/pip install -q -r requirements.txt; \
	.venv/bin/python -m km_worker.main

test: ## Run all tests
	cd apps/api && go test ./...
	cd apps/web && npm run test -- --run
	cd apps/scanner-workers && .venv/bin/python -m pytest -q

build: ## Build API + web
	cd apps/api && go build ./...
	cd apps/web && npm run build

fmt: ## Format Go and frontend sources
	cd apps/api && gofmt -w .
	cd apps/web && npm run format || true

clean: ## Remove build artefacts
	rm -rf data/storage apps/web/dist

db-reset: ## DESTRUCTIVE: drop the local schema and re-run migrations (CONFIRM=RESET)
	@test "$(CONFIRM)" = "RESET" || (echo "Refusing: re-run with CONFIRM=RESET"; exit 1)
	docker compose exec -T postgres psql -U "$${POSTGRES_USER:-kingmalhare}" -d "$${POSTGRES_DB:-kingmalhare}" -c "DROP SCHEMA public CASCADE; CREATE SCHEMA public;"
	$(MAKE) migrate
