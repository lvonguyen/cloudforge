.PHONY: build run dev test clean docker-build docker-up docker-down migrate lint fmt help build-cspm run-cspm test-cspm bedrock-auth bedrock-check bedrock-export dev-ai health smoke bench profile generate-attack-paths load-test-smoke load-test-stress rust-build rust-test rust-bench rust-clean

# Variables
BINARY_NAME=aegis
GO=go
DOCKER_COMPOSE=docker-compose

# Secret management — pulls from 1Password, falls back for CI/offline dev
CF_JWT_SECRET ?= $(shell op read "op://Development/aegis-dev-jwt-secret/password" 2>/dev/null || echo "dev-secret-fallback")

# Default target
help:
	@echo "Cloud Aegis - Enterprise Cloud Governance Platform"
	@echo ""
	@echo "Usage:"
	@echo "  make build        Build the binary"
	@echo "  make run          Run locally (in-memory GRC provider)"
	@echo "  make test         Run tests"
	@echo "  make lint         Run linter"
	@echo "  make fmt          Format code"
	@echo "  make docker-build Build Docker image"
	@echo "  make docker-up    Start all services with Docker Compose"
	@echo "  make docker-down  Stop all services"
	@echo "  make migrate      Run database migrations"
	@echo "  make clean        Clean build artifacts"
	@echo "  make opa-test     Test OPA policies"
	@echo "  make dev          Run backend + frontend dev servers"
	@echo "  make build-cspm   Build cspm-aggregator binary"
	@echo "  make run-cspm     Run cspm-aggregator locally"
	@echo "  make test-cspm    Run cspm-aggregator tests"
	@echo "  make bedrock-auth  Authenticate to AWS SSO for Bedrock"
	@echo "  make bedrock-check Validate Bedrock access (no login)"
	@echo "  make dev-ai        Run dev servers with Bedrock AI enabled"
	@echo "  make health        Check backend health endpoint"
	@echo "  make smoke         Build, smoke-test health endpoints, stop"
	@echo "  make bench         Run Go benchmarks"
	@echo "  make profile       Open pprof heap profile (dev mode only)"

# Build binary
build:
	$(GO) build -o bin/$(BINARY_NAME) ./cmd/server

# Run locally with in-memory provider
run:
	GRC_PROVIDER=memory $(GO) run ./cmd/server

# Run backend + frontend dev servers (Ctrl-C kills both)
dev:
	@trap 'kill 0' EXIT; \
	AEGIS_JWT_SECRET=$(CF_JWT_SECRET) GRC_PROVIDER=memory \
	WS_SERVER_URL=$${WS_SERVER_URL:-} \
	WS_PUBLISH_KEY=$${WS_PUBLISH_KEY:-} \
	$(GO) run ./cmd/server & \
	cd frontend && npm run dev & \
	wait

# Run with Postgres (requires local postgres)
run-postgres:
	GRC_PROVIDER=postgres \
	DATABASE_URL="postgres://aegis:aegis@localhost:5432/aegis?sslmode=disable" \
	$(GO) run ./cmd/server

# Run tests
test:
	$(GO) test -v ./...

# Run tests with coverage
test-coverage:
	$(GO) test -v -coverprofile=coverage.out ./...
	$(GO) tool cover -html=coverage.out -o coverage.html

# Lint code
lint:
	golangci-lint run

# Format code
fmt:
	$(GO) fmt ./...
	gofmt -s -w .

# Build Docker image
docker-build:
	docker build -t aegis:latest .

# Start all services
docker-up:
	$(DOCKER_COMPOSE) up -d

# Stop all services
docker-down:
	$(DOCKER_COMPOSE) down

# View logs
docker-logs:
	$(DOCKER_COMPOSE) logs -f

# Run database migrations
migrate:
	@echo "Running migrations..."
	psql $(DATABASE_URL) -f migrations/001_exception_management.sql

# Test OPA policies
opa-test:
	opa test policies/ -v

# Clean build artifacts
clean:
	rm -rf bin/
	rm -f coverage.out coverage.html

# CSPM Aggregator
build-cspm:
	$(GO) build -o bin/cspm-aggregator ./cmd/cspm-aggregator

run-cspm:
	$(GO) run ./cmd/cspm-aggregator

test-cspm:
	$(GO) test -v ./internal/cspm/...

# Development setup
dev-setup:
	$(GO) mod download
	$(GO) install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

# Bedrock AI targets
bedrock-auth:
	@echo "[*] Authenticating to AWS SSO for Bedrock..."
	@AWS_PROFILE=$${AWS_PROFILE:-lvn-personal} aws sso login --profile $${AWS_PROFILE:-lvn-personal}
	@$(MAKE) bedrock-check

bedrock-check:
	@echo "[*] Validating Bedrock access (profile: $${AWS_PROFILE:-lvn-personal})..."
	@aws bedrock-runtime invoke-model \
	  --profile $${AWS_PROFILE:-lvn-personal} \
	  --region us-east-1 \
	  --model-id us.anthropic.claude-sonnet-4-6 \
	  --content-type application/json \
	  --accept application/json \
	  --body '{"anthropic_version":"bedrock-2023-05-31","max_tokens":20,"messages":[{"role":"user","content":"ping"}]}' \
	  /dev/null 2>&1 && echo "[+] Bedrock access confirmed" || echo "[!] Bedrock access DENIED - check IAM permissions"

bedrock-export:
	@echo "[*] Exporting short-lived Bedrock credentials..."
	@eval $$(aws configure export-credentials --profile $${AWS_PROFILE:-lvn-personal} --format env)
	@echo "[+] Credentials exported to AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN"
	@echo "[!] Valid for ~1 hour"

dev-ai:
	@trap 'kill 0' EXIT; \
	AWS_PROFILE=$${AWS_PROFILE:-lvn-personal} \
	AEGIS_AI_ENABLED=true \
	AEGIS_AI_REGION=$${AEGIS_AI_REGION:-us-east-1} \
	AEGIS_JWT_SECRET=$(CF_JWT_SECRET) \
	GRC_PROVIDER=memory \
	WS_SERVER_URL=$${WS_SERVER_URL:-} \
	WS_PUBLISH_KEY=$${WS_PUBLISH_KEY:-} \
	$(GO) run ./cmd/server & \
	cd frontend && npm run dev & \
	wait

bench:  ## Run Go benchmarks
	$(GO) test ./cmd/server/... -bench=. -benchmem -count=3 -timeout 5m

# Rust hot-path library (libaegispath)
rust-build:  ## Build Rust shared library (release)
	cd rust/libaegispath && cargo build --release

rust-test:  ## Run Rust unit tests
	cd rust/libaegispath && cargo test

rust-bench:  ## Run Rust Criterion benchmarks
	cd rust/libaegispath && cargo bench

rust-clean:  ## Clean Rust build artifacts
	cd rust/libaegispath && cargo clean

profile:  ## Open pprof heap profile (dev server must be running on :6060)
	$(GO) tool pprof http://127.0.0.1:6060/debug/pprof/heap

health:  ## Check backend health
	@curl -sf http://localhost:8080/health | jq . || echo "Backend not reachable"

generate-attack-paths:  ## Regenerate attack path data for R2 upload
	@echo "[*] To regenerate and upload attack path data:"
	@echo "  1. Start server: make run"
	@echo "  2. Export: curl -s http://localhost:8080/api/v1/attack-paths?per_page=100 -H 'Authorization: Bearer <TOKEN>' | jq '.items' > attack-paths.json"
	@echo "  3. Upload: wrangler r2 object put aegis-demo-data/mock/attack-paths.json --file attack-paths.json"
	@echo ""
	@echo "[!] Requires: wrangler CLI authenticated to Cloudflare account"

load-test-smoke:  ## Run k6 smoke test (5 VUs, 30s)
	k6 run k6/smoke.js

load-test-stress:  ## Run k6 stress test (ramp 0→50→0, 3min)
	k6 run k6/stress.js

smoke: build  ## Start backend, verify health, stop
	@echo "Starting backend for smoke test..."
	@AEGIS_JWT_SECRET=$(CF_JWT_SECRET) GRC_PROVIDER=memory ./bin/$(BINARY_NAME) &
	@sleep 2
	@curl -sf http://localhost:8080/healthz && echo "Liveness: OK" || echo "Liveness: FAIL"
	@curl -sf http://localhost:8080/ready && echo "Readiness: OK" || echo "Readiness: FAIL"
	@kill %1 2>/dev/null || true

