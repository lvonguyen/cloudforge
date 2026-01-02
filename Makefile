.PHONY: build run test clean docker-build docker-up docker-down migrate lint fmt help

# Variables
BINARY_NAME=cloudforge
GO=go
DOCKER_COMPOSE=docker-compose

# Default target
help:
	@echo "CloudForge - Enterprise Cloud Governance Platform"
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

# Build binary
build:
	$(GO) build -o bin/$(BINARY_NAME) ./cmd/server

# Run locally with in-memory provider
run:
	GRC_PROVIDER=memory $(GO) run ./cmd/server

# Run with Postgres (requires local postgres)
run-postgres:
	GRC_PROVIDER=postgres \
	DATABASE_URL="postgres://cloudforge:cloudforge@localhost:5432/cloudforge?sslmode=disable" \
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
	docker build -t cloudforge:latest .

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

# Evaluate OPA policy with sample input
opa-eval:
	opa eval -d policies/ -i test/sample_input.json "data.cloudforge.response"

# Clean build artifacts
clean:
	rm -rf bin/
	rm -f coverage.out coverage.html

# Development setup
dev-setup:
	$(GO) mod download
	$(GO) install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

# Generate API documentation
docs:
	@echo "TODO: Add API documentation generation"
