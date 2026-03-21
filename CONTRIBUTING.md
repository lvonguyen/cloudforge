# Contributing to Cloud Aegis

## Development Setup

See [README.md](README.md) for development setup instructions.

## Pull Requests

1. Create a feature branch from `main`
2. Make your changes
3. Run `make lint` and `make test` before submitting
4. Open a PR with a clear description

## Backend (Go)

- Go 1.25+
- `go test ./...` runs all unit tests
- `go test -tags integration ./cmd/server/...` runs integration tests
- `golangci-lint run ./...` runs linters

## Frontend (TypeScript/React)

- Node.js 22+ (see `.nvmrc`)
- `cd frontend && npm install` to install dependencies
- `npm run dev` starts the Vite dev server on `:5173`
- `npm test` runs Vitest
- `npm run lint` runs ESLint
- `npm run build` builds for production (includes `tsc -b`)

## Code Style

- Go: Follow `golangci-lint` rules (see `.golangci.yml`)
- TypeScript: Follow ESLint + Prettier configuration
- Commit messages: Use conventional commits (`feat:`, `fix:`, `docs:`, etc.)
