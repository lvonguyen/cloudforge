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

## Architecture Decision Records (ADRs)

We use ADRs to document significant architectural choices. There are currently 20 accepted ADRs covering language selection, database, caching, authentication, and more.

### ADR Process

1. **Propose**: Create a new file `docs/core/architecture/adr/ADR-NNN-short-title.md` using this template:

   ```markdown
   # ADR-NNN: Short Title

   ## Status
   Proposed

   ## Context
   What problem are we solving? What constraints exist?

   ## Decision
   What did we decide and why?

   ## Consequences
   What are the trade-offs? What becomes easier or harder?
   ```

2. **Review**: Open a PR. ADRs require at least one reviewer with domain expertise.
3. **Accept**: Merge the PR and update `docs/core/architecture/adr/adr-index.md`.
4. **Supersede**: If a decision is reversed, mark the old ADR as `Superseded by ADR-NNN` and create the replacement.

The full ADR index is at [docs/core/architecture/adr/adr-index.md](docs/core/architecture/adr/adr-index.md).

## QA Triad Workflow

Before merging significant changes, run the QA triad: three specialized review agents that score code quality, find bugs, and audit security in parallel.

### Running the QA Triad

**Quick single-agent review:**

```bash
# From the repo root, invoke the QA skill
/qa
```

**Full triad (quality + bugs + security):**

```bash
# Runs all three agents in parallel
/qa-all
```

### Scoring Dimensions

Each agent scores on a 1-5 scale across multiple dimensions:

| Agent | Focus Areas |
|-------|-------------|
| **quality-review** | Code smells, naming, duplication, complexity, test coverage |
| **bug-discovery** | Nil dereferences, race conditions, logic errors, edge cases |
| **security-audit** | Injection, auth bypass, secrets exposure, OWASP top 10 |

### Merge Threshold

All dimensions must reach **>= 4.5/5** before merge (max 3 iterations). If a dimension scores below threshold, the agent provides specific fix recommendations.

## E2E Testing

We use Playwright for end-to-end browser tests against the running frontend.

### Setup

```bash
# Install Playwright browsers (first time only)
cd frontend
npx playwright install chromium

# Start the dev server
npm run dev
```

### Running E2E Tests

```bash
# Run all E2E tests
cd frontend
npx playwright test

# Run a specific test file
npx playwright test e2e/findings.spec.ts

# Run in headed mode (see the browser)
npx playwright test --headed

# Run with UI mode (interactive debugging)
npx playwright test --ui
```

### Writing E2E Tests

Test files live in `frontend/e2e/*.spec.ts`. Use Playwright's locator API:

```typescript
import { test, expect } from '@playwright/test';

test('findings page loads', async ({ page }) => {
  await page.goto('/findings');
  await expect(page.getByRole('heading', { name: /findings/i })).toBeVisible();
});
```

Configuration is at `frontend/playwright.config.ts`. Tests run against `http://localhost:5173` by default.

## Runbooks

Operational runbooks live in `docs/core/runbooks/`. Each runbook covers a specific operational domain (deployment, incident response, DR failover, etc.) with step-by-step procedures.

When adding or updating runbooks, include a Mermaid process flow diagram at the top of each major section to visualize the decision path.
