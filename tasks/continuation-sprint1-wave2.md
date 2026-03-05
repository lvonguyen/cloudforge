# Continuation: Sprint 1 Wave 2+3

**Run after:** /compact or new session
**Context:** Wave 1 complete, builds green. Commit pending.

---

## Status

### Wave 1 — DONE (not yet committed)
- `cmd/server/types.go` — Go structs for all 6 mock data domains
- `cmd/server/mockdata.go` — loadMockData() from frontend/src/lib/mock/*.json
- `cmd/server/main_test.go` — test infra (testServer, makeJWT, adminJWT/operatorJWT/requesterJWT, doRequest, assertStatus, assertJSON)
- `frontend/src/pages/ops/RemediationQueue.tsx` — Execute/DryRun wired to trace panel + useRemediations hook
- `frontend/src/pages/ops/FindingDetail.tsx` — Remediate wired to trace panel + cooldown

### Pre-commit checklist
```bash
go build ./cmd/server && go vet ./cmd/server && cd frontend && npx tsc --noEmit
```

### Commit message
```
feat: Sprint 1 wave 1 — Go types, test infra, P0 button wiring
```

---

## Wave 2 — Launch 2 parallel agents

### Agent C2: API Handlers + Route Wiring

**Read first:**
1. `cmd/server/main.go` — setupRoutes(), existing handler patterns, OTel tracer usage
2. `cmd/server/types.go` — all response types
3. `cmd/server/mockdata.go` — MockData struct, loadMockData()
4. `internal/api/rbac.go` — RequireRole, Role constants

**Task:** Create `cmd/server/handlers_api.go` + modify `cmd/server/main.go`

**handlers_api.go** — 8 handler methods on Server:
```go
// All handlers follow existing pattern: OTel span, JSON response, error handling

func (s *Server) listFindings(w, r)      // GET /api/v1/findings — filter by ?severity=&provider=&status=
func (s *Server) getFinding(w, r)        // GET /api/v1/findings/{id}
func (s *Server) listFrameworks(w, r)    // GET /api/v1/compliance/frameworks
func (s *Server) listAgents(w, r)        // GET /api/v1/agents
func (s *Server) getAgent(w, r)          // GET /api/v1/agents/{id}
func (s *Server) getCostSummary(w, r)    // GET /api/v1/costs/summary
func (s *Server) listRemediations(w, r)  // GET /api/v1/remediations — filter by ?status=&tier=
func (s *Server) executeRemediation(w, r) // POST /api/v1/remediations/{id}/execute — admin only
```

**main.go changes:**
1. Add `mockData *MockData` field to Server struct
2. In main(), after creating server: `mockData, err := loadMockData(mockDataDir()); srv.mockData = mockData`
3. In setupRoutes(), add 8 new routes with RBAC:
   - Read endpoints: RequireRole(RoleOperator, RoleAdmin)
   - Execute endpoint: RequireRole(RoleAdmin)

**RBAC mapping:**
- GET findings, frameworks, agents, costs, remediations → operator, admin
- POST remediations/{id}/execute → admin only

**Verify:** `go build ./cmd/server && go vet ./cmd/server`

### Agent B2a: Tests for Existing Exception Endpoints

**Read first:**
1. `cmd/server/main_test.go` — test helpers (testServer, makeJWT, doRequest, etc.)
2. `cmd/server/main.go` — existing exception handlers (createException, getException, submitApproval, getPendingApprovals, getExpiringExceptions, getExceptionsByApp, validateException, healthCheck)
3. `internal/grc/types.go` — ExceptionRequest, Approver types

**Task:** Create `cmd/server/handlers_test.go`

Test cases per endpoint:
- `TestHealthCheck` — GET /health returns 200 + {"status":"healthy"}
- `TestCreateException_Success` — POST with admin JWT, valid body → 201
- `TestCreateException_Unauthorized` — POST without JWT → 401
- `TestCreateException_Forbidden` — POST with requester JWT → 403
- `TestCreateException_IdentitySpoof` — POST with mismatched requestor_email → 403
- `TestGetException_Success` — Create then GET with admin JWT → 200
- `TestGetException_NotFound` — GET nonexistent → 404
- `TestSubmitApproval_Success` — Create, then POST approve with admin JWT → 200
- `TestGetPendingApprovals` — Create exception, query with matching email → returns it
- `TestGetExpiringExceptions_RequiresComplianceScope` — without compliance scope → 403
- `TestValidateException` — POST validate → returns valid:false for nonexistent

**Verify:** `go test ./cmd/server/... -count=1 -v` (all pass)

---

## Wave 3 — After wave 2 completes

### Agent B2b: Tests for New API Endpoints

**Read first:**
1. `cmd/server/main_test.go` — test helpers
2. `cmd/server/handlers_api.go` — new handlers from C2
3. `cmd/server/types.go` — response types

**Task:** Create `cmd/server/handlers_api_test.go`

Test cases:
- `TestListFindings` — returns 80 findings, check JSON shape
- `TestListFindings_FilterBySeverity` — ?severity=CRITICAL returns 8
- `TestListFindings_FilterByProvider` — ?provider=aws returns 52
- `TestGetFinding` — GET /findings/f-001 returns correct finding
- `TestGetFinding_NotFound` — GET /findings/f-999 returns 404
- `TestListFrameworks` — returns 6 frameworks
- `TestListAgents` — returns 12 agents
- `TestGetAgent` — GET by UUID returns correct agent
- `TestGetCostSummary` — returns cost object with total=2800000
- `TestListRemediations` — returns 50 remediations
- `TestExecuteRemediation_AdminOnly` — operator JWT → 403, admin JWT → 200
- `TestAllEndpoints_RequireAuth` — no JWT → 401 for each

**Note:** testServer needs MockData loaded. Either:
- Have testServer() also call loadMockData() (preferred)
- Or add a testServerWithData() variant

**Verify:** `go test ./cmd/server/... -count=1` (all pass)

---

## After All Waves: Commit + Assess

```bash
git add cmd/server/ frontend/src/pages/ops/
git commit -m "feat: Sprint 1 — API endpoints, handler tests, P0 button wiring"
```

Then assess Sprint 2 readiness.
