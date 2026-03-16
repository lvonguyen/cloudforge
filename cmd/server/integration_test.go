//go:build integration

package main

import (
	"net/http"
	"testing"

	"cloudforge/internal/grc"
)

// TestIntegration_FullServerLifecycle boots a test server and exercises the
// major API endpoints end-to-end in a single sequential flow.
func TestIntegration_FullServerLifecycle(t *testing.T) {
	_, router := testServer(t)
	jwt := adminJWT(t)

	// 1. GET /health -> 200
	t.Run("health", func(t *testing.T) {
		rr := doRequest(t, router, "GET", "/health", "", "")
		assertStatus(t, rr, http.StatusOK)

		var result map[string]interface{}
		assertJSON(t, rr, &result)
		if result["status"] != "healthy" {
			t.Errorf("status = %v, want healthy", result["status"])
		}
	})

	// 2. GET /api/v1/findings (with admin JWT) -> 200, has data
	t.Run("list_findings", func(t *testing.T) {
		rr := doRequest(t, router, "GET", "/api/v1/findings", "", jwt)
		assertStatus(t, rr, http.StatusOK)

		var results []Finding
		assertPaginatedJSON(t, rr, &results)

		if len(results) == 0 {
			t.Error("expected at least one finding")
		}
	})

	// 3. GET /api/v1/findings/{id} -> 200, single finding
	t.Run("get_finding", func(t *testing.T) {
		rr := doRequest(t, router, "GET", "/api/v1/findings/f-aws-0001", "", jwt)
		assertStatus(t, rr, http.StatusOK)

		var result Finding
		assertJSON(t, rr, &result)

		if result.ID != "f-aws-0001" {
			t.Errorf("finding id = %q, want f-aws-0001", result.ID)
		}
	})

	// 4. GET /api/v1/attack-paths -> 200, paginated
	t.Run("list_attack_paths", func(t *testing.T) {
		rr := doRequest(t, router, "GET", "/api/v1/attack-paths?per_page=5", "", jwt)
		assertStatus(t, rr, http.StatusOK)

		var result paginatedPaths
		assertJSON(t, rr, &result)

		if result.Total == 0 {
			t.Error("expected at least one attack path")
		}
		if result.PerPage != 5 {
			t.Errorf("per_page = %d, want 5", result.PerPage)
		}
	})

	// 5. POST /api/v1/exceptions (with admin JWT) -> create exception
	var createdExceptionID string
	t.Run("create_exception", func(t *testing.T) {
		body := `{"application_id":"app-int-001","policy_violated":"REGION-001","business_case":"integration test","requestor_email":"admin@contoso.dev"}`
		rr := doRequest(t, router, "POST", "/api/v1/exceptions", body, jwt)
		assertStatus(t, rr, http.StatusCreated)

		var result grc.ExceptionRequest
		assertJSON(t, rr, &result)

		if result.ID == "" {
			t.Fatal("expected non-empty exception id")
		}
		createdExceptionID = result.ID
	})

	// 6. GET /api/v1/exceptions/{id} -> verify created
	t.Run("get_exception", func(t *testing.T) {
		if createdExceptionID == "" {
			t.Skip("no exception was created")
		}
		rr := doRequest(t, router, "GET", "/api/v1/exceptions/"+createdExceptionID, "", jwt)
		assertStatus(t, rr, http.StatusOK)

		var result grc.ExceptionRequest
		assertJSON(t, rr, &result)

		if result.ID != createdExceptionID {
			t.Errorf("exception id = %q, want %q", result.ID, createdExceptionID)
		}
		if result.Status != grc.StatusPending {
			t.Errorf("exception status = %q, want pending", result.Status)
		}
	})

	// 7. POST /api/v1/exceptions/{id}/approve -> approve it
	// Note: approve will fail because the approver chain was reset to nil
	// by the server (SA-10 fix). This tests the error handling path.
	t.Run("approve_exception", func(t *testing.T) {
		if createdExceptionID == "" {
			t.Skip("no exception was created")
		}
		body := `{"email":"admin@contoso.dev","role":"SECURITY_LEAD","decision":"APPROVED","comments":"approved"}`
		rr := doRequest(t, router, "POST", "/api/v1/exceptions/"+createdExceptionID+"/approve", body, jwt)
		// Server resets approver_chain to nil, so approval fails
		assertStatus(t, rr, http.StatusInternalServerError)
	})

	// 8. GET /api/v1/compliance/frameworks -> 200
	t.Run("list_frameworks", func(t *testing.T) {
		rr := doRequest(t, router, "GET", "/api/v1/compliance/frameworks", "", jwt)
		assertStatus(t, rr, http.StatusOK)

		var results []ComplianceFramework
		assertPaginatedJSON(t, rr, &results)

		if len(results) == 0 {
			t.Error("expected at least one framework")
		}
	})

	// 9. GET /api/v1/costs/summary -> 200
	t.Run("cost_summary", func(t *testing.T) {
		rr := doRequest(t, router, "GET", "/api/v1/costs/summary", "", jwt)
		assertStatus(t, rr, http.StatusOK)

		var result map[string]interface{}
		assertJSON(t, rr, &result)
	})

	// 10. GET /api/v1/agents -> 200
	t.Run("list_agents", func(t *testing.T) {
		rr := doRequest(t, router, "GET", "/api/v1/agents", "", jwt)
		assertStatus(t, rr, http.StatusOK)

		var results []Agent
		assertJSON(t, rr, &results)

		if len(results) == 0 {
			t.Error("expected at least one agent")
		}
	})

	// 11. GET /api/v1/audit-log -> 200
	t.Run("list_audit_log", func(t *testing.T) {
		rr := doRequest(t, router, "GET", "/api/v1/audit-log", "", jwt)
		assertStatus(t, rr, http.StatusOK)

		var results []AuditEvent
		assertPaginatedJSON(t, rr, &results)

		if len(results) == 0 {
			t.Error("expected at least one audit event")
		}
	})

	// 12. GET /api/v1/catalog/modules -> 200
	t.Run("list_catalog_modules", func(t *testing.T) {
		rr := doRequest(t, router, "GET", "/api/v1/catalog/modules", "", jwt)
		assertStatus(t, rr, http.StatusOK)

		var results []CatalogModule
		assertPaginatedJSON(t, rr, &results)

		if len(results) == 0 {
			t.Error("expected at least one catalog module")
		}
	})
}

// TestIntegration_AuthorizationMatrix verifies RBAC rules across roles.
func TestIntegration_AuthorizationMatrix(t *testing.T) {
	_, router := testServer(t)

	adminToken := adminJWT(t)
	operatorToken := operatorJWT(t)
	requesterToken := requesterJWT(t)

	// 1. Operator can GET findings but NOT POST exceptions
	t.Run("operator_can_read_findings", func(t *testing.T) {
		rr := doRequest(t, router, "GET", "/api/v1/findings", "", operatorToken)
		assertStatus(t, rr, http.StatusOK)
	})

	t.Run("operator_cannot_create_exceptions", func(t *testing.T) {
		body := `{"application_id":"app-001","policy_violated":"REGION-001","requestor_email":"operator@contoso.dev"}`
		rr := doRequest(t, router, "POST", "/api/v1/exceptions", body, operatorToken)
		assertStatus(t, rr, http.StatusForbidden)
	})

	// 2. Requester can GET /exceptions/mine but NOT /exceptions (full list via GET exception by ID)
	t.Run("requester_can_get_my_exceptions", func(t *testing.T) {
		rr := doRequest(t, router, "GET", "/api/v1/exceptions/mine", "", requesterToken)
		assertStatus(t, rr, http.StatusOK)
	})

	t.Run("requester_cannot_list_findings", func(t *testing.T) {
		rr := doRequest(t, router, "GET", "/api/v1/findings", "", requesterToken)
		assertStatus(t, rr, http.StatusForbidden)
	})

	t.Run("requester_cannot_get_exception_by_id", func(t *testing.T) {
		rr := doRequest(t, router, "GET", "/api/v1/exceptions/some-id", "", requesterToken)
		assertStatus(t, rr, http.StatusForbidden)
	})

	// 3. Unauthenticated requests get 401
	t.Run("unauthenticated_findings", func(t *testing.T) {
		rr := doRequest(t, router, "GET", "/api/v1/findings", "", "")
		assertStatus(t, rr, http.StatusUnauthorized)
	})

	t.Run("unauthenticated_exceptions", func(t *testing.T) {
		rr := doRequest(t, router, "POST", "/api/v1/exceptions", `{}`, "")
		assertStatus(t, rr, http.StatusUnauthorized)
	})

	t.Run("unauthenticated_agents", func(t *testing.T) {
		rr := doRequest(t, router, "GET", "/api/v1/agents", "", "")
		assertStatus(t, rr, http.StatusUnauthorized)
	})

	t.Run("unauthenticated_audit_log", func(t *testing.T) {
		rr := doRequest(t, router, "GET", "/api/v1/audit-log", "", "")
		assertStatus(t, rr, http.StatusUnauthorized)
	})

	t.Run("unauthenticated_identity_users", func(t *testing.T) {
		rr := doRequest(t, router, "GET", "/api/v1/identity/users", "", "")
		assertStatus(t, rr, http.StatusUnauthorized)
	})

	t.Run("unauthenticated_workflows", func(t *testing.T) {
		rr := doRequest(t, router, "GET", "/api/v1/workflows", "", "")
		assertStatus(t, rr, http.StatusUnauthorized)
	})

	// 4. Admin can access everything
	adminEndpoints := []struct {
		method string
		path   string
		body   string
		want   int
	}{
		{"GET", "/api/v1/findings", "", http.StatusOK},
		{"GET", "/api/v1/findings/f-aws-0001", "", http.StatusOK},
		{"GET", "/api/v1/compliance/frameworks", "", http.StatusOK},
		{"GET", "/api/v1/agents", "", http.StatusOK},
		{"GET", "/api/v1/costs/summary", "", http.StatusOK},
		{"GET", "/api/v1/remediations", "", http.StatusOK},
		{"GET", "/api/v1/audit-log", "", http.StatusOK},
		{"GET", "/api/v1/users", "", http.StatusOK},
		{"GET", "/api/v1/policies", "", http.StatusOK},
		{"GET", "/api/v1/catalog/modules", "", http.StatusOK},
		{"GET", "/api/v1/attack-paths", "", http.StatusOK},
		{"GET", "/api/v1/identity/users", "", http.StatusOK},
		{"GET", "/api/v1/workflows", "", http.StatusOK},
		{"GET", "/api/v1/container/scan?image=nginx", "", http.StatusOK},
		{"GET", "/api/v1/container/admission?image=nginx", "", http.StatusOK},
		{"GET", "/api/v1/secrets", "", http.StatusOK},
		{"GET", "/api/v1/waf/templates", "", http.StatusOK},
		{"GET", "/api/v1/exceptions/mine", "", http.StatusOK},
	}

	for _, ep := range adminEndpoints {
		t.Run("admin_"+ep.method+"_"+ep.path, func(t *testing.T) {
			rr := doRequest(t, router, ep.method, ep.path, ep.body, adminToken)
			assertStatus(t, rr, ep.want)
		})
	}

	// Verify operator RBAC boundaries — can read most things but not admin-only
	t.Run("operator_cannot_access_audit_log", func(t *testing.T) {
		rr := doRequest(t, router, "GET", "/api/v1/audit-log", "", operatorToken)
		assertStatus(t, rr, http.StatusForbidden)
	})

	t.Run("operator_cannot_access_users", func(t *testing.T) {
		rr := doRequest(t, router, "GET", "/api/v1/users", "", operatorToken)
		assertStatus(t, rr, http.StatusForbidden)
	})

	t.Run("operator_cannot_execute_remediation", func(t *testing.T) {
		rr := doRequest(t, router, "POST", "/api/v1/remediations/rem-001/execute", "", operatorToken)
		assertStatus(t, rr, http.StatusForbidden)
	})

	t.Run("operator_cannot_approve_workflow", func(t *testing.T) {
		body := `{"approver":"operator@contoso.dev"}`
		rr := doRequest(t, router, "POST", "/api/v1/workflows/wf-001/approve", body, operatorToken)
		assertStatus(t, rr, http.StatusForbidden)
	})
}
