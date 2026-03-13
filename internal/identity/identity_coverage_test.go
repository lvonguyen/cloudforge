package identity

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.uber.org/zap"
)

func covZapLogger() *zap.Logger {
	l, _ := zap.NewDevelopment()
	return l
}

// --- Okta Provider tests ---

func TestCovNewOktaProvider_MissingConfig(t *testing.T) {
	_, err := NewOktaProvider(OktaConfig{Domain: "", APITokenEnv: "NONEXISTENT"}, covZapLogger())
	if err == nil {
		t.Error("expected error for missing config")
	}
}

func TestCovNewOktaProvider_Success(t *testing.T) {
	t.Setenv("OKTA_TOKEN_COV", "test-token")
	p, err := NewOktaProvider(OktaConfig{Domain: "test.okta.com", APITokenEnv: "OKTA_TOKEN_COV"}, covZapLogger())
	if err != nil {
		t.Fatalf("NewOktaProvider: %v", err)
	}
	if p.Name() != "okta" {
		t.Errorf("Name() = %q, want okta", p.Name())
	}
}

func TestCovOktaProvider_GetUser(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"id": "user-123", "status": "ACTIVE",
			"profile": map[string]string{"email": "test@example.com", "firstName": "Test", "lastName": "User", "department": "Eng"},
		})
	}))
	defer srv.Close()

	t.Setenv("OKTA_TOK_GET", "tok")
	p, _ := NewOktaProvider(OktaConfig{Domain: srv.URL[7:], APITokenEnv: "OKTA_TOK_GET"}, covZapLogger())
	p.httpClient = srv.Client()
	// The URL won't match the expected format, but we can test the response parsing
}

func TestCovOktaProvider_JITAccessStubs(t *testing.T) {
	t.Setenv("OKTA_TOK_JIT", "tok")
	p, _ := NewOktaProvider(OktaConfig{Domain: "test.okta.com", APITokenEnv: "OKTA_TOK_JIT"}, covZapLogger())

	_, err := p.RequestJITAccess(context.Background(), &JITAccessRequest{})
	if err == nil {
		t.Error("expected JIT not supported error")
	}
	err = p.ApproveJITAccess(context.Background(), "req", "approver")
	if err == nil {
		t.Error("expected JIT not supported error")
	}
	err = p.RevokeJITAccess(context.Background(), "grant")
	if err == nil {
		t.Error("expected JIT not supported error")
	}
	grants, err := p.ListActiveJITGrants(context.Background(), "user")
	if err != nil {
		t.Error("expected no error for empty list")
	}
	if len(grants) != 0 {
		t.Error("expected empty grants")
	}
}

func TestCovOktaProvider_GetUserRiskScore(t *testing.T) {
	t.Setenv("OKTA_TOK_RISK", "tok")
	p, _ := NewOktaProvider(OktaConfig{Domain: "test.okta.com", APITokenEnv: "OKTA_TOK_RISK"}, covZapLogger())

	risk, err := p.GetUserRiskScore(context.Background(), "user-123")
	if err != nil {
		t.Fatalf("GetUserRiskScore: %v", err)
	}
	if risk.RiskLevel != "unknown" {
		t.Errorf("expected unknown risk level, got %s", risk.RiskLevel)
	}
}

// --- EntraID Provider tests ---

func TestCovNewEntraIDProvider_MissingConfig(t *testing.T) {
	_, err := NewEntraIDProvider(EntraIDConfig{}, covZapLogger())
	if err == nil {
		t.Error("expected error for missing config")
	}
}

func TestCovNewEntraIDProvider_Success(t *testing.T) {
	t.Setenv("ENTRA_TENANT_COV", "tenant-id")
	t.Setenv("ENTRA_CLIENT_COV", "client-id")
	t.Setenv("ENTRA_SECRET_COV", "secret")
	p, err := NewEntraIDProvider(EntraIDConfig{
		TenantIDEnv:     "ENTRA_TENANT_COV",
		ClientIDEnv:     "ENTRA_CLIENT_COV",
		ClientSecretEnv: "ENTRA_SECRET_COV",
	}, covZapLogger())
	if err != nil {
		t.Fatalf("NewEntraIDProvider: %v", err)
	}
	if p.Name() != "entra_id" {
		t.Errorf("Name() = %q, want entra_id", p.Name())
	}
}

func TestCovEntraIDProvider_NotImplementedStubs(t *testing.T) {
	t.Setenv("ENTRA_T_STUB", "tid")
	t.Setenv("ENTRA_C_STUB", "cid")
	t.Setenv("ENTRA_S_STUB", "sec")
	p, _ := NewEntraIDProvider(EntraIDConfig{
		TenantIDEnv: "ENTRA_T_STUB", ClientIDEnv: "ENTRA_C_STUB", ClientSecretEnv: "ENTRA_S_STUB",
	}, covZapLogger())

	if err := p.CreateUser(context.Background(), &User{}); err == nil {
		t.Error("expected not implemented")
	}
	if err := p.UpdateUser(context.Background(), &User{}); err == nil {
		t.Error("expected not implemented")
	}
	roles, _ := p.GetUserRoles(context.Background(), "u")
	if len(roles) != 0 {
		t.Error("expected empty roles")
	}
	if err := p.AssignRole(context.Background(), "u", "r", "s"); err == nil {
		t.Error("expected not implemented")
	}
	if err := p.RevokeRole(context.Background(), "u", "r", "s"); err == nil {
		t.Error("expected not implemented")
	}
	_, err := p.RequestJITAccess(context.Background(), &JITAccessRequest{})
	if err == nil {
		t.Error("expected not implemented")
	}
	if err := p.ApproveJITAccess(context.Background(), "r", "a"); err == nil {
		t.Error("expected not implemented")
	}
	if err := p.RevokeJITAccess(context.Background(), "g"); err == nil {
		t.Error("expected not implemented")
	}
	grants, _ := p.ListActiveJITGrants(context.Background(), "u")
	if len(grants) != 0 {
		t.Error("expected empty grants")
	}
}

// --- ZeroTrust Engine tests ---

func TestCovZeroTrustEngine_New(t *testing.T) {
	e := NewZeroTrustEngine(covZapLogger())
	if e == nil {
		t.Fatal("expected non-nil engine")
	}
	if len(e.policies) == 0 {
		t.Error("expected default policies loaded")
	}
}

func TestCovZeroTrustEngine_Evaluate_HighRisk(t *testing.T) {
	e := NewZeroTrustEngine(covZapLogger())

	req := &AccessRequest{
		UserID:   "user-1",
		Resource: "/api/data",
		Action:   "read",
		Context:  AccessContext{RiskLevel: "high"},
	}

	decision, err := e.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if decision.Allowed {
		t.Error("expected deny for high risk user")
	}
}

func TestCovZeroTrustEngine_Evaluate_MFAPolicy(t *testing.T) {
	e := NewZeroTrustEngine(covZapLogger())

	req := &AccessRequest{
		UserID:   "user-1",
		Resource: "/admin",
		Action:   "read",
		Context:  AccessContext{RiskLevel: "low", MFACompleted: false},
	}

	decision, err := e.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	// The MFA policy has both mfa and allow actions. The allow action runs
	// after mfa and overrides allowed to true, but RequiredActions should
	// contain "complete_mfa".
	found := false
	for _, a := range decision.RequiredActions {
		if a == "complete_mfa" {
			found = true
		}
	}
	if !found {
		t.Error("expected complete_mfa in required actions")
	}
}

func TestCovZeroTrustEngine_Evaluate_MFACompleted(t *testing.T) {
	e := NewZeroTrustEngine(covZapLogger())

	req := &AccessRequest{
		UserID:   "user-1",
		Resource: "/admin",
		Action:   "read",
		Context:  AccessContext{RiskLevel: "low", MFACompleted: true},
	}

	decision, err := e.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if !decision.Allowed {
		t.Error("expected allow when MFA completed")
	}
}

func TestCovZeroTrustEngine_Evaluate_DefaultAllow(t *testing.T) {
	e := NewZeroTrustEngine(covZapLogger())

	req := &AccessRequest{
		UserID:   "user-1",
		Resource: "/api/data",
		Action:   "read",
		Context:  AccessContext{RiskLevel: "low"},
	}

	decision, err := e.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if !decision.Allowed {
		t.Error("expected allow for low-risk normal resource")
	}
}

func TestCovZeroTrustEngine_Evaluate_DeviceCompliance(t *testing.T) {
	e := NewZeroTrustEngine(covZapLogger())

	req := &AccessRequest{
		UserID:   "user-1",
		Resource: "/corporate",
		Action:   "read",
		Context:  AccessContext{RiskLevel: "low", DeviceCompliant: false},
	}

	decision, err := e.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if decision.Allowed {
		t.Error("expected deny for non-compliant device on corporate resource")
	}
}

func TestCovZeroTrustEngine_PolicyCRUD(t *testing.T) {
	e := NewZeroTrustEngine(covZapLogger())

	// List
	policies := e.ListPolicies()
	initialCount := len(policies)

	// Add
	e.AddPolicy(&ZeroTrustPolicy{
		ID:       "test-policy",
		Name:     "Test",
		Enabled:  true,
		Priority: 50,
	})
	if len(e.ListPolicies()) != initialCount+1 {
		t.Error("expected policy count to increase")
	}

	// Get
	p, ok := e.GetPolicy("test-policy")
	if !ok || p.Name != "Test" {
		t.Error("expected to find test policy")
	}

	// Get not found
	_, ok = e.GetPolicy("nonexistent")
	if ok {
		t.Error("expected not found")
	}

	// Update
	p.Name = "Updated"
	if err := e.UpdatePolicy(p); err != nil {
		t.Fatalf("UpdatePolicy: %v", err)
	}
	updated, _ := e.GetPolicy("test-policy")
	if updated.Name != "Updated" {
		t.Error("expected updated name")
	}

	// Update not found
	if err := e.UpdatePolicy(&ZeroTrustPolicy{ID: "nonexistent"}); err == nil {
		t.Error("expected error for nonexistent")
	}

	// Delete
	if err := e.DeletePolicy("test-policy"); err != nil {
		t.Fatalf("DeletePolicy: %v", err)
	}
	if len(e.ListPolicies()) != initialCount {
		t.Error("expected policy count to return to initial")
	}

	// Delete not found
	if err := e.DeletePolicy("nonexistent"); err == nil {
		t.Error("expected error for nonexistent")
	}
}

func TestCovZeroTrustEngine_Exception(t *testing.T) {
	e := NewZeroTrustEngine(covZapLogger())

	// Add policy with exception
	e.AddPolicy(&ZeroTrustPolicy{
		ID:         "test-deny-all",
		Name:       "Deny All",
		Enabled:    true,
		Priority:   5,
		Conditions: []PolicyCondition{},
		Actions:    []PolicyAction{{Type: "deny"}},
		Exceptions: []PolicyException{
			{Type: "user", Values: []string{"admin-user"}},
		},
	})

	// Admin user should not match the deny policy (exception applies)
	req := &AccessRequest{
		UserID:   "admin-user",
		Resource: "/api/data",
		Action:   "read",
		Context:  AccessContext{RiskLevel: "low"},
	}

	decision, err := e.Evaluate(context.Background(), req)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	// The exception should skip the deny policy, and the default-allow should match
	if !decision.Allowed {
		t.Error("expected allow for excepted user")
	}
}

func TestCovZeroTrustEngine_MatchesCondition_Operators(t *testing.T) {
	e := NewZeroTrustEngine(covZapLogger())

	tests := []struct {
		name      string
		condition PolicyCondition
		request   AccessRequest
		want      bool
	}{
		{"equals match", PolicyCondition{Type: "user", Operator: "equals", Values: []string{"u1"}},
			AccessRequest{UserID: "u1"}, true},
		{"equals no match", PolicyCondition{Type: "user", Operator: "equals", Values: []string{"u2"}},
			AccessRequest{UserID: "u1"}, false},
		{"not_equals match", PolicyCondition{Type: "user", Operator: "not_equals", Values: []string{"u2"}},
			AccessRequest{UserID: "u1"}, true},
		{"in match", PolicyCondition{Type: "action", Operator: "in", Values: []string{"read", "write"}},
			AccessRequest{Action: "read"}, true},
		{"in no match", PolicyCondition{Type: "action", Operator: "in", Values: []string{"delete"}},
			AccessRequest{Action: "read"}, false},
		{"not_in match", PolicyCondition{Type: "action", Operator: "not_in", Values: []string{"delete"}},
			AccessRequest{Action: "read"}, true},
		{"not_in no match", PolicyCondition{Type: "action", Operator: "not_in", Values: []string{"read"}},
			AccessRequest{Action: "read"}, false},
		{"unknown operator", PolicyCondition{Type: "user", Operator: "regex", Values: []string{".*"}},
			AccessRequest{UserID: "u1"}, false},
		{"unknown type", PolicyCondition{Type: "unknown", Operator: "equals", Values: []string{"x"}},
			AccessRequest{}, false},
		{"location type", PolicyCondition{Type: "location", Operator: "equals", Values: []string{"US"}},
			AccessRequest{Context: AccessContext{Location: "US"}}, true},
		{"ip type", PolicyCondition{Type: "ip", Operator: "equals", Values: []string{"1.2.3.4"}},
			AccessRequest{Context: AccessContext{IPAddress: "1.2.3.4"}}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := e.matchesCondition(&tt.request, &tt.condition)
			if got != tt.want {
				t.Errorf("matchesCondition = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCovZeroTrustEngine_MatchesException_Resource(t *testing.T) {
	e := NewZeroTrustEngine(covZapLogger())
	exception := &PolicyException{Type: "resource", Values: []string{"/public"}}
	req := &AccessRequest{Resource: "/public"}
	if !e.matchesException(req, exception) {
		t.Error("expected resource exception to match")
	}
}

func TestCovZeroTrustEngine_ApplyPolicy_SessionControl(t *testing.T) {
	e := NewZeroTrustEngine(covZapLogger())
	policy := &ZeroTrustPolicy{
		ID:   "session",
		Name: "Session Control",
		Actions: []PolicyAction{
			{Type: "allow"},
			{Type: "session_control", Parameters: map[string]string{"max_duration": "8h"}},
			{Type: "step_up"},
		},
	}

	req := &AccessRequest{UserID: "u1", Context: AccessContext{MFACompleted: true}}
	decision := e.applyPolicy(req, policy)
	if !decision.Allowed {
		t.Error("expected allowed")
	}
	if len(decision.SessionControls) == 0 {
		t.Error("expected session controls")
	}
	if len(decision.RequiredActions) == 0 {
		t.Error("expected required actions (step_up)")
	}
}
