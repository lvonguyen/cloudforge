package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// stubResource implements Scopeable for testing.
type stubResource struct {
	AccountID       string
	Region          string
	EnvironmentType string
	LineOfBusiness  string
}

func (s *stubResource) GetAccountID() string       { return s.AccountID }
func (s *stubResource) GetRegion() string          { return s.Region }
func (s *stubResource) GetEnvironmentType() string { return s.EnvironmentType }
func (s *stubResource) GetLineOfBusiness() string  { return s.LineOfBusiness }

func TestEnforceScope_NilAllowsAll(t *testing.T) {
	r := &stubResource{AccountID: "111", Region: "us-east-1", EnvironmentType: "prod", LineOfBusiness: "payments"}
	if err := EnforceScope(nil, r); err != nil {
		t.Fatalf("nil scope should allow all, got: %v", err)
	}
}

func TestEnforceScope_EmptyScopeAllowsAll(t *testing.T) {
	scope := &ResourceScope{} // all dimensions empty = allow all
	r := &stubResource{AccountID: "111", Region: "us-east-1", EnvironmentType: "prod", LineOfBusiness: "payments"}
	if err := EnforceScope(scope, r); err != nil {
		t.Fatalf("empty scope should allow all, got: %v", err)
	}
}

func TestEnforceScope_AccountIDFilter(t *testing.T) {
	scope := &ResourceScope{AccountIDs: []string{"111", "222"}}
	allowed := &stubResource{AccountID: "111", Region: "us-east-1"}
	denied := &stubResource{AccountID: "999", Region: "us-east-1"}

	if err := EnforceScope(scope, allowed); err != nil {
		t.Errorf("should allow account 111: %v", err)
	}
	if err := EnforceScope(scope, denied); err == nil {
		t.Error("should deny account 999")
	}
}

func TestEnforceScope_RegionFilter(t *testing.T) {
	scope := &ResourceScope{Regions: []string{"us-east-1", "eu-west-1"}}
	allowed := &stubResource{Region: "us-east-1"}
	denied := &stubResource{Region: "ap-southeast-1"}

	if err := EnforceScope(scope, allowed); err != nil {
		t.Errorf("should allow us-east-1: %v", err)
	}
	if err := EnforceScope(scope, denied); err == nil {
		t.Error("should deny ap-southeast-1")
	}
}

func TestEnforceScope_EnvironmentFilter(t *testing.T) {
	scope := &ResourceScope{Environments: []string{"production"}}
	allowed := &stubResource{EnvironmentType: "production"}
	denied := &stubResource{EnvironmentType: "staging"}

	if err := EnforceScope(scope, allowed); err != nil {
		t.Errorf("should allow production: %v", err)
	}
	if err := EnforceScope(scope, denied); err == nil {
		t.Error("should deny staging")
	}
}

func TestEnforceScope_BusinessUnitFilter(t *testing.T) {
	scope := &ResourceScope{BusinessUnits: []string{"payments"}}
	allowed := &stubResource{LineOfBusiness: "payments"}
	denied := &stubResource{LineOfBusiness: "marketing"}

	if err := EnforceScope(scope, allowed); err != nil {
		t.Errorf("should allow payments: %v", err)
	}
	if err := EnforceScope(scope, denied); err == nil {
		t.Error("should deny marketing")
	}
}

func TestEnforceScope_MultiDimensionAND(t *testing.T) {
	scope := &ResourceScope{
		AccountIDs: []string{"111"},
		Regions:    []string{"us-east-1"},
	}

	// Both match
	both := &stubResource{AccountID: "111", Region: "us-east-1"}
	if err := EnforceScope(scope, both); err != nil {
		t.Errorf("should allow when both match: %v", err)
	}

	// Account matches, region doesn't
	wrongRegion := &stubResource{AccountID: "111", Region: "eu-west-1"}
	if err := EnforceScope(scope, wrongRegion); err == nil {
		t.Error("should deny when region doesn't match")
	}

	// Region matches, account doesn't
	wrongAccount := &stubResource{AccountID: "999", Region: "us-east-1"}
	if err := EnforceScope(scope, wrongAccount); err == nil {
		t.Error("should deny when account doesn't match")
	}
}

func TestEnforceScope_CaseInsensitive(t *testing.T) {
	scope := &ResourceScope{Regions: []string{"US-EAST-1"}}
	r := &stubResource{Region: "us-east-1"}
	if err := EnforceScope(scope, r); err != nil {
		t.Errorf("should be case-insensitive: %v", err)
	}
}

func TestMatchesDimension_EmptyAllowsAll(t *testing.T) {
	if !MatchesDimension(nil, "anything") {
		t.Error("nil allowed list should match anything")
	}
	if !MatchesDimension([]string{}, "anything") {
		t.Error("empty allowed list should match anything")
	}
}

func TestScopeFromContext_NilClaims(t *testing.T) {
	if scope := ScopeFromContext(nil); scope != nil {
		t.Errorf("nil claims should return nil scope, got: %+v", scope)
	}
}

func TestScopeFromContext_NilScope(t *testing.T) {
	claims := &Claims{Subject: "user1"}
	if scope := ScopeFromContext(claims); scope != nil {
		t.Errorf("claims without scope should return nil, got: %+v", scope)
	}
}

func TestScopeFromContext_WithScope(t *testing.T) {
	scope := &ResourceScope{AccountIDs: []string{"111"}}
	claims := &Claims{Subject: "user1", ResourceScope: scope}
	got := ScopeFromContext(claims)
	if got == nil || len(got.AccountIDs) != 1 || got.AccountIDs[0] != "111" {
		t.Errorf("expected scope with account 111, got: %+v", got)
	}
}

func TestRoleFromClaims_Default(t *testing.T) {
	// Least privilege: no group claims -> viewer (lowest rank)
	claims := &Claims{Subject: "user1"}
	if role := RoleFromClaims(claims); role != RoleViewer {
		t.Errorf("default role should be viewer (least privilege), got: %s", role)
	}
}

func TestRoleFromClaims_ViewerBelowRequester(t *testing.T) {
	claims := &Claims{
		Subject: "viewer1",
		Groups:  []string{"aegis-viewer"},
	}
	if role := RoleFromClaims(claims); role != RoleViewer {
		t.Errorf("viewer group should yield viewer role, got: %s", role)
	}
	if roleRank[RoleViewer] >= roleRank[RoleRequester] {
		t.Errorf("viewer rank (%d) must be below requester rank (%d)", roleRank[RoleViewer], roleRank[RoleRequester])
	}
}

func TestRoleFromClaims_RequesterNeedsGroup(t *testing.T) {
	// Requester role requires explicit aegis-requester group membership.
	// Ungrouped tokens default to viewer (least privilege).
	noGroups := &Claims{Subject: "user1"}
	requesterGroup := &Claims{Subject: "user2", Groups: []string{"aegis-requester"}}
	if RoleFromClaims(noGroups) != RoleViewer {
		t.Fatal("no groups should default to viewer")
	}
	if RoleFromClaims(requesterGroup) != RoleRequester {
		t.Fatal("aegis-requester group should yield requester")
	}
}

func TestRoleFromClaims_HighestWins(t *testing.T) {
	claims := &Claims{
		Subject: "user1",
		Groups:  []string{"aegis-operator", "aegis-admin"},
	}
	if role := RoleFromClaims(claims); role != RoleAdmin {
		t.Errorf("highest role should be admin, got: %s", role)
	}
}

func TestRoleEnforcer_NonDevStripsHeader(t *testing.T) {
	re := &RoleEnforcer{DevMode: false}
	handler := re.Require(RoleAdmin)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if h := r.Header.Get("X-Aegis-Role"); h != "" {
			t.Errorf("X-Aegis-Role header should be stripped in non-dev, got: %s", h)
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("X-Aegis-Role", "admin")
	ctx := context.WithValue(req.Context(), ClaimsContextKey, &Claims{
		Subject: "attacker",
		Groups:  []string{"aegis-admin"},
	})
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

func TestRoleEnforcer_NonDevIgnoresOverride(t *testing.T) {
	re := &RoleEnforcer{DevMode: false}
	// Viewer-only user sends X-Aegis-Role: admin — should still be denied.
	handler := re.Require(RoleAdmin)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not be reached — viewer cannot escalate to admin")
	}))

	req := httptest.NewRequest("GET", "/admin-only", nil)
	req.Header.Set("X-Aegis-Role", "admin")
	ctx := context.WithValue(req.Context(), ClaimsContextKey, &Claims{
		Subject: "viewer-user",
		Groups:  []string{"aegis-viewer"},
	})
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403 (priv-esc blocked), got %d", rr.Code)
	}
}

func TestRoleEnforcer_DevModeAllowsOverride(t *testing.T) {
	re := &RoleEnforcer{DevMode: true}
	handler := re.Require(RoleAdmin)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/admin-only", nil)
	req.Header.Set("X-Aegis-Role", "admin")
	ctx := context.WithValue(req.Context(), ClaimsContextKey, &Claims{
		Subject: "dev-user",
		Groups:  []string{"aegis-viewer"},
	})
	req = req.WithContext(ctx)

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("dev mode should allow X-Aegis-Role override, got %d", rr.Code)
	}
}
