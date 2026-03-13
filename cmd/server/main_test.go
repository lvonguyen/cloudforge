package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"cloudforge/internal/api"
	"cloudforge/internal/audit"
	"cloudforge/internal/grc"
	"cloudforge/internal/identity"
	"cloudforge/internal/ingestion"
	"cloudforge/internal/observability"

	"github.com/gorilla/mux"
	"go.uber.org/zap"
)

// testJWTSecret is the shared secret for test JWT generation.
const testJWTSecret = "test-secret-for-unit-tests-only"

// testServer creates a fully configured Server with in-memory GRC provider
// and test-friendly auth middleware. The env var for the JWT secret is set
// before middleware construction so the middleware reads it during init.
func testServer(t *testing.T) (*Server, *mux.Router) {
	t.Helper()

	// Must be set before NewAuthMiddleware — it reads the env var at construction time.
	t.Setenv("TEST_JWT_SECRET", testJWTSecret)

	logger := zap.NewNop()

	grcProvider, err := grc.NewProvider(grc.Config{Type: grc.ProviderTypeMemory})
	if err != nil {
		t.Fatalf("creating GRC provider: %v", err)
	}

	authMiddleware, err := api.NewAuthMiddleware(api.AuthConfig{
		JWTSecretEnv: "TEST_JWT_SECRET",
		SkipPaths:    []string{"/health"},
	}, logger)
	if err != nil {
		t.Fatalf("creating auth middleware: %v", err)
	}

	mockData, err := loadMockData(mockDataDir())
	if err != nil {
		t.Fatalf("loading mock data: %v", err)
	}

	attackPaths, attackPathStats := computeAttackPaths(mockData.Findings)

	srv := &Server{
		config: Config{
			Port: "0",
		},
		grcProvider:       grcProvider,
		router:            mux.NewRouter(),
		authMiddleware:    authMiddleware,
		healthChecker:     observability.NewHealthChecker(logger, nil),
		logger:            logger,
		mockData:          mockData,
		attackPaths:       attackPaths,
		attackPathStats:   attackPathStats,
		findingEnrichment: make(map[string]*FindingEnrichment),
		roles:             &api.RoleEnforcer{DevMode: false},
		finopsSvc:         newFinopsService(),
		dedupCache:        ingestion.NewDedupCache(24 * time.Hour),
		auditLogger:       audit.NewMemoryAuditLogger(),
		identityProviders: map[string]identity.Provider{
			"okta":     identity.NewMockOktaProvider(),
			"entra_id": identity.NewMockEntraIDProvider(),
		},
	}

	// Build O(1) lookup maps (matches main.go init logic)
	srv.findingsByID = make(map[string]*Finding, len(mockData.Findings))
	for i := range mockData.Findings {
		srv.findingsByID[mockData.Findings[i].ID] = &mockData.Findings[i]
	}
	srv.agentsByID = make(map[string]*Agent, len(mockData.Agents))
	for i := range mockData.Agents {
		srv.agentsByID[mockData.Agents[i].ID] = &mockData.Agents[i]
	}
	srv.remediationsByID = make(map[string]*RemediationRecord, len(mockData.Remediations))
	for i := range mockData.Remediations {
		srv.remediationsByID[mockData.Remediations[i].ID] = &mockData.Remediations[i]
	}
	srv.tracesByAgentID = make(map[string][]AgentTrace, len(mockData.Agents))
	for _, tr := range mockData.Traces {
		srv.tracesByAgentID[tr.AgentID] = append(srv.tracesByAgentID[tr.AgentID], tr)
	}

	srv.setupRoutes()

	return srv, srv.router
}

// makeJWT creates a minimal HS256 JWT for testing.
// The token is signed with testJWTSecret and accepted by the real AuthMiddleware.
func makeJWT(t *testing.T, claims api.Claims) string {
	t.Helper()

	if claims.ExpiresAt == 0 {
		claims.ExpiresAt = time.Now().Add(time.Hour).Unix()
	}
	if claims.IssuedAt == 0 {
		claims.IssuedAt = time.Now().Unix()
	}

	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))

	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	payloadB64 := base64.RawURLEncoding.EncodeToString(payload)

	signingInput := header + "." + payloadB64
	mac := hmac.New(sha256.New, []byte(testJWTSecret))
	mac.Write([]byte(signingInput))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	return signingInput + "." + sig
}

// adminJWT returns a JWT with admin role (cloudforge-admin group).
func adminJWT(t *testing.T) string {
	t.Helper()
	return makeJWT(t, api.Claims{
		Subject: "test-admin",
		Email:   "admin@contoso.dev",
		Groups:  []string{"cloudforge-admin"},
		Scope:   "admin compliance",
	})
}

// operatorJWT returns a JWT with operator role (cloudforge-operator group).
func operatorJWT(t *testing.T) string {
	t.Helper()
	return makeJWT(t, api.Claims{
		Subject: "test-operator",
		Email:   "operator@contoso.dev",
		Groups:  []string{"cloudforge-operator"},
		Scope:   "operator",
	})
}

// requesterJWT returns a JWT with requester role (no special groups).
func requesterJWT(t *testing.T) string {
	t.Helper()
	return makeJWT(t, api.Claims{
		Subject: "test-requester",
		Email:   "user@contoso.dev",
		Scope:   "requester",
	})
}

// doRequest executes an HTTP request against the test router and returns the recorder.
func doRequest(t *testing.T, router http.Handler, method, path, body, jwt string) *httptest.ResponseRecorder {
	t.Helper()

	var req *http.Request
	var err error
	if body != "" {
		req, err = http.NewRequest(method, path, strings.NewReader(body))
	} else {
		req, err = http.NewRequest(method, path, nil)
	}
	if err != nil {
		t.Fatalf("create request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")
	if jwt != "" {
		req.Header.Set("Authorization", "Bearer "+jwt)
	}

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	return rr
}

// assertStatus checks the response status code.
func assertStatus(t *testing.T, rr *httptest.ResponseRecorder, want int) {
	t.Helper()
	if rr.Code != want {
		t.Errorf("status = %d, want %d; body: %s", rr.Code, want, rr.Body.String())
	}
}

// assertJSON unmarshals the response body into dst.
func assertJSON(t *testing.T, rr *httptest.ResponseRecorder, dst interface{}) {
	t.Helper()
	if err := json.NewDecoder(rr.Body).Decode(dst); err != nil {
		t.Fatalf("decode response: %v; body: %s", err, rr.Body.String())
	}
}
