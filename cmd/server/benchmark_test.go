package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"cloudforge/internal/api"
	"cloudforge/internal/grc"
	"cloudforge/internal/identity"
	"cloudforge/internal/observability"

	"github.com/gorilla/mux"
	"go.uber.org/zap"
)

// benchServer creates a Server suitable for use in benchmarks.
// Mirrors testServer but uses testing.B helpers.
func benchServer(b *testing.B) (*Server, *mux.Router) {
	b.Helper()

	b.Setenv("TEST_JWT_SECRET", testJWTSecret)

	logger := zap.NewNop()

	grcProvider, err := grc.NewProvider(grc.Config{Type: grc.ProviderTypeMemory})
	if err != nil {
		b.Fatalf("creating GRC provider: %v", err)
	}

	authMiddleware, err := api.NewAuthMiddleware(api.AuthConfig{
		JWTSecretEnv: "TEST_JWT_SECRET",
		SkipPaths:    []string{"/health"},
	}, logger)
	if err != nil {
		b.Fatalf("creating auth middleware: %v", err)
	}

	mockData, err := loadMockData(mockDataDir())
	if err != nil {
		b.Fatalf("loading mock data: %v", err)
	}

	attackPaths, attackPathStats := computeAttackPaths(mockData.Findings)

	srv := &Server{
		config:            Config{Port: "0"},
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
		identityProviders: map[string]identity.Provider{
			"okta":     identity.NewMockOktaProvider(),
			"entra_id": identity.NewMockEntraIDProvider(),
		},
	}

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

// makeJWTForBench creates a minimal HS256 JWT for use in benchmarks.
// Accepts *testing.B to allow proper error reporting instead of panic.
func makeJWTForBench(b *testing.B, claims api.Claims) string {
	b.Helper()

	if claims.ExpiresAt == 0 {
		claims.ExpiresAt = time.Now().Add(time.Hour).Unix()
	}
	if claims.IssuedAt == 0 {
		claims.IssuedAt = time.Now().Unix()
	}

	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))

	payload, err := json.Marshal(claims)
	if err != nil {
		b.Fatalf("marshal claims: %v", err)
	}
	payloadB64 := base64.RawURLEncoding.EncodeToString(payload)

	signingInput := header + "." + payloadB64
	mac := hmac.New(sha256.New, []byte(testJWTSecret))
	mac.Write([]byte(signingInput))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	return signingInput + "." + sig
}

// adminClaims returns standard admin claims for benchmarks.
func adminClaims() api.Claims {
	return api.Claims{
		Subject: "bench-admin",
		Email:   "admin@contoso.dev",
		Groups:  []string{"cloudforge-admin"},
		Scope:   "admin",
	}
}

// BenchmarkServerStartup measures the time to create a fully configured test server.
func BenchmarkServerStartup(b *testing.B) {
	b.Setenv("TEST_JWT_SECRET", testJWTSecret)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchServer(b)
	}
}

// BenchmarkListFindings measures GET /api/v1/findings throughput.
func BenchmarkListFindings(b *testing.B) {
	_, router := benchServer(b)
	jwt := makeJWTForBench(b, adminClaims())

	req, _ := http.NewRequest("GET", "/api/v1/findings", nil)
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("Content-Type", "application/json")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			b.Fatalf("unexpected status %d", rr.Code)
		}
	}
}

// BenchmarkListAttackPaths measures paginated GET /api/v1/attack-paths throughput.
func BenchmarkListAttackPaths(b *testing.B) {
	_, router := benchServer(b)
	jwt := makeJWTForBench(b, adminClaims())

	req, _ := http.NewRequest("GET", "/api/v1/attack-paths?page=1&per_page=20", nil)
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("Content-Type", "application/json")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			b.Fatalf("unexpected status %d", rr.Code)
		}
	}
}

// BenchmarkGetFinding measures GET /api/v1/findings/:id throughput.
func BenchmarkGetFinding(b *testing.B) {
	srv, router := benchServer(b)
	jwt := makeJWTForBench(b, adminClaims())

	if len(srv.mockData.Findings) == 0 {
		b.Fatal("no mock findings loaded")
	}
	findingID := srv.mockData.Findings[0].ID

	req, _ := http.NewRequest("GET", "/api/v1/findings/"+findingID, nil)
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("Content-Type", "application/json")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			b.Fatalf("unexpected status %d: %s", rr.Code, rr.Body.String())
		}
	}
}

// BenchmarkAttackPathComputation measures the computeAttackPaths algorithm directly.
func BenchmarkAttackPathComputation(b *testing.B) {
	b.Setenv("TEST_JWT_SECRET", testJWTSecret)

	mockData, err := loadMockData(mockDataDir())
	if err != nil {
		b.Fatalf("loading mock data: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		paths, stats := computeAttackPaths(mockData.Findings)
		if len(paths) == 0 || stats == nil {
			b.Fatal("computeAttackPaths returned empty results")
		}
	}
}
