package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"aegis/internal/api"
	"aegis/internal/audit"
	"aegis/internal/finops"
	"aegis/internal/grc"
	"aegis/internal/identity"
	"aegis/internal/observability"

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
		config: Config{Port: "0"},
		grcHandler: &GRCHandler{
			provider:    grcProvider,
			logger:      logger.Named("grc"),
			auditLogger: audit.NewMemoryAuditLogger(),
		},
		router:         mux.NewRouter(),
		authMiddleware: authMiddleware,
		healthChecker:  observability.NewHealthChecker(logger, nil),
		logger:         logger,
		data:           NewDataStore(mockData),
		attackPathSvc: func() *AttackPathService {
			svc := &AttackPathService{Paths: attackPaths, Stats: attackPathStats}
			svc.buildPathIndex()
			return svc
		}(),
		enrichmentSvc: &EnrichmentService{
			Cache:  make(map[string]*FindingEnrichment),
			Logger: logger,
		},
		roles:     &api.RoleEnforcer{DevMode: false},
		finopsSvc: newFinopsServiceFromAggregator(finops.NewMemoryAggregator()),
		identitySvc: NewIdentityService(map[string]identity.Provider{
			"okta":     identity.NewMockOktaProvider(),
			"entra_id": identity.NewMockEntraIDProvider(),
		}),
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
		Groups:  []string{"aegis-admin"},
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

	if len(srv.data.Findings) == 0 {
		b.Fatal("no mock findings loaded")
	}
	findingID := srv.data.Findings[0].ID

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

// BenchmarkGetCached_Hit measures enrichment cache read (RLock path) with a pre-populated entry.
func BenchmarkGetCached_Hit(b *testing.B) {
	svc := &EnrichmentService{
		Cache:  make(map[string]*FindingEnrichment),
		Logger: zap.NewNop(),
	}
	svc.Cache["bench-finding"] = &FindingEnrichment{
		FindingID: "bench-finding",
		CreatedAt: time.Now(),
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cached, ok := svc.GetCached("bench-finding")
		if !ok || cached == nil {
			b.Fatal("expected cache hit")
		}
	}
}

// BenchmarkGetCached_Miss measures enrichment cache read (RLock path) on empty cache.
func BenchmarkGetCached_Miss(b *testing.B) {
	svc := &EnrichmentService{
		Cache:  make(map[string]*FindingEnrichment),
		Logger: zap.NewNop(),
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, ok := svc.GetCached("nonexistent")
		if ok {
			b.Fatal("expected cache miss")
		}
	}
}

// BenchmarkEvictExpired_5000 fills the enrichment cache to 5000+500 entries and
// measures eviction performance (sort.Slice on 5500 items + delete loop).
func BenchmarkEvictExpired_5000(b *testing.B) {
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		b.StopTimer()
		svc := &EnrichmentService{
			Cache:  make(map[string]*FindingEnrichment, 5500),
			Logger: zap.NewNop(),
		}
		// Fill cache: 5000 current + 500 expired
		now := time.Now()
		for j := 0; j < 5000; j++ {
			svc.Cache[fmt.Sprintf("current-%d", j)] = &FindingEnrichment{
				FindingID: fmt.Sprintf("current-%d", j),
				CreatedAt: now,
			}
		}
		for j := 0; j < 500; j++ {
			svc.Cache[fmt.Sprintf("expired-%d", j)] = &FindingEnrichment{
				FindingID: fmt.Sprintf("expired-%d", j),
				CreatedAt: now.Add(-2 * enrichmentCacheTTL),
			}
		}
		b.StartTimer()
		svc.evictExpired()
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
