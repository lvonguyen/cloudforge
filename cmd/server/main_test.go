package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"aegis/internal/api"
	"aegis/internal/asm"
	"aegis/internal/audit"
	"aegis/internal/compliance"
	"aegis/internal/container"
	"aegis/internal/grc"
	"aegis/internal/identity"
	"aegis/internal/ingestion"
	"aegis/internal/integrations"
	"aegis/internal/observability"
	"aegis/internal/secrets"
	"aegis/internal/waf"
	"aegis/internal/webhooks"
	"aegis/internal/workflow"

	"github.com/gorilla/mux"
	"go.uber.org/zap"
)

// Shared test fixtures: uses trimmed 200-finding fixture (not 20k production mock).
// computeAttackPaths is O(n^2) so this cuts setup from ~2min to <1s.
var (
	sharedTestOnce      sync.Once
	sharedTestMockData  *MockData
	sharedTestPaths     []AttackPath
	sharedTestPathStats *AttackPathStats
	sharedTestErr       error
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

	// Load trimmed 200-finding fixture + compute attack paths. Each test gets
	// a shallow copy so mutations (e.g. ingest appending findings) stay isolated.
	sharedTestOnce.Do(func() {
		sharedTestMockData, sharedTestErr = loadTestMockData(mockDataDir())
		if sharedTestErr != nil {
			return
		}
		sharedTestPaths, sharedTestPathStats = computeAttackPaths(sharedTestMockData.Findings)
	})
	if sharedTestErr != nil {
		t.Fatalf("loading mock data: %v", sharedTestErr)
	}

	// Shallow copy — slice headers are copied so append() in ingest tests
	// won't mutate the shared cache.
	mockData := *sharedTestMockData

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

	wfEngine, err := workflow.NewEngine("memory")
	if err != nil {
		t.Fatalf("creating workflow engine: %v", err)
	}
	wafMgr, err := waf.NewTemplateManager("memory")
	if err != nil {
		t.Fatalf("creating WAF template manager: %v", err)
	}
	ctrScanner, err := container.NewScanner("memory")
	if err != nil {
		t.Fatalf("creating container scanner: %v", err)
	}

	srv := &Server{
		config: Config{
			Port: "0",
		},
		grcHandler: &GRCHandler{
			provider:    grcProvider,
			logger:      logger.Named("grc"),
			auditLogger: audit.NewMemoryAuditLogger(),
		},
		router:         mux.NewRouter(),
		authMiddleware: authMiddleware,
		healthChecker:  observability.NewHealthChecker(logger, nil),
		logger:         logger,
		data:           NewDataStore(&mockData),
		attackPathSvc: func() *AttackPathService {
			svc := &AttackPathService{Paths: sharedTestPaths, Stats: sharedTestPathStats}
			svc.buildPathIndex()
			return svc
		}(),
		enrichmentSvc: &EnrichmentService{
			Cache:  make(map[string]*FindingEnrichment),
			Logger: logger,
		},
		roles:       &api.RoleEnforcer{DevMode: false},
		comments:    NewCommentsStore(),
		finopsSvc:   newFinopsService(logger),
		dedupCache:  ingestion.NewDedupCache(24 * time.Hour),
		auditLogger: audit.NewMemoryAuditLogger(),
		identitySvc: NewIdentityService(map[string]identity.Provider{
			"okta":     identity.NewMockOktaProvider(),
			"entra_id": identity.NewMockEntraIDProvider(),
		}),
		workflowEngine:   wfEngine,
		wafManager:       wafMgr,
		secretsProvider:  secrets.NewMemoryProvider("demo"),
		secretsManager:   secrets.NewManager(logger),
		containerScanner: ctrScanner,
		deployTracker:    newDeployTracker(),

		// Integration layer
		integrationHandler: &IntegrationHandler{
			provider:    integrations.NewMockProvider(logger),
			router:      integrations.NewRoutingEngine(integrations.DefaultRules()),
			workflow:    wfEngine,
			auditLogger: audit.NewMemoryAuditLogger(),
			logger:      logger,
		},
		webhookEngine: webhooks.NewMemoryEngine(logger),
		complianceMgr: compliance.NewManager(logger),
		asmSvc:        &asmService{scanner: asm.NewMockScanner()},
		orgScanner:    secrets.NewMockOrgScanner(),
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

// adminJWT returns a JWT with admin role (aegis-admin group).
func adminJWT(t *testing.T) string {
	t.Helper()
	return makeJWT(t, api.Claims{
		Subject: "test-admin",
		Email:   "admin@contoso.dev",
		Groups:  []string{"aegis-admin"},
		Scope:   "admin compliance",
	})
}

// operatorJWT returns a JWT with operator role (aegis-operator group).
func operatorJWT(t *testing.T) string {
	t.Helper()
	return makeJWT(t, api.Claims{
		Subject: "test-operator",
		Email:   "operator@contoso.dev",
		Groups:  []string{"aegis-operator"},
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

// viewerJWT returns a JWT with viewer role (aegis-viewer group).
func viewerJWT(t *testing.T) string {
	t.Helper()
	return makeJWT(t, api.Claims{
		Subject: "test-viewer",
		Email:   "viewer@contoso.dev",
		Groups:  []string{"aegis-viewer"},
		Scope:   "viewer",
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

// assertPaginatedJSON decodes a paginatedResponse and unmarshals the .data
// field into dst. Use this for endpoints that wrap their result in a paginated
// envelope (page, per_page, total, total_pages, data).
func assertPaginatedJSON(t *testing.T, rr *httptest.ResponseRecorder, dst interface{}) {
	t.Helper()
	var wrapper struct {
		Data json.RawMessage `json:"data"`
	}
	body := rr.Body.String()
	if err := json.Unmarshal([]byte(body), &wrapper); err != nil {
		t.Fatalf("decode paginated response: %v; body: %s", err, body)
	}
	if err := json.Unmarshal(wrapper.Data, dst); err != nil {
		t.Fatalf("decode paginated .data: %v; raw: %s", err, string(wrapper.Data))
	}
}
