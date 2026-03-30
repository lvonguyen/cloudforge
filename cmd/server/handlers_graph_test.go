package main

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
)

func TestGraphQuery_GremlinMutationBlocked(t *testing.T) {
	_, router := testServer(t)
	jwt := operatorJWT(t)

	// All Gremlin mutation steps that must be blocked.
	mutations := []string{
		`g.addV('test')`,
		`g.addE('knows')`,
		`g.V().drop()`,
		`g.V().property('key','val')`,
		`g.V().sideEffect{it.get()}`,
		`g.inject(1,2,3)`,
		`g.mergeV([:])`,
		`g.mergeE([:])`,
		`g.io('/etc/hostname').read()`,
		`g.call('custom-op')`,
		// S3 closure bypass vectors
		`g.V().aggregate('all')`,
		`g.V().store('data')`,
		`g.V().cap('x')`,
		// BD-01: NBSP (U+00A0) between dot and keyword — must be blocked after NFKC normalization.
		"g.V().\u00a0inject(1,2,3)",
		"g.V().\u00a0io('/etc/hostname').read()",
		// Regular space between dot and keyword.
		`g.V(). inject(1,2,3)`,
		`g.V(). call('op')`,
	}

	for _, q := range mutations {
		body := fmt.Sprintf(`{"language":"gremlin","query":"%s"}`, q)
		rr := doRequest(t, router, "POST", "/api/v1/graph/query", body, jwt)
		if rr.Code != http.StatusForbidden && rr.Code != http.StatusNotImplemented {
			t.Errorf("mutation %q: want 403 or 501, got %d", q, rr.Code)
		}
	}
}

func TestGraphQuery_GremlinReadAllowed(t *testing.T) {
	_, router := testServer(t)
	jwt := operatorJWT(t)

	reads := []string{
		`g.V().hasLabel('account').limit(10)`,
		`g.V().out('owns').valueMap()`,
		`g.E().hasLabel('accesses').count()`,
		// Read-only steps that must NOT be blocked.
		`g.V().choose(hasLabel('person'), out('knows'), out('created'))`,
		`g.V().coalesce(values('name'), constant('none'))`,
		// BD-01: property names containing blocklist substrings must not false-positive.
		`g.V().has('callback_url', 'https://example.com')`,
		`g.V().has('io_config', 'default')`,
		`g.V().has('evaluate_score', '5')`,
		`g.V().has('program_name', 'demo')`,
		`g.V().has('runtime_version', '1.8')`,
		`g.V().has('system_type', 'linux')`,
		`g.V().has('thread_count', '4')`,
	}

	for _, q := range reads {
		body := fmt.Sprintf(`{"language":"gremlin","query":"%s"}`, q)
		rr := doRequest(t, router, "POST", "/api/v1/graph/query", body, jwt)
		// 501 (not configured) or 200 are both acceptable — just not 403.
		if rr.Code == http.StatusForbidden {
			t.Errorf("read query %q was incorrectly blocked as mutation", q)
		}
	}
}

func TestGraphQuery_CypherMutationBlocked(t *testing.T) {
	_, router := testServer(t)
	jwt := operatorJWT(t)

	mutations := []string{
		`CREATE (n:Test)`,
		`MATCH (n) DELETE n`,
		`MATCH (n) DETACH DELETE n`,
		`MATCH (n) SET n.name = 'x'`,
		`MERGE (n:Test {id: 1})`,
	}

	for _, q := range mutations {
		body := fmt.Sprintf(`{"language":"cypher","query":"%s"}`, q)
		rr := doRequest(t, router, "POST", "/api/v1/graph/query", body, jwt)
		if rr.Code != http.StatusForbidden && rr.Code != http.StatusNotImplemented {
			t.Errorf("cypher mutation %q: want 403 or 501, got %d", q, rr.Code)
		}
	}
}

func TestGraphQuery_ViewerForbidden(t *testing.T) {
	_, router := testServer(t)
	jwt := viewerJWT(t)

	body := `{"language":"gremlin","query":"g.V().count()"}`
	rr := doRequest(t, router, "POST", "/api/v1/graph/query", body, jwt)
	assertStatus(t, rr, http.StatusForbidden)
}

func TestGraphQuery_GroovyTemplateBlocked(t *testing.T) {
	_, router := testServer(t)
	jwt := operatorJWT(t)

	templates := []string{
		`g.V().has('name', '${Runtime.exec("cmd")}')`,
		`g.V().has('id', '${System.getenv("SECRET")}')`,
	}

	for _, q := range templates {
		body := fmt.Sprintf(`{"language":"gremlin","query":"%s"}`, q)
		rr := doRequest(t, router, "POST", "/api/v1/graph/query", body, jwt)
		if rr.Code != http.StatusForbidden && rr.Code != http.StatusNotImplemented {
			t.Errorf("Groovy template %q: want 403 or 501, got %d", q, rr.Code)
		}
	}
}

func TestGraphQuery_InvalidLanguage(t *testing.T) {
	_, router := testServer(t)
	jwt := operatorJWT(t)

	// graphClient is nil in test server, so 501 is returned before language
	// validation. This test verifies the endpoint is reachable and responds.
	body := `{"language":"sparql","query":"SELECT * WHERE {?s ?p ?o}"}`
	rr := doRequest(t, router, "POST", "/api/v1/graph/query", body, jwt)
	// 501 (not configured) or 400 (invalid language) — both acceptable.
	if rr.Code != http.StatusNotImplemented && rr.Code != http.StatusBadRequest {
		t.Errorf("want 501 or 400, got %d", rr.Code)
	}
}

func TestValidateAndNormalizeGraphQuery(t *testing.T) {
	tests := []struct {
		name       string
		language   string
		query      string
		want       string
		wantStatus int
	}{
		{
			name:     "gremlin read query trims and normalizes",
			language: "gremlin",
			query:    "  g.V().count()  ",
			want:     "g.V().count()",
		},
		{
			name:       "gremlin nbsp mutation blocked",
			language:   "gremlin",
			query:      "g.V().\u00a0inject(1,2,3)",
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "cypher comment bypass blocked",
			language:   "cypher",
			query:      `CR/**/EATE (n:Test)`,
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "groovy template blocked",
			language:   "gremlin",
			query:      `g.V().has('name', '${Runtime.exec("cmd")}')`,
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "invalid language rejected",
			language:   "sparql",
			query:      `SELECT * WHERE {?s ?p ?o}`,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "whitespace only rejected",
			language:   "gremlin",
			query:      " \u00a0\u2003 ",
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "cypher comments only rejected",
			language:   "cypher",
			query:      "/* only comment */ -- and more",
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "too long rejected",
			language:   "gremlin",
			query:      strings.Repeat("x", maxGraphQueryLen+1),
			wantStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := validateAndNormalizeGraphQuery(tt.language, tt.query)
			if tt.wantStatus != 0 {
				if err == nil {
					t.Fatalf("expected status %d, got nil error", tt.wantStatus)
				}
				validationErr, ok := err.(*graphQueryValidationError)
				if !ok {
					t.Fatalf("expected *graphQueryValidationError, got %T", err)
				}
				if validationErr.status != tt.wantStatus {
					t.Fatalf("expected status %d, got %d", tt.wantStatus, validationErr.status)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}
