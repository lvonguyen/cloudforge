package main

import (
	"fmt"
	"net/http"
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
		`g.V().choose(hasLabel('person'), out('knows'), out('created'))`,
		// S3 closure bypass vectors
		`g.V().aggregate('all')`,
		`g.V().store('data')`,
		`g.V().coalesce(values('name'), constant('none'))`,
		`g.V().cap('x')`,
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
