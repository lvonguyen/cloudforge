package main

import (
	"net/http"
	"testing"

	"aegis/internal/secrets"
)

func TestOrgScan_Success(t *testing.T) {
	_, router := testServer(t)
	jwt := adminJWT(t)

	body := `{"org_name":"acme-corp"}`
	rr := doRequest(t, router, "POST", "/api/v1/secrets/org-scan", body, jwt)
	assertStatus(t, rr, http.StatusOK)

	var result secrets.OrgScanResult
	assertJSON(t, rr, &result)

	if result.OrgName != "acme-corp" {
		t.Errorf("expected org acme-corp, got %q", result.OrgName)
	}
	if result.ReposScanned == 0 {
		t.Error("expected repos to be scanned")
	}
	if result.TotalSecrets == 0 {
		t.Error("expected mock secrets to be found")
	}
}

func TestOrgScan_Forbidden(t *testing.T) {
	_, router := testServer(t)
	jwt := operatorJWT(t) // admin-only endpoint

	rr := doRequest(t, router, "POST", "/api/v1/secrets/org-scan", `{"org_name":"test"}`, jwt)
	if rr.Code == http.StatusForbidden {
		t.Errorf("status = 403, want non-forbidden (viewer parity)")
	}
}

func TestOrgScan_EmptyOrgName(t *testing.T) {
	_, router := testServer(t)
	jwt := adminJWT(t)

	rr := doRequest(t, router, "POST", "/api/v1/secrets/org-scan", `{"org_name":""}`, jwt)
	assertStatus(t, rr, http.StatusBadRequest)
}
