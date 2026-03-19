package main

import (
	"encoding/json"
	"net/http"
	"testing"
)

func TestGetCompliancePosture_OK(t *testing.T) {
	_, router := testServer(t)
	jwt := operatorJWT(t)

	rr := doRequest(t, router, "GET", "/api/v1/compliance/posture", "", jwt)
	assertStatus(t, rr, http.StatusOK)

	var frameworks []json.RawMessage
	assertJSON(t, rr, &frameworks)

	if len(frameworks) == 0 {
		t.Fatal("expected at least one framework in posture response")
	}
}

func TestGetComplianceControls_ValidFramework(t *testing.T) {
	_, router := testServer(t)
	jwt := operatorJWT(t)

	// CIS is always registered as a built-in framework
	rr := doRequest(t, router, "GET", "/api/v1/compliance/controls/cis-benchmarks", "", jwt)
	assertStatus(t, rr, http.StatusOK)

	var controls []json.RawMessage
	assertJSON(t, rr, &controls)

	if len(controls) == 0 {
		t.Fatal("expected controls for CIS framework")
	}
}

func TestGetComplianceControls_NotFound(t *testing.T) {
	_, router := testServer(t)
	jwt := operatorJWT(t)

	rr := doRequest(t, router, "GET", "/api/v1/compliance/controls/nonexistent-fw", "", jwt)
	assertStatus(t, rr, http.StatusNotFound)
}
