package main

import (
	"encoding/json"
	"net/http"
	"testing"

	"cloudforge/internal/asm"
)

func TestASMScan_Success(t *testing.T) {
	_, router := testServer(t)
	jwt := operatorJWT(t)

	body := `{"domain":"example.com"}`
	rr := doRequest(t, router, "POST", "/api/v1/asm/scan", body, jwt)
	assertStatus(t, rr, http.StatusOK)

	var result asm.ScanResult
	assertJSON(t, rr, &result)

	if result.Domain != "example.com" {
		t.Errorf("expected domain example.com, got %q", result.Domain)
	}
	if len(result.Assets) == 0 {
		t.Fatal("expected at least one asset from mock scanner")
	}
}

func TestASMScan_EmptyDomain(t *testing.T) {
	_, router := testServer(t)
	jwt := operatorJWT(t)

	rr := doRequest(t, router, "POST", "/api/v1/asm/scan", `{"domain":""}`, jwt)
	assertStatus(t, rr, http.StatusBadRequest)
}

func TestASMAssets_EmptyBeforeScan(t *testing.T) {
	_, router := testServer(t)
	jwt := operatorJWT(t)

	rr := doRequest(t, router, "GET", "/api/v1/asm/assets", "", jwt)
	assertStatus(t, rr, http.StatusOK)

	var assets []json.RawMessage
	assertJSON(t, rr, &assets)
	if len(assets) != 0 {
		t.Errorf("expected empty assets before scan, got %d", len(assets))
	}
}
