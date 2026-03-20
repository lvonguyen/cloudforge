package main

import (
	"encoding/json"
	"net/http"
	"testing"
)

func TestListDataClassificationAssets_Success(t *testing.T) {
	_, router := testServer(t)
	jwt := operatorJWT(t)

	rr := doRequest(t, router, "GET", "/api/v1/data-classification/assets", "", jwt)
	assertStatus(t, rr, http.StatusOK)

	var resp struct {
		Data []map[string]interface{} `json:"data"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if len(resp.Data) != 8 {
		t.Fatalf("expected 8 data assets, got %d", len(resp.Data))
	}

	first := resp.Data[0]
	if first["id"] != "da-001" {
		t.Errorf("first asset id = %v, want da-001", first["id"])
	}
	if first["sensitivity"] != "PII" {
		t.Errorf("first asset sensitivity = %v, want PII", first["sensitivity"])
	}
	if first["resource_type"] != "object_storage" {
		t.Errorf("first asset resource_type = %v, want object_storage", first["resource_type"])
	}
}

func TestListDataClassificationAssets_AdminAllowed(t *testing.T) {
	_, router := testServer(t)
	jwt := adminJWT(t)

	rr := doRequest(t, router, "GET", "/api/v1/data-classification/assets", "", jwt)
	assertStatus(t, rr, http.StatusOK)
}

func TestListDataClassificationAssets_ViewerForbidden(t *testing.T) {
	_, router := testServer(t)
	jwt := viewerJWT(t)

	rr := doRequest(t, router, "GET", "/api/v1/data-classification/assets", "", jwt)
	if rr.Code == http.StatusForbidden { t.Errorf("status = 403, want non-forbidden (viewer parity)") }
}

func TestListDataClassificationAssets_Unauthenticated(t *testing.T) {
	_, router := testServer(t)

	rr := doRequest(t, router, "GET", "/api/v1/data-classification/assets", "", "")
	assertStatus(t, rr, http.StatusUnauthorized)
}
