package main

import (
	"net/http"
	"strings"
	"testing"
)

func TestListContainers_Success(t *testing.T) {
	_, router := testServer(t)
	jwt := adminJWT(t)

	rr := doRequest(t, router, "GET", "/api/v1/containers", "", jwt)
	assertStatus(t, rr, http.StatusOK)

	var resp ContainerTopologyResponse
	assertJSON(t, rr, &resp)

	if len(resp.Clusters) == 0 {
		t.Fatal("expected at least 1 cluster, got 0")
	}
}

func TestListContainers_OperatorAllowed(t *testing.T) {
	_, router := testServer(t)
	jwt := operatorJWT(t)

	rr := doRequest(t, router, "GET", "/api/v1/containers", "", jwt)
	assertStatus(t, rr, http.StatusOK)

	var resp ContainerTopologyResponse
	assertJSON(t, rr, &resp)

	if len(resp.Clusters) == 0 {
		t.Fatal("expected at least 1 cluster, got 0")
	}
}

func TestListContainers_ViewerForbidden(t *testing.T) {
	_, router := testServer(t)
	jwt := viewerJWT(t)

	rr := doRequest(t, router, "GET", "/api/v1/containers", "", jwt)
	if rr.Code == http.StatusForbidden {
		t.Errorf("status = 403, want non-forbidden (viewer parity)")
	}
}

func TestListContainers_Unauthenticated(t *testing.T) {
	_, router := testServer(t)

	rr := doRequest(t, router, "GET", "/api/v1/containers", "", "")
	assertStatus(t, rr, http.StatusUnauthorized)
}

func TestGetContainer_Success(t *testing.T) {
	_, router := testServer(t)
	jwt := adminJWT(t)

	rr := doRequest(t, router, "GET", "/api/v1/containers/c-1", "", jwt)
	assertStatus(t, rr, http.StatusOK)

	var c Container
	assertJSON(t, rr, &c)

	if c.ID != "c-1" {
		t.Errorf("container ID = %q, want %q", c.ID, "c-1")
	}
	if c.Name == "" {
		t.Error("container name is empty")
	}
}

func TestGetContainer_NotFound(t *testing.T) {
	_, router := testServer(t)
	jwt := adminJWT(t)

	rr := doRequest(t, router, "GET", "/api/v1/containers/nonexistent", "", jwt)
	assertStatus(t, rr, http.StatusNotFound)

	body := rr.Body.String()
	if !strings.Contains(body, "container not found") {
		t.Errorf("expected 'container not found' in body, got: %s", body)
	}
}

func TestScanContainer_MissingImage(t *testing.T) {
	_, router := testServer(t)
	jwt := adminJWT(t)

	rr := doRequest(t, router, "GET", "/api/v1/container/scan", "", jwt)
	assertStatus(t, rr, http.StatusBadRequest)

	body := rr.Body.String()
	if !strings.Contains(body, "image query parameter is required") {
		t.Errorf("expected 'image query parameter is required' in body, got: %s", body)
	}
}

func TestScanContainer_InvalidImage(t *testing.T) {
	_, router := testServer(t)
	jwt := adminJWT(t)

	rr := doRequest(t, router, "GET", "/api/v1/container/scan?image=../../etc/passwd", "", jwt)
	assertStatus(t, rr, http.StatusBadRequest)

	body := rr.Body.String()
	if !strings.Contains(body, "invalid image reference") {
		t.Errorf("expected 'invalid image reference' in body, got: %s", body)
	}
}
