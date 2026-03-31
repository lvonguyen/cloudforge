package main

import (
	"context"
	"errors"
	"net/http"
	"testing"
)

func TestIngestFinding_Accepted(t *testing.T) {
	_, router := testServer(t)

	body := `{
		"source":"aws-securityhub",
		"source_finding_id":"SH-001",
		"resource_id":"arn:aws:s3:::test-bucket",
		"account_id":"123456789012",
		"severity":"HIGH",
		"finding_type":"S3_PUBLIC_ACCESS",
		"title":"Public S3 Bucket",
		"description":"Bucket allows public reads"
	}`
	rr := doRequest(t, router, "POST", "/api/v1/findings/ingest", body, adminJWT(t))
	assertStatus(t, rr, http.StatusCreated)

	var resp ingestResponse
	assertJSON(t, rr, &resp)
	if resp.Status != "accepted" {
		t.Errorf("status = %q, want %q", resp.Status, "accepted")
	}
	if resp.FindingID == "" {
		t.Error("finding_id should not be empty")
	}
	if resp.DedupKey == "" {
		t.Error("dedup_key should not be empty")
	}
}

func TestIngestFinding_Duplicate(t *testing.T) {
	_, router := testServer(t)

	body := `{
		"source":"aws-securityhub",
		"source_finding_id":"SH-001",
		"resource_id":"arn:aws:s3:::test-bucket",
		"account_id":"123456789012",
		"severity":"HIGH",
		"finding_type":"S3_PUBLIC_ACCESS",
		"title":"Public S3 Bucket",
		"description":"Bucket allows public reads"
	}`

	// First request — accepted
	rr1 := doRequest(t, router, "POST", "/api/v1/findings/ingest", body, adminJWT(t))
	assertStatus(t, rr1, http.StatusCreated)

	// Second identical request — duplicate
	rr2 := doRequest(t, router, "POST", "/api/v1/findings/ingest", body, adminJWT(t))
	assertStatus(t, rr2, http.StatusConflict)

	var resp ingestResponse
	assertJSON(t, rr2, &resp)
	if resp.Status != "duplicate" {
		t.Errorf("status = %q, want %q", resp.Status, "duplicate")
	}
	if resp.Entry == nil {
		t.Error("existing_entry should be present for duplicates")
	}
}

func TestIngestFinding_MissingFields(t *testing.T) {
	_, router := testServer(t)

	body := `{"source":"aws-securityhub"}`
	rr := doRequest(t, router, "POST", "/api/v1/findings/ingest", body, adminJWT(t))
	assertStatus(t, rr, http.StatusBadRequest)
}

func TestIngestFinding_AdminOnly(t *testing.T) {
	_, router := testServer(t)

	body := `{
		"source":"aws-securityhub",
		"source_finding_id":"SH-001",
		"resource_id":"arn:aws:s3:::test",
		"account_id":"123456789012"
	}`

	// Operator should be rejected (admin-only endpoint)
	rr := doRequest(t, router, "POST", "/api/v1/findings/ingest", body, operatorJWT(t))
	assertStatus(t, rr, http.StatusForbidden)

	// Requester should be rejected
	rr2 := doRequest(t, router, "POST", "/api/v1/findings/ingest", body, requesterJWT(t))
	assertStatus(t, rr2, http.StatusForbidden)
}

func TestIngestFinding_Unauthenticated(t *testing.T) {
	_, router := testServer(t)

	body := `{
		"source":"aws-securityhub",
		"source_finding_id":"SH-001",
		"resource_id":"arn:aws:s3:::test",
		"account_id":"123456789012"
	}`
	rr := doRequest(t, router, "POST", "/api/v1/findings/ingest", body, "")
	assertStatus(t, rr, http.StatusUnauthorized)
}

func TestIngestFinding_EmptyBody(t *testing.T) {
	_, router := testServer(t)

	rr := doRequest(t, router, "POST", "/api/v1/findings/ingest", "", adminJWT(t))
	assertStatus(t, rr, http.StatusBadRequest)
}

func TestIngestFinding_TriggersIncrementalSecgraphSync(t *testing.T) {
	srv, router := testServer(t)

	var (
		calls   int
		capture Finding
	)
	srv.secgraphSync = func(_ context.Context, finding Finding) error {
		calls++
		capture = finding
		return nil
	}

	body := `{
		"source":"aws-securityhub",
		"source_finding_id":"SH-002",
		"resource_id":"arn:aws:rds:us-east-1:123456789012:db:payments-prod",
		"account_id":"123456789012",
		"severity":"CRITICAL",
		"finding_type":"DATABASE_PUBLIC_ACCESS",
		"title":"Public database",
		"description":"Database is reachable from the internet"
	}`

	rr := doRequest(t, router, "POST", "/api/v1/findings/ingest", body, adminJWT(t))
	assertStatus(t, rr, http.StatusCreated)

	if calls != 1 {
		t.Fatalf("secgraphSync calls = %d, want 1", calls)
	}
	if capture.SourceFindingID != "SH-002" {
		t.Fatalf("source_finding_id = %q, want SH-002", capture.SourceFindingID)
	}
	if capture.ResourceType != "database" {
		t.Fatalf("resource_type = %q, want database", capture.ResourceType)
	}
	if capture.CloudProvider != "aws" {
		t.Fatalf("cloud_provider = %q, want aws", capture.CloudProvider)
	}
	if capture.Category != "NETWORK" {
		t.Fatalf("category = %q, want NETWORK", capture.Category)
	}
}

func TestIngestFinding_SecgraphSyncIsBestEffort(t *testing.T) {
	srv, router := testServer(t)

	calls := 0
	srv.secgraphSync = func(_ context.Context, _ Finding) error {
		calls++
		return errors.New("secgraph unavailable")
	}

	body := `{
		"source":"aws-securityhub",
		"source_finding_id":"SH-003",
		"resource_id":"arn:aws:s3:::test-bucket",
		"account_id":"123456789012",
		"severity":"HIGH",
		"finding_type":"S3_PUBLIC_ACCESS",
		"title":"Public S3 Bucket",
		"description":"Bucket allows public reads"
	}`

	rr := doRequest(t, router, "POST", "/api/v1/findings/ingest", body, adminJWT(t))
	assertStatus(t, rr, http.StatusCreated)

	if calls != 1 {
		t.Fatalf("secgraphSync calls = %d, want 1", calls)
	}
}

func TestIngestFinding_DuplicateDoesNotTriggerIncrementalSecgraphSync(t *testing.T) {
	srv, router := testServer(t)

	calls := 0
	srv.secgraphSync = func(_ context.Context, _ Finding) error {
		calls++
		return nil
	}

	body := `{
		"source":"aws-securityhub",
		"source_finding_id":"SH-004",
		"resource_id":"arn:aws:s3:::test-bucket",
		"account_id":"123456789012",
		"severity":"HIGH",
		"finding_type":"S3_PUBLIC_ACCESS",
		"title":"Public S3 Bucket",
		"description":"Bucket allows public reads"
	}`

	rr1 := doRequest(t, router, "POST", "/api/v1/findings/ingest", body, adminJWT(t))
	assertStatus(t, rr1, http.StatusCreated)

	rr2 := doRequest(t, router, "POST", "/api/v1/findings/ingest", body, adminJWT(t))
	assertStatus(t, rr2, http.StatusConflict)

	if calls != 1 {
		t.Fatalf("secgraphSync calls = %d, want 1 after duplicate rejection", calls)
	}
}
