package main

import (
	"net/http"
	"strings"
	"testing"
)

func TestQueryFindings_Success(t *testing.T) {
	_, router := testServer(t)
	jwt := adminJWT(t)

	rr := doRequest(t, router, "GET", `/api/v1/findings/query?q=severity = "CRITICAL"`, "", jwt)
	assertStatus(t, rr, http.StatusOK)

	var result map[string]interface{}
	assertJSON(t, rr, &result)

	if result["data"] == nil {
		t.Error("expected data field in paginated response")
	}
}

func TestQueryFindings_MissingQuery(t *testing.T) {
	_, router := testServer(t)
	jwt := adminJWT(t)

	rr := doRequest(t, router, "GET", "/api/v1/findings/query", "", jwt)
	assertStatus(t, rr, http.StatusBadRequest)
}

func TestQueryFindings_TooLong(t *testing.T) {
	_, router := testServer(t)
	jwt := adminJWT(t)

	long := strings.Repeat("x", 1025)
	rr := doRequest(t, router, "GET", "/api/v1/findings/query?q="+long, "", jwt)
	assertStatus(t, rr, http.StatusBadRequest)
}

func TestQueryFindings_InvalidRQL(t *testing.T) {
	_, router := testServer(t)
	jwt := adminJWT(t)

	rr := doRequest(t, router, "GET", "/api/v1/findings/query?q=%40%40%40invalid", "", jwt)
	assertStatus(t, rr, http.StatusBadRequest)
}

func TestQueryFindings_Unauthenticated(t *testing.T) {
	_, router := testServer(t)

	rr := doRequest(t, router, "GET", `/api/v1/findings/query?q=severity = "HIGH"`, "", "")
	assertStatus(t, rr, http.StatusUnauthorized)
}

func TestQueryFindings_ViewerAllowed(t *testing.T) {
	_, router := testServer(t)
	jwt := viewerJWT(t)

	rr := doRequest(t, router, "GET", `/api/v1/findings/query?q=severity = "HIGH"`, "", jwt)
	assertStatus(t, rr, http.StatusOK)
}

func TestFindingAccessor_AllFields(t *testing.T) {
	f := &Finding{
		ID:               "f-001",
		Severity:         "CRITICAL",
		CloudProvider:    "aws",
		Status:           "open",
		ResourceType:     "S3Bucket",
		ResourceID:       "arn:aws:s3:::my-bucket",
		ResourceARN:      "arn:aws:s3:::my-bucket",
		ResourceName:     "my-bucket",
		Region:           "us-east-1",
		Category:         "MISCONFIGURATION",
		AccountID:        "123456789012",
		WorkflowStatus:   "new",
		EnvironmentType:  "production",
		Platform:         "aws",
		AccountName:      "test-account",
		StaticSeverity:   "HIGH",
		ServiceName:      "S3",
		LineOfBusiness:   "engineering",
		AIRiskScore:      8.5,
		AIRiskLevel:      "HIGH",
		CanonicalRuleID:  "S3-001",
		ExploitAvailable: false,
		AutoRemediatable: true,
		Suppressed:       false,
	}

	acc := findingAccessor(f)

	cases := []struct {
		field string
		want  string
	}{
		{"severity", "CRITICAL"},
		{"cloud_provider", "aws"},
		{"provider", "aws"},
		{"status", "open"},
		{"resource_type", "S3Bucket"},
		{"resource.type", "S3Bucket"},
		{"resource_id", "arn:aws:s3:::my-bucket"},
		{"resource.id", "arn:aws:s3:::my-bucket"},
		{"resource_arn", "arn:aws:s3:::my-bucket"},
		{"resource.arn", "arn:aws:s3:::my-bucket"},
		{"resource_name", "my-bucket"},
		{"resource.name", "my-bucket"},
		{"region", "us-east-1"},
		{"category", "MISCONFIGURATION"},
		{"account_id", "123456789012"},
		{"account_name", "test-account"},
		{"workflow_status", "new"},
		{"environment", "production"},
		{"environment_type", "production"},
		{"platform", "aws"},
		{"static_severity", "HIGH"},
		{"service", "S3"},
		{"service_name", "S3"},
		{"line_of_business", "engineering"},
		{"lob", "engineering"},
		{"ai_risk_level", "HIGH"},
		{"canonical_rule_id", "S3-001"},
		{"exploit_available", "false"},
		{"auto_remediatable", "true"},
		{"suppressed", "false"},
	}

	for _, tc := range cases {
		t.Run(tc.field, func(t *testing.T) {
			got, ok := acc(tc.field)
			if !ok {
				t.Errorf("field %q: accessor returned ok=false", tc.field)
				return
			}
			if got != tc.want {
				t.Errorf("field %q: got %q, want %q", tc.field, got, tc.want)
			}
		})
	}

	// Unknown field must return ok=false.
	if _, ok := acc("nonexistent_field"); ok {
		t.Error("expected ok=false for unknown field")
	}
}
