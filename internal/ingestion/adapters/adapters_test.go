package adapters

import (
	"context"
	"testing"
)

// --- Prowler adapter tests ---

func TestProwlerAdapter_ValidJSON(t *testing.T) {
	data := []byte(`[
		{
			"CheckID": "check_s3_public",
			"Status": "FAIL",
			"Severity": "HIGH",
			"ServiceName": "s3",
			"ResourceId": "arn:aws:s3:::my-bucket",
			"ResourceType": "AwsS3Bucket",
			"Region": "us-east-1",
			"AccountId": "123456789012",
			"Description": "S3 bucket is publicly accessible",
			"Risk": "Data exposure",
			"Timestamp": "2026-03-01T12:00:00Z",
			"Provider": "aws"
		},
		{
			"CheckID": "check_iam_root",
			"Status": "PASS",
			"Severity": "CRITICAL"
		}
	]`)

	adapter := NewProwlerAdapter()
	findings, err := adapter.Parse(context.Background(), data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	// Only FAIL records should be included
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	f := findings[0]
	if f.Severity != "HIGH" {
		t.Errorf("expected severity HIGH, got %q", f.Severity)
	}
	if f.Scanner != "prowler" {
		t.Errorf("expected scanner prowler, got %q", f.Scanner)
	}
	if f.CloudProvider != "aws" {
		t.Errorf("expected cloud_provider aws, got %q", f.CloudProvider)
	}
}

func TestProwlerAdapter_EmptyArray(t *testing.T) {
	findings, err := NewProwlerAdapter().Parse(context.Background(), []byte(`[]`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(findings))
	}
}

func TestProwlerAdapter_MalformedJSON(t *testing.T) {
	_, err := NewProwlerAdapter().Parse(context.Background(), []byte(`not json`))
	if err == nil {
		t.Fatal("expected error for malformed JSON")
	}
	pe, ok := err.(*ParseError)
	if !ok {
		t.Fatalf("expected *ParseError, got %T", err)
	}
	if pe.Adapter != "prowler" {
		t.Errorf("expected adapter prowler, got %q", pe.Adapter)
	}
}

// --- Trivy adapter tests ---

func TestTrivyAdapter_Vulnerabilities(t *testing.T) {
	data := []byte(`{
		"Results": [
			{
				"Target": "alpine:3.18",
				"Type": "alpine",
				"Vulnerabilities": [
					{
						"VulnerabilityID": "CVE-2023-1234",
						"PkgName": "openssl",
						"InstalledVersion": "1.1.1",
						"Severity": "CRITICAL",
						"Title": "Buffer overflow",
						"Description": "OpenSSL buffer overflow"
					}
				]
			}
		]
	}`)

	findings, err := NewTrivyAdapter().Parse(context.Background(), data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	f := findings[0]
	if f.Severity != "CRITICAL" {
		t.Errorf("expected CRITICAL, got %q", f.Severity)
	}
	if f.ResourceID != "alpine:3.18/openssl@1.1.1" {
		t.Errorf("unexpected resource_id: %q", f.ResourceID)
	}
	if f.Scanner != "trivy" {
		t.Errorf("expected scanner trivy, got %q", f.Scanner)
	}
}

func TestTrivyAdapter_Misconfigurations(t *testing.T) {
	data := []byte(`{
		"Results": [
			{
				"Target": "Dockerfile",
				"Type": "dockerfile",
				"Misconfigurations": [
					{
						"ID": "DS002",
						"Title": "Root user",
						"Description": "Running as root",
						"Severity": "HIGH",
						"Resolution": "Use non-root user"
					}
				]
			}
		]
	}`)

	findings, err := NewTrivyAdapter().Parse(context.Background(), data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1, got %d", len(findings))
	}
	if findings[0].ResourceType != "iac" {
		t.Errorf("expected resource_type iac, got %q", findings[0].ResourceType)
	}
}

func TestTrivyAdapter_EmptyResults(t *testing.T) {
	findings, err := NewTrivyAdapter().Parse(context.Background(), []byte(`{"Results":[]}`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(findings))
	}
}

func TestTrivyAdapter_MalformedJSON(t *testing.T) {
	_, err := NewTrivyAdapter().Parse(context.Background(), []byte(`{bad`))
	if err == nil {
		t.Fatal("expected error")
	}
}

// --- AWS Config adapter tests ---

func TestAWSConfigAdapter_NonCompliant(t *testing.T) {
	data := []byte(`[
		{
			"ComplianceType": "NON_COMPLIANT",
			"ConfigRuleName": "s3-bucket-public-read-prohibited",
			"ResourceType": "AWS::S3::Bucket",
			"ResourceId": "my-public-bucket",
			"AccountId": "123456789012",
			"AwsRegion": "us-east-1",
			"Annotation": "Bucket allows public read",
			"ResultRecordedTime": "2026-03-01T12:00:00Z"
		},
		{
			"ComplianceType": "COMPLIANT",
			"ConfigRuleName": "s3-bucket-versioning-enabled"
		}
	]`)

	findings, err := NewAWSConfigAdapter().Parse(context.Background(), data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1, got %d", len(findings))
	}
	if findings[0].CloudProvider != "aws" {
		t.Errorf("expected aws, got %q", findings[0].CloudProvider)
	}
	if findings[0].Scanner != "aws-config" {
		t.Errorf("expected aws-config, got %q", findings[0].Scanner)
	}
}

func TestAWSConfigAdapter_EmptyArray(t *testing.T) {
	findings, err := NewAWSConfigAdapter().Parse(context.Background(), []byte(`[]`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0, got %d", len(findings))
	}
}

func TestAWSConfigAdapter_MalformedJSON(t *testing.T) {
	_, err := NewAWSConfigAdapter().Parse(context.Background(), []byte(`not json`))
	if err == nil {
		t.Fatal("expected error")
	}
}

// --- Severity normalization ---

func TestNormalizeSeverity(t *testing.T) {
	tests := []struct {
		input, want string
	}{
		{"CRITICAL", "CRITICAL"},
		{"critical", "CRITICAL"},
		{"CRIT", "CRITICAL"},
		{"HIGH", "HIGH"},
		{"MEDIUM", "MEDIUM"},
		{"MED", "MEDIUM"},
		{"MODERATE", "MEDIUM"},
		{"LOW", "LOW"},
		{"INFO", ""},
		{"INFORMATIONAL", ""},
		{"unknown", ""},
	}
	for _, tt := range tests {
		got := normalizeSeverity(tt.input)
		if got != tt.want {
			t.Errorf("normalizeSeverity(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}
