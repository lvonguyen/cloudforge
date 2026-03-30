package adapters

import (
	"context"
	"strings"
	"testing"
)

var canonicalSeverities = map[string]bool{
	"CRITICAL": true,
	"HIGH":     true,
	"MEDIUM":   true,
	"LOW":      true,
}

func FuzzProwlerAdapterParse(f *testing.F) {
	for _, seed := range [][]byte{
		[]byte(`[]`),
		[]byte(`[{"CheckID":"check_s3_public","Status":"FAIL","Severity":"HIGH","ServiceName":"s3","ResourceId":"arn:aws:s3:::my-bucket","ResourceType":"AwsS3Bucket","Region":"us-east-1","AccountId":"123456789012","Description":"S3 bucket is publicly accessible","Risk":"Data exposure","Timestamp":"2026-03-01T12:00:00Z","Provider":"aws"}]`),
		[]byte(`not json`),
		nil,
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		findings, err := NewProwlerAdapter().Parse(context.Background(), data)
		if err != nil {
			if _, ok := err.(*ParseError); !ok {
				t.Fatalf("expected *ParseError, got %T", err)
			}
			return
		}

		for _, finding := range findings {
			assertCanonicalSeverity(t, finding.Severity)
			if finding.Scanner != "prowler" {
				t.Fatalf("unexpected scanner: %q", finding.Scanner)
			}
			if finding.CloudProvider == "" || finding.CloudProvider != strings.ToLower(finding.CloudProvider) {
				t.Fatalf("unexpected cloud provider: %q", finding.CloudProvider)
			}
			if finding.FoundAt.IsZero() {
				t.Fatal("prowler finding has zero FoundAt")
			}
		}
	})
}

func FuzzTrivyAdapterParse(f *testing.F) {
	for _, seed := range [][]byte{
		[]byte(`{"Results":[]}`),
		[]byte(`{"Results":[{"Target":"alpine:3.18","Type":"alpine","Vulnerabilities":[{"VulnerabilityID":"CVE-2023-1234","PkgName":"openssl","InstalledVersion":"1.1.1","Severity":"CRITICAL","Title":"Buffer overflow","Description":"OpenSSL buffer overflow"}]}]}`),
		[]byte(`{"Results":[{"Target":"Dockerfile","Type":"dockerfile","Misconfigurations":[{"ID":"DS002","Title":"Root user","Description":"Running as root","Severity":"HIGH","Resolution":"Use non-root user"}]}]}`),
		[]byte(`{bad`),
		nil,
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		findings, err := NewTrivyAdapter().Parse(context.Background(), data)
		if err != nil {
			if _, ok := err.(*ParseError); !ok {
				t.Fatalf("expected *ParseError, got %T", err)
			}
			return
		}

		for _, finding := range findings {
			assertCanonicalSeverity(t, finding.Severity)
			if finding.Scanner != "trivy" {
				t.Fatalf("unexpected scanner: %q", finding.Scanner)
			}
			if finding.CloudProvider != "container" {
				t.Fatalf("unexpected cloud provider: %q", finding.CloudProvider)
			}
			if finding.FoundAt.IsZero() {
				t.Fatal("trivy finding has zero FoundAt")
			}
		}
	})
}

func FuzzAWSConfigAdapterParse(f *testing.F) {
	for _, seed := range [][]byte{
		[]byte(`[]`),
		[]byte(`[{"ComplianceType":"NON_COMPLIANT","ConfigRuleName":"s3-bucket-public-read-prohibited","ResourceType":"AWS::S3::Bucket","ResourceId":"my-public-bucket","AccountId":"123456789012","AwsRegion":"us-east-1","Annotation":"Bucket allows public read","ResultRecordedTime":"2026-03-01T12:00:00Z"}]`),
		[]byte(`not json`),
		nil,
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		findings, err := NewAWSConfigAdapter().Parse(context.Background(), data)
		if err != nil {
			if _, ok := err.(*ParseError); !ok {
				t.Fatalf("expected *ParseError, got %T", err)
			}
			return
		}

		for _, finding := range findings {
			assertCanonicalSeverity(t, finding.Severity)
			if finding.Scanner != "aws-config" {
				t.Fatalf("unexpected scanner: %q", finding.Scanner)
			}
			if finding.CloudProvider != "aws" {
				t.Fatalf("unexpected cloud provider: %q", finding.CloudProvider)
			}
			if finding.FoundAt.IsZero() {
				t.Fatal("aws-config finding has zero FoundAt")
			}
		}
	})
}

func FuzzNormalizeSeverity(f *testing.F) {
	for _, seed := range []string{
		"CRITICAL",
		"critical",
		"CRIT",
		"HIGH",
		"MED",
		"MODERATE",
		"INFO",
		"unknown",
		"",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, input string) {
		got := normalizeSeverity(input)
		if got == "" {
			return
		}
		assertCanonicalSeverity(t, got)
		if got != strings.ToUpper(got) {
			t.Fatalf("normalizeSeverity returned non-uppercase value: %q", got)
		}
		if normalizeSeverity(got) != got {
			t.Fatalf("normalizeSeverity is not idempotent for %q", input)
		}
	})
}

func assertCanonicalSeverity(t *testing.T, severity string) {
	t.Helper()
	if !canonicalSeverities[severity] {
		t.Fatalf("unexpected severity %q", severity)
	}
}
