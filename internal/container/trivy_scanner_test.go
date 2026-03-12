package container

import (
	"context"
	"fmt"
	"os/exec"
	"slices"
	"strings"
	"testing"
)

// fakeExecCommand returns a cmdFunc that injects the provided stdout bytes.
// When stdout is nil, it simulates exec.ErrNotFound.
func fakeExecCommand(stdout []byte, _ int) cmdFunc {
	return func(ctx context.Context, name string, args ...string) *exec.Cmd {
		if stdout == nil {
			// Simulate binary not found by returning a command that will fail with ErrNotFound.
			// We create a real exec.Cmd pointing at a path that won't resolve.
			cmd := exec.CommandContext(ctx, "/dev/null/nonexistent-trivy-binary")
			return cmd
		}
		// Use a real process that echoes the desired output.
		// `echo` is universally available; we pass the JSON via the args trick.
		cmd := exec.CommandContext(ctx, "echo", string(stdout))
		return cmd
	}
}

// trivyJSONWithVulns returns a minimal Trivy JSON payload containing one critical vuln.
func trivyJSONWithVulns() []byte {
	return []byte(`{
		"Results": [
			{
				"Target": "nginx:1.24.0 (debian 11.7)",
				"Vulnerabilities": [
					{
						"VulnerabilityID": "CVE-2023-38545",
						"PkgName": "libcurl",
						"InstalledVersion": "7.88.1",
						"FixedVersion": "8.4.0",
						"Severity": "CRITICAL",
						"Title": "curl SOCKS5 heap buffer overflow",
						"Description": "SOCKS5 heap overflow in curl before 8.4.0",
						"CVSS": {
							"nvd": {"V3Score": 9.8}
						},
						"References": ["https://nvd.nist.gov/vuln/detail/CVE-2023-38545"]
					},
					{
						"VulnerabilityID": "CVE-2023-44487",
						"PkgName": "nginx",
						"InstalledVersion": "1.24.0",
						"FixedVersion": "1.25.3",
						"Severity": "HIGH",
						"Title": "HTTP/2 Rapid Reset Attack",
						"Description": "HTTP/2 rapid reset allows denial of service",
						"CVSS": {
							"nvd": {"V3Score": 7.5}
						},
						"References": ["https://nvd.nist.gov/vuln/detail/CVE-2023-44487"]
					}
				]
			}
		]
	}`)
}

// trivyJSONClean returns a Trivy JSON payload with no findings.
func trivyJSONClean() []byte {
	return []byte(`{"Results": [{"Target": "distroless/static:nonroot"}]}`)
}

// trivyJSONWithSecrets returns a Trivy JSON payload with a secret finding.
func trivyJSONWithSecrets() []byte {
	return []byte(`{
		"Results": [
			{
				"Target": "app:v1.0.0",
				"Secrets": [
					{
						"RuleID": "aws-access-key-id",
						"Category": "aws",
						"Title": "AWS Access Key ID",
						"Severity": "CRITICAL",
						"Match": "AKIAIOSFODNN7EXAMPLE"
					}
				]
			}
		]
	}`)
}

func TestTrivyScanner_ScanImage_ParsesVulnsCorrectly(t *testing.T) {
	s := &trivyScanner{execCommand: fakeExecCommand(trivyJSONWithVulns(), 0)}
	ctx := context.Background()

	result, err := s.ScanImage(ctx, "nginx", "1.24.0")
	if err != nil {
		t.Fatalf("ScanImage returned unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("ScanImage returned nil result")
	}
	if len(result.Vulnerabilities) != 2 {
		t.Fatalf("expected 2 vulnerabilities, got %d", len(result.Vulnerabilities))
	}

	critical := result.Vulnerabilities[0]
	if critical.ID != "CVE-2023-38545" {
		t.Errorf("expected first vuln ID CVE-2023-38545, got %q", critical.ID)
	}
	if critical.Severity != "critical" {
		t.Errorf("expected severity=critical (lowercased), got %q", critical.Severity)
	}
	if critical.CVSS != 9.8 {
		t.Errorf("expected CVSS=9.8, got %v", critical.CVSS)
	}

	high := result.Vulnerabilities[1]
	if high.Severity != "high" {
		t.Errorf("expected severity=high, got %q", high.Severity)
	}
}

func TestTrivyScanner_ScanImage_CleanImageReturnsNoVulns(t *testing.T) {
	s := &trivyScanner{execCommand: fakeExecCommand(trivyJSONClean(), 0)}
	ctx := context.Background()

	result, err := s.ScanImage(ctx, "gcr.io/distroless/static", "nonroot")
	if err != nil {
		t.Fatalf("ScanImage returned unexpected error: %v", err)
	}
	if len(result.Vulnerabilities) != 0 {
		t.Errorf("expected 0 vulnerabilities for clean image, got %d", len(result.Vulnerabilities))
	}
	if result.Status != "passed" {
		t.Errorf("expected status=passed for clean image, got %q", result.Status)
	}
}

func TestTrivyScanner_ScanImage_TrivyNotFound(t *testing.T) {
	s := &trivyScanner{execCommand: fakeExecCommand(nil, 0)}
	ctx := context.Background()

	_, err := s.ScanImage(ctx, "nginx", "1.24.0")
	if err == nil {
		t.Fatal("expected error when trivy not found, got nil")
	}
	// Should contain a human-readable hint.
	if !strings.Contains(err.Error(), "trivy") {
		t.Errorf("error message should reference 'trivy', got: %s", err.Error())
	}
}

func TestTrivyScanner_ScanImage_EmptyImageError(t *testing.T) {
	s := &trivyScanner{execCommand: fakeExecCommand(trivyJSONClean(), 0)}
	ctx := context.Background()

	_, err := s.ScanImage(ctx, "", "latest")
	if err == nil {
		t.Fatal("expected error for empty image, got nil")
	}
}

func TestTrivyScanner_CheckAdmission_LatestTagDenied(t *testing.T) {
	s := &trivyScanner{execCommand: fakeExecCommand(trivyJSONClean(), 0)}
	ctx := context.Background()

	decision, err := s.CheckAdmission(ctx, "nginx", "latest", "production")
	if err != nil {
		t.Fatalf("CheckAdmission returned unexpected error: %v", err)
	}
	if decision.Allowed {
		t.Error("expected :latest tag to be denied, but was allowed")
	}
	if decision.Reason == "" {
		t.Error("expected non-empty denial reason for :latest tag")
	}
}

func TestTrivyScanner_CheckAdmission_CriticalVulnDenied(t *testing.T) {
	s := &trivyScanner{execCommand: fakeExecCommand(trivyJSONWithVulns(), 0)}
	ctx := context.Background()

	decision, err := s.CheckAdmission(ctx, "nginx", "1.24.0", "production")
	if err != nil {
		t.Fatalf("CheckAdmission returned unexpected error: %v", err)
	}
	if decision.Allowed {
		t.Error("expected image with critical CVE to be denied admission")
	}
	if !strings.Contains(decision.Reason, "CVE-2023-38545") {
		t.Errorf("expected reason to reference the critical CVE, got: %s", decision.Reason)
	}
}

func TestTrivyScanner_CheckAdmission_CleanImageAllowed(t *testing.T) {
	s := &trivyScanner{execCommand: fakeExecCommand(trivyJSONClean(), 0)}
	ctx := context.Background()

	decision, err := s.CheckAdmission(ctx, "gcr.io/distroless/static", "nonroot", "production")
	if err != nil {
		t.Fatalf("CheckAdmission returned unexpected error: %v", err)
	}
	if !decision.Allowed {
		t.Errorf("expected clean image to be admitted, got denied: %s", decision.Reason)
	}
}

func TestTrivyScanner_ComplianceCalculation_CriticalFails(t *testing.T) {
	s := &trivyScanner{execCommand: fakeExecCommand(trivyJSONWithVulns(), 0)}
	ctx := context.Background()

	result, err := s.ScanImage(ctx, "nginx", "1.24.0")
	if err != nil {
		t.Fatalf("ScanImage returned unexpected error: %v", err)
	}

	if result.Status != "failed" {
		t.Errorf("expected status=failed for image with critical vuln, got %q", result.Status)
	}

	if !slices.Contains(result.Compliance.Failed, "NO_CRITICAL_VULNS") {
		t.Error("expected NO_CRITICAL_VULNS in compliance.failed")
	}
	if result.Compliance.Score >= 100 {
		t.Errorf("expected compliance score < 100 for critical vuln image, got %.1f", result.Compliance.Score)
	}
}

func TestTrivyScanner_ScanImage_SecretFindingMarkedFailed(t *testing.T) {
	s := &trivyScanner{execCommand: fakeExecCommand(trivyJSONWithSecrets(), 0)}
	ctx := context.Background()

	result, err := s.ScanImage(ctx, "app", "v1.0.0")
	if err != nil {
		t.Fatalf("ScanImage returned unexpected error: %v", err)
	}
	if len(result.Secrets) == 0 {
		t.Fatal("expected secret findings, got none")
	}
	if result.Status != "failed" {
		t.Errorf("expected status=failed when secrets are present, got %q", result.Status)
	}
}

func TestNewScanner_TrivyProvider(t *testing.T) {
	// NewScanner("trivy") must not return error and must return a non-nil Scanner.
	s, err := NewScanner("trivy")
	if err != nil {
		t.Fatalf("NewScanner(\"trivy\") returned error: %v", err)
	}
	if s == nil {
		t.Fatal("expected non-nil Scanner for provider=trivy")
	}
	// Verify it satisfies the interface at compile time (the cast below would fail otherwise).
	_ = fmt.Sprintf("%T", s)
}
