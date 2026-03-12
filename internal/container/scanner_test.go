package container

import (
	"context"
	"strings"
	"testing"
)

func TestMockScanner_ScanImage_ReturnsStructure(t *testing.T) {
	s, err := NewScanner("memory")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	result, err := s.ScanImage(ctx, "gcr.io/example/app", "v1.2.3")
	if err != nil {
		t.Fatalf("ScanImage returned unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("ScanImage returned nil result")
	}
	if result.Repository != "gcr.io/example/app" {
		t.Errorf("expected Repository=%q, got %q", "gcr.io/example/app", result.Repository)
	}
	if result.Tag != "v1.2.3" {
		t.Errorf("expected Tag=%q, got %q", "v1.2.3", result.Tag)
	}
	if result.Status == "" {
		t.Error("expected non-empty Status")
	}
	if result.ScannedAt.IsZero() {
		t.Error("expected non-zero ScannedAt")
	}
}

func TestMockScanner_ScanImage_EmptyImageError(t *testing.T) {
	s, err := NewScanner("memory")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	_, err = s.ScanImage(ctx, "", "latest")
	if err == nil {
		t.Fatal("expected error for empty image, got nil")
	}
}

func TestMockScanner_ScanImage_NginxHasCriticalCVE(t *testing.T) {
	s, err := NewScanner("memory")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	result, err := s.ScanImage(ctx, "nginx", "1.24.0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	hasCritical := false
	for _, v := range result.Vulnerabilities {
		if v.Severity == "critical" {
			hasCritical = true
			break
		}
	}
	if !hasCritical {
		t.Error("expected at least one critical vulnerability for nginx:1.24.0")
	}
	if result.Status != "failed" {
		t.Errorf("expected status=failed for image with critical vuln, got %q", result.Status)
	}
}

func TestMockScanner_CheckAdmission_LatestTagDenied(t *testing.T) {
	s, err := NewScanner("memory")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	decision, err := s.CheckAdmission(ctx, "gcr.io/example/app", "latest", "production")
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

func TestMockScanner_CheckAdmission_KnownGoodImageAllowed(t *testing.T) {
	s, err := NewScanner("memory")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	decision, err := s.CheckAdmission(ctx, "gcr.io/distroless/static", "nonroot", "production")
	if err != nil {
		t.Fatalf("CheckAdmission returned unexpected error: %v", err)
	}
	if !decision.Allowed {
		t.Errorf("expected distroless image to be admitted, got denied: %s", decision.Reason)
	}
}

func TestMockScanner_CheckAdmission_CriticalVulnDenied(t *testing.T) {
	s, err := NewScanner("memory")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	// nginx:1.24.0 has a critical CVE (CVE-2023-38545) in the mock.
	decision, err := s.CheckAdmission(ctx, "nginx", "1.24.0", "production")
	if err != nil {
		t.Fatalf("CheckAdmission returned unexpected error: %v", err)
	}
	if decision.Allowed {
		t.Error("expected image with critical CVE to be denied admission")
	}
}

func TestNewScanner_InvalidProvider(t *testing.T) {
	_, err := NewScanner("invalid-provider")
	if err == nil {
		t.Fatal("expected error for invalid provider, got nil")
	}
	if !strings.Contains(err.Error(), "unsupported") {
		t.Errorf("expected error message to contain 'unsupported', got: %v", err)
	}
}
