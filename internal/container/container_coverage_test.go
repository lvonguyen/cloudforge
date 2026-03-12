package container

import (
	"context"
	"testing"

	"go.uber.org/zap"
)

func covContLogger() *zap.Logger {
	l, _ := zap.NewDevelopment()
	return l
}

func TestCovNewScanner_Memory(t *testing.T) {
	s, err := NewScanner("memory")
	if err != nil {
		t.Fatalf("NewScanner: %v", err)
	}
	if s == nil {
		t.Fatal("expected non-nil scanner")
	}
}

func TestCovNewScanner_Empty(t *testing.T) {
	s, err := NewScanner("")
	if err != nil {
		t.Fatalf("NewScanner: %v", err)
	}
	if s == nil {
		t.Fatal("expected non-nil scanner")
	}
}

func TestCovNewScanner_Trivy(t *testing.T) {
	s, err := NewScanner("trivy")
	if err != nil {
		t.Fatalf("NewScanner: %v", err)
	}
	if s == nil {
		t.Fatal("expected non-nil scanner")
	}
}

func TestCovNewScanner_Unknown(t *testing.T) {
	_, err := NewScanner("unknown")
	if err == nil {
		t.Error("expected error for unknown provider")
	}
}

func TestCovSecurityScanner_ScanImage(t *testing.T) {
	cfg := SecurityScannerConfig{
		VulnerabilityThreshold: "critical",
		EnableSecretScan:       true,
		RequireSignedImages:    true,
		AllowedRegistries:      []string{"docker.io"},
	}
	s := NewSecurityScanner(cfg, covContLogger())

	result, err := s.ScanImage(context.Background(), "nginx:latest")
	if err != nil {
		t.Fatalf("ScanImage: %v", err)
	}
	if result.ImageRef != "nginx:latest" {
		t.Error("expected image ref preserved")
	}
	if result.Status == "" {
		t.Error("expected non-empty status")
	}
}

func TestCovSecurityScanner_ScanImage_DisallowedRegistry(t *testing.T) {
	cfg := SecurityScannerConfig{
		AllowedRegistries: []string{"gcr.io"},
	}
	s := NewSecurityScanner(cfg, covContLogger())

	result, err := s.ScanImage(context.Background(), "nginx:latest")
	if err != nil {
		t.Fatalf("ScanImage: %v", err)
	}
	if result.Status != "failed" {
		t.Errorf("expected failed for disallowed registry, got %s", result.Status)
	}
}

func TestCovSecurityScanner_ScanImage_NoAllowlist(t *testing.T) {
	cfg := SecurityScannerConfig{}
	s := NewSecurityScanner(cfg, covContLogger())

	result, err := s.ScanImage(context.Background(), "nginx:latest")
	if err != nil {
		t.Fatalf("ScanImage: %v", err)
	}
	if result == nil {
		t.Error("expected non-nil result")
	}
}

func TestCovSecurityScanner_DetermineStatus(t *testing.T) {
	logger := covContLogger()

	tests := []struct {
		name      string
		threshold string
		vulns     []Vulnerability
		secrets   []SecretFinding
		misconfigs []Misconfiguration
		score     float64
		wantStatus string
	}{
		{"critical vuln with critical threshold", "critical",
			[]Vulnerability{{Severity: "critical"}}, nil, nil, 80, "failed"},
		{"high vuln with high threshold", "high",
			[]Vulnerability{{Severity: "high"}}, nil, nil, 80, "failed"},
		{"high vuln with critical threshold", "critical",
			[]Vulnerability{{Severity: "high"}}, nil, nil, 80, "passed"},
		{"secrets found", "critical",
			nil, []SecretFinding{{Type: "api_key"}}, nil, 80, "failed"},
		{"critical misconfig", "critical",
			nil, nil, []Misconfiguration{{Severity: "critical"}}, 80, "failed"},
		{"low score", "critical",
			nil, nil, nil, 50, "warning"},
		{"all good", "critical",
			nil, nil, nil, 80, "passed"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewSecurityScanner(SecurityScannerConfig{VulnerabilityThreshold: tt.threshold}, logger)
			result := &ImageScanResult{
				Vulnerabilities:   tt.vulns,
				Secrets:           tt.secrets,
				Misconfigurations: tt.misconfigs,
				Compliance:        ComplianceResult{Score: tt.score},
			}
			got := s.determineStatus(result)
			if got != tt.wantStatus {
				t.Errorf("got %q, want %q", got, tt.wantStatus)
			}
		})
	}
}

func TestCovSecurityScanner_IsIgnored(t *testing.T) {
	s := NewSecurityScanner(SecurityScannerConfig{
		IgnoredCVEs: []string{"CVE-2023-001"},
	}, covContLogger())

	if !s.isIgnored("CVE-2023-001") {
		t.Error("expected CVE to be ignored")
	}
	if s.isIgnored("CVE-2023-999") {
		t.Error("expected CVE not to be ignored")
	}
}

func TestCovSecurityScanner_ValidateAdmission(t *testing.T) {
	s := NewSecurityScanner(SecurityScannerConfig{
		VulnerabilityThreshold: "critical",
	}, covContLogger())

	policies := []AdmissionPolicy{
		{
			Name:            "default",
			Enabled:         true,
			BlockOnFailure:  true,
			AllowedRegistries: []string{"gcr.io"},
		},
	}

	allowed, reasons := s.ValidateAdmission(context.Background(), "nginx:latest", policies)
	if allowed {
		t.Error("expected not allowed (docker.io not in allowlist)")
	}
	if len(reasons) == 0 {
		t.Error("expected denial reasons")
	}
}

func TestCovSecurityScanner_ValidateAdmission_Disabled(t *testing.T) {
	s := NewSecurityScanner(SecurityScannerConfig{}, covContLogger())

	policies := []AdmissionPolicy{
		{Name: "disabled", Enabled: false},
	}

	allowed, _ := s.ValidateAdmission(context.Background(), "nginx:latest", policies)
	if !allowed {
		t.Error("expected allowed when all policies disabled")
	}
}
