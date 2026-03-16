package secrets

import (
	"context"
	"testing"

	"go.uber.org/zap"
)

func covSecLogger() *zap.Logger {
	l, _ := zap.NewDevelopment()
	return l
}

func TestCovNewLifecycle_Memory(t *testing.T) {
	lc, err := NewLifecycle("memory")
	if err != nil {
		t.Fatalf("NewLifecycle: %v", err)
	}
	if lc == nil {
		t.Fatal("expected non-nil lifecycle")
	}
}

func TestCovNewLifecycle_Empty(t *testing.T) {
	lc, err := NewLifecycle("")
	if err != nil {
		t.Fatalf("NewLifecycle: %v", err)
	}
	if lc == nil {
		t.Fatal("expected non-nil lifecycle")
	}
}

func TestCovNewLifecycle_Unknown(t *testing.T) {
	_, err := NewLifecycle("vault")
	if err == nil {
		t.Error("expected error for unsupported provider")
	}
}

func TestCovManager_RegisterAndGet(t *testing.T) {
	m := NewManager(covSecLogger())
	mp := NewMemoryProvider("memory")
	m.RegisterProvider(mp)

	ctx := context.Background()
	mp.SetSecret(ctx, "/test/secret", []byte("value"))

	s, err := m.GetSecret(ctx, "memory", "/test/secret")
	if err != nil {
		t.Fatalf("GetSecret: %v", err)
	}
	if string(s.Value) != "value" {
		t.Errorf("value = %q, want value", string(s.Value))
	}
}

func TestCovManager_GetSecret_UnknownProvider(t *testing.T) {
	m := NewManager(covSecLogger())
	_, err := m.GetSecret(context.Background(), "unknown", "/test")
	if err == nil {
		t.Error("expected error for unknown provider")
	}
}

func TestCovScanner_ScanForSecrets(t *testing.T) {
	m := NewManager(covSecLogger())

	tests := []struct {
		name    string
		content string
		wantMin int
	}{
		{"AWS key", "AKIAIOSFODNN7EXAMPLE", 1},
		{"GitHub token", "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij", 1},
		{"private key", "-----BEGIN RSA PRIVATE KEY-----", 1},
		{"database URL", "postgres://user:password@localhost:5432/db", 1},
		{"clean content", "This is clean text with no secrets", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := m.ScanForSecrets(tt.content)
			if len(findings) < tt.wantMin {
				t.Errorf("found %d findings, want at least %d", len(findings), tt.wantMin)
			}
		})
	}
}

func TestCovScanner_ScanFile(t *testing.T) {
	s := NewScanner(covSecLogger())
	findings := s.ScanFile(context.Background(), "/app/config.yaml", "api_key=AKIAIOSFODNN7EXAMPLE")
	for _, f := range findings {
		if f.File != "/app/config.yaml" {
			t.Errorf("expected file path in findings, got %q", f.File)
		}
	}
}

func TestCovScanner_RedactSecret(t *testing.T) {
	tests := []struct {
		input, want string
	}{
		{"short", "***REDACTED***"},
		{"AKIAIOSFODNN7EXAMPLE", "***REDACTED***"},
	}
	for _, tt := range tests {
		got := redactSecret(tt.input)
		if got != tt.want {
			t.Errorf("redactSecret(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestCovSplitLines(t *testing.T) {
	lines := splitLines("line1\nline2\nline3")
	if len(lines) != 3 {
		t.Errorf("expected 3 lines, got %d", len(lines))
	}
	lines2 := splitLines("no newline")
	if len(lines2) != 1 {
		t.Errorf("expected 1 line, got %d", len(lines2))
	}
}

func TestCovGetContext(t *testing.T) {
	lines := []string{"line0", "line1", "line2", "line3"}
	ctx := getContext(lines, 1)
	if ctx == "" {
		t.Error("expected non-empty context")
	}
	// First line
	ctx0 := getContext(lines, 0)
	if ctx0 == "" {
		t.Error("expected non-empty context for first line")
	}
	// Last line
	ctx3 := getContext(lines, 3)
	if ctx3 == "" {
		t.Error("expected non-empty context for last line")
	}
}

func TestCovProviders_NotImplemented(t *testing.T) {
	ctx := context.Background()
	logger := covSecLogger()

	providers := []Provider{
		NewAWSSecretsProvider("us-east-1", logger),
		NewAzureKeyVaultProvider("https://vault.azure.net", logger),
		NewGCPSecretManagerProvider("project-id", logger),
	}

	names := []string{"aws", "azure", "gcp"}

	for i, p := range providers {
		t.Run(names[i], func(t *testing.T) {
			if p.Name() != names[i] {
				t.Errorf("Name() = %q, want %q", p.Name(), names[i])
			}
			if _, err := p.GetSecret(ctx, "/test"); err == nil {
				t.Error("expected not implemented")
			}
			if err := p.SetSecret(ctx, "/test", []byte("v")); err == nil {
				t.Error("expected not implemented")
			}
			if err := p.DeleteSecret(ctx, "/test"); err == nil {
				t.Error("expected not implemented")
			}
			if _, err := p.ListSecrets(ctx, "prefix"); err == nil {
				t.Error("expected not implemented")
			}
			if err := p.RotateSecret(ctx, "/test"); err == nil {
				t.Error("expected not implemented")
			}
		})
	}
}
