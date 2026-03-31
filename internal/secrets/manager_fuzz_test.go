package secrets

import (
	"strings"
	"testing"

	"go.uber.org/zap"
)

func FuzzScannerScan(f *testing.F) {
	for _, seed := range []string{
		"",
		"plain text with no secrets",
		"AKIAIOSFODNN7EXAMPLE",
		"postgres://user:password@localhost:5432/db",
		"api_key=supersecretvalue1234567890\nsecond line",
		"-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----",
		"xoxb-1234567890-1234567890-abcdefghijklmnopqrstuvwx",
		"line1\r\nline2\r\nazure_client_secret=abcdefghijklmnopqrstuvwxyzABCDEFGH",
	} {
		f.Add(seed)
	}

	scanner := NewScanner(zap.NewNop())

	f.Fuzz(func(t *testing.T, content string) {
		findings := scanner.Scan(content)
		lines := splitLines(content)

		for i, finding := range findings {
			if finding.PatternID == "" {
				t.Fatalf("finding[%d] missing pattern id", i)
			}
			if finding.PatternName == "" {
				t.Fatalf("finding[%d] missing pattern name", i)
			}
			if finding.Type == "" {
				t.Fatalf("finding[%d] missing type", i)
			}
			if finding.Severity == "" {
				t.Fatalf("finding[%d] missing severity", i)
			}
			if finding.Line < 1 {
				t.Fatalf("finding[%d] line = %d, want >= 1", i, finding.Line)
			}
			if finding.Column < 1 {
				t.Fatalf("finding[%d] column = %d, want >= 1", i, finding.Column)
			}
			if len(lines) > 0 && finding.Line > len(lines) {
				t.Fatalf("finding[%d] line = %d, max = %d", i, finding.Line, len(lines))
			}
			if finding.Match != "***REDACTED***" {
				t.Fatalf("finding[%d] match = %q, want redacted sentinel", i, finding.Match)
			}
			if finding.File != "" {
				t.Fatalf("finding[%d] file = %q, want empty for Scan()", i, finding.File)
			}
			if finding.Context == "" {
				t.Fatalf("finding[%d] missing context", i)
			}
			if !strings.Contains(finding.Context, ">>> ") {
				t.Fatalf("finding[%d] context missing focus marker: %q", i, finding.Context)
			}
		}
	})
}
