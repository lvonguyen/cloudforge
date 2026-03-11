package waf

import (
	"context"
	"fmt"
	"time"

	"go.uber.org/zap"
)

// mockTemplateManager is an in-memory TemplateManager for testing and demos.
// NOT for production use.
type mockTemplateManager struct {
	gtm *GoldenTemplateManager
	cs  *ComplianceScanner
}

func newMockTemplateManager() *mockTemplateManager {
	logger := zap.NewNop()
	gtm := NewGoldenTemplateManager(logger)
	cs := NewComplianceScanner(gtm, logger)
	return &mockTemplateManager{gtm: gtm, cs: cs}
}

// ListTemplates returns all pre-loaded golden templates.
func (m *mockTemplateManager) ListTemplates(_ context.Context) ([]*GoldenTemplate, error) {
	return m.gtm.ListTemplates(), nil
}

// ValidateCompliance evaluates a mock WAF resource against the given template.
// A templateID of "waf-prod-external" returns a realistic non-compliant result;
// "waf-dev-external" returns a compliant result for demo purposes.
func (m *mockTemplateManager) ValidateCompliance(ctx context.Context, templateID, resourceID string) (*ScanResult, error) {
	template, ok := m.gtm.GetTemplate(templateID)
	if !ok {
		return nil, fmt.Errorf("validating compliance for template %q: %w", templateID, ErrNotFound)
	}

	// Build a synthetic WAF config whose compliance depends on the template tier.
	cfg := WAFConfig{
		ResourceID:   resourceID,
		ResourceType: "aws_wafv2",
		Provider:     template.Provider,
		Environment:  template.Environment,
		Exposure:     template.Exposure,
		Config:       mockResourceConfig(templateID),
	}

	result, err := m.cs.Scan(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("scanning resource %q: %w", resourceID, err)
	}

	// Stamp a deterministic ScannedAt so tests can assert on structure without time drift.
	result.ScannedAt = time.Now()
	return result, nil
}

// mockResourceConfig returns a partially-configured resource map to drive realistic
// compliance findings. Dev templates get a fuller config (fewer violations);
// prod-external gets a sparse config to surface findings.
func mockResourceConfig(templateID string) map[string]interface{} {
	switch templateID {
	case "waf-dev-external":
		return map[string]interface{}{
			"managed_rules": []string{"AWSManagedRulesCommonRuleSet"},
			"rate_limiting": map[string]interface{}{"enabled": false},
		}
	case "waf-prod-internal":
		return map[string]interface{}{
			"managed_rules": []string{"AWSManagedRulesCommonRuleSet", "AWSManagedRulesSQLiRuleSet"},
			"rate_limiting": map[string]interface{}{"enabled": true, "limit": 5000},
			"ip_blocking":   map[string]interface{}{"enabled": true},
		}
	default:
		// Minimal config — most required controls are absent; drives non-compliant results.
		return map[string]interface{}{}
	}
}
