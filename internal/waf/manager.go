// Package waf provides WAF configuration management, golden templates, and compliance scanning.
package waf

import (
	"context"
	"errors"
	"fmt"
)

// ErrNotFound is returned when a requested template or resource is not found.
var ErrNotFound = errors.New("not found")

// TemplateManager manages WAF golden templates and validates resource compliance.
type TemplateManager interface {
	// ListTemplates returns all available golden templates.
	ListTemplates(ctx context.Context) ([]*GoldenTemplate, error)
	// ValidateCompliance checks a WAF resource against its matching golden template.
	ValidateCompliance(ctx context.Context, templateID, resourceID string) (*ScanResult, error)
}

// NewTemplateManager returns a TemplateManager for the given provider name.
// Supports "memory" (in-process mock). Extend the switch for cloud-backed stores.
func NewTemplateManager(provider string) (TemplateManager, error) {
	switch provider {
	case "memory", "":
		return newMockTemplateManager(), nil
	default:
		return nil, fmt.Errorf("unsupported WAF template manager provider: %q", provider)
	}
}
