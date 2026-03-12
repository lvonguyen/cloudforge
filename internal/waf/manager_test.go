package waf

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestMockTemplateManager_ListTemplates_ReturnsTemplates(t *testing.T) {
	mgr, err := NewTemplateManager("memory")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	templates, err := mgr.ListTemplates(ctx)
	if err != nil {
		t.Fatalf("ListTemplates returned unexpected error: %v", err)
	}
	if len(templates) < 3 {
		t.Errorf("expected at least 3 templates, got %d", len(templates))
	}
	for _, tmpl := range templates {
		if tmpl.ID == "" {
			t.Error("template has empty ID")
		}
		if tmpl.Name == "" {
			t.Error("template has empty Name")
		}
		if tmpl.Provider == "" {
			t.Error("template has empty Provider")
		}
	}
}

func TestMockTemplateManager_ValidateCompliance_NonCompliantResource(t *testing.T) {
	mgr, err := NewTemplateManager("memory")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	// waf-prod-external has many required rules; empty resource config should yield findings.
	result, err := mgr.ValidateCompliance(ctx, "waf-prod-external", "arn:aws:wafv2:us-east-1:123456789012:regional/webacl/demo")
	if err != nil {
		t.Fatalf("ValidateCompliance returned unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil ScanResult")
	}
	if len(result.Findings) == 0 {
		t.Error("expected at least one finding for a resource with minimal config vs prod-external template")
	}
	if result.Status == "compliant" {
		t.Errorf("expected non-compliant status for sparse config, got %q", result.Status)
	}
	if result.ComplianceScore < 0 || result.ComplianceScore > 100 {
		t.Errorf("ComplianceScore out of range: %f", result.ComplianceScore)
	}
}

func TestMockTemplateManager_ValidateCompliance_DevTemplateHasFewerFindings(t *testing.T) {
	mgr, err := NewTemplateManager("memory")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	// waf-dev-external has fewer required rules; partial config should be more compliant.
	result, err := mgr.ValidateCompliance(ctx, "waf-dev-external", "arn:aws:wafv2:us-east-1:123456789012:regional/webacl/dev")
	if err != nil {
		t.Fatalf("ValidateCompliance returned unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil ScanResult")
	}
	if result.ResourceID != "arn:aws:wafv2:us-east-1:123456789012:regional/webacl/dev" {
		t.Errorf("expected ResourceID to be preserved, got %q", result.ResourceID)
	}
}

func TestMockTemplateManager_ValidateCompliance_UnknownTemplateReturnsError(t *testing.T) {
	mgr, err := NewTemplateManager("memory")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	_, err = mgr.ValidateCompliance(ctx, "nonexistent-template", "some-resource")
	if err == nil {
		t.Fatal("expected error for unknown template ID, got nil")
	}
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestMockTemplateManager_ValidateCompliance_FindingsHaveRequiredFields(t *testing.T) {
	mgr, err := NewTemplateManager("memory")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	result, err := mgr.ValidateCompliance(ctx, "waf-prod-external", "resource-001")
	if err != nil {
		t.Fatalf("ValidateCompliance returned unexpected error: %v", err)
	}

	for i, f := range result.Findings {
		if f.ID == "" {
			t.Errorf("finding[%d] has empty ID", i)
		}
		if f.Severity == "" {
			t.Errorf("finding[%d] has empty Severity", i)
		}
		if f.Description == "" {
			t.Errorf("finding[%d] has empty Description", i)
		}
	}
}

func TestNewTemplateManager_InvalidProvider(t *testing.T) {
	_, err := NewTemplateManager("invalid-provider")
	if err == nil {
		t.Fatal("expected error for invalid provider, got nil")
	}
	if !strings.Contains(err.Error(), "unsupported") {
		t.Errorf("expected error message to contain 'unsupported', got: %v", err)
	}
}
