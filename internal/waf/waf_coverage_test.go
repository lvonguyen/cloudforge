package waf

import (
	"context"
	"testing"
)

func TestCovNewTemplateManager_Memory(t *testing.T) {
	tm, err := NewTemplateManager("memory")
	if err != nil {
		t.Fatalf("NewTemplateManager: %v", err)
	}
	if tm == nil {
		t.Fatal("expected non-nil template manager")
	}
}

func TestCovNewTemplateManager_Empty(t *testing.T) {
	tm, err := NewTemplateManager("")
	if err != nil {
		t.Fatalf("NewTemplateManager: %v", err)
	}
	if tm == nil {
		t.Fatal("expected non-nil template manager")
	}
}

func TestCovNewTemplateManager_Unknown(t *testing.T) {
	_, err := NewTemplateManager("unknown")
	if err == nil {
		t.Error("expected error for unknown provider")
	}
}

func TestCovTemplateManager_ListTemplates(t *testing.T) {
	tm, _ := NewTemplateManager("memory")
	templates, err := tm.ListTemplates(context.Background())
	if err != nil {
		t.Fatalf("ListTemplates: %v", err)
	}
	if len(templates) == 0 {
		t.Error("expected templates from mock manager")
	}
}

func TestCovTemplateManager_ValidateCompliance(t *testing.T) {
	tm, _ := NewTemplateManager("memory")
	templates, _ := tm.ListTemplates(context.Background())
	if len(templates) == 0 {
		t.Skip("no templates to test")
	}

	result, err := tm.ValidateCompliance(context.Background(), templates[0].ID, "resource-1")
	if err != nil {
		t.Fatalf("ValidateCompliance: %v", err)
	}
	if result == nil {
		t.Error("expected non-nil scan result")
	}
}
