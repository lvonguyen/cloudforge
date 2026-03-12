package scoring

import (
	"strings"
	"testing"
)

// --- Tests for FNRuleSet.Evaluate (integration) ---

func TestFNRuleSet_NoMatch_ReturnsFalse(t *testing.T) {
	rs := NewFNRuleSet()

	// Normal finding with no escalation triggers.
	f := Finding{
		ID:       "fn-int-001",
		Severity: SevMedium,
		Context: FindingContext{
			EnvType:        "dev",
			InternetFacing: false,
		},
	}

	_, matched := rs.Evaluate(f)
	if matched {
		t.Error("expected no FN rule match for normal dev finding")
	}
}

func TestFNRuleSet_PriorityOrder_InternetAdminFirst(t *testing.T) {
	rs := NewFNRuleSet()

	// Finding matches both internet-admin-no-MFA and KEV-production rules.
	f := Finding{
		ID:       "fn-int-002",
		Severity: SevMedium,
		Context: FindingContext{
			InternetFacing:      true,
			HasAdminPermissions: true,
			MFARequired:         false,
			InKEV:               true,
			EnvType:             "prod",
		},
	}

	result, matched := rs.Evaluate(f)
	if !matched {
		t.Fatal("expected FN rule match")
	}
	// Internet-admin-no-MFA has higher priority.
	if result.Pattern != "FN-INET-ADMIN-NOMFA" {
		t.Errorf("expected FN-INET-ADMIN-NOMFA (higher priority), got %s", result.Pattern)
	}
}

// --- Tests for fnRuleInternetExposedAdminNoMFA ---

func TestFN_InternetAdminNoMFA_AllConditions_Escalated(t *testing.T) {
	f := Finding{
		ID:       "fn-inet-001",
		Severity: SevMedium,
		Context: FindingContext{
			InternetFacing:      true,
			HasAdminPermissions: true,
			MFARequired:         false,
		},
	}

	result, matched := fnRuleInternetExposedAdminNoMFA(f)
	if !matched {
		t.Fatal("expected rule match for internet + admin + no MFA")
	}
	if result.AdjustedSeverity != SevCritical {
		t.Errorf("expected CRITICAL, got %s", result.AdjustedSeverity)
	}
	if !result.Applied {
		t.Error("expected Applied=true (MEDIUM -> CRITICAL)")
	}
	if result.Confidence != 0.95 {
		t.Errorf("expected confidence 0.95, got %.2f", result.Confidence)
	}
	if result.SuggestedRiskScore != 95 {
		t.Errorf("expected risk score 95, got %d", result.SuggestedRiskScore)
	}
}

func TestFN_InternetAdminNoMFA_AlreadyCritical_MatchesNotApplied(t *testing.T) {
	f := Finding{
		ID:       "fn-inet-002",
		Severity: SevCritical,
		Context: FindingContext{
			InternetFacing:      true,
			HasAdminPermissions: true,
			MFARequired:         false,
		},
	}

	result, matched := fnRuleInternetExposedAdminNoMFA(f)
	if !matched {
		t.Fatal("expected rule match even when already CRITICAL")
	}
	if result.Applied {
		t.Error("expected Applied=false when severity is already CRITICAL")
	}
}

func TestFN_InternetAdminNoMFA_WithMFA_NotMatched(t *testing.T) {
	f := Finding{
		ID:       "fn-inet-003",
		Severity: SevMedium,
		Context: FindingContext{
			InternetFacing:      true,
			HasAdminPermissions: true,
			MFARequired:         true, // MFA is enforced
		},
	}

	_, matched := fnRuleInternetExposedAdminNoMFA(f)
	if matched {
		t.Error("expected no match when MFA is required")
	}
}

func TestFN_InternetAdminNoMFA_NotInternetFacing_NotMatched(t *testing.T) {
	f := Finding{
		ID:       "fn-inet-004",
		Severity: SevMedium,
		Context: FindingContext{
			InternetFacing:      false,
			HasAdminPermissions: true,
			MFARequired:         false,
		},
	}

	_, matched := fnRuleInternetExposedAdminNoMFA(f)
	if matched {
		t.Error("expected no match when not internet-facing")
	}
}

func TestFN_InternetAdminNoMFA_NotAdmin_NotMatched(t *testing.T) {
	f := Finding{
		ID:       "fn-inet-005",
		Severity: SevMedium,
		Context: FindingContext{
			InternetFacing:      true,
			HasAdminPermissions: false,
			MFARequired:         false,
		},
	}

	_, matched := fnRuleInternetExposedAdminNoMFA(f)
	if matched {
		t.Error("expected no match without admin permissions")
	}
}

// --- Tests for fnRuleKEVProduction ---

func TestFN_KEVProd_AllConditions_Escalated(t *testing.T) {
	f := Finding{
		ID:       "fn-kev-001",
		Severity: SevHigh,
		Context: FindingContext{
			InKEV:   true,
			EnvType: "prod",
		},
	}

	result, matched := fnRuleKEVProduction(f)
	if !matched {
		t.Fatal("expected rule match for KEV + prod")
	}
	if result.AdjustedSeverity != SevCritical {
		t.Errorf("expected CRITICAL, got %s", result.AdjustedSeverity)
	}
	if !result.Applied {
		t.Error("expected Applied=true (HIGH -> CRITICAL)")
	}
	if result.Confidence != 0.90 {
		t.Errorf("expected confidence 0.90, got %.2f", result.Confidence)
	}
	if !strings.Contains(result.Reason, "KEV") {
		t.Error("expected reason to mention KEV")
	}
}

func TestFN_KEVProd_ProductionVariant_Matched(t *testing.T) {
	for _, env := range []string{"prod", "production", "prd"} {
		f := Finding{
			ID:       "fn-kev-env-" + env,
			Severity: SevMedium,
			Context: FindingContext{
				InKEV:   true,
				EnvType: env,
			},
		}

		_, matched := fnRuleKEVProduction(f)
		if !matched {
			t.Errorf("expected rule match for KEV + env %q", env)
		}
	}
}

func TestFN_KEVProd_NotInKEV_NotMatched(t *testing.T) {
	f := Finding{
		ID:       "fn-kev-002",
		Severity: SevHigh,
		Context: FindingContext{
			InKEV:   false,
			EnvType: "prod",
		},
	}

	_, matched := fnRuleKEVProduction(f)
	if matched {
		t.Error("expected no match when not in KEV")
	}
}

func TestFN_KEVProd_NonProdEnv_NotMatched(t *testing.T) {
	f := Finding{
		ID:       "fn-kev-003",
		Severity: SevHigh,
		Context: FindingContext{
			InKEV:   true,
			EnvType: "dev",
		},
	}

	_, matched := fnRuleKEVProduction(f)
	if matched {
		t.Error("expected no match for KEV in non-prod environment")
	}
}

func TestFN_KEVProd_AlreadyCritical_MatchesNotApplied(t *testing.T) {
	f := Finding{
		ID:       "fn-kev-004",
		Severity: SevCritical,
		Context: FindingContext{
			InKEV:   true,
			EnvType: "prod",
		},
	}

	result, matched := fnRuleKEVProduction(f)
	if !matched {
		t.Fatal("expected rule match even when already CRITICAL")
	}
	if result.Applied {
		t.Error("expected Applied=false when severity is already CRITICAL")
	}
}

// --- Tests for fnRuleUnusedAdminCredentials ---

func TestFN_UnusedAdmin_Over90Days_Escalated(t *testing.T) {
	f := Finding{
		ID:       "fn-unused-001",
		Severity: SevLow,
		Context: FindingContext{
			HasAdminPermissions:    true,
			CredentialLastUsedDays: 180,
		},
	}

	result, matched := fnRuleUnusedAdminCredentials(f)
	if !matched {
		t.Fatal("expected rule match for admin + 180 days unused")
	}
	if result.AdjustedSeverity != SevHigh {
		t.Errorf("expected HIGH, got %s", result.AdjustedSeverity)
	}
	if !result.Applied {
		t.Error("expected Applied=true (LOW -> HIGH)")
	}
	if result.Confidence != 0.85 {
		t.Errorf("expected confidence 0.85, got %.2f", result.Confidence)
	}
	if result.SuggestedRiskScore != 75 {
		t.Errorf("expected risk score 75, got %d", result.SuggestedRiskScore)
	}
}

func TestFN_UnusedAdmin_Exactly91Days_Escalated(t *testing.T) {
	f := Finding{
		ID:       "fn-unused-002",
		Severity: SevMedium,
		Context: FindingContext{
			HasAdminPermissions:    true,
			CredentialLastUsedDays: 91,
		},
	}

	result, matched := fnRuleUnusedAdminCredentials(f)
	if !matched {
		t.Fatal("expected rule match for admin + 91 days unused")
	}
	if result.AdjustedSeverity != SevHigh {
		t.Errorf("expected HIGH, got %s", result.AdjustedSeverity)
	}
}

func TestFN_UnusedAdmin_Exactly90Days_NotMatched(t *testing.T) {
	f := Finding{
		ID:       "fn-unused-003",
		Severity: SevLow,
		Context: FindingContext{
			HasAdminPermissions:    true,
			CredentialLastUsedDays: 90,
		},
	}

	_, matched := fnRuleUnusedAdminCredentials(f)
	if matched {
		t.Error("expected no match at exactly 90 days (threshold is > 90)")
	}
}

func TestFN_UnusedAdmin_NotAdmin_NotMatched(t *testing.T) {
	f := Finding{
		ID:       "fn-unused-004",
		Severity: SevLow,
		Context: FindingContext{
			HasAdminPermissions:    false,
			CredentialLastUsedDays: 365,
		},
	}

	_, matched := fnRuleUnusedAdminCredentials(f)
	if matched {
		t.Error("expected no match without admin permissions")
	}
}

func TestFN_UnusedAdmin_AlreadyHighOrAbove_NoEscalation(t *testing.T) {
	f := Finding{
		ID:       "fn-unused-005",
		Severity: SevHigh,
		Context: FindingContext{
			HasAdminPermissions:    true,
			CredentialLastUsedDays: 200,
		},
	}

	result, matched := fnRuleUnusedAdminCredentials(f)
	if !matched {
		t.Fatal("expected rule match even when already HIGH")
	}
	// HIGH -> HIGH: Applied should be false.
	if result.Applied {
		t.Error("expected Applied=false when severity is already HIGH or above")
	}
	if result.AdjustedSeverity != SevHigh {
		t.Errorf("expected HIGH (unchanged), got %s", result.AdjustedSeverity)
	}
}

func TestFN_UnusedAdmin_CriticalSeverity_NoEscalation(t *testing.T) {
	f := Finding{
		ID:       "fn-unused-006",
		Severity: SevCritical,
		Context: FindingContext{
			HasAdminPermissions:    true,
			CredentialLastUsedDays: 365,
		},
	}

	result, matched := fnRuleUnusedAdminCredentials(f)
	if !matched {
		t.Fatal("expected rule match for CRITICAL + dormant admin")
	}
	// CRITICAL is already more severe than HIGH — no escalation applied.
	if result.Applied {
		t.Error("expected Applied=false when already CRITICAL")
	}
	if result.AdjustedSeverity != SevCritical {
		t.Errorf("expected CRITICAL (unchanged), got %s", result.AdjustedSeverity)
	}
}

// --- Tests for helper isProdEnv ---

func TestIsProdEnv(t *testing.T) {
	tests := []struct {
		env      string
		expected bool
	}{
		{"prod", true},
		{"production", true},
		{"prd", true},
		{"dev", false},
		{"staging", false},
		{"sandbox", false},
		{"", false},
	}

	for _, tc := range tests {
		if got := isProdEnv(tc.env); got != tc.expected {
			t.Errorf("isProdEnv(%q) = %v, want %v", tc.env, got, tc.expected)
		}
	}
}
