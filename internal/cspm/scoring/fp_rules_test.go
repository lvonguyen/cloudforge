package scoring

import (
	"strings"
	"testing"
)

// --- Tests for FPRuleSet.Evaluate (integration) ---

func TestFPRuleSet_NoMatch_ReturnsFalse(t *testing.T) {
	rs := NewFPRuleSet()

	// CRITICAL finding in prod — no FP rule should match.
	f := Finding{
		ID:           "fp-int-001",
		Severity:     SevCritical,
		ResourceType: "AWS::EC2::Instance",
		Context: FindingContext{
			EnvType:        "prod",
			InternetFacing: true,
		},
	}

	_, matched := rs.Evaluate(f)
	if matched {
		t.Error("expected no FP rule match for CRITICAL finding in prod")
	}
}

func TestFPRuleSet_PriorityOrder_DevSandboxFirst(t *testing.T) {
	rs := NewFPRuleSet()

	// Finding matches both dev/sandbox and compensating controls rules.
	f := Finding{
		ID:           "fp-int-002",
		Severity:     SevHigh,
		ResourceType: "AWS::EC2::Instance",
		Context: FindingContext{
			EnvType:        "dev",
			InternetFacing: true,
			WAFEnabled:     true,
		},
	}

	result, matched := rs.Evaluate(f)
	if !matched {
		t.Fatal("expected FP rule match for dev + WAF finding")
	}
	// Dev/sandbox rule has higher priority.
	if result.Pattern != "FP-DEV-SANDBOX" {
		t.Errorf("expected FP-DEV-SANDBOX (higher priority), got %s", result.Pattern)
	}
}

// --- Tests for fpRuleDevSandboxNonCritical ---

func TestFP_DevSandbox_HighInDev_Downgraded(t *testing.T) {
	f := Finding{
		ID:       "fp-dev-001",
		Severity: SevHigh,
		Context:  FindingContext{EnvType: "dev"},
	}

	result, matched := fpRuleDevSandboxNonCritical(f)
	if !matched {
		t.Fatal("expected rule match for HIGH in dev")
	}
	if result.AdjustedSeverity != SevLow {
		t.Errorf("expected adjusted severity LOW, got %s", result.AdjustedSeverity)
	}
	if !result.Applied {
		t.Error("expected Applied=true when severity changes")
	}
	if result.Confidence != 0.85 {
		t.Errorf("expected confidence 0.85, got %.2f", result.Confidence)
	}
	if result.Pattern != "FP-DEV-SANDBOX" {
		t.Errorf("expected pattern FP-DEV-SANDBOX, got %s", result.Pattern)
	}
}

func TestFP_DevSandbox_MediumInSandbox_Downgraded(t *testing.T) {
	f := Finding{
		ID:       "fp-dev-002",
		Severity: SevMedium,
		Context:  FindingContext{EnvType: "sandbox"},
	}

	result, matched := fpRuleDevSandboxNonCritical(f)
	if !matched {
		t.Fatal("expected rule match for MEDIUM in sandbox")
	}
	if result.AdjustedSeverity != SevLow {
		t.Errorf("expected adjusted severity LOW, got %s", result.AdjustedSeverity)
	}
}

func TestFP_DevSandbox_LowInQA_MatchesButNotApplied(t *testing.T) {
	f := Finding{
		ID:       "fp-dev-003",
		Severity: SevLow,
		Context:  FindingContext{EnvType: "qa"},
	}

	result, matched := fpRuleDevSandboxNonCritical(f)
	if !matched {
		t.Fatal("expected rule match for LOW in qa")
	}
	// LOW -> LOW: Applied should be false.
	if result.Applied {
		t.Error("expected Applied=false when severity is already LOW")
	}
}

func TestFP_DevSandbox_CriticalInDev_NotMatched(t *testing.T) {
	f := Finding{
		ID:       "fp-dev-004",
		Severity: SevCritical,
		Context:  FindingContext{EnvType: "dev"},
	}

	_, matched := fpRuleDevSandboxNonCritical(f)
	if matched {
		t.Error("expected no match for CRITICAL severity even in dev")
	}
}

func TestFP_DevSandbox_HighInProd_NotMatched(t *testing.T) {
	f := Finding{
		ID:       "fp-dev-005",
		Severity: SevHigh,
		Context:  FindingContext{EnvType: "prod"},
	}

	_, matched := fpRuleDevSandboxNonCritical(f)
	if matched {
		t.Error("expected no match for prod environment")
	}
}

func TestFP_DevSandbox_VariousNonProdEnvs(t *testing.T) {
	envs := []string{"dev", "development", "sandbox", "sbx", "test", "qa", "uat"}

	for _, env := range envs {
		f := Finding{
			ID:       "fp-dev-env-" + env,
			Severity: SevHigh,
			Context:  FindingContext{EnvType: env},
		}

		_, matched := fpRuleDevSandboxNonCritical(f)
		if !matched {
			t.Errorf("expected rule match for env %q", env)
		}
	}
}

// --- Tests for fpRuleCompensatingControls ---

func TestFP_Compensating_WAFEnabled_HighDowngraded(t *testing.T) {
	f := Finding{
		ID:       "fp-comp-001",
		Severity: SevHigh,
		Context: FindingContext{
			InternetFacing: true,
			WAFEnabled:     true,
		},
	}

	result, matched := fpRuleCompensatingControls(f)
	if !matched {
		t.Fatal("expected rule match for HIGH + WAF + internet-facing")
	}
	if result.AdjustedSeverity != SevMedium {
		t.Errorf("expected MEDIUM (one-level downgrade), got %s", result.AdjustedSeverity)
	}
	if !result.Applied {
		t.Error("expected Applied=true")
	}
	if !strings.Contains(result.Reason, "WAF") {
		t.Error("expected reason to mention WAF")
	}
}

func TestFP_Compensating_EDREnabled_MediumDowngraded(t *testing.T) {
	f := Finding{
		ID:       "fp-comp-002",
		Severity: SevMedium,
		Context: FindingContext{
			InternetFacing: true,
			EDREnabled:     true,
		},
	}

	result, matched := fpRuleCompensatingControls(f)
	if !matched {
		t.Fatal("expected rule match for MEDIUM + EDR + internet-facing")
	}
	if result.AdjustedSeverity != SevLow {
		t.Errorf("expected LOW (one-level downgrade), got %s", result.AdjustedSeverity)
	}
	if !strings.Contains(result.Reason, "EDR") {
		t.Error("expected reason to mention EDR/IDS")
	}
}

func TestFP_Compensating_BothWAFAndEDR_ReasonMentionsBoth(t *testing.T) {
	f := Finding{
		ID:       "fp-comp-003",
		Severity: SevHigh,
		Context: FindingContext{
			InternetFacing: true,
			WAFEnabled:     true,
			EDREnabled:     true,
		},
	}

	result, matched := fpRuleCompensatingControls(f)
	if !matched {
		t.Fatal("expected rule match")
	}
	if !strings.Contains(result.Reason, "WAF") || !strings.Contains(result.Reason, "EDR") {
		t.Error("expected reason to mention both WAF and EDR/IDS")
	}
}

func TestFP_Compensating_NotInternetFacing_NotMatched(t *testing.T) {
	f := Finding{
		ID:       "fp-comp-004",
		Severity: SevHigh,
		Context: FindingContext{
			InternetFacing: false,
			WAFEnabled:     true,
		},
	}

	_, matched := fpRuleCompensatingControls(f)
	if matched {
		t.Error("expected no match when not internet-facing")
	}
}

func TestFP_Compensating_NoControls_NotMatched(t *testing.T) {
	f := Finding{
		ID:       "fp-comp-005",
		Severity: SevHigh,
		Context: FindingContext{
			InternetFacing: true,
			WAFEnabled:     false,
			EDREnabled:     false,
		},
	}

	_, matched := fpRuleCompensatingControls(f)
	if matched {
		t.Error("expected no match without compensating controls")
	}
}

func TestFP_Compensating_CriticalSeverity_NotMatched(t *testing.T) {
	f := Finding{
		ID:       "fp-comp-006",
		Severity: SevCritical,
		Context: FindingContext{
			InternetFacing: true,
			WAFEnabled:     true,
		},
	}

	_, matched := fpRuleCompensatingControls(f)
	if matched {
		t.Error("expected no match for CRITICAL severity even with compensating controls")
	}
}

func TestFP_Compensating_LowSeverity_NotMatched(t *testing.T) {
	f := Finding{
		ID:       "fp-comp-007",
		Severity: SevLow,
		Context: FindingContext{
			InternetFacing: true,
			WAFEnabled:     true,
		},
	}

	_, matched := fpRuleCompensatingControls(f)
	if matched {
		t.Error("expected no match for LOW severity (only HIGH/MEDIUM)")
	}
}

// --- Tests for fpRuleTestEphemeralResource ---

func TestFP_Ephemeral_TestResource_Suppressed(t *testing.T) {
	f := Finding{
		ID:           "fp-eph-001",
		Severity:     SevHigh,
		ResourceID:   "arn:aws:ec2:::test-instance-001",
		ResourceType: "AWS::EC2::Instance",
	}

	result, matched := fpRuleTestEphemeralResource(f)
	if !matched {
		t.Fatal("expected rule match for test resource")
	}
	if result.AdjustedSeverity != SevInformational {
		t.Errorf("expected INFORMATIONAL, got %s", result.AdjustedSeverity)
	}
	if !result.Applied {
		t.Error("expected Applied=true")
	}
	if result.Pattern != "FP-TEST-EPHEMERAL" {
		t.Errorf("expected pattern FP-TEST-EPHEMERAL, got %s", result.Pattern)
	}
}

func TestFP_Ephemeral_TmpResource_Suppressed(t *testing.T) {
	f := Finding{
		ID:           "fp-eph-002",
		Severity:     SevMedium,
		ResourceID:   "projects/my-proj/zones/us-central1/instances/tmp-build-runner",
		ResourceType: "google.compute.Instance",
	}

	result, matched := fpRuleTestEphemeralResource(f)
	if !matched {
		t.Fatal("expected rule match for tmp resource")
	}
	if result.AdjustedSeverity != SevInformational {
		t.Errorf("expected INFORMATIONAL, got %s", result.AdjustedSeverity)
	}
}

func TestFP_Ephemeral_QAEnvironment_Suppressed(t *testing.T) {
	f := Finding{
		ID:           "fp-eph-003",
		Severity:     SevHigh,
		ResourceID:   "arn:aws:rds:::my-db",
		ResourceType: "AWS::RDS::DBInstance",
		Context:      FindingContext{EnvType: "qa"},
	}

	result, matched := fpRuleTestEphemeralResource(f)
	if !matched {
		t.Fatal("expected rule match for QA environment")
	}
	if result.AdjustedSeverity != SevInformational {
		t.Errorf("expected INFORMATIONAL, got %s", result.AdjustedSeverity)
	}
}

func TestFP_Ephemeral_CriticalSeverity_NotMatched(t *testing.T) {
	f := Finding{
		ID:           "fp-eph-004",
		Severity:     SevCritical,
		ResourceID:   "test-resource-critical",
		ResourceType: "AWS::EC2::Instance",
		Context:      FindingContext{EnvType: "test"},
	}

	_, matched := fpRuleTestEphemeralResource(f)
	if matched {
		t.Error("expected no match for CRITICAL even on test/ephemeral resource")
	}
}

func TestFP_Ephemeral_ProdNonTestResource_NotMatched(t *testing.T) {
	f := Finding{
		ID:           "fp-eph-005",
		Severity:     SevHigh,
		ResourceID:   "arn:aws:ec2:::prod-web-server",
		ResourceType: "AWS::EC2::Instance",
		Context:      FindingContext{EnvType: "prod"},
	}

	_, matched := fpRuleTestEphemeralResource(f)
	if matched {
		t.Error("expected no match for production non-test resource")
	}
}

func TestFP_Ephemeral_ScratchResource_Suppressed(t *testing.T) {
	f := Finding{
		ID:           "fp-eph-006",
		Severity:     SevMedium,
		ResourceID:   "arn:aws:s3:::scratch-data-bucket",
		ResourceType: "AWS::S3::Bucket",
	}

	_, matched := fpRuleTestEphemeralResource(f)
	if !matched {
		t.Error("expected rule match for scratch resource")
	}
}

// --- Tests for helper functions ---

func TestIsNonProdEnv(t *testing.T) {
	tests := []struct {
		env      string
		expected bool
	}{
		{"dev", true},
		{"development", true},
		{"sandbox", true},
		{"sbx", true},
		{"test", true},
		{"qa", true},
		{"uat", true},
		{"prod", false},
		{"production", false},
		{"staging", false},
		{"", false},
	}

	for _, tc := range tests {
		if got := isNonProdEnv(tc.env); got != tc.expected {
			t.Errorf("isNonProdEnv(%q) = %v, want %v", tc.env, got, tc.expected)
		}
	}
}

func TestDowngradeSev(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{SevCritical, SevHigh},
		{SevHigh, SevMedium},
		{SevMedium, SevLow},
		{SevLow, SevInformational},
		{SevInformational, SevInformational},
	}

	for _, tc := range tests {
		if got := downgradeSev(tc.input); got != tc.expected {
			t.Errorf("downgradeSev(%q) = %q, want %q", tc.input, got, tc.expected)
		}
	}
}
