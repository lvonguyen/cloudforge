package scoring

import "strings"

// FPRuleSet is a concrete FPEvaluator that implements deterministic
// false-positive suppression rules. Rules are evaluated in order; the first
// match is returned.
type FPRuleSet struct {
	rules []fpRule
}

// fpRule is a function that evaluates one deterministic FP suppression rule.
type fpRule func(f Finding) (*DeterministicRuleResult, bool)

// NewFPRuleSet creates an FPRuleSet with the standard FP rules.
func NewFPRuleSet() *FPRuleSet {
	return &FPRuleSet{
		rules: []fpRule{
			fpRuleDevSandboxNonCritical,
			fpRuleCompensatingControls,
			fpRuleTestEphemeralResource,
		},
	}
}

// Evaluate runs each FP rule in priority order and returns the first match.
// Returns (nil, false) when no rule matches.
func (rs *FPRuleSet) Evaluate(f Finding) (*DeterministicRuleResult, bool) {
	for _, rule := range rs.rules {
		if result, matched := rule(f); matched {
			return result, true
		}
	}
	return nil, false
}

// fpRuleDevSandboxNonCritical downgrades non-critical findings in dev/sandbox
// environments. Findings in non-production environments with severity below
// CRITICAL are likely to be noise that distracts from production issues.
//
// Trigger: EnvType in {dev, development, sandbox, sbx, test, qa, uat}
//
//	AND Severity NOT in {CRITICAL}
//
// Effect: Downgrade to LOW, confidence 0.85.
func fpRuleDevSandboxNonCritical(f Finding) (*DeterministicRuleResult, bool) {
	env := strings.ToLower(f.Context.EnvType)
	if !isNonProdEnv(env) {
		return nil, false
	}

	sev := strings.ToUpper(f.Severity)
	if sev == SevCritical {
		return nil, false
	}

	adjusted := SevLow
	applied := sev != adjusted

	return &DeterministicRuleResult{
		OriginalSeverity:   f.Severity,
		AdjustedSeverity:   adjusted,
		Applied:            applied,
		Confidence:         0.85,
		Reason:             "non-production environment (" + env + "); severity downgraded per dev/sandbox FP rule",
		Pattern:            "FP-DEV-SANDBOX",
		SuggestedRiskScore: 20,
	}, true
}

// fpRuleCompensatingControls downgrades findings where compensating controls
// (WAF, IDS/EDR) are present and significantly reduce exploitability.
//
// Trigger: (WAFEnabled OR EDREnabled) AND InternetFacing
//
//	AND Severity in {HIGH, MEDIUM}
//
// Effect: Downgrade by 1 level, confidence 0.80.
func fpRuleCompensatingControls(f Finding) (*DeterministicRuleResult, bool) {
	if !f.Context.InternetFacing {
		return nil, false
	}

	hasCompensation := f.Context.WAFEnabled || f.Context.EDREnabled
	if !hasCompensation {
		return nil, false
	}

	sev := strings.ToUpper(f.Severity)
	if sev != SevHigh && sev != SevMedium {
		return nil, false
	}

	adjusted := downgradeSev(sev)
	applied := adjusted != sev

	controls := make([]string, 0, 2)
	if f.Context.WAFEnabled {
		controls = append(controls, "WAF")
	}
	if f.Context.EDREnabled {
		controls = append(controls, "EDR/IDS")
	}

	return &DeterministicRuleResult{
		OriginalSeverity: f.Severity,
		AdjustedSeverity: adjusted,
		Applied:          applied,
		Confidence:       0.80,
		Reason:           "compensating controls (" + strings.Join(controls, ", ") + ") reduce exploitability",
		Pattern:          "FP-COMPENSATING-CTRL",
	}, true
}

// fpRuleTestEphemeralResource suppresses findings on test or ephemeral
// resources identified by resource type naming patterns. These resources
// have minimal blast radius and are typically short-lived.
//
// Trigger: ResourceType or ResourceID contains test/ephemeral/temp/tmp markers
//
//	OR EnvType in {test, qa, uat}
//	AND Severity in {HIGH, MEDIUM, LOW, INFORMATIONAL}
//
// Effect: Suppress to INFORMATIONAL, confidence 0.90.
func fpRuleTestEphemeralResource(f Finding) (*DeterministicRuleResult, bool) {
	sev := strings.ToUpper(f.Severity)
	if sev == SevCritical {
		return nil, false
	}

	isEphemeral := isEphemeralResource(f)
	isTestEnv := isTestEnvironment(f.Context.EnvType)

	if !isEphemeral && !isTestEnv {
		return nil, false
	}

	adjusted := SevInformational
	applied := sev != adjusted

	return &DeterministicRuleResult{
		OriginalSeverity:   f.Severity,
		AdjustedSeverity:   adjusted,
		Applied:            applied,
		Confidence:         0.90,
		Reason:             "test/ephemeral resource — finding suppressed as low operational risk",
		Pattern:            "FP-TEST-EPHEMERAL",
		SuggestedRiskScore: 5,
	}, true
}

// --- Helpers ---

// isNonProdEnv returns true for environment strings that are clearly non-production.
func isNonProdEnv(env string) bool {
	switch env {
	case "dev", "development", "sandbox", "sbx", "test", "qa", "uat":
		return true
	}
	return false
}

// isTestEnvironment returns true for environments that are specifically test-oriented.
func isTestEnvironment(envType string) bool {
	env := strings.ToLower(envType)
	return env == "test" || env == "qa" || env == "uat"
}

// isEphemeralResource checks resource metadata for test/ephemeral markers.
func isEphemeralResource(f Finding) bool {
	rid := strings.ToLower(f.ResourceID)
	rtype := strings.ToLower(f.ResourceType)
	combined := rid + " " + rtype

	markers := []string{"test", "ephemeral", "temp-", "tmp-", "scratch", "disposable"}
	for _, m := range markers {
		if strings.Contains(combined, m) {
			return true
		}
	}
	return false
}

// downgradeSev reduces severity by one level.
func downgradeSev(sev string) string {
	switch sev {
	case SevCritical:
		return SevHigh
	case SevHigh:
		return SevMedium
	case SevMedium:
		return SevLow
	case SevLow:
		return SevInformational
	default:
		return sev
	}
}
