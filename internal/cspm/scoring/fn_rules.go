package scoring

import "strings"

// FNRuleSet is a concrete FNEvaluator that implements deterministic
// false-negative escalation rules. Rules are evaluated in order; the first
// match is returned.
type FNRuleSet struct {
	rules []fnRule
}

// fnRule is a function that evaluates one deterministic FN escalation rule.
type fnRule func(f Finding) (*DeterministicRuleResult, bool)

// NewFNRuleSet creates an FNRuleSet with the standard FN rules.
func NewFNRuleSet() *FNRuleSet {
	return &FNRuleSet{
		rules: []fnRule{
			fnRuleInternetExposedAdminNoMFA,
			fnRuleKEVProduction,
			fnRuleUnusedAdminCredentials,
		},
	}
}

// Evaluate runs each FN rule in priority order and returns the first match.
// Returns (nil, false) when no rule matches.
func (rs *FNRuleSet) Evaluate(f Finding) (*DeterministicRuleResult, bool) {
	for _, rule := range rs.rules {
		if result, matched := rule(f); matched {
			return result, true
		}
	}
	return nil, false
}

// fnRuleInternetExposedAdminNoMFA escalates findings where an internet-exposed
// resource has admin credentials without MFA. This combination is a top-tier
// attack vector for credential-based account takeover.
//
// Trigger: InternetFacing
//
//	AND HasAdminPermissions
//	AND NOT MFARequired
//
// Effect: Escalate to CRITICAL, confidence 0.95.
func fnRuleInternetExposedAdminNoMFA(f Finding) (*DeterministicRuleResult, bool) {
	if !f.Context.InternetFacing {
		return nil, false
	}
	if !f.Context.HasAdminPermissions {
		return nil, false
	}
	if f.Context.MFARequired {
		return nil, false
	}

	sev := strings.ToUpper(f.Severity)
	adjusted := SevCritical
	applied := sev != adjusted

	return &DeterministicRuleResult{
		OriginalSeverity:   f.Severity,
		AdjustedSeverity:   adjusted,
		Applied:            applied,
		Confidence:         0.95,
		Reason:             "internet-exposed admin credentials without MFA — critical account takeover risk",
		Pattern:            "FN-INET-ADMIN-NOMFA",
		SuggestedRiskScore: 95,
	}, true
}

// fnRuleKEVProduction escalates findings that match a CISA Known Exploited
// Vulnerability (KEV) entry and are in a production environment. KEV entries
// represent actively exploited vulnerabilities that demand immediate attention
// in production systems.
//
// Trigger: InKEV
//
//	AND EnvType in {prod, production, prd}
//
// Effect: Escalate to CRITICAL, confidence 0.90.
func fnRuleKEVProduction(f Finding) (*DeterministicRuleResult, bool) {
	if !f.Context.InKEV {
		return nil, false
	}

	env := strings.ToLower(f.Context.EnvType)
	if !isProdEnv(env) {
		return nil, false
	}

	sev := strings.ToUpper(f.Severity)
	adjusted := SevCritical
	applied := sev != adjusted

	return &DeterministicRuleResult{
		OriginalSeverity:   f.Severity,
		AdjustedSeverity:   adjusted,
		Applied:            applied,
		Confidence:         0.90,
		Reason:             "CISA KEV vulnerability in production environment — actively exploited and requires immediate remediation",
		Pattern:            "FN-KEV-PROD",
		SuggestedRiskScore: 92,
	}, true
}

// fnRuleUnusedAdminCredentials escalates findings involving admin credentials
// that have been unused for more than 90 days. Dormant privileged credentials
// are high-value targets for attackers and indicate poor access hygiene.
//
// Trigger: HasAdminPermissions
//
//	AND CredentialLastUsedDays > 90
//
// Effect: Escalate to HIGH, confidence 0.85.
func fnRuleUnusedAdminCredentials(f Finding) (*DeterministicRuleResult, bool) {
	if !f.Context.HasAdminPermissions {
		return nil, false
	}

	if f.Context.CredentialLastUsedDays <= 90 {
		return nil, false
	}

	sev := strings.ToUpper(f.Severity)
	adjusted := SevHigh
	// Only apply if actually escalating (original is less severe than HIGH).
	if severityToInt(sev) <= severityToInt(SevHigh) {
		adjusted = sev
	}
	applied := adjusted != sev

	return &DeterministicRuleResult{
		OriginalSeverity:   f.Severity,
		AdjustedSeverity:   adjusted,
		Applied:            applied,
		Confidence:         0.85,
		Reason:             "dormant admin credentials (unused > 90 days) are high-value attack targets",
		Pattern:            "FN-UNUSED-ADMIN-CREDS",
		SuggestedRiskScore: 75,
	}, true
}

// --- Helpers ---

// isProdEnv returns true for production environment identifiers.
func isProdEnv(env string) bool {
	switch env {
	case "prod", "production", "prd":
		return true
	}
	return false
}
