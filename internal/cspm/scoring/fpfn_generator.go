package scoring

import (
	"fmt"
	"strings"
)

// FPFNCandidate represents a candidate false-positive or false-negative scenario
// generated from threat intelligence enrichment data. Matches the FPFN JSON schema.
type FPFNCandidate struct {
	ID                   string   `json:"id"`
	Sector               string   `json:"sector"`
	Type                 string   `json:"type"` // "false_positive" or "false_negative"
	EdgeCase             string   `json:"edge_case"`
	CSP                  string   `json:"csp"`
	FindingType          string   `json:"finding_type"`
	FindingClass         string   `json:"finding_class"`
	SeverityReported     string   `json:"severity_reported"`
	SeverityActual       string   `json:"severity_actual"`
	ResourceType         string   `json:"resource_type"`
	Environment          string   `json:"environment"`
	ComplianceFrameworks []string `json:"compliance_frameworks"`
	Scenario             string   `json:"scenario"`
	WhyMisclassified     string   `json:"why_misclassified"`
	DetectionSignal      string   `json:"detection_signal"`
	GroundTruth          string   `json:"ground_truth"`
	RemediationImpact    string   `json:"remediation_impact"`
	Confidence           float64  `json:"confidence"`
}

// ThreatIntelSignals holds threat intelligence data used for FPFN candidate generation.
type ThreatIntelSignals struct {
	EPSSScore       float64
	EPSSPercentile  float64
	InKEV           bool
	GreyNoiseClass  string // "benign", "malicious", "unknown"
	HIBPBreachCount int
}

// GenerateFPFNCandidates produces FPFN candidates from findings combined with
// threat intelligence enrichment results. This is a library function for
// pipeline integration — it does not modify any data stores.
//
// Generation rules:
//   - EPSS > 0.8 + severity LOW/MEDIUM → FN candidate (under-scored high-exploit CVE)
//   - GreyNoise class "benign" + severity HIGH/CRITICAL → FP candidate (benign traffic over-scored)
//   - HIBP breach count >= 3 + severity < HIGH → FN candidate (compromised credential under-scored)
func GenerateFPFNCandidates(findings []Finding, signals map[string]*ThreatIntelSignals) []FPFNCandidate {
	var candidates []FPFNCandidate

	for _, f := range findings {
		sig, ok := signals[f.ID]
		if !ok || sig == nil {
			continue
		}

		if c := generateEPSSCandidate(f, sig); c != nil {
			candidates = append(candidates, *c)
		}
		if c := generateGreyNoiseCandidate(f, sig); c != nil {
			candidates = append(candidates, *c)
		}
		if c := generateHIBPCandidate(f, sig); c != nil {
			candidates = append(candidates, *c)
		}
	}

	return candidates
}

// generateEPSSCandidate produces an FN candidate when EPSS > 0.8 and severity
// is LOW or MEDIUM, indicating the scanner under-scored a highly exploitable CVE.
func generateEPSSCandidate(f Finding, sig *ThreatIntelSignals) *FPFNCandidate {
	if sig.EPSSScore <= 0.8 {
		return nil
	}

	sev := strings.ToUpper(f.Severity)
	if sev != "LOW" && sev != "MEDIUM" {
		return nil
	}

	// Determine expected severity.
	expectedSev := "HIGH"
	if sig.InKEV {
		expectedSev = "CRITICAL"
	}

	// Compute confidence from EPSS strength.
	confidence := 0.75 + (sig.EPSSScore-0.8)*0.5
	if confidence > 0.95 {
		confidence = 0.95
	}

	return &FPFNCandidate{
		ID:                   fmt.Sprintf("FN-AUTO-EPSS-%s", f.ID),
		Sector:               "auto-generated",
		Type:                 "false_negative",
		EdgeCase:             "EC-EPSS",
		CSP:                  inferCSP(f.ResourceType),
		FindingType:          f.FindingType,
		FindingClass:         "VULNERABILITY",
		SeverityReported:     f.Severity,
		SeverityActual:       expectedSev,
		ResourceType:         f.ResourceType,
		Environment:          f.Context.EnvType,
		ComplianceFrameworks: f.Context.ComplianceScopes,
		Scenario: fmt.Sprintf(
			"Finding %q rated %s by scanner. EPSS exploitation probability is %.2f (%.0fth percentile), indicating near-certain exploitation within 30 days.",
			f.Title, f.Severity, sig.EPSSScore, sig.EPSSPercentile*100,
		),
		WhyMisclassified: fmt.Sprintf(
			"Scanner assigns %s based on CVSS base score without incorporating EPSS exploitation probability (%.2f). High EPSS scores correlate with active real-world exploitation.",
			f.Severity, sig.EPSSScore,
		),
		DetectionSignal: fmt.Sprintf(
			"%s %s. EPSS: %.2f (%.0fth percentile).",
			f.FindingType, f.Severity, sig.EPSSScore, sig.EPSSPercentile*100,
		),
		GroundTruth: fmt.Sprintf(
			"EPSS score %.2f indicates %.0f%% exploitation probability. %s",
			sig.EPSSScore, sig.EPSSScore*100, kevStatus(sig.InKEV),
		),
		RemediationImpact: fmt.Sprintf(
			"Escalation to %s triggers SLA-driven patching, preventing exploitation of high-probability vulnerability.",
			expectedSev,
		),
		Confidence: confidence,
	}
}

// generateGreyNoiseCandidate produces an FP candidate when GreyNoise classifies
// traffic as "benign" and severity is HIGH or CRITICAL.
func generateGreyNoiseCandidate(f Finding, sig *ThreatIntelSignals) *FPFNCandidate {
	if strings.ToLower(sig.GreyNoiseClass) != "benign" {
		return nil
	}

	sev := strings.ToUpper(f.Severity)
	if sev != "HIGH" && sev != "CRITICAL" {
		return nil
	}

	expectedSev := downgradeSev(sev)

	return &FPFNCandidate{
		ID:                   fmt.Sprintf("FP-AUTO-GN-%s", f.ID),
		Sector:               "auto-generated",
		Type:                 "false_positive",
		EdgeCase:             "EC-GREYNOISE",
		CSP:                  inferCSP(f.ResourceType),
		FindingType:          f.FindingType,
		FindingClass:         "NETWORK_EXPOSURE",
		SeverityReported:     f.Severity,
		SeverityActual:       expectedSev,
		ResourceType:         f.ResourceType,
		Environment:          f.Context.EnvType,
		ComplianceFrameworks: f.Context.ComplianceScopes,
		Scenario: fmt.Sprintf(
			"Finding %q rated %s by scanner. GreyNoise classifies source traffic as benign — legitimate crawlers, health checks, or monitoring services.",
			f.Title, f.Severity,
		),
		WhyMisclassified: "Scanner flags network exposure at face value without considering traffic source intelligence. GreyNoise benign classification indicates no malicious activity.",
		DetectionSignal: fmt.Sprintf(
			"%s %s. GreyNoise: benign.",
			f.FindingType, f.Severity,
		),
		GroundTruth:       "GreyNoise analysis confirms traffic is from known benign sources. No exploit attempts or malicious scanning detected.",
		RemediationImpact: fmt.Sprintf("Downgrade to %s prevents unnecessary incident response for benign traffic patterns.", expectedSev),
		Confidence:        0.80,
	}
}

// generateHIBPCandidate produces an FN candidate when HIBP breach count >= 3
// and severity is below HIGH.
func generateHIBPCandidate(f Finding, sig *ThreatIntelSignals) *FPFNCandidate {
	if sig.HIBPBreachCount < 3 {
		return nil
	}

	sev := strings.ToUpper(f.Severity)
	sevInt := severityToInt(sev)
	if sevInt <= severityToInt(SevHigh) {
		return nil // already HIGH or above
	}

	// Confidence scales with breach count.
	confidence := 0.80
	if sig.HIBPBreachCount >= 5 {
		confidence = 0.88
	}
	if sig.HIBPBreachCount >= 8 {
		confidence = 0.92
	}

	return &FPFNCandidate{
		ID:                   fmt.Sprintf("FN-AUTO-HIBP-%s", f.ID),
		Sector:               "auto-generated",
		Type:                 "false_negative",
		EdgeCase:             "EC-HIBP",
		CSP:                  inferCSP(f.ResourceType),
		FindingType:          f.FindingType,
		FindingClass:         "IAM",
		SeverityReported:     f.Severity,
		SeverityActual:       "CRITICAL",
		ResourceType:         f.ResourceType,
		Environment:          f.Context.EnvType,
		ComplianceFrameworks: f.Context.ComplianceScopes,
		Scenario: fmt.Sprintf(
			"Finding %q rated %s by scanner. HIBP shows associated credentials in %d data breaches, indicating high risk of credential compromise.",
			f.Title, f.Severity, sig.HIBPBreachCount,
		),
		WhyMisclassified: fmt.Sprintf(
			"Scanner rates credential findings at %s without cross-referencing breach exposure. %d HIBP breaches significantly elevate the risk of credential stuffing attacks.",
			f.Severity, sig.HIBPBreachCount,
		),
		DetectionSignal: fmt.Sprintf(
			"%s %s. HIBP: %d breaches.",
			f.FindingType, f.Severity, sig.HIBPBreachCount,
		),
		GroundTruth: fmt.Sprintf(
			"Associated credentials appear in %d data breaches. High probability of credential reuse or exposure in public dumps.",
			sig.HIBPBreachCount,
		),
		RemediationImpact: "Escalation to CRITICAL triggers immediate credential rotation and MFA enforcement.",
		Confidence:        confidence,
	}
}

// inferCSP guesses the cloud provider from the resource type string.
func inferCSP(resourceType string) string {
	rt := strings.ToLower(resourceType)
	switch {
	case strings.HasPrefix(rt, "aws") || strings.Contains(rt, "aws_"):
		return "aws"
	case strings.HasPrefix(rt, "azure") || strings.Contains(rt, "azurerm_"):
		return "azure"
	case strings.HasPrefix(rt, "google") || strings.Contains(rt, "google_"):
		return "gcp"
	default:
		return "unknown"
	}
}

// kevStatus returns a human-readable KEV status string.
func kevStatus(inKEV bool) string {
	if inKEV {
		return "CVE is in CISA Known Exploited Vulnerabilities catalog — actively exploited."
	}
	return "CVE is not in CISA KEV."
}
