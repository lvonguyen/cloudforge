package scoring

import "testing"

func TestGenerateFPFNCandidates_EPSSHighProdLow(t *testing.T) {
	findings := []Finding{
		{
			ID:          "FIND-001",
			Severity:    "LOW",
			FindingType: "CVE-2024-21338",
			Title:       "Windows kernel elevation of privilege",
			Context: FindingContext{
				EnvType:          "prod",
				ComplianceScopes: []string{"SOC2"},
			},
		},
	}
	signals := map[string]*ThreatIntelSignals{
		"FIND-001": {
			EPSSScore:      0.92,
			EPSSPercentile: 0.98,
			InKEV:          true,
		},
	}

	candidates := GenerateFPFNCandidates(findings, signals)
	if len(candidates) == 0 {
		t.Fatal("expected at least 1 FN candidate for high EPSS + LOW severity, got 0")
	}

	found := false
	for _, c := range candidates {
		if c.EdgeCase == "EC-EPSS" {
			found = true
			if c.Type != "false_negative" {
				t.Errorf("expected type false_negative, got %s", c.Type)
			}
			if c.SeverityReported != "LOW" {
				t.Errorf("expected severity_reported LOW, got %s", c.SeverityReported)
			}
			if c.SeverityActual != "CRITICAL" {
				t.Errorf("expected severity_actual CRITICAL (KEV=true), got %s", c.SeverityActual)
			}
			if c.Confidence < 0.75 || c.Confidence > 0.95 {
				t.Errorf("expected confidence in [0.75, 0.95], got %f", c.Confidence)
			}
			break
		}
	}
	if !found {
		t.Error("expected an EC-EPSS candidate, found none")
	}
}

func TestGenerateFPFNCandidates_EPSSLowNoCandidate(t *testing.T) {
	findings := []Finding{
		{
			ID:          "FIND-002",
			Severity:    "LOW",
			FindingType: "CVE-2024-12345",
			Title:       "Minor vulnerability",
			Context:     FindingContext{EnvType: "prod"},
		},
	}
	signals := map[string]*ThreatIntelSignals{
		"FIND-002": {EPSSScore: 0.3, EPSSPercentile: 0.5},
	}

	candidates := GenerateFPFNCandidates(findings, signals)
	for _, c := range candidates {
		if c.EdgeCase == "EC-EPSS" {
			t.Error("should not generate EPSS candidate when score is below 0.8")
		}
	}
}

func TestGenerateFPFNCandidates_EPSSHighAlreadyHigh(t *testing.T) {
	findings := []Finding{
		{
			ID:          "FIND-003",
			Severity:    "HIGH",
			FindingType: "CVE-2024-38063",
			Title:       "Windows TCP/IP RCE",
			Context:     FindingContext{EnvType: "prod"},
		},
	}
	signals := map[string]*ThreatIntelSignals{
		"FIND-003": {EPSSScore: 0.89, EPSSPercentile: 0.97},
	}

	candidates := GenerateFPFNCandidates(findings, signals)
	for _, c := range candidates {
		if c.EdgeCase == "EC-EPSS" {
			t.Error("should not generate EPSS candidate when severity is already HIGH")
		}
	}
}

func TestGenerateFPFNCandidates_GreyNoiseBenignHigh(t *testing.T) {
	findings := []Finding{
		{
			ID:           "FIND-004",
			Severity:     "HIGH",
			FindingType:  "OPEN_SECURITY_GROUP",
			Title:        "Open security group",
			ResourceType: "aws_security_group",
			Context: FindingContext{
				EnvType:          "prod",
				ComplianceScopes: []string{"SOC2"},
			},
		},
	}
	signals := map[string]*ThreatIntelSignals{
		"FIND-004": {GreyNoiseClass: "benign"},
	}

	candidates := GenerateFPFNCandidates(findings, signals)
	found := false
	for _, c := range candidates {
		if c.EdgeCase == "EC-GREYNOISE" {
			found = true
			if c.Type != "false_positive" {
				t.Errorf("expected type false_positive, got %s", c.Type)
			}
			if c.SeverityActual != "MEDIUM" {
				t.Errorf("expected severity_actual MEDIUM (one level down from HIGH), got %s", c.SeverityActual)
			}
			if c.Confidence != 0.80 {
				t.Errorf("expected confidence 0.80, got %f", c.Confidence)
			}
			break
		}
	}
	if !found {
		t.Error("expected an EC-GREYNOISE candidate, found none")
	}
}

func TestGenerateFPFNCandidates_GreyNoiseMaliciousNoCandidate(t *testing.T) {
	findings := []Finding{
		{
			ID:          "FIND-005",
			Severity:    "HIGH",
			FindingType: "OPEN_SECURITY_GROUP",
			Title:       "Open security group",
			Context:     FindingContext{EnvType: "prod"},
		},
	}
	signals := map[string]*ThreatIntelSignals{
		"FIND-005": {GreyNoiseClass: "malicious"},
	}

	candidates := GenerateFPFNCandidates(findings, signals)
	for _, c := range candidates {
		if c.EdgeCase == "EC-GREYNOISE" {
			t.Error("should not generate GreyNoise candidate when classification is malicious")
		}
	}
}

func TestGenerateFPFNCandidates_HIBPHighBreachCount(t *testing.T) {
	findings := []Finding{
		{
			ID:           "FIND-006",
			Severity:     "MEDIUM",
			FindingType:  "STALE_ACCESS_KEY",
			Title:        "Stale admin access key",
			ResourceType: "aws_iam_user",
			Context: FindingContext{
				EnvType:          "prod",
				ComplianceScopes: []string{"PCI-DSS"},
			},
		},
	}
	signals := map[string]*ThreatIntelSignals{
		"FIND-006": {HIBPBreachCount: 7},
	}

	candidates := GenerateFPFNCandidates(findings, signals)
	found := false
	for _, c := range candidates {
		if c.EdgeCase == "EC-HIBP" {
			found = true
			if c.Type != "false_negative" {
				t.Errorf("expected type false_negative, got %s", c.Type)
			}
			if c.SeverityActual != "CRITICAL" {
				t.Errorf("expected severity_actual CRITICAL, got %s", c.SeverityActual)
			}
			if c.Confidence < 0.80 {
				t.Errorf("expected confidence >= 0.80, got %f", c.Confidence)
			}
			break
		}
	}
	if !found {
		t.Error("expected an EC-HIBP candidate, found none")
	}
}

func TestGenerateFPFNCandidates_HIBPLowBreachCount(t *testing.T) {
	findings := []Finding{
		{
			ID:          "FIND-007",
			Severity:    "MEDIUM",
			FindingType: "STALE_ACCESS_KEY",
			Title:       "Stale access key",
			Context:     FindingContext{EnvType: "prod"},
		},
	}
	signals := map[string]*ThreatIntelSignals{
		"FIND-007": {HIBPBreachCount: 2},
	}

	candidates := GenerateFPFNCandidates(findings, signals)
	for _, c := range candidates {
		if c.EdgeCase == "EC-HIBP" {
			t.Error("should not generate HIBP candidate when breach count is below 3")
		}
	}
}

func TestGenerateFPFNCandidates_HIBPAlreadyHigh(t *testing.T) {
	findings := []Finding{
		{
			ID:          "FIND-008",
			Severity:    "HIGH",
			FindingType: "STALE_ACCESS_KEY",
			Title:       "Stale admin key",
			Context:     FindingContext{EnvType: "prod"},
		},
	}
	signals := map[string]*ThreatIntelSignals{
		"FIND-008": {HIBPBreachCount: 5},
	}

	candidates := GenerateFPFNCandidates(findings, signals)
	for _, c := range candidates {
		if c.EdgeCase == "EC-HIBP" {
			t.Error("should not generate HIBP candidate when severity is already HIGH or above")
		}
	}
}

func TestGenerateFPFNCandidates_NoSignals(t *testing.T) {
	findings := []Finding{
		{
			ID:       "FIND-009",
			Severity: "LOW",
			Title:    "Some finding",
		},
	}
	signals := map[string]*ThreatIntelSignals{}

	candidates := GenerateFPFNCandidates(findings, signals)
	if len(candidates) != 0 {
		t.Errorf("expected 0 candidates with no signals, got %d", len(candidates))
	}
}

func TestGenerateFPFNCandidates_MultipleCandidatesPerFinding(t *testing.T) {
	// A finding that triggers both EPSS and HIBP candidates.
	findings := []Finding{
		{
			ID:           "FIND-010",
			Severity:     "MEDIUM",
			FindingType:  "CVE-2024-21338",
			Title:        "Windows kernel elevation",
			ResourceType: "aws_ec2_instance",
			Context: FindingContext{
				EnvType: "prod",
			},
		},
	}
	signals := map[string]*ThreatIntelSignals{
		"FIND-010": {
			EPSSScore:       0.92,
			EPSSPercentile:  0.98,
			InKEV:           true,
			HIBPBreachCount: 5,
		},
	}

	candidates := GenerateFPFNCandidates(findings, signals)
	epssFound := false
	hibpFound := false
	for _, c := range candidates {
		if c.EdgeCase == "EC-EPSS" {
			epssFound = true
		}
		if c.EdgeCase == "EC-HIBP" {
			hibpFound = true
		}
	}
	if !epssFound {
		t.Error("expected EPSS candidate for MEDIUM severity + high EPSS")
	}
	if !hibpFound {
		t.Error("expected HIBP candidate for MEDIUM severity + 5 breaches")
	}
}

func TestInferCSP(t *testing.T) {
	cases := []struct {
		resourceType string
		expected     string
	}{
		{"aws_ec2_instance", "aws"},
		{"AWS::S3::Bucket", "aws"},
		{"azurerm_virtual_machine", "azure"},
		{"google_compute_instance", "gcp"},
		{"unknown_resource", "unknown"},
	}

	for _, tc := range cases {
		got := inferCSP(tc.resourceType)
		if got != tc.expected {
			t.Errorf("inferCSP(%q) = %q, want %q", tc.resourceType, got, tc.expected)
		}
	}
}

func TestGenerateFPFNCandidates_ConfidenceScalesWithBreachCount(t *testing.T) {
	makeFinding := func(id string) Finding {
		return Finding{
			ID:          id,
			Severity:    "LOW",
			FindingType: "STALE_ACCESS_KEY",
			Title:       "Stale key",
			Context:     FindingContext{EnvType: "prod"},
		}
	}

	cases := []struct {
		breachCount int
		minConf     float64
	}{
		{3, 0.80},
		{5, 0.88},
		{8, 0.92},
	}

	for _, tc := range cases {
		f := makeFinding("FIND-CONF")
		sigs := map[string]*ThreatIntelSignals{
			"FIND-CONF": {HIBPBreachCount: tc.breachCount},
		}
		candidates := GenerateFPFNCandidates([]Finding{f}, sigs)
		for _, c := range candidates {
			if c.EdgeCase == "EC-HIBP" {
				if c.Confidence < tc.minConf {
					t.Errorf("breach count %d: expected confidence >= %.2f, got %.2f",
						tc.breachCount, tc.minConf, c.Confidence)
				}
			}
		}
	}
}
