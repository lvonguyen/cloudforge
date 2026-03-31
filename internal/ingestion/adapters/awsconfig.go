package adapters

import (
	"context"
	"encoding/json"
	"strings"
)

// AWSConfigAdapter parses AWS Config evaluation results.
type AWSConfigAdapter struct{}

func NewAWSConfigAdapter() ScannerAdapter { return &AWSConfigAdapter{} }

func (a *AWSConfigAdapter) Name() string { return "aws-config" }

type awsConfigEvaluation struct {
	ComplianceType     string `json:"ComplianceType"`
	ConfigRuleName     string `json:"ConfigRuleName"`
	ResourceType       string `json:"ResourceType"`
	ResourceID         string `json:"ResourceId"`
	AccountID          string `json:"AccountId"`
	AwsRegion          string `json:"AwsRegion"`
	Annotation         string `json:"Annotation"`
	OrderingTimestamp  string `json:"OrderingTimestamp"`
	ResultRecordedTime string `json:"ResultRecordedTime"`
}

func (a *AWSConfigAdapter) Parse(_ context.Context, data []byte) ([]NormalizedFinding, error) {
	var evals []awsConfigEvaluation
	if err := json.Unmarshal(data, &evals); err != nil {
		return nil, &ParseError{Adapter: "aws-config", Message: "invalid JSON: " + err.Error()}
	}

	var findings []NormalizedFinding
	for _, ev := range evals {
		if !strings.EqualFold(ev.ComplianceType, "NON_COMPLIANT") {
			continue
		}

		foundAt, timestampData := parseFindingTimestamp(
			timestampCandidate{name: "result_recorded_time", value: ev.ResultRecordedTime},
			timestampCandidate{name: "ordering_timestamp", value: ev.OrderingTimestamp},
		)

		severity := ruleNameToSeverity(ev.ConfigRuleName)

		findings = append(findings, NormalizedFinding{
			Title:         ev.ConfigRuleName + ": non-compliant",
			Description:   ev.Annotation,
			Severity:      severity,
			ResourceID:    ev.ResourceID,
			ResourceType:  ev.ResourceType,
			CloudProvider: "aws",
			Region:        ev.AwsRegion,
			AccountID:     ev.AccountID,
			Scanner:       "aws-config",
			SourceCheckID: ev.ConfigRuleName,
			FoundAt:       foundAt,
			RawData:       timestampData,
		})
	}
	return findings, nil
}

// ruleNameToSeverity maps well-known Config rule prefixes to severity.
// Unknown rules default to MEDIUM.
func ruleNameToSeverity(ruleName string) string {
	lower := strings.ToLower(ruleName)
	switch {
	case strings.Contains(lower, "root-account") || strings.Contains(lower, "mfa"):
		return "CRITICAL"
	case strings.Contains(lower, "encrypted") || strings.Contains(lower, "public"):
		return "HIGH"
	case strings.Contains(lower, "logging") || strings.Contains(lower, "monitoring"):
		return "MEDIUM"
	default:
		return "MEDIUM"
	}
}

// normalizeSeverity normalises vendor severity strings to CF's canonical set.
// Shared by all adapters in this package.
func normalizeSeverity(s string) string {
	switch strings.ToUpper(s) {
	case "CRITICAL", "CRIT":
		return "CRITICAL"
	case "HIGH":
		return "HIGH"
	case "MEDIUM", "MED", "MODERATE":
		return "MEDIUM"
	case "LOW":
		return "LOW"
	case "INFO", "INFORMATIONAL":
		return "" // skip informational
	default:
		return ""
	}
}
