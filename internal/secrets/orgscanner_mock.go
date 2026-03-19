package secrets

import (
	"context"
	"fmt"
)

// mockOrgScanner returns synthetic results for development and testing.
type mockOrgScanner struct{}

// NewMockOrgScanner creates an in-memory org scanner.
func NewMockOrgScanner() OrgScanner {
	return &mockOrgScanner{}
}

func (m *mockOrgScanner) ScanOrg(_ context.Context, cfg OrgConfig) (*OrgScanResult, error) {
	if cfg.OrgName == "" {
		return nil, fmt.Errorf("org_name is required")
	}

	repos := cfg.Repos
	if len(repos) == 0 {
		repos = []string{
			cfg.OrgName + "/frontend",
			cfg.OrgName + "/backend-api",
			cfg.OrgName + "/infra-terraform",
		}
	}

	var results []RepoResult
	total := 0

	for _, repo := range repos {
		findings := []SecretFinding{
			{
				PatternID:   "aws-access-key",
				PatternName: "AWS Access Key",
				Type:        "credential",
				Severity:    "critical",
				File:        ".env.example",
				Line:        12,
				Column:      1,
				Match:       "AKIA****REDACTED",
				Context:     "AWS_ACCESS_KEY_ID=AKIA****REDACTED",
			},
			{
				PatternID:   "generic-api-key",
				PatternName: "Generic API Key",
				Type:        "api_key",
				Severity:    "high",
				File:        "config/defaults.yaml",
				Line:        45,
				Column:      5,
				Match:       "api_key=****REDACTED",
				Context:     "api_key=****REDACTED # placeholder",
			},
		}
		total += len(findings)
		results = append(results, RepoResult{Repo: repo, Findings: findings})
	}

	return &OrgScanResult{
		OrgName:      cfg.OrgName,
		ReposScanned: len(repos),
		TotalSecrets: total,
		Results:      results,
	}, nil
}
