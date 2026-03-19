package adapters

import (
	"context"
	"encoding/json"
	"time"
)

// TrivyAdapter parses Trivy JSON output (not SARIF).
type TrivyAdapter struct{}

func NewTrivyAdapter() ScannerAdapter { return &TrivyAdapter{} }

func (a *TrivyAdapter) Name() string { return "trivy" }

// trivyReport is the top-level Trivy JSON schema.
type trivyReport struct {
	Results []trivyResult `json:"Results"`
}

type trivyResult struct {
	Target          string           `json:"Target"`
	Class           string           `json:"Class"`
	Type            string           `json:"Type"`
	Vulnerabilities []trivyVuln      `json:"Vulnerabilities"`
	Misconfigs      []trivyMisconfig `json:"Misconfigurations"`
}

type trivyVuln struct {
	VulnerabilityID  string `json:"VulnerabilityID"`
	PkgName          string `json:"PkgName"`
	InstalledVersion string `json:"InstalledVersion"`
	Severity         string `json:"Severity"`
	Title            string `json:"Title"`
	Description      string `json:"Description"`
}

type trivyMisconfig struct {
	ID          string `json:"ID"`
	Title       string `json:"Title"`
	Description string `json:"Description"`
	Severity    string `json:"Severity"`
	Resolution  string `json:"Resolution"`
}

func (a *TrivyAdapter) Parse(_ context.Context, data []byte) ([]NormalizedFinding, error) {
	var report trivyReport
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, &ParseError{Adapter: "trivy", Message: "invalid JSON: " + err.Error()}
	}

	now := time.Now().UTC()
	var findings []NormalizedFinding

	for _, result := range report.Results {
		// Vulnerabilities
		for _, v := range result.Vulnerabilities {
			sev := normalizeSeverity(v.Severity)
			if sev == "" {
				continue
			}
			resourceID := result.Target + "/" + v.PkgName + "@" + v.InstalledVersion

			findings = append(findings, NormalizedFinding{
				Title:         v.VulnerabilityID + ": " + v.Title,
				Description:   v.Description,
				Severity:      sev,
				ResourceID:    resourceID,
				ResourceType:  result.Type,
				CloudProvider: "container",
				Scanner:       "trivy",
				SourceCheckID: v.VulnerabilityID,
				FoundAt:       now,
				RawData: map[string]string{
					"target":  result.Target,
					"package": v.PkgName,
					"version": v.InstalledVersion,
				},
			})
		}

		// Misconfigurations
		for _, mc := range result.Misconfigs {
			sev := normalizeSeverity(mc.Severity)
			if sev == "" {
				continue
			}

			findings = append(findings, NormalizedFinding{
				Title:         mc.ID + ": " + mc.Title,
				Description:   mc.Description,
				Severity:      sev,
				ResourceID:    result.Target,
				ResourceType:  "iac",
				CloudProvider: "container",
				Scanner:       "trivy",
				SourceCheckID: mc.ID,
				FoundAt:       now,
				RawData: map[string]string{
					"target":     result.Target,
					"resolution": mc.Resolution,
				},
			})
		}
	}
	return findings, nil
}
