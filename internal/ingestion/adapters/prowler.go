package adapters

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
)

// ProwlerAdapter parses Prowler v3/v4 JSON output.
type ProwlerAdapter struct{}

func NewProwlerAdapter() ScannerAdapter { return &ProwlerAdapter{} }

func (a *ProwlerAdapter) Name() string { return "prowler" }

// prowlerFinding is the JSON schema emitted by Prowler v3/v4.
type prowlerFinding struct {
	CheckID       string `json:"CheckID"`
	Status        string `json:"Status"`
	Severity      string `json:"Severity"`
	ServiceName   string `json:"ServiceName"`
	ResourceID    string `json:"ResourceId"`
	ResourceType  string `json:"ResourceType"`
	Region        string `json:"Region"`
	AccountID     string `json:"AccountId"`
	StatusExtInfo string `json:"StatusExtendedInfo"`
	Description   string `json:"Description"`
	Risk          string `json:"Risk"`
	Timestamp     string `json:"Timestamp"`
	Provider      string `json:"Provider"`
}

func (a *ProwlerAdapter) Parse(_ context.Context, data []byte) ([]NormalizedFinding, error) {
	var raw []prowlerFinding
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, &ParseError{Adapter: "prowler", Message: "invalid JSON: " + err.Error()}
	}

	var findings []NormalizedFinding
	for i, pf := range raw {
		if !strings.EqualFold(pf.Status, "FAIL") {
			continue
		}

		sev := normalizeSeverity(pf.Severity)
		if sev == "" {
			continue
		}

		foundAt, timestampData := parseFindingTimestamp(
			timestampCandidate{name: "timestamp", value: pf.Timestamp},
		)

		cloud := strings.ToLower(pf.Provider)
		if cloud == "" {
			cloud = "aws"
		}

		findings = append(findings, NormalizedFinding{
			Title:         pf.CheckID + ": " + pf.Description,
			Description:   pf.Risk,
			Severity:      sev,
			ResourceID:    pf.ResourceID,
			ResourceType:  pf.ResourceType,
			CloudProvider: cloud,
			Region:        pf.Region,
			AccountID:     pf.AccountID,
			Scanner:       "prowler",
			SourceCheckID: pf.CheckID,
			FoundAt:       foundAt,
			RawData: mergeRawData(map[string]string{
				"index":         strconv.Itoa(i),
				"service":       pf.ServiceName,
				"extended_info": pf.StatusExtInfo,
			}, timestampData),
		})
	}
	return findings, nil
}
