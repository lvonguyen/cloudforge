package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// CatalogModule represents a Terraform golden module in the service catalogue.
type CatalogModule struct {
	ID               string   `json:"id"`
	Name             string   `json:"name"`
	Description      string   `json:"description"`
	Provider         string   `json:"provider"`
	ResourceType     string   `json:"resource_type"`
	Version          string   `json:"version"`
	CostEstimate     string   `json:"cost_estimate"`
	Tags             []string `json:"tags"`
	Icon             string   `json:"icon"`
	Category         string   `json:"category"`
	ComplianceTags   []string `json:"compliance_tags"`
	AutoApproved     bool     `json:"auto_approved"`
	ProvisioningTime string   `json:"provisioning_time"`
}

// MockData holds all loaded mock data for the API.
type MockData struct {
	Findings       []Finding
	Agents         []Agent
	Traces         []AgentTrace
	Frameworks     []ComplianceFramework
	Costs          *CostSummary
	Remediations   []RemediationRecord
	AuditEvents    []AuditEvent
	Users          []UserRow
	Policies       []Policy
	CatalogModules []CatalogModule
}

// loadMockData loads all mock JSON files from the frontend mock directory.
// basePath should be the project root (where frontend/ lives).
func loadMockData(basePath string) (*MockData, error) {
	mockDir := filepath.Join(basePath, "frontend", "src", "lib", "mock")
	publicMockDir := filepath.Join(basePath, "frontend", "public", "mock")

	data := &MockData{}

	if err := loadJSON(filepath.Join(publicMockDir, "findings.json"), &data.Findings); err != nil {
		return nil, fmt.Errorf("loading findings: %w", err)
	}
	if err := loadJSON(filepath.Join(mockDir, "agents.json"), &data.Agents); err != nil {
		return nil, fmt.Errorf("loading agents: %w", err)
	}
	if err := loadJSON(filepath.Join(mockDir, "traces.json"), &data.Traces); err != nil {
		return nil, fmt.Errorf("loading traces: %w", err)
	}
	if err := loadJSON(filepath.Join(mockDir, "frameworks.json"), &data.Frameworks); err != nil {
		return nil, fmt.Errorf("loading frameworks: %w", err)
	}
	if err := loadJSON(filepath.Join(mockDir, "costs.json"), &data.Costs); err != nil {
		return nil, fmt.Errorf("loading costs: %w", err)
	}
	if err := loadJSON(filepath.Join(mockDir, "remediations.json"), &data.Remediations); err != nil {
		return nil, fmt.Errorf("loading remediations: %w", err)
	}
	if err := loadJSON(filepath.Join(mockDir, "audit-log.json"), &data.AuditEvents); err != nil {
		return nil, fmt.Errorf("loading audit log: %w", err)
	}
	if err := loadJSON(filepath.Join(mockDir, "users.json"), &data.Users); err != nil {
		return nil, fmt.Errorf("loading users: %w", err)
	}
	if err := loadJSON(filepath.Join(mockDir, "policies.json"), &data.Policies); err != nil {
		return nil, fmt.Errorf("loading policies: %w", err)
	}
	if err := loadJSON(filepath.Join(mockDir, "catalog.json"), &data.CatalogModules); err != nil {
		return nil, fmt.Errorf("loading catalog: %w", err)
	}

	// Compute tamper-evident integrity hashes for all findings.
	for i := range data.Findings {
		data.Findings[i].IntegrityHash = data.Findings[i].ComputeIntegrityHash()
	}

	return data, nil
}

// DataStore wraps MockData with O(1) lookup maps for hot-path handlers.
// Extracted from Server to decouple data access from HTTP wiring.
type DataStore struct {
	*MockData
	FindingsByID     map[string]*Finding
	AgentsByID       map[string]*Agent
	TracesByAgentID  map[string][]AgentTrace
	RemediationsByID map[string]*RemediationRecord
}

// NewDataStore builds a DataStore from loaded mock data, constructing all
// O(1) lookup maps and computing integrity hashes.
func NewDataStore(md *MockData) *DataStore {
	ds := &DataStore{MockData: md}

	ds.FindingsByID = make(map[string]*Finding, len(md.Findings))
	for i := range md.Findings {
		ds.FindingsByID[md.Findings[i].ID] = &md.Findings[i]
	}
	ds.AgentsByID = make(map[string]*Agent, len(md.Agents))
	for i := range md.Agents {
		ds.AgentsByID[md.Agents[i].ID] = &md.Agents[i]
	}
	ds.RemediationsByID = make(map[string]*RemediationRecord, len(md.Remediations))
	for i := range md.Remediations {
		ds.RemediationsByID[md.Remediations[i].ID] = &md.Remediations[i]
	}
	ds.TracesByAgentID = make(map[string][]AgentTrace, len(md.Agents))
	for _, tr := range md.Traces {
		ds.TracesByAgentID[tr.AgentID] = append(ds.TracesByAgentID[tr.AgentID], tr)
	}

	return ds
}

// loadJSON reads a JSON file from disk and unmarshals it into dst.
func loadJSON(path string, dst interface{}) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading %s: %w", path, err)
	}
	if err := json.Unmarshal(raw, dst); err != nil {
		return fmt.Errorf("parsing %s: %w", path, err)
	}
	return nil
}

// mockDataDir finds the project root by walking up from the current working
// directory looking for go.mod. Falls back to "." if not found.
func mockDataDir() string {
	dir, err := os.Getwd()
	if err != nil {
		return "."
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "."
		}
		dir = parent
	}
}
