// Package compliance provides compliance framework mapping and assessment
package compliance

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"go.uber.org/zap"
)

// Framework represents a compliance framework
type Framework struct {
	ID          string            `json:"id" yaml:"id"`
	Name        string            `json:"name" yaml:"name"`
	Version     string            `json:"version" yaml:"version"`
	Description string            `json:"description" yaml:"description"`
	Sector      Sector            `json:"sector" yaml:"sector"`
	URL         string            `json:"url" yaml:"url"`
	Controls    map[string]*Control `json:"controls" yaml:"controls"`
}

// Sector represents an industry sector
type Sector string

const (
	SectorGeneral    Sector = "general"
	SectorHealthcare Sector = "healthcare"
	SectorFinance    Sector = "finance"
	SectorGovernment Sector = "government"
	SectorAI         Sector = "ai"
	SectorRetail     Sector = "retail"
	SectorTech       Sector = "technology"
)

// Control represents a compliance control
type Control struct {
	ID          string   `json:"id" yaml:"id"`
	Title       string   `json:"title" yaml:"title"`
	Description string   `json:"description" yaml:"description"`
	Section     string   `json:"section" yaml:"section"`
	Subsection  string   `json:"subsection" yaml:"subsection"`
	Category    string   `json:"category" yaml:"category"`
	Severity    string   `json:"severity" yaml:"severity"`
	URL         string   `json:"url" yaml:"url"`
	Mappings    []string `json:"mappings" yaml:"mappings"` // Cross-framework mappings
	Keywords    []string `json:"keywords" yaml:"keywords"` // For matching
}

// Finding represents a security finding with compliance mappings
type Finding struct {
	ID                string                `json:"id"`
	Source            string                `json:"source"`
	Type              string                `json:"type"` // misconfiguration, vulnerability, toxic_combo
	Title             string                `json:"title"`
	Description       string                `json:"description"`
	Severity          string                `json:"severity"`
	Resource          string                `json:"resource"`
	ResourceType      string                `json:"resource_type"`
	CloudProvider     string                `json:"cloud_provider"`
	Region            string                `json:"region"`
	CVEs              []CVEReference        `json:"cves"`
	CWEs              []string              `json:"cwes"`
	ComplianceMappings []ComplianceMapping  `json:"compliance_mappings"`
	Remediation       string                `json:"remediation"`
	ToxicComboDetails *ToxicComboDetails    `json:"toxic_combo_details,omitempty"`
	DeduplicationKey  string                `json:"deduplication_key"`
	CanonicalRuleID   string                `json:"canonical_rule_id"`
	RelatedRules      []string              `json:"related_rules"`
	Timestamp         time.Time             `json:"timestamp"`
	RawData           map[string]interface{} `json:"raw_data,omitempty"`
}

// CVEReference represents a CVE with hyperlink
type CVEReference struct {
	ID          string  `json:"id"`
	URL         string  `json:"url"`
	Description string  `json:"description"`
	CVSS        float64 `json:"cvss"`
	CVSSVector  string  `json:"cvss_vector"`
	Published   string  `json:"published"`
	Modified    string  `json:"modified"`
}

// ComplianceMapping maps a finding to a compliance control
type ComplianceMapping struct {
	FrameworkID   string `json:"framework_id"`
	FrameworkName string `json:"framework_name"`
	ControlID     string `json:"control_id"`
	ControlTitle  string `json:"control_title"`
	Section       string `json:"section"`
	Severity      string `json:"severity"`
	URL           string `json:"url"`
}

// ToxicComboDetails describes a toxic combination of findings
type ToxicComboDetails struct {
	ComboType        string   `json:"combo_type"`
	Description      string   `json:"description"`
	RelatedFindings  []string `json:"related_findings"`
	AttackVector     string   `json:"attack_vector"`
	ExploitPotential string   `json:"exploit_potential"`
	MITRETechniques  []string `json:"mitre_techniques"`
}

// Manager manages compliance frameworks and mapping
type Manager struct {
	frameworks     map[string]*Framework
	sectorProfiles map[Sector]*SectorProfile
	deduplicator   *Deduplicator
	logger         *zap.Logger
}

// SectorProfile defines sector-specific compliance requirements
type SectorProfile struct {
	Sector           Sector   `json:"sector"`
	Name             string   `json:"name"`
	Description      string   `json:"description"`
	RequiredFrameworks []string `json:"required_frameworks"`
	OptionalFrameworks []string `json:"optional_frameworks"`
	CustomControls    []*Control `json:"custom_controls"`
}

// NewManager creates a new compliance manager
func NewManager(logger *zap.Logger) *Manager {
	m := &Manager{
		frameworks:     make(map[string]*Framework),
		sectorProfiles: make(map[Sector]*SectorProfile),
		deduplicator:   NewDeduplicator(),
		logger:         logger,
	}

	// Load built-in frameworks
	m.loadBuiltInFrameworks()
	m.loadSectorProfiles()

	return m
}

// loadBuiltInFrameworks loads all built-in compliance frameworks
func (m *Manager) loadBuiltInFrameworks() {
	// CIS Benchmarks
	m.RegisterFramework(m.buildCISFramework())

	// NIST Frameworks
	m.RegisterFramework(m.buildNIST80053Framework())
	m.RegisterFramework(m.buildNISTCSFFramework())
	m.RegisterFramework(m.buildNISTAIRMFFramework())

	// ISO Frameworks
	m.RegisterFramework(m.buildISO27001Framework())
	m.RegisterFramework(m.buildISO27017Framework())
	m.RegisterFramework(m.buildISO42001Framework())

	// PCI-DSS
	m.RegisterFramework(m.buildPCIDSSFramework())

	// Cloud Provider Specific
	m.RegisterFramework(m.buildAWSSecurityBestPracticesFramework())
	m.RegisterFramework(m.buildGCPCISFramework())
	m.RegisterFramework(m.buildAzureMCSBFramework())

	// Healthcare
	m.RegisterFramework(m.buildHIPAAFramework())
	m.RegisterFramework(m.buildHITRUSTFramework())

	// Finance
	m.RegisterFramework(m.buildSOXFramework())
	m.RegisterFramework(m.buildGLBAFramework())
	m.RegisterFramework(m.buildFFIECFramework())

	// Government (Core)
	m.RegisterFramework(m.buildFedRAMPFramework())
	m.RegisterFramework(m.buildSTIGFramework())

	// Government (Extended)
	m.loadExtendedGovernmentFrameworks()

	// Automotive
	m.loadAutomotiveFrameworks()

	m.logger.Info("Loaded compliance frameworks",
		zap.Int("count", len(m.frameworks)),
	)
}

// RegisterFramework registers a compliance framework
func (m *Manager) RegisterFramework(fw *Framework) {
	m.frameworks[fw.ID] = fw
}

// GetFramework returns a framework by ID
func (m *Manager) GetFramework(id string) (*Framework, bool) {
	fw, ok := m.frameworks[id]
	return fw, ok
}

// GetFrameworksForSector returns frameworks applicable to a sector
func (m *Manager) GetFrameworksForSector(sector Sector) []*Framework {
	profile, ok := m.sectorProfiles[sector]
	if !ok {
		profile = m.sectorProfiles[SectorGeneral]
	}

	var frameworks []*Framework
	for _, fwID := range profile.RequiredFrameworks {
		if fw, ok := m.frameworks[fwID]; ok {
			frameworks = append(frameworks, fw)
		}
	}
	for _, fwID := range profile.OptionalFrameworks {
		if fw, ok := m.frameworks[fwID]; ok {
			frameworks = append(frameworks, fw)
		}
	}

	return frameworks
}

// MapFinding maps a finding to compliance controls
func (m *Manager) MapFinding(ctx context.Context, finding *Finding, sector Sector) (*Finding, error) {
	frameworks := m.GetFrameworksForSector(sector)

	for _, fw := range frameworks {
		mappings := m.findMatchingControls(finding, fw)
		finding.ComplianceMappings = append(finding.ComplianceMappings, mappings...)
	}

	// Enrich CVE references with URLs
	for i := range finding.CVEs {
		if finding.CVEs[i].URL == "" {
			finding.CVEs[i].URL = m.buildCVEURL(finding.CVEs[i].ID)
		}
	}

	return finding, nil
}

// findMatchingControls finds controls that match a finding
func (m *Manager) findMatchingControls(finding *Finding, fw *Framework) []ComplianceMapping {
	var mappings []ComplianceMapping

	findingText := strings.ToLower(finding.Title + " " + finding.Description + " " + finding.ResourceType)

	for _, control := range fw.Controls {
		if m.controlMatchesFinding(control, finding, findingText) {
			mappings = append(mappings, ComplianceMapping{
				FrameworkID:   fw.ID,
				FrameworkName: fw.Name,
				ControlID:     control.ID,
				ControlTitle:  control.Title,
				Section:       control.Section,
				Severity:      control.Severity,
				URL:           control.URL,
			})
		}
	}

	return mappings
}

// controlMatchesFinding checks if a control matches a finding
func (m *Manager) controlMatchesFinding(control *Control, finding *Finding, findingText string) bool {
	// Check keywords
	for _, keyword := range control.Keywords {
		if strings.Contains(findingText, strings.ToLower(keyword)) {
			return true
		}
	}

	// Check CWE mappings
	for _, cwe := range finding.CWEs {
		for _, mapping := range control.Mappings {
			if strings.Contains(mapping, cwe) {
				return true
			}
		}
	}

	return false
}

// buildCVEURL builds a hyperlinked CVE URL
func (m *Manager) buildCVEURL(cveID string) string {
	// NVD URL
	return fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", cveID)
}

// DeduplicateFinding deduplicates a finding against existing findings
func (m *Manager) DeduplicateFinding(finding *Finding, existingFindings []*Finding) (*Finding, bool) {
	return m.deduplicator.Deduplicate(finding, existingFindings)
}

// loadSectorProfiles loads sector-specific compliance profiles
func (m *Manager) loadSectorProfiles() {
	// Load automotive sector profile
	m.loadAutomotiveSectorProfile()
	// General/Technology
	m.sectorProfiles[SectorGeneral] = &SectorProfile{
		Sector:      SectorGeneral,
		Name:        "General/Technology",
		Description: "Baseline security frameworks for all organizations",
		RequiredFrameworks: []string{
			"cis-benchmarks", "nist-csf", "iso-27001",
		},
		OptionalFrameworks: []string{
			"aws-security-bp", "gcp-cis", "azure-mcsb",
		},
	}

	m.sectorProfiles[SectorTech] = m.sectorProfiles[SectorGeneral]

	// Healthcare
	m.sectorProfiles[SectorHealthcare] = &SectorProfile{
		Sector:      SectorHealthcare,
		Name:        "Healthcare",
		Description: "HIPAA and healthcare-specific compliance",
		RequiredFrameworks: []string{
			"hipaa", "hitrust", "nist-csf", "cis-benchmarks",
		},
		OptionalFrameworks: []string{
			"iso-27001", "aws-security-bp", "gcp-cis", "azure-mcsb",
		},
	}

	// Finance
	m.sectorProfiles[SectorFinance] = &SectorProfile{
		Sector:      SectorFinance,
		Name:        "Financial Services",
		Description: "PCI-DSS, SOX, and financial regulatory compliance",
		RequiredFrameworks: []string{
			"pci-dss", "sox", "glba", "ffiec", "nist-csf", "cis-benchmarks",
		},
		OptionalFrameworks: []string{
			"iso-27001", "aws-security-bp", "gcp-cis", "azure-mcsb",
		},
	}

	// Government
	m.sectorProfiles[SectorGovernment] = &SectorProfile{
		Sector:      SectorGovernment,
		Name:        "Government",
		Description: "FedRAMP, NIST 800-53, and government compliance",
		RequiredFrameworks: []string{
			"fedramp", "nist-800-53", "stig", "cis-benchmarks",
		},
		OptionalFrameworks: []string{
			"iso-27001", "aws-security-bp", "gcp-cis", "azure-mcsb",
		},
	}

	// AI/ML
	m.sectorProfiles[SectorAI] = &SectorProfile{
		Sector:      SectorAI,
		Name:        "AI/ML",
		Description: "AI-specific governance and security frameworks",
		RequiredFrameworks: []string{
			"nist-ai-rmf", "iso-42001", "nist-csf", "cis-benchmarks",
		},
		OptionalFrameworks: []string{
			"iso-27001", "aws-security-bp", "gcp-cis", "azure-mcsb",
		},
	}

	// Retail
	m.sectorProfiles[SectorRetail] = &SectorProfile{
		Sector:      SectorRetail,
		Name:        "Retail",
		Description: "PCI-DSS and retail security compliance",
		RequiredFrameworks: []string{
			"pci-dss", "nist-csf", "cis-benchmarks",
		},
		OptionalFrameworks: []string{
			"iso-27001", "aws-security-bp", "gcp-cis", "azure-mcsb",
		},
	}
}

