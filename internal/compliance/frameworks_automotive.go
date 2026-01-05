// Package compliance provides compliance framework mapping and assessment
package compliance

// Sector constants for new industries
const (
	SectorAutomotive Sector = "automotive"
)

// buildAutomotiveSPICEFramework builds Automotive SPICE framework
func (m *Manager) buildAutomotiveSPICEFramework() *Framework {
	return &Framework{
		ID:          "automotive-spice",
		Name:        "Automotive SPICE",
		Version:     "3.1",
		Description: "Automotive Software Process Improvement and Capability dEtermination",
		Sector:      SectorAutomotive,
		URL:         "https://www.automotivespice.com/",
		Controls: map[string]*Control{
			"SWE.1": {ID: "SWE.1", Title: "Software Requirements Analysis", Section: "SWE", Category: "Development", Severity: "high", Keywords: []string{"requirements", "software", "analysis"}},
			"SWE.2": {ID: "SWE.2", Title: "Software Architectural Design", Section: "SWE", Category: "Development", Severity: "high", Keywords: []string{"architecture", "design", "software"}},
			"SWE.3": {ID: "SWE.3", Title: "Software Detailed Design", Section: "SWE", Category: "Development", Severity: "medium", Keywords: []string{"detailed", "design", "implementation"}},
			"SWE.4": {ID: "SWE.4", Title: "Software Unit Verification", Section: "SWE", Category: "Testing", Severity: "high", Keywords: []string{"unit", "test", "verification"}},
			"SWE.5": {ID: "SWE.5", Title: "Software Integration and Testing", Section: "SWE", Category: "Testing", Severity: "high", Keywords: []string{"integration", "test", "verification"}},
			"SWE.6": {ID: "SWE.6", Title: "Software Qualification Test", Section: "SWE", Category: "Testing", Severity: "high", Keywords: []string{"qualification", "test", "validation"}},
			"SEC.1": {ID: "SEC.1", Title: "Cybersecurity Management", Section: "SEC", Category: "Security", Severity: "critical", Keywords: []string{"cybersecurity", "management", "governance"}},
			"SEC.2": {ID: "SEC.2", Title: "Threat Analysis and Risk Assessment", Section: "SEC", Category: "Security", Severity: "critical", Keywords: []string{"threat", "risk", "analysis", "tara"}},
			"SEC.3": {ID: "SEC.3", Title: "Cybersecurity Concept", Section: "SEC", Category: "Security", Severity: "high", Keywords: []string{"concept", "security", "architecture"}},
			"SEC.4": {ID: "SEC.4", Title: "Product Security Validation", Section: "SEC", Category: "Testing", Severity: "high", Keywords: []string{"validation", "security", "penetration"}},
		},
	}
}

// buildISO21434Framework builds ISO/SAE 21434 Automotive Cybersecurity framework
func (m *Manager) buildISO21434Framework() *Framework {
	return &Framework{
		ID:          "iso-21434",
		Name:        "ISO/SAE 21434",
		Version:     "2021",
		Description: "Road vehicles - Cybersecurity engineering",
		Sector:      SectorAutomotive,
		URL:         "https://www.iso.org/standard/70918.html",
		Controls: map[string]*Control{
			// Organizational cybersecurity management
			"5.4.1": {ID: "5.4.1", Title: "Cybersecurity Governance", Section: "5", Category: "Governance", Severity: "high", Keywords: []string{"governance", "policy", "management"}},
			"5.4.2": {ID: "5.4.2", Title: "Cybersecurity Culture", Section: "5", Category: "Governance", Severity: "medium", Keywords: []string{"culture", "awareness", "training"}},
			"5.4.3": {ID: "5.4.3", Title: "Information Sharing", Section: "5", Category: "Governance", Severity: "medium", Keywords: []string{"sharing", "information", "isac"}},
			"5.4.4": {ID: "5.4.4", Title: "Management Systems", Section: "5", Category: "Governance", Severity: "high", Keywords: []string{"management", "system", "isms"}},
			"5.4.5": {ID: "5.4.5", Title: "Tool Management", Section: "5", Category: "Governance", Severity: "medium", Keywords: []string{"tool", "management", "configuration"}},
			"5.4.6": {ID: "5.4.6", Title: "Information Security Management", Section: "5", Category: "Governance", Severity: "high", Keywords: []string{"information", "security", "isms"}},
			"5.4.7": {ID: "5.4.7", Title: "Organizational Cybersecurity Audit", Section: "5", Category: "Audit", Severity: "high", Keywords: []string{"audit", "assessment", "compliance"}},

			// Project-dependent cybersecurity management
			"6.4.1": {ID: "6.4.1", Title: "Cybersecurity Responsibilities", Section: "6", Category: "Project", Severity: "high", Keywords: []string{"responsibility", "role", "accountability"}},
			"6.4.2": {ID: "6.4.2", Title: "Cybersecurity Planning", Section: "6", Category: "Project", Severity: "high", Keywords: []string{"planning", "project", "lifecycle"}},
			"6.4.3": {ID: "6.4.3", Title: "Tailoring", Section: "6", Category: "Project", Severity: "medium", Keywords: []string{"tailoring", "customization", "adaptation"}},
			"6.4.4": {ID: "6.4.4", Title: "Reuse", Section: "6", Category: "Project", Severity: "medium", Keywords: []string{"reuse", "component", "legacy"}},
			"6.4.5": {ID: "6.4.5", Title: "Component Out of Context", Section: "6", Category: "Project", Severity: "medium", Keywords: []string{"component", "context", "integration"}},
			"6.4.6": {ID: "6.4.6", Title: "Off-the-shelf Component", Section: "6", Category: "Project", Severity: "high", Keywords: []string{"cots", "third-party", "component"}},
			"6.4.7": {ID: "6.4.7", Title: "Cybersecurity Case", Section: "6", Category: "Project", Severity: "high", Keywords: []string{"case", "argument", "evidence"}},
			"6.4.8": {ID: "6.4.8", Title: "Cybersecurity Assessment", Section: "6", Category: "Project", Severity: "high", Keywords: []string{"assessment", "evaluation", "review"}},
			"6.4.9": {ID: "6.4.9", Title: "Release for Post-development", Section: "6", Category: "Project", Severity: "high", Keywords: []string{"release", "production", "deployment"}},

			// Continuous cybersecurity activities
			"7.4.1": {ID: "7.4.1", Title: "Cybersecurity Monitoring", Section: "7", Category: "Continuous", Severity: "critical", Keywords: []string{"monitoring", "detection", "siem"}},
			"7.4.2": {ID: "7.4.2", Title: "Cybersecurity Event Evaluation", Section: "7", Category: "Continuous", Severity: "critical", Keywords: []string{"event", "evaluation", "triage"}},
			"7.4.3": {ID: "7.4.3", Title: "Vulnerability Analysis", Section: "7", Category: "Continuous", Severity: "critical", Keywords: []string{"vulnerability", "analysis", "cve"}},
			"7.4.4": {ID: "7.4.4", Title: "Vulnerability Management", Section: "7", Category: "Continuous", Severity: "critical", Keywords: []string{"vulnerability", "management", "remediation"}},

			// Risk assessment methods
			"8.3":   {ID: "8.3", Title: "Asset Identification", Section: "8", Category: "Risk", Severity: "high", Keywords: []string{"asset", "identification", "inventory"}},
			"8.4":   {ID: "8.4", Title: "Threat Scenario Identification", Section: "8", Category: "Risk", Severity: "critical", Keywords: []string{"threat", "scenario", "attack"}},
			"8.5":   {ID: "8.5", Title: "Impact Rating", Section: "8", Category: "Risk", Severity: "high", Keywords: []string{"impact", "rating", "severity"}},
			"8.6":   {ID: "8.6", Title: "Attack Path Analysis", Section: "8", Category: "Risk", Severity: "critical", Keywords: []string{"attack", "path", "vector"}},
			"8.7":   {ID: "8.7", Title: "Attack Feasibility Rating", Section: "8", Category: "Risk", Severity: "high", Keywords: []string{"feasibility", "rating", "likelihood"}},
			"8.8":   {ID: "8.8", Title: "Risk Value Determination", Section: "8", Category: "Risk", Severity: "critical", Keywords: []string{"risk", "value", "determination"}},
			"8.9":   {ID: "8.9", Title: "Risk Treatment Decision", Section: "8", Category: "Risk", Severity: "critical", Keywords: []string{"risk", "treatment", "mitigation"}},

			// Concept phase
			"9.3":   {ID: "9.3", Title: "Item Definition", Section: "9", Category: "Concept", Severity: "high", Keywords: []string{"item", "definition", "scope"}},
			"9.4":   {ID: "9.4", Title: "Cybersecurity Goals", Section: "9", Category: "Concept", Severity: "high", Keywords: []string{"goal", "objective", "requirement"}},
			"9.5":   {ID: "9.5", Title: "Cybersecurity Concept", Section: "9", Category: "Concept", Severity: "high", Keywords: []string{"concept", "architecture", "design"}},

			// Product development
			"10.4.1": {ID: "10.4.1", Title: "Cybersecurity Specifications", Section: "10", Category: "Development", Severity: "high", Keywords: []string{"specification", "requirement", "security"}},
			"10.4.2": {ID: "10.4.2", Title: "Integration and Verification", Section: "10", Category: "Development", Severity: "high", Keywords: []string{"integration", "verification", "testing"}},

			// Post-development
			"12.4": {ID: "12.4", Title: "Cybersecurity Incident Response", Section: "12", Category: "Operations", Severity: "critical", Keywords: []string{"incident", "response", "handling"}},
			"12.5": {ID: "12.5", Title: "Updates", Section: "12", Category: "Operations", Severity: "high", Keywords: []string{"update", "patch", "ota"}},
		},
	}
}

// buildUNECER155Framework builds UN ECE R155 Cyber Security framework
func (m *Manager) buildUNECER155Framework() *Framework {
	return &Framework{
		ID:          "unece-r155",
		Name:        "UN ECE R155",
		Version:     "2021",
		Description: "UN Regulation on Cyber Security and Cyber Security Management System",
		Sector:      SectorAutomotive,
		URL:         "https://unece.org/transport/documents/2021/03/standards/un-regulation-no-155",
		Controls: map[string]*Control{
			// CSMS Requirements
			"7.2.1": {ID: "7.2.1", Title: "Processes for Risk Identification", Section: "7.2", Category: "CSMS", Severity: "critical", Keywords: []string{"risk", "identification", "threat"}},
			"7.2.2": {ID: "7.2.2", Title: "Processes for Risk Assessment", Section: "7.2", Category: "CSMS", Severity: "critical", Keywords: []string{"risk", "assessment", "analysis"}},
			"7.2.3": {ID: "7.2.3", Title: "Processes for Risk Mitigation", Section: "7.2", Category: "CSMS", Severity: "critical", Keywords: []string{"risk", "mitigation", "control"}},
			"7.2.4": {ID: "7.2.4", Title: "Processes for Verification", Section: "7.2", Category: "CSMS", Severity: "high", Keywords: []string{"verification", "testing", "validation"}},
			"7.2.5": {ID: "7.2.5", Title: "Processes for Monitoring", Section: "7.2", Category: "CSMS", Severity: "critical", Keywords: []string{"monitoring", "detection", "logging"}},
			"7.2.6": {ID: "7.2.6", Title: "Processes for Incident Response", Section: "7.2", Category: "CSMS", Severity: "critical", Keywords: []string{"incident", "response", "handling"}},
			"7.2.7": {ID: "7.2.7", Title: "Processes for Data Forensics", Section: "7.2", Category: "CSMS", Severity: "high", Keywords: []string{"forensics", "analysis", "investigation"}},

			// Vehicle Type Approval
			"7.3.1": {ID: "7.3.1", Title: "Risk Assessment for Vehicle Type", Section: "7.3", Category: "Vehicle", Severity: "critical", Keywords: []string{"vehicle", "type", "risk"}},
			"7.3.2": {ID: "7.3.2", Title: "Mitigations Identification", Section: "7.3", Category: "Vehicle", Severity: "high", Keywords: []string{"mitigation", "control", "measure"}},
			"7.3.3": {ID: "7.3.3", Title: "Testing of Mitigations", Section: "7.3", Category: "Vehicle", Severity: "high", Keywords: []string{"testing", "validation", "verification"}},
			"7.3.4": {ID: "7.3.4", Title: "Aftermarket Software Management", Section: "7.3", Category: "Vehicle", Severity: "high", Keywords: []string{"aftermarket", "software", "update"}},

			// Threat Categories (Annex 5)
			"A5.1": {ID: "A5.1", Title: "Backend Server Threats", Section: "Annex 5", Category: "Threat", Severity: "critical", Keywords: []string{"backend", "server", "api"}},
			"A5.2": {ID: "A5.2", Title: "Communication Channel Threats", Section: "Annex 5", Category: "Threat", Severity: "critical", Keywords: []string{"communication", "channel", "network"}},
			"A5.3": {ID: "A5.3", Title: "Update Procedure Threats", Section: "Annex 5", Category: "Threat", Severity: "critical", Keywords: []string{"update", "ota", "firmware"}},
			"A5.4": {ID: "A5.4", Title: "Unintended Human Actions", Section: "Annex 5", Category: "Threat", Severity: "medium", Keywords: []string{"human", "error", "misconfiguration"}},
			"A5.5": {ID: "A5.5", Title: "External Connectivity Threats", Section: "Annex 5", Category: "Threat", Severity: "critical", Keywords: []string{"external", "connectivity", "interface"}},
			"A5.6": {ID: "A5.6", Title: "Data/Code Threats", Section: "Annex 5", Category: "Threat", Severity: "critical", Keywords: []string{"data", "code", "tampering"}},
			"A5.7": {ID: "A5.7", Title: "Potential Vulnerabilities", Section: "Annex 5", Category: "Threat", Severity: "high", Keywords: []string{"vulnerability", "weakness", "flaw"}},
		},
	}
}

// buildTISAXFramework builds TISAX (Trusted Information Security Assessment Exchange) framework
func (m *Manager) buildTISAXFramework() *Framework {
	return &Framework{
		ID:          "tisax",
		Name:        "TISAX",
		Version:     "6.0",
		Description: "Trusted Information Security Assessment Exchange for Automotive",
		Sector:      SectorAutomotive,
		URL:         "https://www.enx.com/tisax/",
		Controls: map[string]*Control{
			// Information Security
			"1.1": {ID: "1.1", Title: "IS Policies", Section: "1", Category: "Policy", Severity: "high", Keywords: []string{"policy", "security", "governance"}},
			"1.2": {ID: "1.2", Title: "Organization of IS", Section: "1", Category: "Organization", Severity: "high", Keywords: []string{"organization", "roles", "responsibilities"}},
			"1.3": {ID: "1.3", Title: "Human Resource Security", Section: "1", Category: "HR", Severity: "medium", Keywords: []string{"hr", "employee", "screening"}},
			"1.4": {ID: "1.4", Title: "Asset Management", Section: "1", Category: "Asset", Severity: "high", Keywords: []string{"asset", "inventory", "classification"}},
			"1.5": {ID: "1.5", Title: "Access Control", Section: "1", Category: "Access", Severity: "critical", Keywords: []string{"access", "control", "authentication"}},
			"1.6": {ID: "1.6", Title: "Cryptography", Section: "1", Category: "Crypto", Severity: "high", Keywords: []string{"encryption", "cryptography", "key"}},
			"2.1": {ID: "2.1", Title: "Physical Security", Section: "2", Category: "Physical", Severity: "high", Keywords: []string{"physical", "facility", "access"}},
			"3.1": {ID: "3.1", Title: "Operations Security", Section: "3", Category: "Operations", Severity: "high", Keywords: []string{"operations", "change", "capacity"}},
			"4.1": {ID: "4.1", Title: "Communications Security", Section: "4", Category: "Network", Severity: "high", Keywords: []string{"network", "communication", "segmentation"}},
			"5.1": {ID: "5.1", Title: "Supplier Relationships", Section: "5", Category: "Vendor", Severity: "high", Keywords: []string{"supplier", "vendor", "third-party"}},
			"6.1": {ID: "6.1", Title: "Incident Management", Section: "6", Category: "Incident", Severity: "critical", Keywords: []string{"incident", "response", "handling"}},
			"7.1": {ID: "7.1", Title: "Business Continuity", Section: "7", Category: "BCP", Severity: "high", Keywords: []string{"continuity", "disaster", "recovery"}},
			"8.1": {ID: "8.1", Title: "Compliance", Section: "8", Category: "Compliance", Severity: "high", Keywords: []string{"compliance", "audit", "regulatory"}},

			// Prototype Protection
			"PP.1": {ID: "PP.1", Title: "Prototype Classification", Section: "PP", Category: "Prototype", Severity: "high", Keywords: []string{"prototype", "classification", "confidential"}},
			"PP.2": {ID: "PP.2", Title: "Prototype Handling", Section: "PP", Category: "Prototype", Severity: "high", Keywords: []string{"prototype", "handling", "storage"}},
			"PP.3": {ID: "PP.3", Title: "Test Vehicle Protection", Section: "PP", Category: "Prototype", Severity: "high", Keywords: []string{"vehicle", "test", "protection"}},
			"PP.4": {ID: "PP.4", Title: "Prototype Photography", Section: "PP", Category: "Prototype", Severity: "medium", Keywords: []string{"photography", "documentation", "media"}},

			// Data Protection
			"DP.1": {ID: "DP.1", Title: "Personal Data Processing", Section: "DP", Category: "Privacy", Severity: "critical", Keywords: []string{"personal", "data", "gdpr"}},
			"DP.2": {ID: "DP.2", Title: "Data Subject Rights", Section: "DP", Category: "Privacy", Severity: "high", Keywords: []string{"subject", "rights", "access"}},
		},
	}
}

// buildNHTSACybersecurityFramework builds NHTSA Cybersecurity Best Practices
func (m *Manager) buildNHTSACybersecurityFramework() *Framework {
	return &Framework{
		ID:          "nhtsa-cyber",
		Name:        "NHTSA Cybersecurity Best Practices",
		Version:     "2022",
		Description: "NHTSA Cybersecurity Best Practices for the Safety of Modern Vehicles",
		Sector:      SectorAutomotive,
		URL:         "https://www.nhtsa.gov/technology-innovation/vehicle-cybersecurity",
		Controls: map[string]*Control{
			"1.1": {ID: "1.1", Title: "Layered Approach", Section: "1", Category: "Architecture", Severity: "high", Keywords: []string{"defense", "depth", "layered"}},
			"1.2": {ID: "1.2", Title: "Segment and Isolate", Section: "1", Category: "Architecture", Severity: "critical", Keywords: []string{"segment", "isolate", "network"}},
			"1.3": {ID: "1.3", Title: "Internal Vehicle Communications", Section: "1", Category: "Network", Severity: "critical", Keywords: []string{"can", "bus", "internal"}},
			"2.1": {ID: "2.1", Title: "Limit Entry Points", Section: "2", Category: "Attack Surface", Severity: "critical", Keywords: []string{"entry", "point", "interface"}},
			"2.2": {ID: "2.2", Title: "Disable Unnecessary Services", Section: "2", Category: "Attack Surface", Severity: "high", Keywords: []string{"service", "disable", "minimal"}},
			"3.1": {ID: "3.1", Title: "Software Update Process", Section: "3", Category: "Updates", Severity: "critical", Keywords: []string{"update", "ota", "patch"}},
			"3.2": {ID: "3.2", Title: "Secure Boot", Section: "3", Category: "Firmware", Severity: "critical", Keywords: []string{"boot", "secure", "firmware"}},
			"4.1": {ID: "4.1", Title: "Logging and Monitoring", Section: "4", Category: "Detection", Severity: "high", Keywords: []string{"log", "monitor", "detection"}},
			"4.2": {ID: "4.2", Title: "Incident Response", Section: "4", Category: "Response", Severity: "critical", Keywords: []string{"incident", "response", "handling"}},
			"5.1": {ID: "5.1", Title: "Risk Assessment", Section: "5", Category: "Risk", Severity: "critical", Keywords: []string{"risk", "assessment", "threat"}},
			"5.2": {ID: "5.2", Title: "Penetration Testing", Section: "5", Category: "Testing", Severity: "high", Keywords: []string{"penetration", "test", "security"}},
		},
	}
}

// loadAutomotiveFrameworks loads all automotive-related frameworks
func (m *Manager) loadAutomotiveFrameworks() {
	m.RegisterFramework(m.buildISO21434Framework())
	m.RegisterFramework(m.buildUNECER155Framework())
	m.RegisterFramework(m.buildTISAXFramework())
	m.RegisterFramework(m.buildAutomotiveSPICEFramework())
	m.RegisterFramework(m.buildNHTSACybersecurityFramework())
}

// loadAutomotiveSectorProfile loads the automotive sector profile
func (m *Manager) loadAutomotiveSectorProfile() {
	m.sectorProfiles[SectorAutomotive] = &SectorProfile{
		Sector:      SectorAutomotive,
		Name:        "Automotive",
		Description: "Automotive industry cybersecurity and safety frameworks",
		RequiredFrameworks: []string{
			"iso-21434", "unece-r155", "tisax", "nhtsa-cyber",
		},
		OptionalFrameworks: []string{
			"automotive-spice", "iso-27001", "nist-csf", "cis-benchmarks",
		},
	}
}

