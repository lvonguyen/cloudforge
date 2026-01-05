// Package compliance provides compliance framework mapping and assessment
package compliance

// buildHIPAAFramework builds HIPAA Security Rule framework
func (m *Manager) buildHIPAAFramework() *Framework {
	return &Framework{
		ID:          "hipaa",
		Name:        "HIPAA Security Rule",
		Version:     "2013",
		Description: "Health Insurance Portability and Accountability Act Security Rule",
		Sector:      SectorHealthcare,
		URL:         "https://www.hhs.gov/hipaa/for-professionals/security/",
		Controls: map[string]*Control{
			"164.308(a)(1)":  {ID: "164.308(a)(1)", Title: "Security Management Process", Section: "Administrative Safeguards", Category: "Risk Management", Severity: "high", Keywords: []string{"risk", "analysis", "management"}},
			"164.308(a)(3)":  {ID: "164.308(a)(3)", Title: "Workforce Security", Section: "Administrative Safeguards", Category: "Access Control", Severity: "high", Keywords: []string{"workforce", "access", "authorization"}},
			"164.308(a)(4)":  {ID: "164.308(a)(4)", Title: "Information Access Management", Section: "Administrative Safeguards", Category: "Access Control", Severity: "critical", Keywords: []string{"access", "phi", "authorization"}},
			"164.308(a)(5)":  {ID: "164.308(a)(5)", Title: "Security Awareness Training", Section: "Administrative Safeguards", Category: "Training", Severity: "medium", Keywords: []string{"training", "awareness"}},
			"164.308(a)(6)":  {ID: "164.308(a)(6)", Title: "Security Incident Procedures", Section: "Administrative Safeguards", Category: "Incident Response", Severity: "high", Keywords: []string{"incident", "response", "breach"}},
			"164.308(a)(7)":  {ID: "164.308(a)(7)", Title: "Contingency Plan", Section: "Administrative Safeguards", Category: "Business Continuity", Severity: "high", Keywords: []string{"backup", "disaster", "recovery"}},
			"164.310(a)(1)":  {ID: "164.310(a)(1)", Title: "Facility Access Controls", Section: "Physical Safeguards", Category: "Physical", Severity: "high", Keywords: []string{"physical", "facility", "access"}},
			"164.310(d)(1)":  {ID: "164.310(d)(1)", Title: "Device and Media Controls", Section: "Physical Safeguards", Category: "Media", Severity: "high", Keywords: []string{"media", "device", "disposal"}},
			"164.312(a)(1)":  {ID: "164.312(a)(1)", Title: "Access Control", Section: "Technical Safeguards", Category: "Access Control", Severity: "critical", Keywords: []string{"access", "unique user", "automatic logoff"}},
			"164.312(b)":     {ID: "164.312(b)", Title: "Audit Controls", Section: "Technical Safeguards", Category: "Audit", Severity: "high", Keywords: []string{"audit", "log", "monitoring"}},
			"164.312(c)(1)":  {ID: "164.312(c)(1)", Title: "Integrity", Section: "Technical Safeguards", Category: "Integrity", Severity: "high", Keywords: []string{"integrity", "ephi", "alteration"}},
			"164.312(d)":     {ID: "164.312(d)", Title: "Person or Entity Authentication", Section: "Technical Safeguards", Category: "Authentication", Severity: "critical", Keywords: []string{"authentication", "identity", "verification"}},
			"164.312(e)(1)":  {ID: "164.312(e)(1)", Title: "Transmission Security", Section: "Technical Safeguards", Category: "Encryption", Severity: "critical", Keywords: []string{"encryption", "transmission", "transit"}},
		},
	}
}

// buildHITRUSTFramework builds HITRUST CSF framework
func (m *Manager) buildHITRUSTFramework() *Framework {
	return &Framework{
		ID:          "hitrust",
		Name:        "HITRUST CSF",
		Version:     "v11",
		Description: "HITRUST Common Security Framework",
		Sector:      SectorHealthcare,
		URL:         "https://hitrustalliance.net/hitrust-csf/",
		Controls: map[string]*Control{
			"01.a":  {ID: "01.a", Title: "Access Control Policy", Section: "01", Category: "Access Control", Severity: "high", Keywords: []string{"access", "policy"}},
			"01.c":  {ID: "01.c", Title: "Privilege Management", Section: "01", Category: "Access Control", Severity: "critical", Keywords: []string{"privilege", "admin", "least privilege"}},
			"01.j":  {ID: "01.j", Title: "User Authentication", Section: "01", Category: "Authentication", Severity: "critical", Keywords: []string{"authentication", "mfa", "password"}},
			"06.d":  {ID: "06.d", Title: "Data Classification", Section: "06", Category: "Data", Severity: "high", Keywords: []string{"classification", "data", "sensitive"}},
			"06.f":  {ID: "06.f", Title: "Encryption", Section: "06", Category: "Encryption", Severity: "critical", Keywords: []string{"encryption", "cryptography", "key"}},
			"09.aa": {ID: "09.aa", Title: "Audit Logging", Section: "09", Category: "Logging", Severity: "high", Keywords: []string{"audit", "log", "monitoring"}},
			"10.c":  {ID: "10.c", Title: "Secure Development", Section: "10", Category: "Development", Severity: "high", Keywords: []string{"development", "secure", "sdlc"}},
			"11.a":  {ID: "11.a", Title: "Incident Management", Section: "11", Category: "Incident Response", Severity: "high", Keywords: []string{"incident", "response", "breach"}},
		},
	}
}

// buildSOXFramework builds SOX framework
func (m *Manager) buildSOXFramework() *Framework {
	return &Framework{
		ID:          "sox",
		Name:        "Sarbanes-Oxley Act",
		Version:     "2002",
		Description: "SOX IT General Controls",
		Sector:      SectorFinance,
		URL:         "https://www.sec.gov/spotlight/sarbanes-oxley.htm",
		Controls: map[string]*Control{
			"ITGC.1": {ID: "ITGC.1", Title: "Access to Programs and Data", Section: "Access Controls", Category: "Access Control", Severity: "critical", Keywords: []string{"access", "authorization", "segregation"}},
			"ITGC.2": {ID: "ITGC.2", Title: "Program Changes", Section: "Change Management", Category: "Change Management", Severity: "high", Keywords: []string{"change", "deployment", "approval"}},
			"ITGC.3": {ID: "ITGC.3", Title: "Program Development", Section: "Development", Category: "Development", Severity: "high", Keywords: []string{"development", "testing", "approval"}},
			"ITGC.4": {ID: "ITGC.4", Title: "Computer Operations", Section: "Operations", Category: "Operations", Severity: "high", Keywords: []string{"backup", "recovery", "job scheduling"}},
			"ITGC.5": {ID: "ITGC.5", Title: "System Security", Section: "Security", Category: "Security", Severity: "critical", Keywords: []string{"security", "authentication", "monitoring"}},
		},
	}
}

// buildGLBAFramework builds GLBA Safeguards Rule framework
func (m *Manager) buildGLBAFramework() *Framework {
	return &Framework{
		ID:          "glba",
		Name:        "GLBA Safeguards Rule",
		Version:     "2023",
		Description: "Gramm-Leach-Bliley Act Safeguards Rule",
		Sector:      SectorFinance,
		URL:         "https://www.ftc.gov/business-guidance/privacy-security/gramm-leach-bliley-act",
		Controls: map[string]*Control{
			"314.4(b)": {ID: "314.4(b)", Title: "Risk Assessment", Section: "Information Security Program", Category: "Risk", Severity: "high", Keywords: []string{"risk", "assessment"}},
			"314.4(c)": {ID: "314.4(c)", Title: "Access Controls", Section: "Information Security Program", Category: "Access Control", Severity: "critical", Keywords: []string{"access", "control", "authentication"}},
			"314.4(d)": {ID: "314.4(d)", Title: "Inventory of Data Systems", Section: "Information Security Program", Category: "Asset Management", Severity: "high", Keywords: []string{"inventory", "data", "system"}},
			"314.4(e)": {ID: "314.4(e)", Title: "Encryption", Section: "Information Security Program", Category: "Encryption", Severity: "critical", Keywords: []string{"encryption", "transit", "rest"}},
			"314.4(f)": {ID: "314.4(f)", Title: "Secure Development", Section: "Information Security Program", Category: "Development", Severity: "high", Keywords: []string{"development", "secure", "change"}},
			"314.4(g)": {ID: "314.4(g)", Title: "Multi-Factor Authentication", Section: "Information Security Program", Category: "Authentication", Severity: "critical", Keywords: []string{"mfa", "authentication", "multi-factor"}},
			"314.4(h)": {ID: "314.4(h)", Title: "Disposal Procedures", Section: "Information Security Program", Category: "Data Disposal", Severity: "high", Keywords: []string{"disposal", "destruction", "data"}},
			"314.4(i)": {ID: "314.4(i)", Title: "Change Management", Section: "Information Security Program", Category: "Change Management", Severity: "high", Keywords: []string{"change", "management", "approval"}},
			"314.4(j)": {ID: "314.4(j)", Title: "Monitoring and Logging", Section: "Information Security Program", Category: "Logging", Severity: "high", Keywords: []string{"monitoring", "log", "detection"}},
		},
	}
}

// buildFFIECFramework builds FFIEC IT Examination Handbook framework
func (m *Manager) buildFFIECFramework() *Framework {
	return &Framework{
		ID:          "ffiec",
		Name:        "FFIEC IT Examination Handbook",
		Version:     "2023",
		Description: "Federal Financial Institutions Examination Council IT Handbook",
		Sector:      SectorFinance,
		URL:         "https://ithandbook.ffiec.gov/",
		Controls: map[string]*Control{
			"IS.2.A": {ID: "IS.2.A", Title: "Information Security Program", Section: "Information Security", Category: "Governance", Severity: "high", Keywords: []string{"program", "governance", "policy"}},
			"IS.2.B": {ID: "IS.2.B", Title: "Security Risk Assessment", Section: "Information Security", Category: "Risk", Severity: "high", Keywords: []string{"risk", "assessment", "threat"}},
			"IS.2.C": {ID: "IS.2.C", Title: "Security Monitoring", Section: "Information Security", Category: "Monitoring", Severity: "high", Keywords: []string{"monitoring", "detection", "siem"}},
			"AC.1":   {ID: "AC.1", Title: "Access Control Administration", Section: "Access Control", Category: "Access Control", Severity: "critical", Keywords: []string{"access", "authentication", "authorization"}},
			"AC.2":   {ID: "AC.2", Title: "User Enrollment", Section: "Access Control", Category: "Identity", Severity: "high", Keywords: []string{"user", "identity", "provisioning"}},
			"BC.1":   {ID: "BC.1", Title: "Business Continuity Planning", Section: "Business Continuity", Category: "BCP", Severity: "high", Keywords: []string{"continuity", "disaster", "recovery"}},
			"OPS.1":  {ID: "OPS.1", Title: "IT Operations", Section: "Operations", Category: "Operations", Severity: "high", Keywords: []string{"operations", "change", "incident"}},
		},
	}
}

// buildFedRAMPFramework builds FedRAMP framework
func (m *Manager) buildFedRAMPFramework() *Framework {
	return &Framework{
		ID:          "fedramp",
		Name:        "FedRAMP",
		Version:     "Rev 5",
		Description: "Federal Risk and Authorization Management Program",
		Sector:      SectorGovernment,
		URL:         "https://www.fedramp.gov/",
		Controls: map[string]*Control{
			"AC-2":  {ID: "AC-2", Title: "Account Management", Section: "Access Control", Category: "Access Control", Severity: "high", Keywords: []string{"account", "management", "user"}},
			"AC-17": {ID: "AC-17", Title: "Remote Access", Section: "Access Control", Category: "Access Control", Severity: "high", Keywords: []string{"remote", "access", "vpn"}},
			"AU-2":  {ID: "AU-2", Title: "Audit Events", Section: "Audit", Category: "Logging", Severity: "high", Keywords: []string{"audit", "log", "event"}},
			"CA-7":  {ID: "CA-7", Title: "Continuous Monitoring", Section: "Security Assessment", Category: "Monitoring", Severity: "high", Keywords: []string{"continuous", "monitoring", "assessment"}},
			"CM-2":  {ID: "CM-2", Title: "Baseline Configuration", Section: "Configuration Management", Category: "Configuration", Severity: "high", Keywords: []string{"baseline", "configuration", "hardening"}},
			"IA-2":  {ID: "IA-2", Title: "Identification and Authentication", Section: "Identification", Category: "Authentication", Severity: "critical", Keywords: []string{"authentication", "mfa", "identity"}},
			"IR-4":  {ID: "IR-4", Title: "Incident Handling", Section: "Incident Response", Category: "Incident Response", Severity: "high", Keywords: []string{"incident", "handling", "response"}},
			"RA-5":  {ID: "RA-5", Title: "Vulnerability Scanning", Section: "Risk Assessment", Category: "Vulnerability", Severity: "high", Keywords: []string{"vulnerability", "scan", "assessment"}},
			"SC-7":  {ID: "SC-7", Title: "Boundary Protection", Section: "System Protection", Category: "Network", Severity: "critical", Keywords: []string{"boundary", "firewall", "network"}},
			"SC-28": {ID: "SC-28", Title: "Protection of Information at Rest", Section: "System Protection", Category: "Encryption", Severity: "high", Keywords: []string{"encryption", "rest", "storage"}},
		},
	}
}

// buildSTIGFramework builds DISA STIG framework
func (m *Manager) buildSTIGFramework() *Framework {
	return &Framework{
		ID:          "stig",
		Name:        "DISA STIGs",
		Version:     "2024",
		Description: "Defense Information Systems Agency Security Technical Implementation Guides",
		Sector:      SectorGovernment,
		URL:         "https://public.cyber.mil/stigs/",
		Controls: map[string]*Control{
			"V-1": {ID: "V-1", Title: "Operating System Security", Section: "OS", Category: "Configuration", Severity: "high", Keywords: []string{"os", "windows", "linux", "hardening"}},
			"V-2": {ID: "V-2", Title: "Application Security", Section: "Application", Category: "Application", Severity: "high", Keywords: []string{"application", "web", "secure"}},
			"V-3": {ID: "V-3", Title: "Network Security", Section: "Network", Category: "Network", Severity: "high", Keywords: []string{"network", "firewall", "router"}},
			"V-4": {ID: "V-4", Title: "Database Security", Section: "Database", Category: "Database", Severity: "high", Keywords: []string{"database", "sql", "oracle"}},
			"V-5": {ID: "V-5", Title: "Cloud Security", Section: "Cloud", Category: "Cloud", Severity: "high", Keywords: []string{"cloud", "aws", "azure", "gcp"}},
		},
	}
}

