// Package compliance provides compliance framework mapping and assessment
package compliance

// buildCMMCFramework builds CMMC 2.0 framework
func (m *Manager) buildCMMCFramework() *Framework {
	return &Framework{
		ID:          "cmmc",
		Name:        "CMMC 2.0",
		Version:     "2.0",
		Description: "Cybersecurity Maturity Model Certification",
		Sector:      SectorGovernment,
		URL:         "https://www.acq.osd.mil/cmmc/",
		Controls: map[string]*Control{
			// Level 1 - Foundational
			"AC.L1-3.1.1":  {ID: "AC.L1-3.1.1", Title: "Authorized Access Control", Section: "AC", Category: "Access Control", Severity: "high", Keywords: []string{"access", "authorized", "user"}},
			"AC.L1-3.1.2":  {ID: "AC.L1-3.1.2", Title: "Transaction & Function Control", Section: "AC", Category: "Access Control", Severity: "high", Keywords: []string{"transaction", "function", "control"}},
			"AC.L1-3.1.20": {ID: "AC.L1-3.1.20", Title: "External Connections", Section: "AC", Category: "Access Control", Severity: "high", Keywords: []string{"external", "connection", "verification"}},
			"AC.L1-3.1.22": {ID: "AC.L1-3.1.22", Title: "Control Public Information", Section: "AC", Category: "Access Control", Severity: "medium", Keywords: []string{"public", "information", "posting"}},
			"IA.L1-3.5.1":  {ID: "IA.L1-3.5.1", Title: "Identification", Section: "IA", Category: "Identification", Severity: "critical", Keywords: []string{"identify", "user", "device"}},
			"IA.L1-3.5.2":  {ID: "IA.L1-3.5.2", Title: "Authentication", Section: "IA", Category: "Authentication", Severity: "critical", Keywords: []string{"authenticate", "verify", "credential"}},
			"MP.L1-3.8.3":  {ID: "MP.L1-3.8.3", Title: "Media Disposal", Section: "MP", Category: "Media", Severity: "high", Keywords: []string{"media", "disposal", "sanitize"}},
			"PE.L1-3.10.1": {ID: "PE.L1-3.10.1", Title: "Limit Physical Access", Section: "PE", Category: "Physical", Severity: "high", Keywords: []string{"physical", "access", "limit"}},
			"PE.L1-3.10.3": {ID: "PE.L1-3.10.3", Title: "Escort Visitors", Section: "PE", Category: "Physical", Severity: "medium", Keywords: []string{"visitor", "escort", "access"}},
			"PE.L1-3.10.4": {ID: "PE.L1-3.10.4", Title: "Physical Access Logs", Section: "PE", Category: "Physical", Severity: "high", Keywords: []string{"log", "physical", "access"}},
			"PE.L1-3.10.5": {ID: "PE.L1-3.10.5", Title: "Manage Physical Access", Section: "PE", Category: "Physical", Severity: "high", Keywords: []string{"manage", "physical", "access"}},
			"SC.L1-3.13.1": {ID: "SC.L1-3.13.1", Title: "Boundary Protection", Section: "SC", Category: "System", Severity: "critical", Keywords: []string{"boundary", "monitor", "communications"}},
			"SC.L1-3.13.5": {ID: "SC.L1-3.13.5", Title: "Public-Access System Separation", Section: "SC", Category: "System", Severity: "high", Keywords: []string{"public", "separation", "subnetwork"}},
			"SI.L1-3.14.1": {ID: "SI.L1-3.14.1", Title: "Flaw Remediation", Section: "SI", Category: "System", Severity: "critical", Keywords: []string{"flaw", "remediation", "patch"}},
			"SI.L1-3.14.2": {ID: "SI.L1-3.14.2", Title: "Malicious Code Protection", Section: "SI", Category: "System", Severity: "critical", Keywords: []string{"malicious", "code", "malware"}},
			"SI.L1-3.14.4": {ID: "SI.L1-3.14.4", Title: "Update Malicious Code Protection", Section: "SI", Category: "System", Severity: "high", Keywords: []string{"update", "signature", "antivirus"}},
			"SI.L1-3.14.5": {ID: "SI.L1-3.14.5", Title: "System & File Scanning", Section: "SI", Category: "System", Severity: "high", Keywords: []string{"scan", "periodic", "realtime"}},

			// Level 2 - Advanced (selected key controls)
			"AC.L2-3.1.3":  {ID: "AC.L2-3.1.3", Title: "Control CUI Flow", Section: "AC", Category: "Access Control", Severity: "critical", Keywords: []string{"cui", "flow", "control"}},
			"AC.L2-3.1.5":  {ID: "AC.L2-3.1.5", Title: "Least Privilege", Section: "AC", Category: "Access Control", Severity: "critical", Keywords: []string{"least", "privilege", "minimal"}},
			"AC.L2-3.1.6":  {ID: "AC.L2-3.1.6", Title: "Non-Privileged Account Use", Section: "AC", Category: "Access Control", Severity: "high", Keywords: []string{"non-privileged", "account", "admin"}},
			"AC.L2-3.1.7":  {ID: "AC.L2-3.1.7", Title: "Privileged Functions", Section: "AC", Category: "Access Control", Severity: "critical", Keywords: []string{"privileged", "function", "prevent"}},
			"AU.L2-3.3.1":  {ID: "AU.L2-3.3.1", Title: "System Auditing", Section: "AU", Category: "Audit", Severity: "high", Keywords: []string{"audit", "log", "record"}},
			"AU.L2-3.3.2":  {ID: "AU.L2-3.3.2", Title: "User Accountability", Section: "AU", Category: "Audit", Severity: "high", Keywords: []string{"accountability", "trace", "user"}},
			"CA.L2-3.12.1": {ID: "CA.L2-3.12.1", Title: "Security Assessment", Section: "CA", Category: "Assessment", Severity: "high", Keywords: []string{"assessment", "security", "control"}},
			"CA.L2-3.12.4": {ID: "CA.L2-3.12.4", Title: "System Security Plan", Section: "CA", Category: "Assessment", Severity: "high", Keywords: []string{"plan", "system", "security"}},
			"CM.L2-3.4.1":  {ID: "CM.L2-3.4.1", Title: "System Baselining", Section: "CM", Category: "Configuration", Severity: "high", Keywords: []string{"baseline", "configuration", "system"}},
			"CM.L2-3.4.2":  {ID: "CM.L2-3.4.2", Title: "Security Configuration Enforcement", Section: "CM", Category: "Configuration", Severity: "high", Keywords: []string{"enforce", "configuration", "setting"}},
			"IA.L2-3.5.3":  {ID: "IA.L2-3.5.3", Title: "Multi-Factor Authentication", Section: "IA", Category: "Authentication", Severity: "critical", Keywords: []string{"mfa", "multi-factor", "authentication"}},
			"IR.L2-3.6.1":  {ID: "IR.L2-3.6.1", Title: "Incident Handling", Section: "IR", Category: "Incident Response", Severity: "critical", Keywords: []string{"incident", "handling", "response"}},
			"IR.L2-3.6.2":  {ID: "IR.L2-3.6.2", Title: "Incident Reporting", Section: "IR", Category: "Incident Response", Severity: "high", Keywords: []string{"report", "incident", "notify"}},
			"RA.L2-3.11.1": {ID: "RA.L2-3.11.1", Title: "Risk Assessment", Section: "RA", Category: "Risk", Severity: "critical", Keywords: []string{"risk", "assessment", "operations"}},
			"RA.L2-3.11.2": {ID: "RA.L2-3.11.2", Title: "Vulnerability Scan", Section: "RA", Category: "Vulnerability", Severity: "high", Keywords: []string{"vulnerability", "scan", "remediate"}},
			"SC.L2-3.13.6": {ID: "SC.L2-3.13.6", Title: "Network Communication by Exception", Section: "SC", Category: "Network", Severity: "high", Keywords: []string{"deny", "exception", "network"}},
			"SC.L2-3.13.8": {ID: "SC.L2-3.13.8", Title: "Data in Transit Protection", Section: "SC", Category: "Encryption", Severity: "critical", Keywords: []string{"encrypt", "transit", "transmission"}},
		},
	}
}

// buildITARFramework builds ITAR compliance framework
func (m *Manager) buildITARFramework() *Framework {
	return &Framework{
		ID:          "itar",
		Name:        "ITAR",
		Version:     "2024",
		Description: "International Traffic in Arms Regulations",
		Sector:      SectorGovernment,
		URL:         "https://www.pmddtc.state.gov/ddtc_public/ddtc_public?id=ddtc_kb_article_page&sys_id=24d528fddbfc930044f9ff621f961987",
		Controls: map[string]*Control{
			"120.1":  {ID: "120.1", Title: "General Provisions", Section: "120", Category: "General", Severity: "critical", Keywords: []string{"export", "control", "defense"}},
			"120.10": {ID: "120.10", Title: "Technical Data Definition", Section: "120", Category: "Data", Severity: "critical", Keywords: []string{"technical", "data", "defense"}},
			"120.17": {ID: "120.17", Title: "Export Definition", Section: "120", Category: "Export", Severity: "critical", Keywords: []string{"export", "transfer", "disclosure"}},
			"122.1":  {ID: "122.1", Title: "Registration Requirement", Section: "122", Category: "Registration", Severity: "high", Keywords: []string{"registration", "manufacturer", "exporter"}},
			"123.1":  {ID: "123.1", Title: "License Requirements", Section: "123", Category: "Licensing", Severity: "critical", Keywords: []string{"license", "export", "approval"}},
			"125.1":  {ID: "125.1", Title: "Technical Data Licenses", Section: "125", Category: "Data", Severity: "critical", Keywords: []string{"technical", "data", "license"}},
			"126.1":  {ID: "126.1", Title: "Prohibited Exports", Section: "126", Category: "Prohibition", Severity: "critical", Keywords: []string{"prohibited", "country", "export"}},
			"127.1":  {ID: "127.1", Title: "Violations and Penalties", Section: "127", Category: "Enforcement", Severity: "critical", Keywords: []string{"violation", "penalty", "enforcement"}},
			"ACC.1":  {ID: "ACC.1", Title: "Access Control for ITAR Data", Section: "Access", Category: "Access Control", Severity: "critical", Keywords: []string{"access", "control", "itar", "need-to-know"}},
			"ACC.2":  {ID: "ACC.2", Title: "Foreign Person Access", Section: "Access", Category: "Access Control", Severity: "critical", Keywords: []string{"foreign", "person", "access", "citizen"}},
			"ENC.1":  {ID: "ENC.1", Title: "Encryption of ITAR Data", Section: "Encryption", Category: "Data Protection", Severity: "critical", Keywords: []string{"encryption", "itar", "data", "transit"}},
			"AUD.1":  {ID: "AUD.1", Title: "ITAR Access Auditing", Section: "Audit", Category: "Logging", Severity: "high", Keywords: []string{"audit", "log", "access", "itar"}},
			"RET.1":  {ID: "RET.1", Title: "ITAR Record Retention", Section: "Retention", Category: "Records", Severity: "high", Keywords: []string{"retention", "record", "5 years"}},
		},
	}
}

// buildEARFramework builds EAR compliance framework
func (m *Manager) buildEARFramework() *Framework {
	return &Framework{
		ID:          "ear",
		Name:        "EAR",
		Version:     "2024",
		Description: "Export Administration Regulations",
		Sector:      SectorGovernment,
		URL:         "https://www.bis.doc.gov/index.php/regulations/export-administration-regulations-ear",
		Controls: map[string]*Control{
			"730.1":  {ID: "730.1", Title: "Scope of EAR", Section: "730", Category: "General", Severity: "high", Keywords: []string{"scope", "dual-use", "export"}},
			"732.1":  {ID: "732.1", Title: "Steps for Using EAR", Section: "732", Category: "Process", Severity: "high", Keywords: []string{"steps", "classification", "license"}},
			"734.3":  {ID: "734.3", Title: "Items Subject to EAR", Section: "734", Category: "Scope", Severity: "high", Keywords: []string{"subject", "items", "technology"}},
			"736.1":  {ID: "736.1", Title: "General Prohibitions", Section: "736", Category: "Prohibition", Severity: "critical", Keywords: []string{"prohibition", "export", "reexport"}},
			"740.1":  {ID: "740.1", Title: "License Exceptions", Section: "740", Category: "Exception", Severity: "high", Keywords: []string{"license", "exception", "authorization"}},
			"742.1":  {ID: "742.1", Title: "Control Policy", Section: "742", Category: "Policy", Severity: "high", Keywords: []string{"control", "policy", "reason"}},
			"744.1":  {ID: "744.1", Title: "Entity List", Section: "744", Category: "Restriction", Severity: "critical", Keywords: []string{"entity", "list", "denied", "restricted"}},
			"764.1":  {ID: "764.1", Title: "Enforcement and Penalties", Section: "764", Category: "Enforcement", Severity: "critical", Keywords: []string{"enforcement", "penalty", "violation"}},
		},
	}
}

// buildDFARSFramework builds DFARS 252.204-7012 framework
func (m *Manager) buildDFARSFramework() *Framework {
	return &Framework{
		ID:          "dfars",
		Name:        "DFARS 252.204-7012",
		Version:     "2024",
		Description: "Safeguarding Covered Defense Information",
		Sector:      SectorGovernment,
		URL:         "https://www.acquisition.gov/dfars/252.204-7012-safeguarding-covered-defense-information-and-cyber-incident-reporting",
		Controls: map[string]*Control{
			"(b)(1)": {ID: "(b)(1)", Title: "Adequate Security", Section: "b", Category: "Security", Severity: "critical", Keywords: []string{"adequate", "security", "nist"}},
			"(b)(2)": {ID: "(b)(2)", Title: "NIST SP 800-171", Section: "b", Category: "Security", Severity: "critical", Keywords: []string{"nist", "800-171", "controls"}},
			"(c)(1)": {ID: "(c)(1)", Title: "Cyber Incident Reporting", Section: "c", Category: "Incident", Severity: "critical", Keywords: []string{"cyber", "incident", "report", "72 hours"}},
			"(c)(2)": {ID: "(c)(2)", Title: "Medium Assurance Certificate", Section: "c", Category: "Incident", Severity: "high", Keywords: []string{"certificate", "assurance", "dod"}},
			"(d)":    {ID: "(d)", Title: "Malicious Software", Section: "d", Category: "Malware", Severity: "critical", Keywords: []string{"malicious", "software", "isolation"}},
			"(e)":    {ID: "(e)", Title: "Media Preservation", Section: "e", Category: "Forensics", Severity: "high", Keywords: []string{"media", "preservation", "forensic"}},
			"(f)":    {ID: "(f)", Title: "Access to Information", Section: "f", Category: "Access", Severity: "high", Keywords: []string{"access", "dod", "information"}},
			"(g)":    {ID: "(g)", Title: "Subcontractor Flow Down", Section: "g", Category: "Supply Chain", Severity: "high", Keywords: []string{"subcontractor", "flow", "requirement"}},
		},
	}
}

// buildNIST800171Framework builds NIST SP 800-171 framework
func (m *Manager) buildNIST800171Framework() *Framework {
	return &Framework{
		ID:          "nist-800-171",
		Name:        "NIST SP 800-171",
		Version:     "Rev 3",
		Description: "Protecting Controlled Unclassified Information in Nonfederal Systems",
		Sector:      SectorGovernment,
		URL:         "https://csrc.nist.gov/publications/detail/sp/800-171/rev-3/final",
		Controls: map[string]*Control{
			// Access Control
			"3.1.1":  {ID: "3.1.1", Title: "Limit System Access", Section: "3.1", Category: "Access Control", Severity: "critical", Keywords: []string{"access", "authorized", "limit"}},
			"3.1.2":  {ID: "3.1.2", Title: "Limit Transaction Types", Section: "3.1", Category: "Access Control", Severity: "high", Keywords: []string{"transaction", "function", "permitted"}},
			"3.1.3":  {ID: "3.1.3", Title: "Control CUI Flow", Section: "3.1", Category: "Access Control", Severity: "critical", Keywords: []string{"cui", "flow", "control"}},
			"3.1.4":  {ID: "3.1.4", Title: "Separation of Duties", Section: "3.1", Category: "Access Control", Severity: "high", Keywords: []string{"separation", "duties", "conflict"}},
			"3.1.5":  {ID: "3.1.5", Title: "Least Privilege", Section: "3.1", Category: "Access Control", Severity: "critical", Keywords: []string{"least", "privilege", "minimal"}},
			"3.1.6":  {ID: "3.1.6", Title: "Non-Privileged Account Use", Section: "3.1", Category: "Access Control", Severity: "high", Keywords: []string{"non-privileged", "security", "function"}},
			"3.1.7":  {ID: "3.1.7", Title: "Prevent Non-Privileged Users", Section: "3.1", Category: "Access Control", Severity: "critical", Keywords: []string{"prevent", "privileged", "function"}},
			"3.1.8":  {ID: "3.1.8", Title: "Limit Unsuccessful Logons", Section: "3.1", Category: "Access Control", Severity: "high", Keywords: []string{"unsuccessful", "logon", "limit"}},
			"3.1.12": {ID: "3.1.12", Title: "Remote Access Control", Section: "3.1", Category: "Access Control", Severity: "critical", Keywords: []string{"remote", "access", "monitor"}},
			"3.1.13": {ID: "3.1.13", Title: "Cryptographic Remote Access", Section: "3.1", Category: "Access Control", Severity: "critical", Keywords: []string{"cryptographic", "remote", "session"}},
			"3.1.14": {ID: "3.1.14", Title: "Remote Access Routing", Section: "3.1", Category: "Access Control", Severity: "high", Keywords: []string{"route", "remote", "access point"}},
			"3.1.15": {ID: "3.1.15", Title: "Privileged Remote Access Authorization", Section: "3.1", Category: "Access Control", Severity: "critical", Keywords: []string{"authorize", "remote", "privileged"}},
			"3.1.16": {ID: "3.1.16", Title: "Wireless Access Authorization", Section: "3.1", Category: "Access Control", Severity: "high", Keywords: []string{"wireless", "access", "authorize"}},
			"3.1.17": {ID: "3.1.17", Title: "Wireless Access Protection", Section: "3.1", Category: "Access Control", Severity: "critical", Keywords: []string{"wireless", "protect", "authentication"}},
			"3.1.18": {ID: "3.1.18", Title: "Mobile Device Access Control", Section: "3.1", Category: "Access Control", Severity: "high", Keywords: []string{"mobile", "device", "control"}},
			"3.1.19": {ID: "3.1.19", Title: "Encrypt CUI on Mobile", Section: "3.1", Category: "Access Control", Severity: "critical", Keywords: []string{"encrypt", "mobile", "cui"}},

			// Awareness and Training
			"3.2.1": {ID: "3.2.1", Title: "Security Awareness Training", Section: "3.2", Category: "Training", Severity: "medium", Keywords: []string{"awareness", "training", "risk"}},
			"3.2.2": {ID: "3.2.2", Title: "Insider Threat Awareness", Section: "3.2", Category: "Training", Severity: "medium", Keywords: []string{"insider", "threat", "awareness"}},

			// Audit and Accountability
			"3.3.1": {ID: "3.3.1", Title: "Create Audit Records", Section: "3.3", Category: "Audit", Severity: "critical", Keywords: []string{"audit", "record", "event"}},
			"3.3.2": {ID: "3.3.2", Title: "Audit User Actions", Section: "3.3", Category: "Audit", Severity: "high", Keywords: []string{"audit", "trace", "user"}},
			"3.3.4": {ID: "3.3.4", Title: "Alert on Audit Failure", Section: "3.3", Category: "Audit", Severity: "high", Keywords: []string{"alert", "audit", "failure"}},
			"3.3.5": {ID: "3.3.5", Title: "Correlate Audit Records", Section: "3.3", Category: "Audit", Severity: "high", Keywords: []string{"correlate", "audit", "review"}},

			// Configuration Management
			"3.4.1": {ID: "3.4.1", Title: "Baseline Configuration", Section: "3.4", Category: "Configuration", Severity: "high", Keywords: []string{"baseline", "configuration", "inventory"}},
			"3.4.2": {ID: "3.4.2", Title: "Security Configuration Settings", Section: "3.4", Category: "Configuration", Severity: "high", Keywords: []string{"configuration", "setting", "security"}},
			"3.4.6": {ID: "3.4.6", Title: "Least Functionality", Section: "3.4", Category: "Configuration", Severity: "high", Keywords: []string{"least", "functionality", "disable"}},

			// Identification and Authentication
			"3.5.1":  {ID: "3.5.1", Title: "Identify Users", Section: "3.5", Category: "Identification", Severity: "critical", Keywords: []string{"identify", "user", "process"}},
			"3.5.2":  {ID: "3.5.2", Title: "Authenticate Identities", Section: "3.5", Category: "Authentication", Severity: "critical", Keywords: []string{"authenticate", "identity", "credential"}},
			"3.5.3":  {ID: "3.5.3", Title: "Multi-Factor Authentication", Section: "3.5", Category: "Authentication", Severity: "critical", Keywords: []string{"mfa", "multi-factor", "privileged"}},

			// Incident Response
			"3.6.1": {ID: "3.6.1", Title: "Incident Handling Capability", Section: "3.6", Category: "Incident Response", Severity: "critical", Keywords: []string{"incident", "handling", "capability"}},
			"3.6.2": {ID: "3.6.2", Title: "Track and Document Incidents", Section: "3.6", Category: "Incident Response", Severity: "high", Keywords: []string{"track", "document", "report"}},

			// System Protection
			"3.13.1":  {ID: "3.13.1", Title: "Monitor Communications", Section: "3.13", Category: "System Protection", Severity: "critical", Keywords: []string{"monitor", "communications", "boundary"}},
			"3.13.8":  {ID: "3.13.8", Title: "Cryptographic Protection in Transit", Section: "3.13", Category: "Encryption", Severity: "critical", Keywords: []string{"cryptographic", "transit", "transmission"}},
			"3.13.16": {ID: "3.13.16", Title: "Protect CUI at Rest", Section: "3.13", Category: "Encryption", Severity: "critical", Keywords: []string{"rest", "storage", "encrypt"}},
		},
	}
}

// buildStateRAMPFramework builds StateRAMP framework
func (m *Manager) buildStateRAMPFramework() *Framework {
	return &Framework{
		ID:          "stateramp",
		Name:        "StateRAMP",
		Version:     "2024",
		Description: "StateRAMP Security Framework for State and Local Government",
		Sector:      SectorGovernment,
		URL:         "https://stateramp.org/",
		Controls: map[string]*Control{
			"AC-1":  {ID: "AC-1", Title: "Access Control Policy", Section: "AC", Category: "Access Control", Severity: "high", Keywords: []string{"access", "policy", "procedure"}},
			"AC-2":  {ID: "AC-2", Title: "Account Management", Section: "AC", Category: "Access Control", Severity: "high", Keywords: []string{"account", "management", "user"}},
			"AU-2":  {ID: "AU-2", Title: "Audit Events", Section: "AU", Category: "Audit", Severity: "high", Keywords: []string{"audit", "event", "log"}},
			"CA-2":  {ID: "CA-2", Title: "Security Assessments", Section: "CA", Category: "Assessment", Severity: "high", Keywords: []string{"assessment", "security", "control"}},
			"CM-2":  {ID: "CM-2", Title: "Baseline Configuration", Section: "CM", Category: "Configuration", Severity: "high", Keywords: []string{"baseline", "configuration", "documented"}},
			"IA-2":  {ID: "IA-2", Title: "Identification and Authentication", Section: "IA", Category: "Authentication", Severity: "critical", Keywords: []string{"identification", "authentication", "mfa"}},
			"IR-1":  {ID: "IR-1", Title: "Incident Response Policy", Section: "IR", Category: "Incident Response", Severity: "high", Keywords: []string{"incident", "response", "policy"}},
			"RA-5":  {ID: "RA-5", Title: "Vulnerability Scanning", Section: "RA", Category: "Vulnerability", Severity: "high", Keywords: []string{"vulnerability", "scan", "assessment"}},
			"SC-7":  {ID: "SC-7", Title: "Boundary Protection", Section: "SC", Category: "System Protection", Severity: "critical", Keywords: []string{"boundary", "protection", "firewall"}},
			"SI-2":  {ID: "SI-2", Title: "Flaw Remediation", Section: "SI", Category: "System Integrity", Severity: "high", Keywords: []string{"flaw", "remediation", "patch"}},
		},
	}
}

// buildCJISFramework builds FBI CJIS Security Policy framework
func (m *Manager) buildCJISFramework() *Framework {
	return &Framework{
		ID:          "cjis",
		Name:        "FBI CJIS Security Policy",
		Version:     "5.9.2",
		Description: "Criminal Justice Information Services Security Policy",
		Sector:      SectorGovernment,
		URL:         "https://www.fbi.gov/services/cjis/cjis-security-policy-resource-center",
		Controls: map[string]*Control{
			"5.1":  {ID: "5.1", Title: "Information Exchange Agreements", Section: "5.1", Category: "Agreement", Severity: "high", Keywords: []string{"agreement", "exchange", "information"}},
			"5.2":  {ID: "5.2", Title: "Security Awareness Training", Section: "5.2", Category: "Training", Severity: "medium", Keywords: []string{"awareness", "training", "security"}},
			"5.3":  {ID: "5.3", Title: "Incident Response", Section: "5.3", Category: "Incident Response", Severity: "critical", Keywords: []string{"incident", "response", "reporting"}},
			"5.4":  {ID: "5.4", Title: "Auditing and Accountability", Section: "5.4", Category: "Audit", Severity: "critical", Keywords: []string{"audit", "log", "accountability"}},
			"5.5":  {ID: "5.5", Title: "Access Control", Section: "5.5", Category: "Access Control", Severity: "critical", Keywords: []string{"access", "control", "authorization"}},
			"5.6":  {ID: "5.6", Title: "Identification and Authentication", Section: "5.6", Category: "Authentication", Severity: "critical", Keywords: []string{"identification", "authentication", "credential"}},
			"5.7":  {ID: "5.7", Title: "Configuration Management", Section: "5.7", Category: "Configuration", Severity: "high", Keywords: []string{"configuration", "management", "baseline"}},
			"5.8":  {ID: "5.8", Title: "Media Protection", Section: "5.8", Category: "Media", Severity: "high", Keywords: []string{"media", "protection", "sanitization"}},
			"5.9":  {ID: "5.9", Title: "Physical Protection", Section: "5.9", Category: "Physical", Severity: "high", Keywords: []string{"physical", "protection", "access"}},
			"5.10": {ID: "5.10", Title: "Systems and Communications Protection", Section: "5.10", Category: "System Protection", Severity: "critical", Keywords: []string{"encryption", "boundary", "protection"}},
			"5.11": {ID: "5.11", Title: "Formal Audits", Section: "5.11", Category: "Audit", Severity: "high", Keywords: []string{"audit", "formal", "triennial"}},
			"5.12": {ID: "5.12", Title: "Personnel Security", Section: "5.12", Category: "Personnel", Severity: "high", Keywords: []string{"personnel", "screening", "background"}},
			"5.13": {ID: "5.13", Title: "Mobile Devices", Section: "5.13", Category: "Mobile", Severity: "high", Keywords: []string{"mobile", "device", "management"}},
		},
	}
}

// loadExtendedGovernmentFrameworks loads all extended government frameworks
func (m *Manager) loadExtendedGovernmentFrameworks() {
	m.RegisterFramework(m.buildCMMCFramework())
	m.RegisterFramework(m.buildITARFramework())
	m.RegisterFramework(m.buildEARFramework())
	m.RegisterFramework(m.buildDFARSFramework())
	m.RegisterFramework(m.buildNIST800171Framework())
	m.RegisterFramework(m.buildStateRAMPFramework())
	m.RegisterFramework(m.buildCJISFramework())
}

