// Package compliance provides compliance framework mapping and assessment
package compliance

// buildCISFramework builds CIS Benchmarks framework
func (m *Manager) buildCISFramework() *Framework {
	return &Framework{
		ID:          "cis-benchmarks",
		Name:        "CIS Benchmarks",
		Version:     "v8.0",
		Description: "Center for Internet Security Benchmarks",
		Sector:      SectorGeneral,
		URL:         "https://www.cisecurity.org/cis-benchmarks",
		Controls: map[string]*Control{
			"1.1": {ID: "1.1", Title: "Inventory and Control of Enterprise Assets", Section: "1", Category: "Asset Management",
				Severity: "high", Keywords: []string{"inventory", "asset", "hardware", "software"}},
			"2.1": {ID: "2.1", Title: "Inventory and Control of Software Assets", Section: "2", Category: "Software Management",
				Severity: "high", Keywords: []string{"software", "application", "inventory"}},
			"3.1": {ID: "3.1", Title: "Data Protection", Section: "3", Category: "Data Protection",
				Severity: "critical", Keywords: []string{"encryption", "data", "protect", "sensitive"}},
			"4.1": {ID: "4.1", Title: "Secure Configuration of Enterprise Assets", Section: "4", Category: "Configuration",
				Severity: "high", Keywords: []string{"configuration", "hardening", "baseline"}},
			"5.1": {ID: "5.1", Title: "Account Management", Section: "5", Category: "Access Control",
				Severity: "critical", Keywords: []string{"account", "user", "access", "identity", "iam"}},
			"6.1": {ID: "6.1", Title: "Access Control Management", Section: "6", Category: "Access Control",
				Severity: "critical", Keywords: []string{"access", "permission", "privilege", "rbac"}},
			"7.1": {ID: "7.1", Title: "Continuous Vulnerability Management", Section: "7", Category: "Vulnerability",
				Severity: "high", Keywords: []string{"vulnerability", "patch", "cve", "scan"}},
			"8.1": {ID: "8.1", Title: "Audit Log Management", Section: "8", Category: "Logging",
				Severity: "high", Keywords: []string{"log", "audit", "monitoring", "trail"}},
			"9.1": {ID: "9.1", Title: "Email and Web Browser Protections", Section: "9", Category: "Network",
				Severity: "medium", Keywords: []string{"email", "browser", "phishing"}},
			"10.1": {ID: "10.1", Title: "Malware Defenses", Section: "10", Category: "Malware",
				Severity: "high", Keywords: []string{"malware", "antivirus", "edr"}},
			"11.1": {ID: "11.1", Title: "Data Recovery", Section: "11", Category: "Backup",
				Severity: "high", Keywords: []string{"backup", "recovery", "disaster"}},
			"12.1": {ID: "12.1", Title: "Network Infrastructure Management", Section: "12", Category: "Network",
				Severity: "high", Keywords: []string{"network", "firewall", "segmentation"}},
			"13.1": {ID: "13.1", Title: "Network Monitoring and Defense", Section: "13", Category: "Monitoring",
				Severity: "high", Keywords: []string{"ids", "ips", "detection", "monitoring"}},
			"14.1": {ID: "14.1", Title: "Security Awareness Training", Section: "14", Category: "Training",
				Severity: "medium", Keywords: []string{"training", "awareness", "phishing"}},
			"15.1": {ID: "15.1", Title: "Service Provider Management", Section: "15", Category: "Third Party",
				Severity: "medium", Keywords: []string{"vendor", "supplier", "third-party"}},
			"16.1": {ID: "16.1", Title: "Application Software Security", Section: "16", Category: "AppSec",
				Severity: "high", Keywords: []string{"application", "secure", "development", "sdlc"}},
			"17.1": {ID: "17.1", Title: "Incident Response Management", Section: "17", Category: "IR",
				Severity: "high", Keywords: []string{"incident", "response", "breach"}},
			"18.1": {ID: "18.1", Title: "Penetration Testing", Section: "18", Category: "Testing",
				Severity: "medium", Keywords: []string{"pentest", "penetration", "assessment"}},
		},
	}
}

// buildNIST80053Framework builds NIST 800-53 framework
func (m *Manager) buildNIST80053Framework() *Framework {
	return &Framework{
		ID:          "nist-800-53",
		Name:        "NIST SP 800-53",
		Version:     "Rev 5",
		Description: "Security and Privacy Controls for Information Systems",
		Sector:      SectorGovernment,
		URL:         "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final",
		Controls: map[string]*Control{
			"AC-1":  {ID: "AC-1", Title: "Access Control Policy", Section: "AC", Category: "Access Control", Severity: "high", Keywords: []string{"access", "policy"}},
			"AC-2":  {ID: "AC-2", Title: "Account Management", Section: "AC", Category: "Access Control", Severity: "high", Keywords: []string{"account", "user", "management"}},
			"AC-3":  {ID: "AC-3", Title: "Access Enforcement", Section: "AC", Category: "Access Control", Severity: "critical", Keywords: []string{"access", "enforcement", "permission"}},
			"AC-6":  {ID: "AC-6", Title: "Least Privilege", Section: "AC", Category: "Access Control", Severity: "critical", Keywords: []string{"privilege", "least", "minimal"}},
			"AU-2":  {ID: "AU-2", Title: "Audit Events", Section: "AU", Category: "Audit", Severity: "high", Keywords: []string{"audit", "log", "event"}},
			"AU-6":  {ID: "AU-6", Title: "Audit Review", Section: "AU", Category: "Audit", Severity: "medium", Keywords: []string{"audit", "review", "analysis"}},
			"CA-7":  {ID: "CA-7", Title: "Continuous Monitoring", Section: "CA", Category: "Assessment", Severity: "high", Keywords: []string{"monitoring", "continuous"}},
			"CM-2":  {ID: "CM-2", Title: "Baseline Configuration", Section: "CM", Category: "Configuration", Severity: "high", Keywords: []string{"baseline", "configuration"}},
			"CM-6":  {ID: "CM-6", Title: "Configuration Settings", Section: "CM", Category: "Configuration", Severity: "high", Keywords: []string{"configuration", "settings", "hardening"}},
			"CP-9":  {ID: "CP-9", Title: "System Backup", Section: "CP", Category: "Contingency", Severity: "high", Keywords: []string{"backup", "recovery"}},
			"IA-2":  {ID: "IA-2", Title: "User Identification", Section: "IA", Category: "Identification", Severity: "critical", Keywords: []string{"authentication", "mfa", "identity"}},
			"IA-5":  {ID: "IA-5", Title: "Authenticator Management", Section: "IA", Category: "Identification", Severity: "critical", Keywords: []string{"password", "credential", "secret"}},
			"IR-4":  {ID: "IR-4", Title: "Incident Handling", Section: "IR", Category: "Incident Response", Severity: "high", Keywords: []string{"incident", "response", "handling"}},
			"RA-5":  {ID: "RA-5", Title: "Vulnerability Monitoring", Section: "RA", Category: "Risk Assessment", Severity: "high", Keywords: []string{"vulnerability", "scan", "assessment"}},
			"SC-7":  {ID: "SC-7", Title: "Boundary Protection", Section: "SC", Category: "System Protection", Severity: "critical", Keywords: []string{"firewall", "boundary", "network"}},
			"SC-8":  {ID: "SC-8", Title: "Transmission Confidentiality", Section: "SC", Category: "System Protection", Severity: "high", Keywords: []string{"encryption", "tls", "transit"}},
			"SC-28": {ID: "SC-28", Title: "Protection of Information at Rest", Section: "SC", Category: "System Protection", Severity: "high", Keywords: []string{"encryption", "rest", "storage"}},
			"SI-2":  {ID: "SI-2", Title: "Flaw Remediation", Section: "SI", Category: "System Integrity", Severity: "high", Keywords: []string{"patch", "remediation", "update"}},
			"SI-3":  {ID: "SI-3", Title: "Malicious Code Protection", Section: "SI", Category: "System Integrity", Severity: "high", Keywords: []string{"malware", "antivirus"}},
		},
	}
}

// buildNISTCSFFramework builds NIST Cybersecurity Framework
func (m *Manager) buildNISTCSFFramework() *Framework {
	return &Framework{
		ID:          "nist-csf",
		Name:        "NIST Cybersecurity Framework",
		Version:     "2.0",
		Description: "Framework for Improving Critical Infrastructure Cybersecurity",
		Sector:      SectorGeneral,
		URL:         "https://www.nist.gov/cyberframework",
		Controls: map[string]*Control{
			"ID.AM": {ID: "ID.AM", Title: "Asset Management", Section: "Identify", Category: "Asset", Severity: "high", Keywords: []string{"asset", "inventory"}},
			"ID.RA": {ID: "ID.RA", Title: "Risk Assessment", Section: "Identify", Category: "Risk", Severity: "high", Keywords: []string{"risk", "assessment"}},
			"PR.AC": {ID: "PR.AC", Title: "Access Control", Section: "Protect", Category: "Access", Severity: "critical", Keywords: []string{"access", "control", "identity"}},
			"PR.DS": {ID: "PR.DS", Title: "Data Security", Section: "Protect", Category: "Data", Severity: "critical", Keywords: []string{"data", "encryption", "protection"}},
			"PR.IP": {ID: "PR.IP", Title: "Information Protection", Section: "Protect", Category: "Protection", Severity: "high", Keywords: []string{"configuration", "baseline"}},
			"PR.PT": {ID: "PR.PT", Title: "Protective Technology", Section: "Protect", Category: "Technology", Severity: "high", Keywords: []string{"network", "firewall", "security"}},
			"DE.AE": {ID: "DE.AE", Title: "Anomalies and Events", Section: "Detect", Category: "Detection", Severity: "high", Keywords: []string{"anomaly", "detection", "monitoring"}},
			"DE.CM": {ID: "DE.CM", Title: "Continuous Monitoring", Section: "Detect", Category: "Monitoring", Severity: "high", Keywords: []string{"monitoring", "continuous", "log"}},
			"RS.RP": {ID: "RS.RP", Title: "Response Planning", Section: "Respond", Category: "Response", Severity: "high", Keywords: []string{"incident", "response", "plan"}},
			"RC.RP": {ID: "RC.RP", Title: "Recovery Planning", Section: "Recover", Category: "Recovery", Severity: "high", Keywords: []string{"recovery", "disaster", "backup"}},
		},
	}
}

// buildNISTAIRMFFramework builds NIST AI Risk Management Framework
func (m *Manager) buildNISTAIRMFFramework() *Framework {
	return &Framework{
		ID:          "nist-ai-rmf",
		Name:        "NIST AI Risk Management Framework",
		Version:     "1.0",
		Description: "Framework for AI Risk Management",
		Sector:      SectorAI,
		URL:         "https://www.nist.gov/itl/ai-risk-management-framework",
		Controls: map[string]*Control{
			"GOV.1": {ID: "GOV.1", Title: "AI Governance", Section: "Govern", Category: "Governance", Severity: "high", Keywords: []string{"ai", "governance", "policy"}},
			"GOV.2": {ID: "GOV.2", Title: "AI Risk Culture", Section: "Govern", Category: "Governance", Severity: "medium", Keywords: []string{"ai", "risk", "culture"}},
			"MAP.1": {ID: "MAP.1", Title: "AI System Context", Section: "Map", Category: "Mapping", Severity: "high", Keywords: []string{"ai", "context", "use case"}},
			"MAP.2": {ID: "MAP.2", Title: "AI Categorization", Section: "Map", Category: "Mapping", Severity: "medium", Keywords: []string{"ai", "categorization", "classification"}},
			"MEA.1": {ID: "MEA.1", Title: "AI Metrics", Section: "Measure", Category: "Measurement", Severity: "high", Keywords: []string{"ai", "metrics", "performance"}},
			"MEA.2": {ID: "MEA.2", Title: "AI Testing", Section: "Measure", Category: "Testing", Severity: "high", Keywords: []string{"ai", "testing", "validation"}},
			"MAN.1": {ID: "MAN.1", Title: "AI Risk Response", Section: "Manage", Category: "Management", Severity: "high", Keywords: []string{"ai", "risk", "response"}},
			"MAN.2": {ID: "MAN.2", Title: "AI Lifecycle Management", Section: "Manage", Category: "Lifecycle", Severity: "medium", Keywords: []string{"ai", "lifecycle", "deployment"}},
		},
	}
}

// buildISO27001Framework builds ISO 27001 framework
func (m *Manager) buildISO27001Framework() *Framework {
	return &Framework{
		ID:          "iso-27001",
		Name:        "ISO/IEC 27001:2022",
		Version:     "2022",
		Description: "Information Security Management System",
		Sector:      SectorGeneral,
		URL:         "https://www.iso.org/standard/27001",
		Controls: map[string]*Control{
			"A.5.1":  {ID: "A.5.1", Title: "Policies for Information Security", Section: "A.5", Category: "Organizational", Severity: "high", Keywords: []string{"policy", "security"}},
			"A.5.15": {ID: "A.5.15", Title: "Access Control", Section: "A.5", Category: "Organizational", Severity: "critical", Keywords: []string{"access", "control"}},
			"A.5.23": {ID: "A.5.23", Title: "Information Security for Cloud Services", Section: "A.5", Category: "Organizational", Severity: "high", Keywords: []string{"cloud", "security"}},
			"A.6.1":  {ID: "A.6.1", Title: "Screening", Section: "A.6", Category: "People", Severity: "medium", Keywords: []string{"background", "screening"}},
			"A.7.9":  {ID: "A.7.9", Title: "Security of Assets Off-premises", Section: "A.7", Category: "Physical", Severity: "medium", Keywords: []string{"physical", "asset"}},
			"A.8.2":  {ID: "A.8.2", Title: "Privileged Access Rights", Section: "A.8", Category: "Technological", Severity: "critical", Keywords: []string{"privileged", "access", "admin"}},
			"A.8.5":  {ID: "A.8.5", Title: "Secure Authentication", Section: "A.8", Category: "Technological", Severity: "critical", Keywords: []string{"authentication", "mfa"}},
			"A.8.9":  {ID: "A.8.9", Title: "Configuration Management", Section: "A.8", Category: "Technological", Severity: "high", Keywords: []string{"configuration", "baseline"}},
			"A.8.12": {ID: "A.8.12", Title: "Data Leakage Prevention", Section: "A.8", Category: "Technological", Severity: "high", Keywords: []string{"dlp", "data", "leakage"}},
			"A.8.15": {ID: "A.8.15", Title: "Logging", Section: "A.8", Category: "Technological", Severity: "high", Keywords: []string{"log", "audit"}},
			"A.8.20": {ID: "A.8.20", Title: "Networks Security", Section: "A.8", Category: "Technological", Severity: "high", Keywords: []string{"network", "firewall"}},
			"A.8.24": {ID: "A.8.24", Title: "Use of Cryptography", Section: "A.8", Category: "Technological", Severity: "high", Keywords: []string{"encryption", "cryptography"}},
			"A.8.28": {ID: "A.8.28", Title: "Secure Coding", Section: "A.8", Category: "Technological", Severity: "high", Keywords: []string{"secure", "coding", "development"}},
		},
	}
}

// buildISO27017Framework builds ISO 27017 (cloud security) framework
func (m *Manager) buildISO27017Framework() *Framework {
	return &Framework{
		ID:          "iso-27017",
		Name:        "ISO/IEC 27017:2015",
		Version:     "2015",
		Description: "Cloud Security Controls",
		Sector:      SectorGeneral,
		URL:         "https://www.iso.org/standard/43757.html",
		Controls: map[string]*Control{
			"CLD.6.3":  {ID: "CLD.6.3", Title: "Cloud Service Customer Responsibilities", Section: "CLD.6", Category: "Cloud", Severity: "high", Keywords: []string{"cloud", "responsibility"}},
			"CLD.8.1":  {ID: "CLD.8.1", Title: "Virtual Machine Hardening", Section: "CLD.8", Category: "Cloud", Severity: "high", Keywords: []string{"vm", "virtual", "hardening"}},
			"CLD.9.5":  {ID: "CLD.9.5", Title: "Cloud Resource Isolation", Section: "CLD.9", Category: "Cloud", Severity: "critical", Keywords: []string{"isolation", "segmentation"}},
			"CLD.12.1": {ID: "CLD.12.1", Title: "Cloud Audit Logging", Section: "CLD.12", Category: "Cloud", Severity: "high", Keywords: []string{"cloud", "audit", "log"}},
		},
	}
}

// buildISO42001Framework builds ISO 42001 (AI management) framework
func (m *Manager) buildISO42001Framework() *Framework {
	return &Framework{
		ID:          "iso-42001",
		Name:        "ISO/IEC 42001:2023",
		Version:     "2023",
		Description: "AI Management System",
		Sector:      SectorAI,
		URL:         "https://www.iso.org/standard/81230.html",
		Controls: map[string]*Control{
			"5.1": {ID: "5.1", Title: "AI System Leadership", Section: "5", Category: "Leadership", Severity: "high", Keywords: []string{"ai", "leadership", "governance"}},
			"6.1": {ID: "6.1", Title: "AI Risk Management", Section: "6", Category: "Planning", Severity: "high", Keywords: []string{"ai", "risk", "management"}},
			"7.2": {ID: "7.2", Title: "AI Competence", Section: "7", Category: "Support", Severity: "medium", Keywords: []string{"ai", "competence", "training"}},
			"8.2": {ID: "8.2", Title: "AI Development Requirements", Section: "8", Category: "Operation", Severity: "high", Keywords: []string{"ai", "development", "lifecycle"}},
			"8.4": {ID: "8.4", Title: "AI System Verification", Section: "8", Category: "Operation", Severity: "high", Keywords: []string{"ai", "verification", "validation"}},
			"9.1": {ID: "9.1", Title: "AI Performance Monitoring", Section: "9", Category: "Evaluation", Severity: "high", Keywords: []string{"ai", "monitoring", "performance"}},
		},
	}
}

// buildPCIDSSFramework builds PCI-DSS framework
func (m *Manager) buildPCIDSSFramework() *Framework {
	return &Framework{
		ID:          "pci-dss",
		Name:        "PCI DSS",
		Version:     "4.0",
		Description: "Payment Card Industry Data Security Standard",
		Sector:      SectorFinance,
		URL:         "https://www.pcisecuritystandards.org/",
		Controls: map[string]*Control{
			"1.1":  {ID: "1.1", Title: "Network Security Controls", Section: "1", Category: "Network", Severity: "critical", Keywords: []string{"firewall", "network", "security"}},
			"2.1":  {ID: "2.1", Title: "Secure Configurations", Section: "2", Category: "Configuration", Severity: "high", Keywords: []string{"configuration", "default", "hardening"}},
			"3.1":  {ID: "3.1", Title: "Protect Stored Account Data", Section: "3", Category: "Data Protection", Severity: "critical", Keywords: []string{"encryption", "cardholder", "pan", "storage"}},
			"4.1":  {ID: "4.1", Title: "Protect Cardholder Data in Transit", Section: "4", Category: "Data Protection", Severity: "critical", Keywords: []string{"encryption", "tls", "transit"}},
			"5.1":  {ID: "5.1", Title: "Protect from Malicious Software", Section: "5", Category: "Malware", Severity: "high", Keywords: []string{"antivirus", "malware"}},
			"6.1":  {ID: "6.1", Title: "Secure Development", Section: "6", Category: "Application", Severity: "high", Keywords: []string{"development", "secure", "sdlc"}},
			"6.2":  {ID: "6.2", Title: "Security Vulnerabilities", Section: "6", Category: "Vulnerability", Severity: "critical", Keywords: []string{"vulnerability", "patch", "cve"}},
			"7.1":  {ID: "7.1", Title: "Restrict Access", Section: "7", Category: "Access Control", Severity: "critical", Keywords: []string{"access", "least privilege", "need-to-know"}},
			"8.1":  {ID: "8.1", Title: "Identify and Authenticate", Section: "8", Category: "Authentication", Severity: "critical", Keywords: []string{"authentication", "mfa", "password"}},
			"9.1":  {ID: "9.1", Title: "Physical Access", Section: "9", Category: "Physical", Severity: "high", Keywords: []string{"physical", "access"}},
			"10.1": {ID: "10.1", Title: "Log and Monitor Access", Section: "10", Category: "Logging", Severity: "critical", Keywords: []string{"log", "audit", "monitoring"}},
			"11.1": {ID: "11.1", Title: "Test Security Regularly", Section: "11", Category: "Testing", Severity: "high", Keywords: []string{"test", "vulnerability", "scan"}},
			"12.1": {ID: "12.1", Title: "Security Policy", Section: "12", Category: "Policy", Severity: "high", Keywords: []string{"policy", "security"}},
		},
	}
}

// buildAWSSecurityBestPracticesFramework builds AWS Security Best Practices
func (m *Manager) buildAWSSecurityBestPracticesFramework() *Framework {
	return &Framework{
		ID:          "aws-security-bp",
		Name:        "AWS Security Best Practices",
		Version:     "2024",
		Description: "AWS Well-Architected Security Pillar",
		Sector:      SectorGeneral,
		URL:         "https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/",
		Controls: map[string]*Control{
			"SEC01": {ID: "SEC01", Title: "Implement Strong Identity Foundation", Section: "Identity", Category: "IAM", Severity: "critical", Keywords: []string{"iam", "identity", "mfa", "root"}},
			"SEC02": {ID: "SEC02", Title: "Enable Traceability", Section: "Detection", Category: "Logging", Severity: "high", Keywords: []string{"cloudtrail", "log", "audit"}},
			"SEC03": {ID: "SEC03", Title: "Apply Security at All Layers", Section: "Infrastructure", Category: "Network", Severity: "high", Keywords: []string{"vpc", "security group", "nacl"}},
			"SEC04": {ID: "SEC04", Title: "Automate Security Best Practices", Section: "Automation", Category: "Automation", Severity: "medium", Keywords: []string{"automation", "config", "guarduty"}},
			"SEC05": {ID: "SEC05", Title: "Protect Data in Transit", Section: "Data", Category: "Encryption", Severity: "high", Keywords: []string{"encryption", "tls", "ssl", "transit"}},
			"SEC06": {ID: "SEC06", Title: "Protect Data at Rest", Section: "Data", Category: "Encryption", Severity: "high", Keywords: []string{"encryption", "kms", "s3", "ebs"}},
			"SEC07": {ID: "SEC07", Title: "Prepare for Security Events", Section: "Incident", Category: "IR", Severity: "high", Keywords: []string{"incident", "response", "security hub"}},
		},
	}
}

// buildGCPCISFramework builds GCP CIS Benchmark
func (m *Manager) buildGCPCISFramework() *Framework {
	return &Framework{
		ID:          "gcp-cis",
		Name:        "CIS Google Cloud Platform Foundation",
		Version:     "2.0",
		Description: "CIS Benchmark for Google Cloud Platform",
		Sector:      SectorGeneral,
		URL:         "https://www.cisecurity.org/benchmark/google_cloud_computing_platform",
		Controls: map[string]*Control{
			"1.1":  {ID: "1.1", Title: "IAM Policies", Section: "1", Category: "IAM", Severity: "critical", Keywords: []string{"iam", "service account", "role"}},
			"1.4":  {ID: "1.4", Title: "Service Account Keys", Section: "1", Category: "IAM", Severity: "high", Keywords: []string{"service account", "key", "rotation"}},
			"2.1":  {ID: "2.1", Title: "Cloud Logging", Section: "2", Category: "Logging", Severity: "high", Keywords: []string{"logging", "audit", "stackdriver"}},
			"3.1":  {ID: "3.1", Title: "VPC Networking", Section: "3", Category: "Network", Severity: "high", Keywords: []string{"vpc", "firewall", "network"}},
			"4.1":  {ID: "4.1", Title: "Compute Engine", Section: "4", Category: "Compute", Severity: "high", Keywords: []string{"compute", "vm", "instance"}},
			"5.1":  {ID: "5.1", Title: "Cloud Storage", Section: "5", Category: "Storage", Severity: "critical", Keywords: []string{"storage", "bucket", "public"}},
			"6.1":  {ID: "6.1", Title: "Cloud SQL", Section: "6", Category: "Database", Severity: "high", Keywords: []string{"sql", "database", "mysql", "postgres"}},
			"7.1":  {ID: "7.1", Title: "BigQuery", Section: "7", Category: "Data", Severity: "high", Keywords: []string{"bigquery", "data", "analytics"}},
		},
	}
}

// buildAzureMCSBFramework builds Azure MCSB (Microsoft Cloud Security Benchmark)
func (m *Manager) buildAzureMCSBFramework() *Framework {
	return &Framework{
		ID:          "azure-mcsb",
		Name:        "Microsoft Cloud Security Benchmark",
		Version:     "v1",
		Description: "Azure Security Baseline",
		Sector:      SectorGeneral,
		URL:         "https://learn.microsoft.com/en-us/security/benchmark/azure/",
		Controls: map[string]*Control{
			"NS-1":  {ID: "NS-1", Title: "Network Security", Section: "NS", Category: "Network", Severity: "high", Keywords: []string{"nsg", "firewall", "network"}},
			"IM-1":  {ID: "IM-1", Title: "Identity Management", Section: "IM", Category: "Identity", Severity: "critical", Keywords: []string{"azure ad", "entra", "identity", "mfa"}},
			"PA-1":  {ID: "PA-1", Title: "Privileged Access", Section: "PA", Category: "Access", Severity: "critical", Keywords: []string{"pim", "privileged", "admin"}},
			"DP-1":  {ID: "DP-1", Title: "Data Protection", Section: "DP", Category: "Data", Severity: "high", Keywords: []string{"encryption", "key vault", "data"}},
			"AM-1":  {ID: "AM-1", Title: "Asset Management", Section: "AM", Category: "Asset", Severity: "medium", Keywords: []string{"asset", "inventory", "resource"}},
			"LT-1":  {ID: "LT-1", Title: "Logging and Threat Detection", Section: "LT", Category: "Logging", Severity: "high", Keywords: []string{"monitor", "log", "sentinel"}},
			"IR-1":  {ID: "IR-1", Title: "Incident Response", Section: "IR", Category: "IR", Severity: "high", Keywords: []string{"incident", "response", "defender"}},
			"PV-1":  {ID: "PV-1", Title: "Posture and Vulnerability Management", Section: "PV", Category: "Vulnerability", Severity: "high", Keywords: []string{"vulnerability", "defender", "scan"}},
			"ES-1":  {ID: "ES-1", Title: "Endpoint Security", Section: "ES", Category: "Endpoint", Severity: "high", Keywords: []string{"endpoint", "defender", "edr"}},
			"BR-1":  {ID: "BR-1", Title: "Backup and Recovery", Section: "BR", Category: "Backup", Severity: "high", Keywords: []string{"backup", "recovery", "vault"}},
			"DS-1":  {ID: "DS-1", Title: "DevOps Security", Section: "DS", Category: "DevOps", Severity: "high", Keywords: []string{"devops", "pipeline", "cicd"}},
			"GS-1":  {ID: "GS-1", Title: "Governance and Strategy", Section: "GS", Category: "Governance", Severity: "medium", Keywords: []string{"governance", "policy", "blueprint"}},
		},
	}
}

