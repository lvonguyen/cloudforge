package scoring

import (
	"fmt"
	"strings"
)

// ToxicComboType identifies the category of a toxic combination.
type ToxicComboType string

const (
	// ComboPublicStorageSensitiveData: public S3/Blob storage + sensitive data tags.
	ComboPublicStorageSensitiveData ToxicComboType = "PUBLIC_STORAGE_SENSITIVE_DATA"

	// ComboIAMAdminNoMFA: IAM admin permissions without MFA enforcement.
	ComboIAMAdminNoMFA ToxicComboType = "IAM_ADMIN_NO_MFA"

	// ComboInternetFacingUnpatchedCVE: internet-facing resource + unpatched CVE with high EPSS.
	ComboInternetFacingUnpatchedCVE ToxicComboType = "INTERNET_FACING_UNPATCHED_CVE"

	// ComboPermissiveSGDatabase: overly permissive security group + database resource.
	ComboPermissiveSGDatabase ToxicComboType = "PERMISSIVE_SG_DATABASE"
)

// ToxicCombination describes a dangerous multi-finding pattern that elevates
// overall risk beyond what individual finding scores indicate.
type ToxicCombination struct {
	// FindingIDs lists the IDs of findings involved in this combination.
	FindingIDs []string `json:"finding_ids"`

	// ComboType classifies the kind of toxic combination detected.
	ComboType ToxicComboType `json:"combo_type"`

	// RiskMultiplier is the factor applied to risk scores for involved findings.
	// A value of 2.0 means the effective risk is doubled.
	RiskMultiplier float64 `json:"risk_multiplier"`

	// Reason provides a human-readable explanation for the combination.
	Reason string `json:"reason"`
}

// ToxicComboDetector identifies dangerous multi-finding combinations.
type ToxicComboDetector struct{}

// NewToxicComboDetector creates a new detector.
func NewToxicComboDetector() *ToxicComboDetector {
	return &ToxicComboDetector{}
}

// DetectToxicCombinations scans a set of findings for dangerous multi-finding
// patterns. Each detected pattern returns a ToxicCombination describing the
// involved findings, combo type, and risk multiplier.
func (d *ToxicComboDetector) DetectToxicCombinations(findings []Finding) []ToxicCombination {
	var combos []ToxicCombination

	combos = append(combos, d.detectPublicStorageSensitiveData(findings)...)
	combos = append(combos, d.detectIAMAdminNoMFA(findings)...)
	combos = append(combos, d.detectInternetFacingUnpatchedCVE(findings)...)
	combos = append(combos, d.detectPermissiveSGDatabase(findings)...)

	return combos
}

// detectPublicStorageSensitiveData finds public S3/Blob + sensitive data tag combinations.
// A public storage finding paired with a sensitive-data-classified finding on the
// same account creates a high-risk data exfiltration path.
func (d *ToxicComboDetector) detectPublicStorageSensitiveData(findings []Finding) []ToxicCombination {
	var combos []ToxicCombination

	// Index public storage findings by account.
	publicStorage := make(map[string][]Finding)
	sensitiveData := make(map[string][]Finding)

	for _, f := range findings {
		if isPublicStorageFinding(f) {
			publicStorage[f.AccountID] = append(publicStorage[f.AccountID], f)
		}
		if isSensitiveDataFinding(f) {
			sensitiveData[f.AccountID] = append(sensitiveData[f.AccountID], f)
		}
	}

	for acct, pubFindings := range publicStorage {
		sensFindings, ok := sensitiveData[acct]
		if !ok {
			continue
		}
		for _, pub := range pubFindings {
			for _, sens := range sensFindings {
				if pub.ID == sens.ID {
					continue
				}
				combos = append(combos, ToxicCombination{
					FindingIDs:     []string{pub.ID, sens.ID},
					ComboType:      ComboPublicStorageSensitiveData,
					RiskMultiplier: 2.5,
					Reason: fmt.Sprintf(
						"Public storage (%s) in same account as sensitive data (%s classification) creates data exfiltration risk",
						pub.ResourceType, sens.Context.DataClassification,
					),
				})
			}
		}
	}

	return combos
}

// detectIAMAdminNoMFA finds IAM admin + no-MFA combinations within the same account.
func (d *ToxicComboDetector) detectIAMAdminNoMFA(findings []Finding) []ToxicCombination {
	var combos []ToxicCombination

	adminFindings := make(map[string][]Finding)
	noMFAFindings := make(map[string][]Finding)

	for _, f := range findings {
		if isIAMAdminFinding(f) {
			adminFindings[f.AccountID] = append(adminFindings[f.AccountID], f)
		}
		if isNoMFAFinding(f) {
			noMFAFindings[f.AccountID] = append(noMFAFindings[f.AccountID], f)
		}
	}

	for acct, admins := range adminFindings {
		mfas, ok := noMFAFindings[acct]
		if !ok {
			continue
		}
		for _, admin := range admins {
			for _, mfa := range mfas {
				if admin.ID == mfa.ID {
					continue
				}
				combos = append(combos, ToxicCombination{
					FindingIDs:     []string{admin.ID, mfa.ID},
					ComboType:      ComboIAMAdminNoMFA,
					RiskMultiplier: 3.0,
					Reason:         "IAM admin permissions without MFA enforcement enables credential-based account takeover",
				})
			}
		}
	}

	return combos
}

// detectInternetFacingUnpatchedCVE finds internet-facing + unpatched high-EPSS CVE combinations.
func (d *ToxicComboDetector) detectInternetFacingUnpatchedCVE(findings []Finding) []ToxicCombination {
	var combos []ToxicCombination

	internetFacing := make(map[string][]Finding) // keyed by accountID
	unpatchedCVE := make(map[string][]Finding)

	for _, f := range findings {
		if f.Context.InternetFacing {
			internetFacing[f.AccountID] = append(internetFacing[f.AccountID], f)
		}
		if isHighEPSSUnpatchedCVE(f) {
			unpatchedCVE[f.AccountID] = append(unpatchedCVE[f.AccountID], f)
		}
	}

	for acct, inetFindings := range internetFacing {
		cveFindings, ok := unpatchedCVE[acct]
		if !ok {
			continue
		}
		for _, inet := range inetFindings {
			for _, cve := range cveFindings {
				if inet.ID == cve.ID {
					continue
				}
				combos = append(combos, ToxicCombination{
					FindingIDs:     []string{inet.ID, cve.ID},
					ComboType:      ComboInternetFacingUnpatchedCVE,
					RiskMultiplier: 2.0,
					Reason: fmt.Sprintf(
						"Internet-facing resource in same account as unpatched CVE (EPSS %.4f) creates remote exploitation path",
						cve.Context.EPSSScore,
					),
				})
			}
		}
	}

	return combos
}

// detectPermissiveSGDatabase finds overly permissive security group + database resource combinations.
func (d *ToxicComboDetector) detectPermissiveSGDatabase(findings []Finding) []ToxicCombination {
	var combos []ToxicCombination

	permissiveSG := make(map[string][]Finding)
	dbFindings := make(map[string][]Finding)

	for _, f := range findings {
		if isPermissiveSecurityGroupFinding(f) {
			permissiveSG[f.AccountID] = append(permissiveSG[f.AccountID], f)
		}
		if isDatabaseResourceFinding(f) {
			dbFindings[f.AccountID] = append(dbFindings[f.AccountID], f)
		}
	}

	for acct, sgFindings := range permissiveSG {
		dbs, ok := dbFindings[acct]
		if !ok {
			continue
		}
		for _, sg := range sgFindings {
			for _, db := range dbs {
				if sg.ID == db.ID {
					continue
				}
				combos = append(combos, ToxicCombination{
					FindingIDs:     []string{sg.ID, db.ID},
					ComboType:      ComboPermissiveSGDatabase,
					RiskMultiplier: 2.0,
					Reason:         "Overly permissive security group in same account as database resource exposes data stores to unauthorized access",
				})
			}
		}
	}

	return combos
}

// --- Classification helpers ---

func isPublicStorageFinding(f Finding) bool {
	ft := strings.ToUpper(f.FindingType)
	rt := strings.ToLower(f.ResourceType)
	return strings.Contains(ft, "PUBLIC") &&
		(strings.Contains(rt, "s3") || strings.Contains(rt, "bucket") ||
			strings.Contains(rt, "blob") || strings.Contains(rt, "storage"))
}

func isSensitiveDataFinding(f Finding) bool {
	dc := strings.ToUpper(f.Context.DataClassification)
	return dc == "PCI" || dc == "PII" || dc == "PHI"
}

func isIAMAdminFinding(f Finding) bool {
	ft := strings.ToUpper(f.FindingType)
	return f.Context.HasAdminPermissions ||
		strings.Contains(ft, "ADMIN") ||
		strings.Contains(ft, "IAM_POLICY_FULL_ACCESS") ||
		strings.Contains(ft, "OVERLY_PERMISSIVE")
}

func isNoMFAFinding(f Finding) bool {
	ft := strings.ToUpper(f.FindingType)
	return !f.Context.MFARequired &&
		(strings.Contains(ft, "NO_MFA") || strings.Contains(ft, "MFA_DISABLED") ||
			strings.Contains(ft, "MFA_NOT_ENABLED"))
}

func isHighEPSSUnpatchedCVE(f Finding) bool {
	return f.Context.EPSSScore > 0.5 && !f.Context.PatchAvailable &&
		strings.Contains(strings.ToUpper(f.FindingType), "CVE")
}

func isPermissiveSecurityGroupFinding(f Finding) bool {
	ft := strings.ToUpper(f.FindingType)
	return strings.Contains(ft, "SECURITY_GROUP") &&
		(strings.Contains(ft, "OPEN") || strings.Contains(ft, "UNRESTRICTED") ||
			strings.Contains(ft, "WIDE") || strings.Contains(ft, "PERMISSIVE") ||
			strings.Contains(ft, "0.0.0.0"))
}

func isDatabaseResourceFinding(f Finding) bool {
	rt := strings.ToLower(f.ResourceType)
	return strings.Contains(rt, "rds") || strings.Contains(rt, "database") ||
		strings.Contains(rt, "dynamodb") || strings.Contains(rt, "sql") ||
		strings.Contains(rt, "cosmosdb") || strings.Contains(rt, "aurora") ||
		strings.Contains(rt, "redshift") || strings.Contains(rt, "spanner")
}
