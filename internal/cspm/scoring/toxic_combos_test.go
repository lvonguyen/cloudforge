package scoring

import (
	"testing"
)

// --- Tests for DetectToxicCombinations: Public Storage + Sensitive Data ---

func TestToxicCombo_PublicStorage_SensitiveData_Detected(t *testing.T) {
	detector := NewToxicComboDetector()

	findings := []Finding{
		{
			ID:           "pub-s3-001",
			AccountID:    "acct-1",
			FindingType:  "S3_BUCKET_PUBLIC_READ",
			ResourceType: "AWS::S3::Bucket",
		},
		{
			ID:           "pci-data-001",
			AccountID:    "acct-1",
			FindingType:  "DATA_EXPOSURE",
			ResourceType: "AWS::DynamoDB::Table",
			Context:      FindingContext{DataClassification: "PCI"},
		},
	}

	combos := detector.DetectToxicCombinations(findings)

	found := false
	for _, c := range combos {
		if c.ComboType == ComboPublicStorageSensitiveData {
			found = true
			if c.RiskMultiplier < 2.0 {
				t.Errorf("expected risk multiplier >= 2.0, got %.1f", c.RiskMultiplier)
			}
			if len(c.FindingIDs) != 2 {
				t.Errorf("expected 2 finding IDs, got %d", len(c.FindingIDs))
			}
		}
	}
	if !found {
		t.Error("expected PUBLIC_STORAGE_SENSITIVE_DATA combo to be detected")
	}
}

func TestToxicCombo_PublicStorage_DifferentAccount_NotDetected(t *testing.T) {
	detector := NewToxicComboDetector()

	findings := []Finding{
		{
			ID:           "pub-s3-002",
			AccountID:    "acct-1",
			FindingType:  "S3_BUCKET_PUBLIC_READ",
			ResourceType: "AWS::S3::Bucket",
		},
		{
			ID:           "pci-data-002",
			AccountID:    "acct-2", // different account
			FindingType:  "DATA_EXPOSURE",
			ResourceType: "AWS::S3::Bucket",
			Context:      FindingContext{DataClassification: "PII"},
		},
	}

	combos := detector.DetectToxicCombinations(findings)

	for _, c := range combos {
		if c.ComboType == ComboPublicStorageSensitiveData {
			t.Error("should not detect combo across different accounts")
		}
	}
}

func TestToxicCombo_PublicStorage_NonSensitiveData_NotDetected(t *testing.T) {
	detector := NewToxicComboDetector()

	findings := []Finding{
		{
			ID:           "pub-s3-003",
			AccountID:    "acct-1",
			FindingType:  "S3_BUCKET_PUBLIC_READ",
			ResourceType: "AWS::S3::Bucket",
		},
		{
			ID:           "internal-data-003",
			AccountID:    "acct-1",
			FindingType:  "DATA_EXPOSURE",
			ResourceType: "AWS::S3::Bucket",
			Context:      FindingContext{DataClassification: "Internal"},
		},
	}

	combos := detector.DetectToxicCombinations(findings)

	for _, c := range combos {
		if c.ComboType == ComboPublicStorageSensitiveData {
			t.Error("should not detect combo when data is not sensitive")
		}
	}
}

func TestToxicCombo_PublicBlobStorage_PHI_Detected(t *testing.T) {
	detector := NewToxicComboDetector()

	findings := []Finding{
		{
			ID:           "pub-blob-001",
			AccountID:    "acct-1",
			FindingType:  "BLOB_CONTAINER_PUBLIC_ACCESS",
			ResourceType: "microsoft.storage/storageaccounts/blobservices",
		},
		{
			ID:           "phi-data-001",
			AccountID:    "acct-1",
			FindingType:  "DATA_AT_REST",
			ResourceType: "microsoft.sql/servers",
			Context:      FindingContext{DataClassification: "PHI"},
		},
	}

	combos := detector.DetectToxicCombinations(findings)

	found := false
	for _, c := range combos {
		if c.ComboType == ComboPublicStorageSensitiveData {
			found = true
		}
	}
	if !found {
		t.Error("expected PUBLIC_STORAGE_SENSITIVE_DATA combo for Azure blob + PHI")
	}
}

// --- Tests for DetectToxicCombinations: IAM Admin + No MFA ---

func TestToxicCombo_IAMAdmin_NoMFA_Detected(t *testing.T) {
	detector := NewToxicComboDetector()

	findings := []Finding{
		{
			ID:           "admin-001",
			AccountID:    "acct-1",
			FindingType:  "IAM_POLICY_FULL_ACCESS",
			ResourceType: "AWS::IAM::Policy",
			Context:      FindingContext{HasAdminPermissions: true},
		},
		{
			ID:           "nomfa-001",
			AccountID:    "acct-1",
			FindingType:  "IAM_USER_NO_MFA",
			ResourceType: "AWS::IAM::User",
			Context:      FindingContext{MFARequired: false},
		},
	}

	combos := detector.DetectToxicCombinations(findings)

	found := false
	for _, c := range combos {
		if c.ComboType == ComboIAMAdminNoMFA {
			found = true
			if c.RiskMultiplier < 2.5 {
				t.Errorf("expected risk multiplier >= 2.5, got %.1f", c.RiskMultiplier)
			}
		}
	}
	if !found {
		t.Error("expected IAM_ADMIN_NO_MFA combo to be detected")
	}
}

func TestToxicCombo_IAMAdmin_WithMFA_NotDetected(t *testing.T) {
	detector := NewToxicComboDetector()

	findings := []Finding{
		{
			ID:           "admin-002",
			AccountID:    "acct-1",
			FindingType:  "IAM_POLICY_FULL_ACCESS",
			ResourceType: "AWS::IAM::Policy",
			Context:      FindingContext{HasAdminPermissions: true},
		},
		{
			ID:           "mfa-ok-002",
			AccountID:    "acct-1",
			FindingType:  "OTHER_FINDING",
			ResourceType: "AWS::IAM::User",
			Context:      FindingContext{MFARequired: true}, // MFA is enforced
		},
	}

	combos := detector.DetectToxicCombinations(findings)

	for _, c := range combos {
		if c.ComboType == ComboIAMAdminNoMFA {
			t.Error("should not detect combo when MFA is enforced")
		}
	}
}

func TestToxicCombo_IAMAdmin_NoMFA_DifferentAccount_NotDetected(t *testing.T) {
	detector := NewToxicComboDetector()

	findings := []Finding{
		{
			ID:           "admin-003",
			AccountID:    "acct-1",
			FindingType:  "IAM_POLICY_FULL_ACCESS",
			ResourceType: "AWS::IAM::Policy",
			Context:      FindingContext{HasAdminPermissions: true},
		},
		{
			ID:           "nomfa-003",
			AccountID:    "acct-2",
			FindingType:  "IAM_USER_NO_MFA",
			ResourceType: "AWS::IAM::User",
		},
	}

	combos := detector.DetectToxicCombinations(findings)

	for _, c := range combos {
		if c.ComboType == ComboIAMAdminNoMFA {
			t.Error("should not detect combo across different accounts")
		}
	}
}

// --- Tests for DetectToxicCombinations: Internet-Facing + Unpatched CVE ---

func TestToxicCombo_InternetFacing_UnpatchedCVE_Detected(t *testing.T) {
	detector := NewToxicComboDetector()

	findings := []Finding{
		{
			ID:           "inet-001",
			AccountID:    "acct-1",
			FindingType:  "OPEN_PORT_443",
			ResourceType: "AWS::EC2::Instance",
			Context:      FindingContext{InternetFacing: true},
		},
		{
			ID:           "cve-001",
			AccountID:    "acct-1",
			FindingType:  "CVE-2024-9999",
			ResourceType: "AWS::EC2::Instance",
			Context: FindingContext{
				EPSSScore:      0.85,
				PatchAvailable: false,
			},
		},
	}

	combos := detector.DetectToxicCombinations(findings)

	found := false
	for _, c := range combos {
		if c.ComboType == ComboInternetFacingUnpatchedCVE {
			found = true
			if c.RiskMultiplier < 1.5 {
				t.Errorf("expected risk multiplier >= 1.5, got %.1f", c.RiskMultiplier)
			}
		}
	}
	if !found {
		t.Error("expected INTERNET_FACING_UNPATCHED_CVE combo to be detected")
	}
}

func TestToxicCombo_InternetFacing_PatchedCVE_NotDetected(t *testing.T) {
	detector := NewToxicComboDetector()

	findings := []Finding{
		{
			ID:           "inet-002",
			AccountID:    "acct-1",
			FindingType:  "OPEN_PORT_443",
			ResourceType: "AWS::EC2::Instance",
			Context:      FindingContext{InternetFacing: true},
		},
		{
			ID:           "cve-002",
			AccountID:    "acct-1",
			FindingType:  "CVE-2024-8888",
			ResourceType: "AWS::EC2::Instance",
			Context: FindingContext{
				EPSSScore:      0.9,
				PatchAvailable: true, // patch available
			},
		},
	}

	combos := detector.DetectToxicCombinations(findings)

	for _, c := range combos {
		if c.ComboType == ComboInternetFacingUnpatchedCVE {
			t.Error("should not detect combo when CVE is patched")
		}
	}
}

func TestToxicCombo_InternetFacing_LowEPSS_NotDetected(t *testing.T) {
	detector := NewToxicComboDetector()

	findings := []Finding{
		{
			ID:           "inet-003",
			AccountID:    "acct-1",
			FindingType:  "OPEN_PORT_443",
			ResourceType: "AWS::EC2::Instance",
			Context:      FindingContext{InternetFacing: true},
		},
		{
			ID:           "cve-003",
			AccountID:    "acct-1",
			FindingType:  "CVE-2024-7777",
			ResourceType: "AWS::EC2::Instance",
			Context: FindingContext{
				EPSSScore:      0.1, // below 0.5 threshold
				PatchAvailable: false,
			},
		},
	}

	combos := detector.DetectToxicCombinations(findings)

	for _, c := range combos {
		if c.ComboType == ComboInternetFacingUnpatchedCVE {
			t.Error("should not detect combo when EPSS <= 0.5")
		}
	}
}

// --- Tests for DetectToxicCombinations: Permissive SG + Database ---

func TestToxicCombo_PermissiveSG_Database_Detected(t *testing.T) {
	detector := NewToxicComboDetector()

	findings := []Finding{
		{
			ID:           "sg-001",
			AccountID:    "acct-1",
			FindingType:  "SECURITY_GROUP_UNRESTRICTED_INGRESS",
			ResourceType: "AWS::EC2::SecurityGroup",
		},
		{
			ID:           "db-001",
			AccountID:    "acct-1",
			FindingType:  "RDS_ENCRYPTION_DISABLED",
			ResourceType: "AWS::RDS::DBInstance",
		},
	}

	combos := detector.DetectToxicCombinations(findings)

	found := false
	for _, c := range combos {
		if c.ComboType == ComboPermissiveSGDatabase {
			found = true
			if len(c.FindingIDs) != 2 {
				t.Errorf("expected 2 finding IDs, got %d", len(c.FindingIDs))
			}
		}
	}
	if !found {
		t.Error("expected PERMISSIVE_SG_DATABASE combo to be detected")
	}
}

func TestToxicCombo_PermissiveSG_NonDatabase_NotDetected(t *testing.T) {
	detector := NewToxicComboDetector()

	findings := []Finding{
		{
			ID:           "sg-002",
			AccountID:    "acct-1",
			FindingType:  "SECURITY_GROUP_OPEN_TO_WORLD",
			ResourceType: "AWS::EC2::SecurityGroup",
		},
		{
			ID:           "ec2-002",
			AccountID:    "acct-1",
			FindingType:  "EC2_INSTANCE_NO_IMDSv2",
			ResourceType: "AWS::EC2::Instance", // not a database
		},
	}

	combos := detector.DetectToxicCombinations(findings)

	for _, c := range combos {
		if c.ComboType == ComboPermissiveSGDatabase {
			t.Error("should not detect combo when resource is not a database")
		}
	}
}

func TestToxicCombo_PermissiveSG_Database_DifferentAccount_NotDetected(t *testing.T) {
	detector := NewToxicComboDetector()

	findings := []Finding{
		{
			ID:           "sg-003",
			AccountID:    "acct-1",
			FindingType:  "SECURITY_GROUP_UNRESTRICTED_INGRESS",
			ResourceType: "AWS::EC2::SecurityGroup",
		},
		{
			ID:           "db-003",
			AccountID:    "acct-2",
			FindingType:  "RDS_FINDING",
			ResourceType: "AWS::RDS::DBInstance",
		},
	}

	combos := detector.DetectToxicCombinations(findings)

	for _, c := range combos {
		if c.ComboType == ComboPermissiveSGDatabase {
			t.Error("should not detect combo across different accounts")
		}
	}
}

// --- Edge cases ---

func TestToxicCombo_EmptyFindings_NoCombos(t *testing.T) {
	detector := NewToxicComboDetector()
	combos := detector.DetectToxicCombinations(nil)
	if len(combos) != 0 {
		t.Errorf("expected 0 combos for nil findings, got %d", len(combos))
	}
}

func TestToxicCombo_SingleFinding_NoCombos(t *testing.T) {
	detector := NewToxicComboDetector()

	findings := []Finding{
		{
			ID:           "solo-001",
			AccountID:    "acct-1",
			FindingType:  "S3_BUCKET_PUBLIC_READ",
			ResourceType: "AWS::S3::Bucket",
			Context:      FindingContext{DataClassification: "PCI"},
		},
	}

	combos := detector.DetectToxicCombinations(findings)

	// A single finding that is both public storage and sensitive cannot form a combo with itself.
	if len(combos) != 0 {
		t.Errorf("expected 0 combos for single finding, got %d", len(combos))
	}
}

func TestToxicCombo_MultipleCombosDetected(t *testing.T) {
	detector := NewToxicComboDetector()

	findings := []Finding{
		{
			ID:           "pub-s3-multi",
			AccountID:    "acct-1",
			FindingType:  "S3_BUCKET_PUBLIC_READ",
			ResourceType: "AWS::S3::Bucket",
		},
		{
			ID:           "pci-multi",
			AccountID:    "acct-1",
			FindingType:  "DATA_FINDING",
			ResourceType: "AWS::DynamoDB::Table",
			Context:      FindingContext{DataClassification: "PCI"},
		},
		{
			ID:           "sg-multi",
			AccountID:    "acct-1",
			FindingType:  "SECURITY_GROUP_OPEN_TO_WORLD",
			ResourceType: "AWS::EC2::SecurityGroup",
		},
		{
			ID:           "rds-multi",
			AccountID:    "acct-1",
			FindingType:  "RDS_UNENCRYPTED",
			ResourceType: "AWS::RDS::DBInstance",
		},
	}

	combos := detector.DetectToxicCombinations(findings)

	comboTypes := make(map[ToxicComboType]bool)
	for _, c := range combos {
		comboTypes[c.ComboType] = true
	}

	if !comboTypes[ComboPublicStorageSensitiveData] {
		t.Error("expected PUBLIC_STORAGE_SENSITIVE_DATA combo")
	}
	if !comboTypes[ComboPermissiveSGDatabase] {
		t.Error("expected PERMISSIVE_SG_DATABASE combo")
	}
}
