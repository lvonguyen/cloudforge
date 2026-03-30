package main

import (
	"database/sql"
	"testing"
	"time"

	"github.com/lib/pq"
)

func TestPostgresFindingRow_ToFinding(t *testing.T) {
	firstFound := time.Date(2026, 3, 29, 16, 30, 0, 0, time.UTC)
	lastSeen := firstFound.Add(2 * time.Hour)
	due := firstFound.Add(7 * 24 * time.Hour)

	row := postgresFindingRow{
		ID:                  "f-12345",
		Source:              "aws-security-hub",
		SourceFindingID:     sql.NullString{String: "src-123", Valid: true},
		Type:                "vulnerability",
		Title:               "Public RDS instance with critical CVE",
		Description:         sql.NullString{String: "Database reachable from the internet.", Valid: true},
		ResourceType:        sql.NullString{String: "database", Valid: true},
		ResourceID:          sql.NullString{String: "db-001", Valid: true},
		ResourceName:        sql.NullString{String: "payments-prod-db", Valid: true},
		ResourceARN:         sql.NullString{String: "arn:aws:rds:us-east-1:123456789012:db:payments-prod-db", Valid: true},
		Platform:            sql.NullString{String: "cloud", Valid: true},
		CloudProvider:       "aws",
		Region:              sql.NullString{String: "us-east-1", Valid: true},
		AccountID:           sql.NullString{String: "123456789012", Valid: true},
		AccountName:         sql.NullString{String: "payments-prod", Valid: true},
		EnvironmentType:     sql.NullString{String: "production", Valid: true},
		StaticSeverity:      "CRITICAL",
		Severity:            "CRITICAL",
		AIRiskScore:         sql.NullFloat64{Float64: 9.2, Valid: true},
		AIRiskLevel:         sql.NullString{String: "critical", Valid: true},
		AIRiskRationale:     sql.NullString{String: "Internet exposure with known exploit path.", Valid: true},
		AIContextualFactors: pq.StringArray{"production_environment", "exploit_available"},
		CVSS:                sql.NullFloat64{Float64: 9.8, Valid: true},
		CVSSVector:          sql.NullString{String: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", Valid: true},
		EPSS:                sql.NullFloat64{Float64: 0.91, Valid: true},
		ExploitAvailable:    true,
		CVEsRaw:             []byte(`[{"id":"CVE-2026-0001","description":"Critical RCE","cisa_known_exploited":true,"published":"2026-01-01T00:00:00Z","modified":"2026-01-02T00:00:00Z"}]`),
		MITRETactics:        pq.StringArray{"TA0001"},
		MITRETechniques:     pq.StringArray{"T1190"},
		ComplianceRaw:       []byte(`[{"framework_id":"pci-dss","framework_name":"PCI-DSS v4.0","control_id":"REQ.1.2","control_title":"Restrict inbound traffic","section":"REQ.1","severity":"critical","url":""}]`),
		Remediation:         sql.NullString{String: "Restrict network access and patch immediately.", Valid: true},
		AutoRemediatable:    false,
		Category:            sql.NullString{String: "VULNERABILITY", Valid: true},
		Status:              "open",
		WorkflowStatus:      sql.NullString{String: "assigned", Valid: true},
		Suppressed:          false,
		ServiceName:         sql.NullString{String: "Payments API", Valid: true},
		LineOfBusiness:      sql.NullString{String: "finance", Valid: true},
		FirstFoundAt:        firstFound,
		LastSeenAt:          sql.NullTime{Time: lastSeen, Valid: true},
		DueDate:             sql.NullTime{Time: due, Valid: true},
		DeduplicationKey:    sql.NullString{String: "dedupe-123", Valid: true},
		CanonicalRuleID:     sql.NullString{String: "CVE-2026-0001", Valid: true},
	}

	finding, err := row.toFinding()
	if err != nil {
		t.Fatalf("toFinding returned error: %v", err)
	}

	if finding.ID != row.ID {
		t.Fatalf("expected id %q, got %q", row.ID, finding.ID)
	}
	if finding.FirstFoundAt != firstFound.Format(time.RFC3339) {
		t.Fatalf("expected first_found_at %q, got %q", firstFound.Format(time.RFC3339), finding.FirstFoundAt)
	}
	if finding.LastSeenAt != lastSeen.Format(time.RFC3339) {
		t.Fatalf("expected last_seen_at %q, got %q", lastSeen.Format(time.RFC3339), finding.LastSeenAt)
	}
	if finding.DueDate != due.Format(time.RFC3339) {
		t.Fatalf("expected due_date %q, got %q", due.Format(time.RFC3339), finding.DueDate)
	}
	if finding.CVSS == nil || *finding.CVSS != 9.8 {
		t.Fatalf("expected CVSS 9.8, got %#v", finding.CVSS)
	}
	if finding.EPSS == nil || *finding.EPSS != 0.91 {
		t.Fatalf("expected EPSS 0.91, got %#v", finding.EPSS)
	}
	if len(finding.CVEs) != 1 || finding.CVEs[0].ID != "CVE-2026-0001" {
		t.Fatalf("expected parsed CVE payload, got %#v", finding.CVEs)
	}
	if len(finding.ComplianceMappings) != 1 || finding.ComplianceMappings[0].FrameworkID != "pci-dss" {
		t.Fatalf("expected parsed compliance mapping, got %#v", finding.ComplianceMappings)
	}
	if len(finding.AIContextualFactors) != 2 {
		t.Fatalf("expected 2 contextual factors, got %#v", finding.AIContextualFactors)
	}
	if finding.IntegrityHash == "" {
		t.Fatal("expected integrity hash to be computed")
	}
}

func TestPostgresFindingRow_ToFinding_HandlesNulls(t *testing.T) {
	row := postgresFindingRow{
		ID:             "f-empty",
		Source:         "aws-security-hub",
		Type:           "misconfiguration",
		Title:          "Missing encryption",
		CloudProvider:  "aws",
		StaticSeverity: "HIGH",
		Severity:       "HIGH",
		Status:         "open",
		FirstFoundAt:   time.Date(2026, 3, 29, 18, 0, 0, 0, time.UTC),
	}

	finding, err := row.toFinding()
	if err != nil {
		t.Fatalf("toFinding returned error: %v", err)
	}

	if finding.Platform != "cloud" {
		t.Fatalf("expected default platform cloud, got %q", finding.Platform)
	}
	if finding.LastSeenAt != "" || finding.DueDate != "" || finding.SLABreachDate != "" {
		t.Fatalf("expected empty timestamp strings for null times, got %+v", finding)
	}
	if len(finding.CVEs) != 0 {
		t.Fatalf("expected no CVEs, got %#v", finding.CVEs)
	}
	if len(finding.ComplianceMappings) != 0 {
		t.Fatalf("expected no compliance mappings, got %#v", finding.ComplianceMappings)
	}
}
