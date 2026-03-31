package main

import (
	"database/sql"
	"testing"
	"time"
)

func FuzzPostgresFindingRowToFinding(f *testing.F) {
	f.Add([]byte(`[]`), []byte(`[]`))
	f.Add(
		[]byte(`[{"id":"CVE-2026-0001","description":"Critical RCE"}]`),
		[]byte(`[{"framework_id":"pci-dss","control_id":"REQ.1.2"}]`),
	)
	f.Add([]byte(`{"unexpected":"object"}`), []byte(`null`))
	f.Add([]byte(`not-json`), []byte(`{"also":"bad"}`))

	firstFound := time.Date(2026, 3, 29, 16, 30, 0, 0, time.UTC)
	lastSeen := firstFound.Add(2 * time.Hour)

	f.Fuzz(func(t *testing.T, cvesRaw []byte, complianceRaw []byte) {
		row := postgresFindingRow{
			ID:             "f-fuzz",
			Source:         "fuzz-source",
			Type:           "vulnerability",
			Title:          "Fuzzed finding",
			CloudProvider:  "aws",
			StaticSeverity: "HIGH",
			Severity:       "HIGH",
			Status:         "open",
			FirstFoundAt:   firstFound,
			LastSeenAt:     sql.NullTime{Time: lastSeen, Valid: true},
			CVEsRaw:        append([]byte(nil), cvesRaw...),
			ComplianceRaw:  append([]byte(nil), complianceRaw...),
		}

		finding, err := row.toFinding()
		if err != nil {
			return
		}

		if finding.ID != row.ID {
			t.Fatalf("id = %q, want %q", finding.ID, row.ID)
		}
		if finding.Platform != "cloud" {
			t.Fatalf("platform = %q, want cloud", finding.Platform)
		}
		if finding.FirstFoundAt != firstFound.Format(time.RFC3339) {
			t.Fatalf("first_found_at = %q, want %q", finding.FirstFoundAt, firstFound.Format(time.RFC3339))
		}
		if finding.LastSeenAt != lastSeen.Format(time.RFC3339) {
			t.Fatalf("last_seen_at = %q, want %q", finding.LastSeenAt, lastSeen.Format(time.RFC3339))
		}
		if finding.IntegrityHash == "" {
			t.Fatal("integrity hash must be computed on successful conversion")
		}
	})
}
