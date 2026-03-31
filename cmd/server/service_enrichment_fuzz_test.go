package main

import (
	"net"
	"strings"
	"testing"
)

func FuzzParseFindingEnrichment(f *testing.F) {
	f.Add(`{"root_cause":"Overly permissive IAM policy","impact":"Exposure","remediation":"Tighten access","related_controls":["CIS 1.2","NIST AC-3"]}`)
	f.Add(`analysis: {"root_cause":"Secret leaked","impact":"Credential theft","remediation":"Rotate secret","related_controls":["SOC 2","garbage"]}`)
	f.Add(`{"root_cause":"","impact":"bad","remediation":"fix","related_controls":[]}`)
	f.Add(`no json here`)
	f.Add(`{"root_cause":"` + "x" + `","impact":"` + "y" + `","remediation":"` + "z" + `","related_controls":["PCI DSS 1.2"]}`)

	f.Fuzz(func(t *testing.T, response string) {
		got, err := parseFindingEnrichment("finding-fuzz", response)
		if err != nil {
			return
		}

		if got.FindingID != "finding-fuzz" {
			t.Fatalf("finding id = %q, want %q", got.FindingID, "finding-fuzz")
		}
		if got.RootCause == "" {
			t.Fatal("root_cause must not be empty on success")
		}
		if got.Impact == "" {
			t.Fatal("impact must not be empty on success")
		}
		if got.Remediation == "" {
			t.Fatal("remediation must not be empty on success")
		}
		if len([]rune(got.RootCause)) > 2000 {
			t.Fatalf("root_cause length = %d, want <= 2000", len([]rune(got.RootCause)))
		}
		if len([]rune(got.Impact)) > 2000 {
			t.Fatalf("impact length = %d, want <= 2000", len([]rune(got.Impact)))
		}
		if len([]rune(got.Remediation)) > 2000 {
			t.Fatalf("remediation length = %d, want <= 2000", len([]rune(got.Remediation)))
		}
		if got.EnrichedAt == "" {
			t.Fatal("enriched_at must not be empty on success")
		}
		if got.CreatedAt.IsZero() {
			t.Fatal("created_at must not be zero on success")
		}
		filtered := filterValidControls(got.RelatedControls)
		if len(filtered) != len(got.RelatedControls) {
			t.Fatalf("related_controls contains invalid entries: got=%v filtered=%v", got.RelatedControls, filtered)
		}
	})
}

func FuzzExtractIPsFromText(f *testing.F) {
	for _, seed := range []string{
		"",
		"8.8.8.8",
		"src=1.1.1.1 dst=8.8.8.8 duplicate=1.1.1.1",
		"ignore 127.0.0.1 169.254.1.2 0.0.0.0 255.255.255.255",
		"bad 999.999.999.999 version 1.2.3",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, text string) {
		ips := extractIPsFromText(text)
		if len(ips) > 50 {
			t.Fatalf("returned %d IPs, want <= 50", len(ips))
		}

		seen := make(map[string]struct{}, len(ips))
		for _, ip := range ips {
			if net.ParseIP(ip) == nil {
				t.Fatalf("returned invalid IP %q", ip)
			}
			if strings.HasPrefix(ip, "127.") || strings.HasPrefix(ip, "169.254.") ||
				ip == "0.0.0.0" || ip == "255.255.255.255" {
				t.Fatalf("returned blocked IP %q", ip)
			}
			if _, ok := seen[ip]; ok {
				t.Fatalf("returned duplicate IP %q", ip)
			}
			seen[ip] = struct{}{}
		}
	})
}
