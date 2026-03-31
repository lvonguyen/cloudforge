package main

import (
	"strings"
	"testing"
	"unicode"
)

func FuzzParseEnrichmentResponse(f *testing.F) {
	f.Add(`{"description":"Internet-exposed workload reaches storage account","remediation":"Restrict ingress","likelihood":"HIGH","confidence":1.2,"validated":true,"risk_narrative":"High blast radius"}`)
	f.Add("```json\n{\"description\":\"Lateral movement path\",\"remediation\":\"Rotate credentials\",\"likelihood\":\"low\",\"confidence\":-0.1}\n```")
	f.Add(`{"description":"","remediation":"fix","likelihood":"weird","confidence":42}`)
	f.Add(`surrounding text {"description":"Embedded JSON","remediation":"Patch","likelihood":"medium","confidence":0.5} trailing`)
	f.Add(`no json`)

	f.Fuzz(func(t *testing.T, response string) {
		got, err := parseEnrichmentResponse(response)
		if err != nil {
			return
		}

		if got.Description == "" {
			t.Fatal("description must not be empty on success")
		}
		switch got.Likelihood {
		case "low", "medium", "high":
		default:
			t.Fatalf("likelihood = %q, want low|medium|high", got.Likelihood)
		}
		if got.Confidence < 0 || got.Confidence > 1 {
			t.Fatalf("confidence = %f, want within [0,1]", got.Confidence)
		}
	})
}

func FuzzBuildEnrichmentPrompt(f *testing.F) {
	f.Add("prod-api", "HIGH", "network access", "TA0001", "payments-db")
	f.Add("evil\x00title", "CRITICAL", "edge\r\nlabel", "TA0001\u202Ehidden", "db\tname")
	f.Add("", "", "", "", "")

	f.Fuzz(func(t *testing.T, title, severity, edgeLabel, tactic, resourceName string) {
		path := &AttackPath{
			Title:    title,
			Severity: severity,
			Score:    87,
			HopCount: 2,
			EntryPoint: AttackPathNode{
				ResourceName: resourceName,
				ResourceType: "compute",
				Category:     "NETWORK",
				Provider:     "aws",
				Region:       "us-east-1",
				Severity:     severity,
				AccountID:    "123456789012",
			},
			Target: AttackPathNode{
				ResourceName: resourceName,
				ResourceType: "database",
				Category:     "DATA",
				Provider:     "aws",
				Region:       "us-east-1",
				Severity:     "HIGH",
				AccountID:    "123456789012",
			},
			Nodes: []AttackPathNode{
				{
					ResourceName: resourceName,
					ResourceType: "compute",
					Category:     "NETWORK",
					Provider:     "aws",
					Region:       "us-east-1",
					Severity:     severity,
					AccountID:    "123456789012",
				},
				{
					ResourceName: resourceName,
					ResourceType: "database",
					Category:     "DATA",
					Provider:     "aws",
					Region:       "us-east-1",
					Severity:     "HIGH",
					AccountID:    "123456789012",
				},
			},
			Edges: []AttackPathEdge{{Label: edgeLabel}},
			MITRETactics: []string{
				tactic,
			},
		}

		prompt := buildEnrichmentPrompt(path)
		if !strings.Contains(prompt, "Attack Path:") {
			t.Fatal("prompt missing Attack Path header")
		}
		if !strings.Contains(prompt, "Entry Point:") {
			t.Fatal("prompt missing Entry Point section")
		}
		if !strings.Contains(prompt, "Target:") {
			t.Fatal("prompt missing Target section")
		}

		for _, r := range prompt {
			if (r < 32 && r != '\n') || r == 127 {
				t.Fatalf("prompt contains ASCII control rune %U", r)
			}
			if unicode.Is(unicode.Cf, r) {
				t.Fatalf("prompt contains Unicode format rune %U", r)
			}
			if r != ' ' && unicode.Is(unicode.Zs, r) {
				t.Fatalf("prompt contains Unicode space separator rune %U", r)
			}
		}
	})
}
