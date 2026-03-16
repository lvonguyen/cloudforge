package main

import (
	"fmt"
	"sort"
	"strings"
)

// AttackPath represents a computed chain of findings forming an exploitable path.
type AttackPath struct {
	ID           string           `json:"id"`
	Title        string           `json:"title"`
	Description  string           `json:"description"`
	Severity     string           `json:"severity"`
	Score        float64          `json:"score"`
	HopCount     int              `json:"hop_count"`
	EntryPoint   AttackPathNode   `json:"entry_point"`
	Target       AttackPathNode   `json:"target"`
	Nodes        []AttackPathNode `json:"nodes"`
	Edges        []AttackPathEdge `json:"edges"`
	MITRETactics []string         `json:"mitre_tactics"`
	FindingIDs   []string         `json:"finding_ids"`

	// AI-enriched fields (populated when AI provider is available).
	AIDescription string `json:"ai_description,omitempty"`
	AIRemediation string `json:"ai_remediation,omitempty"`
	AILikelihood  string `json:"ai_likelihood,omitempty"`
	AIEnriched    bool   `json:"ai_enriched"`
}

// AttackPathNode is a node (resource) in an attack path.
type AttackPathNode struct {
	ID           string `json:"id"`
	FindingID    string `json:"finding_id"`
	ResourceID   string `json:"resource_id"`
	ResourceName string `json:"resource_name"`
	ResourceType string `json:"resource_type"`
	Provider     string `json:"provider"`
	AccountID    string `json:"account_id"`
	Region       string `json:"region"`
	Severity     string `json:"severity"`
	Category     string `json:"category"`
	Label        string `json:"label"`
}

// AttackPathEdge connects two nodes in a path.
type AttackPathEdge struct {
	ID       string `json:"id"`
	Source   string `json:"source"`
	Target   string `json:"target"`
	Label    string `json:"label"`
	EdgeType string `json:"edge_type"`
}

// AttackPathStats holds coverage statistics.
type AttackPathStats struct {
	TotalFindings    int            `json:"total_findings"`
	FindingsInPaths  int            `json:"findings_in_paths"`
	IsolatedFindings int            `json:"isolated_findings"`
	CoveragePercent  float64        `json:"coverage_percent"`
	TotalPaths       int            `json:"total_paths"`
	CriticalPaths    int            `json:"critical_paths"`
	HighPaths        int            `json:"high_paths"`
	MediumPaths      int            `json:"medium_paths"`
	ByProvider       map[string]int `json:"by_provider"`
}

// severityRank orders severities for comparison.
var severityRank = map[string]int{
	"CRITICAL": 4,
	"HIGH":     3,
	"MEDIUM":   2,
	"LOW":      1,
}

// computeAttackPaths builds an in-memory graph from findings and runs BFS
// from entry points (internet-exposed/NETWORK/VULNERABILITY with exploit)
// to targets (storage/database resources).
func computeAttackPaths(findings []Finding) ([]AttackPath, *AttackPathStats) {
	if len(findings) == 0 {
		return nil, &AttackPathStats{}
	}

	// Build adjacency: group findings by account, infer edges within each account
	byAccount := make(map[string][]Finding)
	for _, f := range findings {
		byAccount[f.AccountID] = append(byAccount[f.AccountID], f)
	}

	var paths []AttackPath
	pathID := 0
	findingsInPaths := make(map[string]bool)

	for accountID, accountFindings := range byAccount {
		if len(accountFindings) < 2 {
			continue
		}

		var entryPoints, intermediates, targets []Finding
		for _, f := range accountFindings {
			switch {
			case isEntryPoint(f):
				entryPoints = append(entryPoints, f)
			case isTarget(f):
				targets = append(targets, f)
			default:
				intermediates = append(intermediates, f)
			}
		}

		// For each entry point, try to build a path to each target through intermediates
		for _, entry := range entryPoints {
			for _, target := range targets {
				chain := buildChain(entry, intermediates, target)
				if chain == nil {
					continue
				}

				pathID++
				path := buildAttackPath(fmt.Sprintf("ap-%03d", pathID), accountID, chain)
				paths = append(paths, path)

				for _, n := range chain {
					findingsInPaths[n.ID] = true
				}
			}
		}

		// Build lateral movement paths from CRITICAL/HIGH findings
		for i, f1 := range accountFindings {
			if findingsInPaths[f1.ID] {
				continue
			}
			if severityRank[f1.Severity] < 3 {
				continue
			}
			for j := i + 1; j < len(accountFindings); j++ {
				f2 := accountFindings[j]
				if severityRank[f2.Severity] < 3 {
					continue
				}
				if findingsInPaths[f1.ID] || findingsInPaths[f2.ID] {
					continue
				}
				if canConnect(f1, f2) {
					pathID++
					chain := []Finding{f1, f2}
					path := buildAttackPath(fmt.Sprintf("ap-%03d", pathID), accountID, chain)
					paths = append(paths, path)
					findingsInPaths[f1.ID] = true
					findingsInPaths[f2.ID] = true
				}
			}
		}
	}

	// Sort paths by severity (CRITICAL first), then by score descending
	sort.Slice(paths, func(i, j int) bool {
		ri, rj := severityRank[paths[i].Severity], severityRank[paths[j].Severity]
		if ri != rj {
			return ri > rj
		}
		return paths[i].Score > paths[j].Score
	})

	stats := &AttackPathStats{
		TotalFindings:    len(findings),
		FindingsInPaths:  len(findingsInPaths),
		IsolatedFindings: len(findings) - len(findingsInPaths),
		TotalPaths:       len(paths),
		ByProvider:       make(map[string]int),
	}
	if stats.TotalFindings > 0 {
		stats.CoveragePercent = float64(stats.FindingsInPaths) / float64(stats.TotalFindings) * 100
	}
	for _, p := range paths {
		switch p.Severity {
		case "CRITICAL":
			stats.CriticalPaths++
		case "HIGH":
			stats.HighPaths++
		default:
			stats.MediumPaths++
		}
		if len(p.Nodes) > 0 {
			stats.ByProvider[p.Nodes[0].Provider]++
		}
	}

	return paths, stats
}

// isEntryPoint returns true if a finding represents an internet-exposed or
// externally-reachable resource.
func isEntryPoint(f Finding) bool {
	if f.Category == "NETWORK" {
		return true
	}
	if f.Category == "VULNERABILITY" && f.ExploitAvailable {
		return true
	}
	rt := strings.ToLower(f.ResourceType)
	if rt == "compute" || rt == "container" || rt == "serverless" {
		if f.Severity == "CRITICAL" || f.Severity == "HIGH" {
			return true
		}
	}
	return false
}

// isTarget returns true if a finding involves a data-bearing resource.
func isTarget(f Finding) bool {
	rt := strings.ToLower(f.ResourceType)
	return rt == "storage" || rt == "database" || rt == "secret" || rt == "encryption"
}

// canConnect returns true if two findings could be linked in an attack chain
// (same account and compatible resource types).
func canConnect(a, b Finding) bool {
	if a.AccountID != b.AccountID {
		return false
	}
	if a.ResourceID == b.ResourceID {
		return false
	}
	return a.Region == b.Region || a.ResourceType == b.ResourceType
}

// buildChain attempts to build a chain from entry through intermediates to target.
// Returns nil if no viable chain exists.
func buildChain(entry Finding, intermediates []Finding, target Finding) []Finding {
	if entry.AccountID != target.AccountID {
		return nil
	}

	// Direct connection: entry -> target
	if entry.Region == target.Region {
		return []Finding{entry, target}
	}

	// Try to find an intermediate that bridges entry and target
	for _, mid := range intermediates {
		if mid.ID == entry.ID || mid.ID == target.ID {
			continue
		}
		if canConnect(entry, mid) && canConnect(mid, target) &&
			(mid.Region == entry.Region || mid.Region == target.Region) {
			return []Finding{entry, mid, target}
		}
	}

	// Cross-region but same account: direct link only if connectable
	if canConnect(entry, target) {
		return []Finding{entry, target}
	}
	return nil
}

// buildAttackPath constructs an AttackPath from a chain of findings.
func buildAttackPath(id, accountID string, chain []Finding) AttackPath {
	nodes := make([]AttackPathNode, len(chain))
	edges := make([]AttackPathEdge, 0, len(chain)-1)
	findingIDs := make([]string, len(chain))
	tacticsSet := make(map[string]bool)
	maxSeverity := "LOW"
	var score float64

	for i, f := range chain {
		nodeID := fmt.Sprintf("%s-node-%d", id, i)
		nodes[i] = AttackPathNode{
			ID:           nodeID,
			FindingID:    f.ID,
			ResourceID:   f.ResourceID,
			ResourceName: f.ResourceName,
			ResourceType: f.ResourceType,
			Provider:     f.CloudProvider,
			AccountID:    f.AccountID,
			Region:       f.Region,
			Severity:     f.Severity,
			Category:     f.Category,
			Label:        f.ResourceName,
		}
		findingIDs[i] = f.ID

		if severityRank[f.Severity] > severityRank[maxSeverity] {
			maxSeverity = f.Severity
		}
		score += float64(severityRank[f.Severity]) * 25

		for _, t := range f.MITRETactics {
			tacticsSet[t] = true
		}

		if i > 0 {
			edgeType := inferEdgeType(chain[i-1], f) //nolint:gosec // bounds checked by i > 0
			edges = append(edges, AttackPathEdge{
				ID:       fmt.Sprintf("%s-edge-%d", id, i-1),
				Source:   fmt.Sprintf("%s-node-%d", id, i-1),
				Target:   nodeID,
				Label:    edgeTypeLabel(edgeType),
				EdgeType: edgeType,
			})
		}
	}

	if score > 100 {
		score = 100
	}

	tactics := make([]string, 0, len(tacticsSet))
	for t := range tacticsSet {
		tactics = append(tactics, t)
	}
	sort.Strings(tactics)

	title := fmt.Sprintf("%s → %s", chain[0].ResourceName, chain[len(chain)-1].ResourceName)
	desc := fmt.Sprintf(
		"%d-hop path in %s account %s: %s (%s) to %s (%s)",
		len(chain)-1,
		chain[0].CloudProvider,
		accountID,
		chain[0].ResourceName, chain[0].Category,
		chain[len(chain)-1].ResourceName, chain[len(chain)-1].Category,
	)

	return AttackPath{
		ID:           id,
		Title:        title,
		Description:  desc,
		Severity:     maxSeverity,
		Score:        score,
		HopCount:     len(chain) - 1,
		EntryPoint:   nodes[0],
		Target:       nodes[len(nodes)-1],
		Nodes:        nodes,
		Edges:        edges,
		MITRETactics: tactics,
		FindingIDs:   findingIDs,
	}
}

// inferEdgeType determines the relationship type between two adjacent findings.
func inferEdgeType(from, to Finding) string {
	toRT := strings.ToLower(to.ResourceType)
	fromCat := from.Category
	toCat := to.Category

	if toRT == "storage" || toRT == "database" || toRT == "secret" {
		return "data_access"
	}
	if fromCat == "IDENTITY" || toCat == "IDENTITY" {
		return "iam_trust"
	}
	if fromCat == "NETWORK" || toCat == "NETWORK" {
		return "network_reachable"
	}
	return "lateral_movement"
}

// edgeTypeLabel returns a human-readable label for an edge type.
func edgeTypeLabel(edgeType string) string {
	switch edgeType {
	case "network_reachable":
		return "network access"
	case "data_access":
		return "data access"
	case "iam_trust":
		return "IAM trust"
	case "lateral_movement":
		return "lateral movement"
	default:
		return edgeType
	}
}
