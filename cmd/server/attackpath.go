package main

import (
	"aegis/internal/secgraph"
	"context"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
)

// AttackPath represents a computed chain of findings forming an exploitable path.
type AttackPath struct {
	ID                string           `json:"id"`
	Title             string           `json:"title"`
	Description       string           `json:"description"`
	Severity          string           `json:"severity"`
	Score             float64          `json:"score"`
	HopCount          int              `json:"hop_count"`
	EntryPoint        AttackPathNode   `json:"entry_point"`
	Target            AttackPathNode   `json:"target"`
	Nodes             []AttackPathNode `json:"nodes"`
	Edges             []AttackPathEdge `json:"edges"`
	MITRETactics      []string         `json:"mitre_tactics"`
	FindingIDs        []string         `json:"finding_ids"`
	MissionContext    string           `json:"mission_context,omitempty"`
	RiskFactors       []string         `json:"risk_factors,omitempty"`
	ControlGaps       []string         `json:"control_gaps,omitempty"`
	RecommendedBreaks []string         `json:"recommended_breaks,omitempty"`
	EvidenceMode      string           `json:"evidence_mode,omitempty"`
	RollbackSummary   string           `json:"rollback_summary,omitempty"`

	// AI-enriched fields (populated when AI provider is available).
	AIDescription   string  `json:"ai_description,omitempty"`
	AIRemediation   string  `json:"ai_remediation,omitempty"`
	AILikelihood    string  `json:"ai_likelihood,omitempty"`
	AIConfidence    float64 `json:"ai_confidence,omitempty"`
	AIValidated     bool    `json:"ai_validated,omitempty"`
	AIRiskNarrative string  `json:"ai_risk_narrative,omitempty"`
	AIEnriched      bool    `json:"ai_enriched"`
	LowConfidence   bool    `json:"low_confidence,omitempty"`
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
	TotalFindings     int            `json:"total_findings"`
	FindingsInPaths   int            `json:"findings_in_paths"`
	IsolatedFindings  int            `json:"isolated_findings"`
	CoveragePercent   float64        `json:"coverage_percent"`
	TotalPaths        int            `json:"total_paths"`
	CriticalPaths     int            `json:"critical_paths"`
	HighPaths         int            `json:"high_paths"`
	MediumPaths       int            `json:"medium_paths"`
	Mode              string         `json:"mode,omitempty"`
	CandidateFindings int            `json:"candidate_findings,omitempty"`
	ByProvider        map[string]int `json:"by_provider"`
}

const (
	defaultDeferredAttackPathMaxFindings   = 5000
	defaultDeferredAttackPathMaxPerAccount = 125
)

// severityRank orders severities for comparison.
var severityRank = map[string]int{
	"CRITICAL":      4,
	"HIGH":          3,
	"MEDIUM":        2,
	"LOW":           1,
	"INFO":          0,
	"INFORMATIONAL": 0,
}

// getSeverityRank normalizes severity to uppercase before lookup.
func getSeverityRank(s string) int {
	return severityRank[strings.ToUpper(s)]
}

func deferredAttackPathMaxFindings() int {
	raw := strings.TrimSpace(os.Getenv("ATTACK_PATH_MAX_FINDINGS"))
	if raw == "" {
		return defaultDeferredAttackPathMaxFindings
	}

	n, err := strconv.Atoi(raw)
	if err != nil || n <= 0 {
		return defaultDeferredAttackPathMaxFindings
	}
	return n
}

func deferredAttackPathMaxPerAccount() int {
	raw := strings.TrimSpace(os.Getenv("ATTACK_PATH_MAX_PER_ACCOUNT"))
	if raw == "" {
		return defaultDeferredAttackPathMaxPerAccount
	}

	n, err := strconv.Atoi(raw)
	if err != nil || n <= 0 {
		return defaultDeferredAttackPathMaxPerAccount
	}
	return n
}

type rankedAttackPathFinding struct {
	Finding Finding
	Score   int
}

func deferredAttackPathPriority(f Finding) int {
	score := getSeverityRank(f.Severity) * 100
	if isEntryPoint(f) {
		score += 220
	}
	if isTarget(f) {
		score += 180
	}
	if f.ExploitAvailable {
		score += 120
	}

	switch strings.ToLower(f.EnvironmentType) {
	case "production":
		score += 40
	case "staging":
		score += 20
	}

	switch strings.ToLower(f.Status) {
	case "open":
		score += 30
	case "in_progress":
		score += 20
	}

	switch strings.ToUpper(f.Category) {
	case "NETWORK":
		score += 50
	case "IDENTITY":
		score += 40
	case "DATA_EXPOSURE":
		score += 30
	}

	if len(f.CVEs) > 0 {
		score += min(len(f.CVEs), 3) * 10
	}
	if f.ResourceID != "" {
		score += 5
	}

	return score
}

func sortRankedAttackPathFindings(findings []rankedAttackPathFinding) {
	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].Score != findings[j].Score {
			return findings[i].Score > findings[j].Score
		}
		if findings[i].Finding.FirstFoundAt != findings[j].Finding.FirstFoundAt {
			return findings[i].Finding.FirstFoundAt > findings[j].Finding.FirstFoundAt
		}
		return findings[i].Finding.ID < findings[j].Finding.ID
	})
}

func selectDeferredAttackPathCandidates(findings []Finding, maxFindings, maxPerAccount int) []Finding {
	if len(findings) == 0 {
		return nil
	}
	if maxFindings <= 0 || len(findings) <= maxFindings {
		return append([]Finding(nil), findings...)
	}
	if maxPerAccount <= 0 {
		maxPerAccount = maxFindings
	}

	byAccount := make(map[string][]rankedAttackPathFinding)
	for _, finding := range findings {
		accountID := finding.AccountID
		if accountID == "" {
			accountID = "__unknown__"
		}
		byAccount[accountID] = append(byAccount[accountID], rankedAttackPathFinding{
			Finding: finding,
			Score:   deferredAttackPathPriority(finding),
		})
	}

	accountIDs := make([]string, 0, len(byAccount))
	for accountID := range byAccount {
		accountIDs = append(accountIDs, accountID)
	}
	sort.Strings(accountIDs)

	selected := make([]Finding, 0, min(maxFindings, len(findings)))
	leftovers := make([]rankedAttackPathFinding, 0, len(findings))
	for _, accountID := range accountIDs {
		ranked := byAccount[accountID]
		sortRankedAttackPathFindings(ranked)

		limit := min(maxPerAccount, len(ranked))
		if remaining := maxFindings - len(selected); remaining < limit {
			limit = remaining
		}
		for i := 0; i < limit; i++ {
			selected = append(selected, ranked[i].Finding)
		}
		if limit < len(ranked) {
			leftovers = append(leftovers, ranked[limit:]...)
		}
		if len(selected) == maxFindings {
			return selected
		}
	}

	sortRankedAttackPathFindings(leftovers)
	for _, ranked := range leftovers {
		if len(selected) == maxFindings {
			break
		}
		selected = append(selected, ranked.Finding)
	}

	return selected
}

func computeDeferredAttackPaths(findings []Finding, adj *secgraph.AdjacencySet) ([]AttackPath, *AttackPathStats) {
	candidates := selectDeferredAttackPathCandidates(
		findings,
		deferredAttackPathMaxFindings(),
		deferredAttackPathMaxPerAccount(),
	)

	paths, stats := computeAttackPaths(candidates, adj)
	mode := "full"
	if len(candidates) < len(findings) {
		mode = "sampled"
	}
	if len(paths) == 0 && adj != nil {
		paths, stats = computeAttackPaths(candidates, nil)
		mode += "_heuristic"
	}
	if stats == nil {
		stats = &AttackPathStats{ByProvider: map[string]int{}}
	}
	if stats.ByProvider == nil {
		stats.ByProvider = map[string]int{}
	}

	stats.CandidateFindings = len(candidates)
	if len(candidates) < len(findings) {
		stats.Mode = mode
		stats.TotalFindings = len(findings)
		stats.IsolatedFindings = len(findings) - stats.FindingsInPaths
		if stats.IsolatedFindings < 0 {
			stats.IsolatedFindings = 0
		}
		if len(findings) > 0 {
			stats.CoveragePercent = float64(stats.FindingsInPaths) / float64(len(findings)) * 100
		}
		return paths, stats
	}

	stats.Mode = mode
	return paths, stats
}

// computeAttackPaths builds an in-memory graph from findings and runs BFS
// from entry points to targets. When adj is non-nil, edge connectivity is
// resolved from the pre-built graph_edges adjacency set (ADR-020 Phase 2).
// When adj is nil, falls back to heuristic co-location inference.
func computeAttackPaths(findings []Finding, adj *secgraph.AdjacencySet) ([]AttackPath, *AttackPathStats) {
	_, span := otel.Tracer("aegis.compute").Start(context.Background(), "compute.attack_paths")
	defer span.End()
	span.SetAttributes(attribute.Int("findings.input_count", len(findings)))

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
	seenPaths := make(map[string]bool)

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
				chain := buildChain(entry, accountFindings, intermediates, target, adj)
				if chain == nil {
					continue
				}
				fp := pathFingerprint(chain)
				if seenPaths[fp] {
					continue
				}

				pathID++
				path := buildAttackPath(fmt.Sprintf("ap-%03d", pathID), accountID, chain, adj)
				paths = append(paths, path)
				seenPaths[fp] = true

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
			if getSeverityRank(f1.Severity) < 3 {
				continue
			}
			for j := i + 1; j < len(accountFindings); j++ {
				f2 := accountFindings[j]
				if getSeverityRank(f2.Severity) < 3 {
					continue
				}
				if findingsInPaths[f2.ID] {
					continue
				}
				chain := buildLateralChain(f1, accountFindings, f2, adj)
				if chain != nil {
					fp := pathFingerprint(chain)
					if seenPaths[fp] {
						continue
					}
					pathID++
					path := buildAttackPath(fmt.Sprintf("ap-%03d", pathID), accountID, chain, adj)
					paths = append(paths, path)
					seenPaths[fp] = true
					for _, n := range chain {
						findingsInPaths[n.ID] = true
					}
				}
			}
		}
	}

	// Sort paths by severity (CRITICAL first), then by score descending
	sort.Slice(paths, func(i, j int) bool {
		ri, rj := getSeverityRank(paths[i].Severity), getSeverityRank(paths[j].Severity)
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

	span.SetAttributes(
		attribute.Int("attack_paths.total", stats.TotalPaths),
		attribute.Int("attack_paths.critical", stats.CriticalPaths),
	)

	return paths, stats
}

// isEntryPoint returns true if a finding represents an internet-exposed or
// externally-reachable resource.
func isEntryPoint(f Finding) bool {
	cat := strings.ToUpper(f.Category)
	if cat == "NETWORK" {
		return true
	}
	if cat == "VULNERABILITY" && f.ExploitAvailable {
		return true
	}
	rt := strings.ToLower(f.ResourceType)
	sev := strings.ToUpper(f.Severity)
	if rt == "compute" || rt == "container" || rt == "serverless" {
		if sev == "CRITICAL" || sev == "HIGH" {
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

// canConnect returns true if two findings could be linked in an attack chain.
// When adj is non-nil, checks for an explicit edge between the resources
// in graph_edges (evidence-based). When adj is nil, falls back to heuristic:
// same account AND (same region OR same resource type).
func canConnect(a, b Finding, adj *secgraph.AdjacencySet) bool {
	if a.AccountID != b.AccountID {
		return false
	}
	if a.ResourceID == b.ResourceID {
		return false
	}
	// Graph-native: check explicit edge
	if adj != nil && adj.Connected(a.ResourceID, b.ResourceID) {
		return true
	}
	// Heuristic fallback (used when no graph_edges data)
	if adj != nil {
		return false // adj available but no edge — not connected
	}
	return a.Region == b.Region || a.ResourceType == b.ResourceType
}

// buildChain attempts to build a chain from entry through intermediates to target.
// When adjacency is available, it uses an explicit-edge BFS over findings in the
// account. Otherwise it falls back to the original direct/one-intermediate heuristic.
func buildChain(entry Finding, accountFindings []Finding, intermediates []Finding, target Finding, adj *secgraph.AdjacencySet) []Finding {
	if adj != nil {
		return buildFindingChainBFS(entry, accountFindings, target, adj, 4)
	}
	return buildHeuristicChain(entry, intermediates, target, nil)
}

// buildLateralChain attempts to connect two high-severity findings.
func buildLateralChain(from Finding, accountFindings []Finding, to Finding, adj *secgraph.AdjacencySet) []Finding {
	if adj != nil {
		return buildFindingChainBFS(from, accountFindings, to, adj, 4)
	}
	if canConnect(from, to, nil) {
		return []Finding{from, to}
	}
	return nil
}

func buildHeuristicChain(entry Finding, intermediates []Finding, target Finding, adj *secgraph.AdjacencySet) []Finding {
	if entry.AccountID != target.AccountID {
		return nil
	}
	if entry.ID == target.ID {
		return nil
	}

	// Direct connection: entry -> target (must pass canConnect gate)
	if canConnect(entry, target, adj) {
		return []Finding{entry, target}
	}

	// Try to find an intermediate that bridges entry and target
	for _, mid := range intermediates {
		if mid.ID == entry.ID || mid.ID == target.ID {
			continue
		}
		if canConnect(entry, mid, adj) && canConnect(mid, target, adj) &&
			(mid.Region == entry.Region || mid.Region == target.Region) {
			return []Finding{entry, mid, target}
		}
	}

	return nil
}

// buildFindingChainBFS returns the shortest simple path between two findings
// using explicit resource adjacency. All nodes in the path are findings.
func buildFindingChainBFS(start Finding, candidates []Finding, target Finding, adj *secgraph.AdjacencySet, maxHops int) []Finding {
	if adj == nil {
		return nil
	}
	if start.AccountID != target.AccountID || start.ID == target.ID {
		return nil
	}
	if maxHops <= 0 {
		maxHops = 4
	}

	queue := []string{start.ID}
	visited := map[string]bool{start.ID: true}
	depth := map[string]int{start.ID: 0}
	parents := make(map[string]string)
	byID := make(map[string]Finding, len(candidates))
	for _, finding := range candidates {
		byID[finding.ID] = finding
	}
	byID[start.ID] = start
	byID[target.ID] = target

	for len(queue) > 0 {
		currentID := queue[0]
		queue = queue[1:]
		current := byID[currentID]
		currentDepth := depth[currentID]
		if currentDepth >= maxHops {
			continue
		}

		for _, next := range candidates {
			if next.ID == currentID || visited[next.ID] {
				continue
			}
			if !canConnect(current, next, adj) {
				continue
			}

			visited[next.ID] = true
			parents[next.ID] = currentID
			depth[next.ID] = currentDepth + 1

			if next.ID == target.ID {
				return reconstructFindingPath(start.ID, target.ID, parents, byID)
			}

			queue = append(queue, next.ID)
		}
	}

	return nil
}

func reconstructFindingPath(startID, targetID string, parents map[string]string, byID map[string]Finding) []Finding {
	var reversed []Finding
	for currentID := targetID; currentID != ""; currentID = parents[currentID] {
		finding, ok := byID[currentID]
		if !ok {
			return nil
		}
		reversed = append(reversed, finding)
		if currentID == startID {
			break
		}
	}
	if len(reversed) == 0 || reversed[len(reversed)-1].ID != startID {
		return nil
	}

	chain := make([]Finding, 0, len(reversed))
	for i := len(reversed) - 1; i >= 0; i-- {
		chain = append(chain, reversed[i])
	}
	return chain
}

func pathFingerprint(chain []Finding) string {
	if len(chain) == 0 {
		return ""
	}
	ids := make([]string, len(chain))
	for i, finding := range chain {
		ids[i] = finding.ID
	}
	return strings.Join(ids, "->")
}

// buildAttackPath constructs an AttackPath from a chain of findings.
func buildAttackPath(id, accountID string, chain []Finding, adj *secgraph.AdjacencySet) AttackPath {
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

		if getSeverityRank(f.Severity) > getSeverityRank(maxSeverity) {
			maxSeverity = f.Severity
		}
		score += float64(getSeverityRank(f.Severity)) * 25

		for _, t := range f.MITRETactics {
			tacticsSet[t] = true
		}

		if i > 0 {
			edgeType := inferEdgeType(chain[i-1], f, adj) //nolint:gosec // bounds checked by i > 0
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
	evidenceMode := "heuristic_colocation"
	if adj != nil {
		evidenceMode = "graph_adjacency"
	}

	return AttackPath{
		ID:                id,
		Title:             title,
		Description:       desc,
		Severity:          maxSeverity,
		Score:             score,
		HopCount:          len(chain) - 1,
		EntryPoint:        nodes[0],
		Target:            nodes[len(nodes)-1],
		Nodes:             nodes,
		Edges:             edges,
		MITRETactics:      tactics,
		FindingIDs:        findingIDs,
		MissionContext:    inferAttackPathMissionContext(chain),
		RiskFactors:       inferAttackPathRiskFactors(chain, edges),
		ControlGaps:       inferAttackPathControlGaps(chain),
		RecommendedBreaks: inferAttackPathBreaks(chain, edges),
		EvidenceMode:      evidenceMode,
		RollbackSummary:   "Break the path with reversible network, IAM, and data-access changes backed by captured pre-state where available.",
	}
}

func inferAttackPathMissionContext(chain []Finding) string {
	if len(chain) == 0 {
		return ""
	}
	entry := chain[0]
	target := chain[len(chain)-1]
	provider := strings.ToUpper(entry.CloudProvider)
	if provider == "" {
		provider = "CLOUD"
	}
	return fmt.Sprintf(
		"%s path from %s to %s across %s/%s; prioritize as a workload-migration or restricted-data guardrail when compliance mappings are present.",
		provider,
		entry.ResourceName,
		target.ResourceName,
		entry.AccountID,
		entry.Region,
	)
}

func inferAttackPathRiskFactors(chain []Finding, edges []AttackPathEdge) []string {
	factors := make([]string, 0, 6)
	if len(chain) > 0 && isEntryPoint(chain[0]) {
		factors = append(factors, "Entry point resembles an externally reachable foothold")
	}
	if len(chain) > 1 && isTarget(chain[len(chain)-1]) {
		factors = append(factors, "Terminal resource resembles data, secrets, or privileged control plane access")
	}
	for _, edge := range edges {
		switch edge.EdgeType {
		case "iam_trust":
			factors = append(factors, "Path crosses an identity or CI/CD trust boundary")
		case "data_access":
			factors = append(factors, "Path reaches a storage, database, or secret-bearing resource")
		case "network_reachable":
			factors = append(factors, "Path begins with network reachability that can be reduced at an ingress boundary")
		}
	}
	return uniqueStrings(factors)
}

func inferAttackPathControlGaps(chain []Finding) []string {
	gaps := make([]string, 0, 6)
	for _, f := range chain {
		switch strings.ToUpper(f.Category) {
		case "NETWORK":
			gaps = append(gaps, "boundary protection")
		case "IDENTITY":
			gaps = append(gaps, "least privilege")
		case "DATA_EXPOSURE", "DATA_PROTECTION":
			gaps = append(gaps, "restricted data access")
		case "COMPLIANCE":
			gaps = append(gaps, "audit evidence")
		case "CONTAINER":
			gaps = append(gaps, "supply-chain promotion guardrails")
		}
		for _, mapping := range f.ComplianceMappings {
			if mapping.FrameworkName != "" && mapping.ControlID != "" {
				gaps = append(gaps, mapping.FrameworkName+" "+mapping.ControlID)
			}
		}
	}
	return uniqueStrings(gaps)
}

func inferAttackPathBreaks(chain []Finding, edges []AttackPathEdge) []string {
	breaks := make([]string, 0, 4)
	if len(chain) > 0 {
		breaks = append(breaks, "Reduce exposure on "+chain[0].ResourceName)
	}
	for _, edge := range edges {
		switch edge.EdgeType {
		case "iam_trust":
			breaks = append(breaks, "Constrain IAM or pipeline trust before allowing production promotion")
		case "data_access":
			breaks = append(breaks, "Remove broad data access and capture policy evidence")
		case "network_reachable":
			breaks = append(breaks, "Move ingress behind approved ZTNA, IAP, or private endpoints")
		}
	}
	if len(chain) > 1 {
		breaks = append(breaks, "Validate rollback plan for "+chain[len(chain)-1].ResourceName)
	}
	return uniqueStrings(breaks)
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]bool, len(values))
	unique := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		unique = append(unique, value)
	}
	return unique
}

// inferEdgeType determines the relationship type between two adjacent findings.
func inferEdgeType(from, to Finding, adj *secgraph.AdjacencySet) string {
	if adj != nil {
		if edgeType := adj.EdgeBetween(from.ResourceID, to.ResourceID); edgeType != "" {
			return string(edgeType)
		}
	}
	toRT := strings.ToLower(to.ResourceType)
	fromCat := strings.ToUpper(from.Category)
	toCat := strings.ToUpper(to.Category)

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
	case "same_region":
		return "same region"
	case "same_account":
		return "same account"
	default:
		return edgeType
	}
}
