// Package secgraph materializes security findings into a typed graph of
// controls, evaluations, issues, and edges suitable for risk scoring,
// blast-radius analysis, and compliance reporting.
package secgraph

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"aegis/internal/compliance"
)

var severityWeight = map[string]float64{
	"CRITICAL": 9,
	"HIGH":     7,
	"MEDIUM":   5,
	"LOW":      3,
}

var severityBaseScore = map[string]float64{
	"CRITICAL": 90,
	"HIGH":     75,
	"MEDIUM":   50,
	"LOW":      25,
}

// MaterializeOptions controls optional graph-aware enrichment when deriving
// secgraph artifacts from findings.
type MaterializeOptions struct {
	Adjacency       *AdjacencySet
	BlastRadiusHops int
}

// IssueSurfaceAccumulator merges operator-facing issue artifacts in place so
// large corpus syncs do not repeatedly rebuild and sort the full result set.
type IssueSurfaceAccumulator struct {
	evaluationsByID map[string]ControlEvaluation
	issuesByID      map[string]Issue
	linksByKey      map[string]IssueFindingLink
}

// NewIssueSurfaceAccumulator allocates an accumulator sized for the expected
// number of unique issue/evaluation records.
func NewIssueSurfaceAccumulator(capacity int) *IssueSurfaceAccumulator {
	if capacity < 0 {
		capacity = 0
	}
	return &IssueSurfaceAccumulator{
		evaluationsByID: make(map[string]ControlEvaluation, capacity),
		issuesByID:      make(map[string]Issue, capacity),
		linksByKey:      make(map[string]IssueFindingLink, capacity),
	}
}

// Add folds a per-finding materialization result into the accumulator.
func (a *IssueSurfaceAccumulator) Add(result MaterializationResult) {
	if a == nil {
		return
	}
	if a.evaluationsByID == nil {
		a.evaluationsByID = make(map[string]ControlEvaluation)
	}
	if a.issuesByID == nil {
		a.issuesByID = make(map[string]Issue)
	}
	if a.linksByKey == nil {
		a.linksByKey = make(map[string]IssueFindingLink)
	}

	for _, evaluation := range result.Evaluations {
		if existing, ok := a.evaluationsByID[evaluation.ID]; ok {
			a.evaluationsByID[evaluation.ID] = mergeControlEvaluations(existing, evaluation)
			continue
		}
		a.evaluationsByID[evaluation.ID] = evaluation
	}
	for _, issue := range result.Issues {
		if existing, ok := a.issuesByID[issue.ID]; ok {
			a.issuesByID[issue.ID] = mergeIssues(existing, issue)
			continue
		}
		a.issuesByID[issue.ID] = issue
	}
	for _, link := range result.IssueFindings {
		key := link.IssueID + "|" + link.FindingID
		if existing, ok := a.linksByKey[key]; ok {
			if link.CreatedAt.Before(existing.CreatedAt) {
				a.linksByKey[key] = link
			}
			continue
		}
		a.linksByKey[key] = link
	}
}

// Counts returns the current buffered issue-surface cardinalities.
func (a *IssueSurfaceAccumulator) Counts() (evaluations, issues, links int) {
	if a == nil {
		return 0, 0, 0
	}
	return len(a.evaluationsByID), len(a.issuesByID), len(a.linksByKey)
}

// Snapshot returns a deterministic materialization result view of the
// accumulated issue surface.
func (a *IssueSurfaceAccumulator) Snapshot() MaterializationResult {
	if a == nil {
		return MaterializationResult{}
	}

	result := MaterializationResult{
		Evaluations:   make([]ControlEvaluation, 0, len(a.evaluationsByID)),
		Issues:        make([]Issue, 0, len(a.issuesByID)),
		IssueFindings: make([]IssueFindingLink, 0, len(a.linksByKey)),
	}
	for _, evaluation := range a.evaluationsByID {
		result.Evaluations = append(result.Evaluations, evaluation)
	}
	for _, issue := range a.issuesByID {
		result.Issues = append(result.Issues, issue)
	}
	for _, link := range a.linksByKey {
		result.IssueFindings = append(result.IssueFindings, link)
	}

	sort.Slice(result.Evaluations, func(i, j int) bool { return result.Evaluations[i].ID < result.Evaluations[j].ID })
	sort.Slice(result.Issues, func(i, j int) bool { return result.Issues[i].ID < result.Issues[j].ID })
	sort.Slice(result.IssueFindings, func(i, j int) bool {
		if result.IssueFindings[i].IssueID == result.IssueFindings[j].IssueID {
			return result.IssueFindings[i].FindingID < result.IssueFindings[j].FindingID
		}
		return result.IssueFindings[i].IssueID < result.IssueFindings[j].IssueID
	})

	return result
}

// BuildControlsFromManager flattens compliance frameworks into control rows
// suitable for seeding the security graph control catalog.
func BuildControlsFromManager(mgr *compliance.Manager, tenantID string, now time.Time) []Control {
	if mgr == nil {
		return nil
	}
	return BuildControlsFromFrameworks(mgr.ListFrameworks(), tenantID, now)
}

// BuildFrameworkDefinitionsFromManager flattens compliance frameworks into
// compliance_framework rows needed by the secgraph control catalog.
func BuildFrameworkDefinitionsFromManager(mgr *compliance.Manager, now time.Time) []FrameworkDefinition {
	if mgr == nil {
		return nil
	}
	return BuildFrameworkDefinitionsFromFrameworks(mgr.ListFrameworks(), now)
}

// BuildFrameworkDefinitionsFromFrameworks deterministically converts
// compliance frameworks into framework catalog rows.
func BuildFrameworkDefinitionsFromFrameworks(frameworks []*compliance.Framework, now time.Time) []FrameworkDefinition {
	definitions := make([]FrameworkDefinition, 0, len(frameworks))
	for _, framework := range frameworks {
		if framework == nil {
			continue
		}
		category := strings.TrimSpace(string(framework.Sector))
		if category == "" {
			category = "general"
		}
		definitions = append(definitions, FrameworkDefinition{
			ID:            framework.ID,
			Name:          framework.Name,
			Description:   framework.Description,
			Version:       framework.Version,
			Category:      category,
			TotalControls: len(framework.Controls),
			CreatedAt:     now.UTC(),
			UpdatedAt:     now.UTC(),
		})
	}

	sort.Slice(definitions, func(i, j int) bool {
		return definitions[i].ID < definitions[j].ID
	})

	return definitions
}

// BuildControlsFromFrameworks deterministically converts framework controls
// into secgraph controls.
func BuildControlsFromFrameworks(frameworks []*compliance.Framework, tenantID string, now time.Time) []Control {
	controls := make([]Control, 0)
	for _, framework := range frameworks {
		if framework == nil {
			continue
		}
		for _, control := range framework.Controls {
			if control == nil {
				continue
			}
			controls = append(controls, Control{
				ID:             CanonicalControlID(framework.ID, control.ID),
				FrameworkID:    framework.ID,
				Title:          control.Title,
				Description:    control.Description,
				Category:       normalizeCategory(control.Category),
				Severity:       normalizeSeverity(control.Severity),
				Provider:       inferProvider(framework.ID),
				ResourceTypes:  inferResourceTypes(control.Keywords),
				EvalLogicRef:   control.ID,
				AutoRemediable: false,
				RemediationRef: "",
				Keywords:       append([]string(nil), control.Keywords...),
				Status:         ControlActive,
				TenantID:       tenantID,
				CreatedAt:      now.UTC(),
				UpdatedAt:      now.UTC(),
			})
		}
	}

	sort.Slice(controls, func(i, j int) bool {
		return controls[i].ID < controls[j].ID
	})

	return controls
}

// MaterializeFinding converts a mapped finding into control evaluations,
// issues, issue-finding links, and graph edges. Duplicate mappings collapse to
// a single issue/evaluation per (control, resource, tenant).
func MaterializeFinding(finding *compliance.Finding, tenantID string, evaluatedAt time.Time) MaterializationResult {
	return MaterializeFindingWithOptions(finding, tenantID, evaluatedAt, MaterializeOptions{})
}

// MaterializeFindingWithOptions converts a finding into secgraph artifacts and
// optionally folds graph-derived context such as adjacency blast radius into
// issue scoring.
func MaterializeFindingWithOptions(finding *compliance.Finding, tenantID string, evaluatedAt time.Time, opts MaterializeOptions) MaterializationResult {
	if finding == nil {
		return MaterializationResult{}
	}

	now := evaluatedAt.UTC()
	seen := make(map[string]struct{})
	result := MaterializationResult{}

	for _, mapping := range finding.ComplianceMappings {
		controlID := CanonicalControlID(mapping.FrameworkID, mapping.ControlID)
		dedupKey := IssueDedupKey(controlID, finding.ResourceID, tenantID)
		if _, ok := seen[dedupKey]; ok {
			continue
		}
		seen[dedupKey] = struct{}{}

		evaluationID := prefixedHash("EVAL", dedupKey)
		issueID := prefixedHash("ISS", dedupKey)
		severity := maxSeverity(mapping.Severity, finding.Severity)
		blastRadius := deriveBlastRadius(finding, opts)
		score := computeRiskScore(finding, severity, blastRadius)
		control := Control{
			ID:             controlID,
			FrameworkID:    mapping.FrameworkID,
			Title:          mapping.ControlTitle,
			Description:    mapping.ControlTitle,
			Category:       normalizeCategory(string(finding.Category)),
			Severity:       normalizeSeverity(mapping.Severity),
			Provider:       string(finding.CloudProvider),
			ResourceTypes:  []string{string(finding.ResourceType)},
			EvalLogicRef:   mapping.ControlID,
			AutoRemediable: finding.AutoRemediatable,
			RemediationRef: "",
			Keywords:       nil,
			Status:         ControlActive,
			TenantID:       tenantID,
			CreatedAt:      now,
			UpdatedAt:      now,
		}

		result.Controls = append(result.Controls, control)
		evaluationStatus := deriveEvaluationStatus(finding)
		issueStatus := deriveIssueStatus(finding)
		result.Evaluations = append(result.Evaluations, ControlEvaluation{
			ID:          evaluationID,
			ControlID:   controlID,
			ResourceID:  finding.ResourceID,
			Status:      evaluationStatus,
			Evidence:    []string{finding.ID},
			EvaluatedAt: now,
			TenantID:    tenantID,
		})
		result.Issues = append(result.Issues, Issue{
			ID:            issueID,
			Title:         fmt.Sprintf("%s %s violated on %s", mapping.FrameworkName, mapping.ControlID, finding.ResourceName),
			Description:   finding.Title,
			Severity:      severity,
			RiskScore:     score,
			BlastRadius:   blastRadius,
			Status:        issueStatus,
			ControlID:     controlID,
			ResourceID:    finding.ResourceID,
			AccountID:     finding.AccountID,
			Provider:      string(finding.CloudProvider),
			SLABreachAt:   cloneTimePtr(finding.SLABreachDate),
			ExposurePaths: exposurePathCount(finding),
			TenantID:      tenantID,
			CreatedAt:     now,
			UpdatedAt:     now,
			ResolvedAt:    deriveIssueResolvedAt(finding, issueStatus, now),
		})
		result.IssueFindings = append(result.IssueFindings, IssueFindingLink{
			IssueID:   issueID,
			FindingID: finding.ID,
			CreatedAt: now,
		})
		result.Edges = append(result.Edges,
			newEdge(NodeFinding, finding.ID, NodeControl, controlID, EdgeViolates, tenantID, now, nil),
			newEdge(NodeResource, finding.ResourceID, NodeControl, controlID, EdgeEvaluatedBy, tenantID, now, nil),
			newEdge(NodeControl, controlID, NodeComplianceFramework, mapping.FrameworkID, EdgeMapsTo, tenantID, now, nil),
			newEdge(NodeFinding, finding.ID, NodeIssue, issueID, EdgeMaterializesTo, tenantID, now, map[string]string{
				"evaluation_id": evaluationID,
			}),
		)
	}

	return result
}

// MergeMaterializationResults combines per-finding materialization output into a
// single deterministic batch keyed by the issue/control/evaluation identifiers.
func MergeMaterializationResults(base, next MaterializationResult) MaterializationResult {
	if len(base.Controls) == 0 && len(base.Evaluations) == 0 && len(base.Issues) == 0 &&
		len(base.IssueFindings) == 0 && len(base.Edges) == 0 {
		return next
	}
	if len(next.Controls) == 0 && len(next.Evaluations) == 0 && len(next.Issues) == 0 &&
		len(next.IssueFindings) == 0 && len(next.Edges) == 0 {
		return base
	}

	merged := MaterializationResult{}

	controlsByID := make(map[string]Control, len(base.Controls)+len(next.Controls))
	for _, control := range base.Controls {
		controlsByID[control.ID] = control
	}
	for _, control := range next.Controls {
		controlsByID[control.ID] = control
	}

	evaluationsByID := make(map[string]ControlEvaluation, len(base.Evaluations)+len(next.Evaluations))
	for _, evaluation := range base.Evaluations {
		evaluationsByID[evaluation.ID] = evaluation
	}
	for _, evaluation := range next.Evaluations {
		if existing, ok := evaluationsByID[evaluation.ID]; ok {
			evaluationsByID[evaluation.ID] = mergeControlEvaluations(existing, evaluation)
			continue
		}
		evaluationsByID[evaluation.ID] = evaluation
	}

	issuesByID := make(map[string]Issue, len(base.Issues)+len(next.Issues))
	for _, issue := range base.Issues {
		issuesByID[issue.ID] = issue
	}
	for _, issue := range next.Issues {
		if existing, ok := issuesByID[issue.ID]; ok {
			issuesByID[issue.ID] = mergeIssues(existing, issue)
			continue
		}
		issuesByID[issue.ID] = issue
	}

	linksByKey := make(map[string]IssueFindingLink, len(base.IssueFindings)+len(next.IssueFindings))
	for _, link := range base.IssueFindings {
		linksByKey[link.IssueID+"|"+link.FindingID] = link
	}
	for _, link := range next.IssueFindings {
		key := link.IssueID + "|" + link.FindingID
		if existing, ok := linksByKey[key]; ok {
			if link.CreatedAt.Before(existing.CreatedAt) {
				linksByKey[key] = link
			}
			continue
		}
		linksByKey[key] = link
	}

	edgesByID := make(map[string]GraphEdge, len(base.Edges)+len(next.Edges))
	for _, edge := range base.Edges {
		edgesByID[edge.ID] = edge
	}
	for _, edge := range next.Edges {
		edgesByID[edge.ID] = edge
	}

	for _, control := range controlsByID {
		merged.Controls = append(merged.Controls, control)
	}
	for _, evaluation := range evaluationsByID {
		merged.Evaluations = append(merged.Evaluations, evaluation)
	}
	for _, issue := range issuesByID {
		merged.Issues = append(merged.Issues, issue)
	}
	for _, link := range linksByKey {
		merged.IssueFindings = append(merged.IssueFindings, link)
	}
	for _, edge := range edgesByID {
		merged.Edges = append(merged.Edges, edge)
	}

	sort.Slice(merged.Controls, func(i, j int) bool { return merged.Controls[i].ID < merged.Controls[j].ID })
	sort.Slice(merged.Evaluations, func(i, j int) bool { return merged.Evaluations[i].ID < merged.Evaluations[j].ID })
	sort.Slice(merged.Issues, func(i, j int) bool { return merged.Issues[i].ID < merged.Issues[j].ID })
	sort.Slice(merged.IssueFindings, func(i, j int) bool {
		if merged.IssueFindings[i].IssueID == merged.IssueFindings[j].IssueID {
			return merged.IssueFindings[i].FindingID < merged.IssueFindings[j].FindingID
		}
		return merged.IssueFindings[i].IssueID < merged.IssueFindings[j].IssueID
	})
	sort.Slice(merged.Edges, func(i, j int) bool { return merged.Edges[i].ID < merged.Edges[j].ID })

	return merged
}

// MergeIssueSurfaceResults combines only the operator-facing issue artifacts.
// It intentionally excludes controls and graph edges so large-corpus startup
// syncs can bound memory while still materializing the issue surface.
func MergeIssueSurfaceResults(base, next MaterializationResult) MaterializationResult {
	accumulator := NewIssueSurfaceAccumulator(len(base.Issues) + len(next.Issues))
	accumulator.Add(base)
	accumulator.Add(next)
	return accumulator.Snapshot()
}

// CanonicalControlID returns a stable control identifier suitable for graph and
// relational storage.
func CanonicalControlID(frameworkID, controlID string) string {
	return fmt.Sprintf("%s:%s", strings.TrimSpace(frameworkID), strings.TrimSpace(controlID))
}

// IssueDedupKey returns the logical uniqueness key for issue materialization.
func IssueDedupKey(controlID, resourceID, tenantID string) string {
	return strings.Join([]string{
		strings.TrimSpace(controlID),
		strings.TrimSpace(resourceID),
		strings.TrimSpace(tenantID),
	}, "|")
}

func newEdge(sourceType NodeType, sourceID string, targetType NodeType, targetID string, edgeType EdgeType, tenantID string, createdAt time.Time, properties map[string]string) GraphEdge {
	edgeID := prefixedHash("EDGE", strings.Join([]string{
		string(sourceType), sourceID, string(targetType), targetID, string(edgeType), tenantID,
	}, "|"))
	return GraphEdge{
		ID:         edgeID,
		SourceType: sourceType,
		SourceID:   sourceID,
		TargetType: targetType,
		TargetID:   targetID,
		EdgeType:   edgeType,
		Properties: properties,
		TenantID:   tenantID,
		CreatedAt:  createdAt,
	}
}

func prefixedHash(prefix, input string) string {
	sum := sha256.Sum256([]byte(input))
	return prefix + "-" + strings.ToUpper(hex.EncodeToString(sum[:6]))
}

func normalizeSeverity(severity string) string {
	normalized := strings.ToUpper(strings.TrimSpace(severity))
	switch normalized {
	case "CRITICAL", "HIGH", "MEDIUM", "LOW":
		return normalized
	default:
		return "MEDIUM"
	}
}

func maxSeverity(values ...string) string {
	best := "LOW"
	bestWeight := severityWeight[best]
	for _, value := range values {
		normalized := normalizeSeverity(value)
		if severityWeight[normalized] > bestWeight {
			best = normalized
			bestWeight = severityWeight[normalized]
		}
	}
	return best
}

func computeRiskScore(finding *compliance.Finding, severity string, blastRadius int) float64 {
	normalizedSeverity := normalizeSeverity(severity)
	score := severityBaseScore[normalizedSeverity]
	if score == 0 {
		score = severityBaseScore["MEDIUM"]
	}
	if finding == nil {
		return score
	}

	score *= 1 + float64(minInt(blastRadius, 5))*0.05

	exposureFactor := maxInt(1, exposurePathCount(finding))
	score *= 1 + float64(exposureFactor-1)*0.10

	if finding.AIRiskScore > 0 {
		score = maxFloat(score, finding.AIRiskScore*10)
	}
	if score > 100 {
		return 100
	}
	if score < 0 {
		return 0
	}
	return score
}

func deriveBlastRadius(finding *compliance.Finding, opts MaterializeOptions) int {
	if finding == nil {
		return 0
	}

	baseline := len(finding.ImpactedResources)
	if opts.Adjacency == nil || strings.TrimSpace(finding.ResourceID) == "" {
		return baseline
	}

	graphRadius := opts.Adjacency.BlastRadius(finding.ResourceID, opts.BlastRadiusHops)
	if graphRadius > baseline {
		return graphRadius
	}
	return baseline
}

func mergeControlEvaluations(existing, incoming ControlEvaluation) ControlEvaluation {
	merged := existing
	merged.Status = mergeEvalStatus(existing.Status, incoming.Status)
	merged.Evidence = mergeStringSets(existing.Evidence, incoming.Evidence)
	if incoming.EvaluatedAt.After(merged.EvaluatedAt) {
		merged.EvaluatedAt = incoming.EvaluatedAt
	}
	return merged
}

func mergeIssues(existing, incoming Issue) Issue {
	merged := existing
	replaceNarrative := severityWeight[normalizeSeverity(incoming.Severity)] > severityWeight[normalizeSeverity(existing.Severity)] ||
		incoming.RiskScore > existing.RiskScore
	if replaceNarrative {
		merged.Title = incoming.Title
		merged.Description = incoming.Description
	}
	merged.Severity = maxSeverity(existing.Severity, incoming.Severity)
	merged.RiskScore = maxFloat(existing.RiskScore, incoming.RiskScore)
	merged.BlastRadius = maxInt(existing.BlastRadius, incoming.BlastRadius)
	merged.ExposurePaths = maxInt(existing.ExposurePaths, incoming.ExposurePaths)
	merged.Status = mergeIssueStatus(existing.Status, incoming.Status)
	merged.SLABreachAt = minTimePtr(existing.SLABreachAt, incoming.SLABreachAt)
	merged.ResolvedAt = mergeResolvedAt(merged.Status, existing.ResolvedAt, incoming.ResolvedAt)
	if incoming.CreatedAt.Before(merged.CreatedAt) || merged.CreatedAt.IsZero() {
		merged.CreatedAt = incoming.CreatedAt
	}
	if incoming.UpdatedAt.After(merged.UpdatedAt) {
		merged.UpdatedAt = incoming.UpdatedAt
	}
	if merged.ControlID == "" {
		merged.ControlID = incoming.ControlID
	}
	if merged.ResourceID == "" {
		merged.ResourceID = incoming.ResourceID
	}
	if merged.AccountID == "" {
		merged.AccountID = incoming.AccountID
	}
	if merged.Provider == "" {
		merged.Provider = incoming.Provider
	}
	if merged.AssigneeID == "" {
		merged.AssigneeID = incoming.AssigneeID
	}
	if merged.TicketID == "" {
		merged.TicketID = incoming.TicketID
	}
	if merged.TicketURL == "" {
		merged.TicketURL = incoming.TicketURL
	}
	return merged
}

func mergeIssueStatus(existing, incoming IssueStatus) IssueStatus {
	if issueStatusPriority(incoming) > issueStatusPriority(existing) {
		return incoming
	}
	return existing
}

func issueStatusPriority(status IssueStatus) int {
	switch status {
	case IssueInProgress:
		return 5
	case IssueAcknowledged:
		return 4
	case IssueOpen:
		return 3
	case IssueSuppressed:
		return 2
	case IssueResolved:
		return 1
	default:
		return 0
	}
}

func mergeEvalStatus(existing, incoming EvalStatus) EvalStatus {
	if evalStatusPriority(incoming) > evalStatusPriority(existing) {
		return incoming
	}
	return existing
}

func evalStatusPriority(status EvalStatus) int {
	switch status {
	case EvalFail:
		return 3
	case EvalNotApplicable:
		return 2
	case EvalPass:
		return 1
	case EvalError:
		return 0
	}
	return 0
}

func inferProvider(frameworkID string) string {
	lower := strings.ToLower(frameworkID)
	switch {
	case strings.Contains(lower, "aws"):
		return "aws"
	case strings.Contains(lower, "azure"):
		return "azure"
	case strings.Contains(lower, "gcp"):
		return "gcp"
	default:
		return "*"
	}
}

func normalizeCategory(category string) string {
	switch strings.ToUpper(strings.TrimSpace(category)) {
	case "IAM":
		return "IDENTITY"
	case "":
		return "GENERAL"
	default:
		return strings.ToUpper(strings.TrimSpace(category))
	}
}

func inferResourceTypes(keywords []string) []string {
	resourceTypes := make(map[string]struct{})
	for _, keyword := range keywords {
		lower := strings.ToLower(keyword)
		switch {
		case strings.Contains(lower, "s3"), strings.Contains(lower, "bucket"), strings.Contains(lower, "blob"):
			resourceTypes["storage"] = struct{}{}
		case strings.Contains(lower, "iam"), strings.Contains(lower, "identity"), strings.Contains(lower, "role"), strings.Contains(lower, "access"):
			resourceTypes["identity"] = struct{}{}
		case strings.Contains(lower, "network"), strings.Contains(lower, "ingress"), strings.Contains(lower, "egress"), strings.Contains(lower, "port"):
			resourceTypes["network"] = struct{}{}
		case strings.Contains(lower, "db"), strings.Contains(lower, "database"), strings.Contains(lower, "rds"), strings.Contains(lower, "sql"):
			resourceTypes["database"] = struct{}{}
		case strings.Contains(lower, "container"), strings.Contains(lower, "kubernetes"), strings.Contains(lower, "pod"):
			resourceTypes["container"] = struct{}{}
		case strings.Contains(lower, "lambda"), strings.Contains(lower, "function"), strings.Contains(lower, "serverless"):
			resourceTypes["serverless"] = struct{}{}
		}
	}

	if len(resourceTypes) == 0 {
		return nil
	}

	out := make([]string, 0, len(resourceTypes))
	for resourceType := range resourceTypes {
		out = append(out, resourceType)
	}
	sort.Strings(out)
	return out
}

func exposurePathCount(finding *compliance.Finding) int {
	count := 0
	if finding.ExploitAvailable {
		count++
	}
	if finding.Category == compliance.CategoryNetwork {
		count++
	}
	if len(finding.ImpactedResources) > 0 {
		count++
	}
	return count
}

func deriveEvaluationStatus(finding *compliance.Finding) EvalStatus {
	switch deriveIssueStatus(finding) {
	case IssueResolved:
		return EvalPass
	case IssueSuppressed:
		return EvalNotApplicable
	case IssueOpen, IssueAcknowledged, IssueInProgress:
		return EvalFail
	}
	return EvalFail
}

func deriveIssueStatus(finding *compliance.Finding) IssueStatus {
	if finding == nil {
		return IssueOpen
	}

	status := strings.ToLower(strings.TrimSpace(finding.Status))
	workflow := strings.ToLower(strings.TrimSpace(string(finding.WorkflowStatus)))

	switch {
	case finding.Suppressed,
		status == "suppressed",
		workflow == string(compliance.StatusSuppressed),
		workflow == string(compliance.StatusFalsePositive),
		workflow == string(compliance.StatusRiskAccepted),
		workflow == string(compliance.StatusWontFix):
		return IssueSuppressed
	case status == "resolved",
		status == "closed",
		workflow == string(compliance.StatusRemediated),
		workflow == string(compliance.StatusVerified),
		workflow == string(compliance.StatusClosed):
		return IssueResolved
	case status == "in_progress",
		workflow == string(compliance.StatusInProgress):
		return IssueInProgress
	case status == "acknowledged",
		workflow == string(compliance.StatusTriaged),
		workflow == string(compliance.StatusAssigned),
		workflow == string(compliance.StatusPendingInfo),
		workflow == string(compliance.StatusPendingApproval):
		return IssueAcknowledged
	default:
		return IssueOpen
	}
}

func deriveIssueResolvedAt(finding *compliance.Finding, status IssueStatus, fallback time.Time) *time.Time {
	if finding == nil {
		return nil
	}
	if status != IssueResolved && status != IssueSuppressed {
		return nil
	}
	if finding.ResolvedAt != nil {
		return cloneTimePtr(finding.ResolvedAt)
	}
	if !finding.LastSeenAt.IsZero() {
		resolvedAt := finding.LastSeenAt.UTC()
		return &resolvedAt
	}
	resolvedAt := fallback.UTC()
	return &resolvedAt
}

func cloneTimePtr(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	copied := value.UTC()
	return &copied
}

func minTimePtr(a, b *time.Time) *time.Time {
	if a == nil {
		return cloneTimePtr(b)
	}
	if b == nil {
		return cloneTimePtr(a)
	}
	if b.Before(*a) {
		return cloneTimePtr(b)
	}
	return cloneTimePtr(a)
}

func mergeResolvedAt(status IssueStatus, a, b *time.Time) *time.Time {
	if status != IssueResolved && status != IssueSuppressed {
		return nil
	}
	if a == nil {
		return cloneTimePtr(b)
	}
	if b == nil {
		return cloneTimePtr(a)
	}
	if b.After(*a) {
		return cloneTimePtr(b)
	}
	return cloneTimePtr(a)
}

func mergeStringSets(existing, incoming []string) []string {
	if len(existing) == 0 {
		return append([]string(nil), incoming...)
	}
	set := make(map[string]struct{}, len(existing)+len(incoming))
	merged := make([]string, 0, len(existing)+len(incoming))
	for _, value := range existing {
		if _, ok := set[value]; ok {
			continue
		}
		set[value] = struct{}{}
		merged = append(merged, value)
	}
	for _, value := range incoming {
		if _, ok := set[value]; ok {
			continue
		}
		set[value] = struct{}{}
		merged = append(merged, value)
	}
	sort.Strings(merged)
	return merged
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func maxFloat(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}
