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

// BuildControlsFromManager flattens compliance frameworks into control rows
// suitable for seeding the security graph control catalog.
func BuildControlsFromManager(mgr *compliance.Manager, tenantID string, now time.Time) []Control {
	if mgr == nil {
		return nil
	}
	return BuildControlsFromFrameworks(mgr.ListFrameworks(), tenantID, now)
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
		score := computeRiskScore(finding, severity)
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
			BlastRadius:   len(finding.ImpactedResources),
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

func computeRiskScore(finding *compliance.Finding, severity string) float64 {
	score := severityWeight[normalizeSeverity(severity)]
	score += float64(minInt(len(finding.ImpactedResources), 5)) * 0.4
	if finding.ExploitAvailable {
		score += 1.0
	}
	switch finding.Category {
	case compliance.CategoryNetwork, compliance.CategoryIdentity:
		score += 0.5
	}
	if score > 10 {
		return 10
	}
	return score
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
	default:
		return EvalFail
	}
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

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
