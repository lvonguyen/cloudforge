package main

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strings"
	"time"

	"aegis/internal/compliance"
	"aegis/internal/integrations"
	"aegis/internal/secgraph"

	"go.uber.org/zap"
)

const defaultSecgraphTenantID = "default"

type secgraphPersister interface {
	UpsertControls(ctx context.Context, controls []secgraph.Control) error
	UpsertMaterialization(ctx context.Context, result secgraph.MaterializationResult) error
}

type secgraphIssueDispatcher interface {
	Dispatch(ctx context.Context, issue *secgraph.Issue) error
}

type secgraphIssueTicketState struct {
	TicketID    string
	TicketURL   string
	AssigneeID  string
	SLABreachAt *time.Time
}

type secgraphIssueTicketLoader interface {
	LoadIssueTicketState(ctx context.Context, issueID string) (secgraphIssueTicketState, error)
}

type sqlSecgraphIssueTicketLoader struct {
	db *sql.DB
}

func (l sqlSecgraphIssueTicketLoader) LoadIssueTicketState(ctx context.Context, issueID string) (secgraphIssueTicketState, error) {
	if l.db == nil {
		return secgraphIssueTicketState{}, nil
	}

	const query = `
		SELECT ticket_id, ticket_url, assignee_id, sla_breach_at
		FROM issues
		WHERE id = $1
	`

	var (
		ticketID   sql.NullString
		ticketURL  sql.NullString
		assigneeID sql.NullString
		slaBreach  sql.NullTime
	)
	err := l.db.QueryRowContext(ctx, query, issueID).Scan(&ticketID, &ticketURL, &assigneeID, &slaBreach)
	if err == sql.ErrNoRows {
		return secgraphIssueTicketState{}, nil
	}
	if err != nil {
		return secgraphIssueTicketState{}, err
	}

	state := secgraphIssueTicketState{
		TicketID:   strings.TrimSpace(ticketID.String),
		TicketURL:  strings.TrimSpace(ticketURL.String),
		AssigneeID: strings.TrimSpace(assigneeID.String),
	}
	if slaBreach.Valid {
		value := slaBreach.Time.UTC()
		state.SLABreachAt = &value
	}
	return state, nil
}

type secgraphTicketDispatcher struct {
	provider     integrations.TicketProvider
	router       integrations.RoutingEngine
	loader       secgraphIssueTicketLoader
	autoDispatch bool
	logger       *zap.Logger
}

func (d *secgraphTicketDispatcher) Dispatch(ctx context.Context, issue *secgraph.Issue) error {
	if issue == nil {
		return nil
	}

	state, err := d.loadExisting(ctx, issue.ID)
	if err != nil {
		return fmt.Errorf("load existing issue ticket state for %s: %w", issue.ID, err)
	}
	mergeIssueTicketState(issue, state)
	if issue.TicketID != "" || !d.autoDispatch || d.provider == nil || d.router == nil {
		return nil
	}

	decision, err := d.router.Route(ctx, integrations.RoutingInput{
		Severity:       strings.ToUpper(strings.TrimSpace(issue.Severity)),
		IsChokePoint:   issue.ExposurePaths > 0,
		ComplianceHits: 1,
	})
	if err != nil {
		return fmt.Errorf("route issue %s: %w", issue.ID, err)
	}

	dueDate := decision.SLADeadline(time.Now().UTC())
	ticket, err := d.provider.CreateTicket(ctx, integrations.CreateTicketRequest{
		FindingID:   issue.ID,
		Title:       fmt.Sprintf("[Cloud Aegis] Remediate issue %s", issue.ID),
		Description: buildSecgraphIssueTicketDescription(*issue, decision),
		Priority:    decision.Priority,
		Assignee:    issue.AssigneeID,
		DueDate:     &dueDate,
		Labels: []string{
			"secgraph-issue",
			strings.ToLower(issue.Severity),
		},
		Metadata: map[string]string{
			"team":         decision.Team,
			"sla_rule":     decision.Reason,
			"issue_id":     issue.ID,
			"control_id":   issue.ControlID,
			"resource_id":  issue.ResourceID,
			"account_id":   issue.AccountID,
			"provider":     issue.Provider,
			"tenant_id":    issue.TenantID,
			"risk_score":   fmt.Sprintf("%.2f", issue.RiskScore),
			"blast_radius": fmt.Sprintf("%d", issue.BlastRadius),
		},
	})
	if err != nil {
		return fmt.Errorf("create ticket for issue %s: %w", issue.ID, err)
	}

	issue.TicketID = ticket.ExternalID
	issue.TicketURL = ticket.URL
	if issue.AssigneeID == "" {
		issue.AssigneeID = ticket.Assignee
	}
	if issue.SLABreachAt == nil {
		issue.SLABreachAt = &dueDate
	}
	if d.logger != nil {
		d.logger.Info("Secgraph issue ticket created",
			zap.String("issue_id", issue.ID),
			zap.String("ticket_id", issue.TicketID),
			zap.String("provider", ticket.Provider),
		)
	}
	return nil
}

func (d *secgraphTicketDispatcher) loadExisting(ctx context.Context, issueID string) (secgraphIssueTicketState, error) {
	if d == nil || d.loader == nil {
		return secgraphIssueTicketState{}, nil
	}
	return d.loader.LoadIssueTicketState(ctx, issueID)
}

func syncSecurityGraph(ctx context.Context, db *sql.DB, mgr *compliance.Manager, findings []Finding, provider integrations.TicketProvider, router integrations.RoutingEngine, logger *zap.Logger) error {
	if db == nil {
		return nil
	}
	dispatcher := &secgraphTicketDispatcher{
		provider:     provider,
		router:       router,
		loader:       sqlSecgraphIssueTicketLoader{db: db},
		autoDispatch: secgraphAutoTicketsEnabled(),
		logger:       logger,
	}
	return syncSecurityGraphWithStoreAndDispatcher(ctx, secgraph.NewStore(db), mgr, findings, defaultSecgraphTenantID, time.Now().UTC(), dispatcher, logger)
}

func syncSecurityGraphWithStore(ctx context.Context, store secgraphPersister, mgr *compliance.Manager, findings []Finding, tenantID string, now time.Time, logger *zap.Logger) error {
	return syncSecurityGraphWithStoreAndDispatcher(ctx, store, mgr, findings, tenantID, now, nil, logger)
}

func syncSecurityGraphWithStoreAndDispatcher(ctx context.Context, store secgraphPersister, mgr *compliance.Manager, findings []Finding, tenantID string, now time.Time, dispatcher secgraphIssueDispatcher, logger *zap.Logger) error {
	if store == nil || mgr == nil {
		return nil
	}

	controls := secgraph.BuildControlsFromManager(mgr, tenantID, now)
	if err := store.UpsertControls(ctx, controls); err != nil {
		return fmt.Errorf("seed secgraph controls: %w", err)
	}

	seenControls := make(map[string]struct{}, len(controls))
	for _, control := range controls {
		seenControls[control.ID] = struct{}{}
	}

	materializedFindings := 0
	materializedIssues := 0
	for _, finding := range findings {
		complianceFinding := toComplianceFinding(finding)
		if len(complianceFinding.ComplianceMappings) == 0 {
			mapped, err := mgr.MapFinding(ctx, &complianceFinding, compliance.SectorGeneral)
			if err != nil {
				return fmt.Errorf("map finding %s: %w", finding.ID, err)
			}
			complianceFinding = *mapped
		}

		result := secgraph.MaterializeFinding(&complianceFinding, tenantID, now)
		if len(result.Issues) == 0 && len(result.Evaluations) == 0 && len(result.Edges) == 0 {
			continue
		}

		var extraControls []secgraph.Control
		for _, control := range result.Controls {
			if _, ok := seenControls[control.ID]; ok {
				continue
			}
			seenControls[control.ID] = struct{}{}
			extraControls = append(extraControls, control)
		}
		if len(extraControls) > 0 {
			if err := store.UpsertControls(ctx, extraControls); err != nil {
				return fmt.Errorf("seed materialized controls for finding %s: %w", finding.ID, err)
			}
		}
		for idx := range result.Issues {
			if dispatcher == nil {
				continue
			}
			if err := dispatcher.Dispatch(ctx, &result.Issues[idx]); err != nil {
				return fmt.Errorf("dispatch issue ticket for finding %s: %w", finding.ID, err)
			}
		}
		if err := store.UpsertMaterialization(ctx, result); err != nil {
			return fmt.Errorf("persist secgraph artifacts for finding %s: %w", finding.ID, err)
		}
		materializedFindings++
		materializedIssues += len(result.Issues)
	}

	if logger != nil {
		logger.Info("Security graph sync complete",
			zap.Int("controls_seeded", len(controls)),
			zap.Int("findings_materialized", materializedFindings),
			zap.Int("issues_materialized", materializedIssues),
		)
	}

	return nil
}

func buildSecgraphIssueTicketDescription(issue secgraph.Issue, decision *integrations.RoutingDecision) string {
	parts := []string{
		"Security Graph issue materialized from control evaluation.",
		fmt.Sprintf("Severity: %s", issue.Severity),
		fmt.Sprintf("Risk Score: %.2f", issue.RiskScore),
		fmt.Sprintf("Blast Radius: %d", issue.BlastRadius),
		fmt.Sprintf("Exposure Paths: %d", issue.ExposurePaths),
	}
	if issue.ControlID != "" {
		parts = append(parts, fmt.Sprintf("Control: %s", issue.ControlID))
	}
	if issue.ResourceID != "" {
		parts = append(parts, fmt.Sprintf("Resource: %s", issue.ResourceID))
	}
	if decision != nil {
		parts = append(parts,
			fmt.Sprintf("Routed Team: %s", decision.Team),
			fmt.Sprintf("SLA Hours: %d", decision.SLAHours),
			fmt.Sprintf("Routing Rule: %s", decision.Reason),
		)
	}
	if issue.Description != "" {
		parts = append(parts, "", issue.Description)
	}
	return strings.Join(parts, "\n")
}

func mergeIssueTicketState(issue *secgraph.Issue, state secgraphIssueTicketState) {
	if issue == nil {
		return
	}
	if issue.TicketID == "" {
		issue.TicketID = state.TicketID
	}
	if issue.TicketURL == "" {
		issue.TicketURL = state.TicketURL
	}
	if issue.AssigneeID == "" {
		issue.AssigneeID = state.AssigneeID
	}
	if issue.SLABreachAt == nil && state.SLABreachAt != nil {
		value := state.SLABreachAt.UTC()
		issue.SLABreachAt = &value
	}
}

func secgraphAutoTicketsEnabled() bool {
	return strings.EqualFold(strings.TrimSpace(os.Getenv("SECGRAPH_AUTO_TICKETS")), "true")
}

func toComplianceFinding(f Finding) compliance.Finding {
	converted := compliance.Finding{
		ID:                  f.ID,
		Source:              f.Source,
		SourceFindingID:     f.SourceFindingID,
		Type:                compliance.FindingType(strings.TrimSpace(f.Type)),
		Title:               f.Title,
		Description:         f.Description,
		ResourceType:        compliance.ResourceType(strings.TrimSpace(strings.ToLower(f.ResourceType))),
		ResourceID:          f.ResourceID,
		ResourceName:        f.ResourceName,
		ResourceARN:         f.ResourceARN,
		Platform:            compliance.Platform(strings.TrimSpace(strings.ToLower(f.Platform))),
		CloudProvider:       compliance.CloudProvider(strings.TrimSpace(strings.ToLower(f.CloudProvider))),
		Region:              f.Region,
		AccountID:           f.AccountID,
		AccountName:         f.AccountName,
		EnvironmentType:     compliance.EnvironmentType(strings.TrimSpace(strings.ToLower(f.EnvironmentType))),
		StaticSeverity:      f.StaticSeverity,
		Severity:            f.Severity,
		AIRiskScore:         f.AIRiskScore,
		AIRiskLevel:         f.AIRiskLevel,
		AIRiskRationale:     f.AIRiskRationale,
		AIContextualFactors: append([]string(nil), f.AIContextualFactors...),
		ExploitAvailable:    f.ExploitAvailable,
		CVEs:                toComplianceCVEReferences(f.CVEs),
		ComplianceMappings:  toComplianceMappings(f.ComplianceMappings),
		MITRETactics:        append([]string(nil), f.MITRETactics...),
		MITRETechniques:     append([]string(nil), f.MITRETechniques...),
		Remediation:         f.Remediation,
		AutoRemediatable:    f.AutoRemediatable,
		Category:            compliance.FindingCategory(strings.TrimSpace(strings.ToUpper(f.Category))),
		Status:              f.Status,
		WorkflowStatus:      compliance.WorkflowStatus(strings.TrimSpace(strings.ToLower(f.WorkflowStatus))),
		ServiceName:         f.ServiceName,
		LineOfBusiness:      f.LineOfBusiness,
		FirstFoundAt:        parseRFC3339OrZero(f.FirstFoundAt),
		LastSeenAt:          parseRFC3339OrZero(f.LastSeenAt),
		DeduplicationKey:    f.DeduplicationKey,
		CanonicalRuleID:     f.CanonicalRuleID,
	}

	if f.CVSS != nil {
		converted.CVSS = *f.CVSS
	}
	if f.EPSS != nil {
		converted.EPSS = *f.EPSS
	}
	if dueDate := parseRFC3339Ptr(f.DueDate); dueDate != nil {
		converted.DueDate = dueDate
	}
	if breachAt := parseRFC3339Ptr(f.SLABreachDate); breachAt != nil {
		converted.SLABreachDate = breachAt
	}

	return converted
}

func toComplianceMappings(mappings []ComplianceMapping) []compliance.ComplianceMapping {
	converted := make([]compliance.ComplianceMapping, 0, len(mappings))
	for _, mapping := range mappings {
		converted = append(converted, compliance.ComplianceMapping{
			FrameworkID:   mapping.FrameworkID,
			FrameworkName: mapping.FrameworkName,
			ControlID:     mapping.ControlID,
			ControlTitle:  mapping.ControlTitle,
			Section:       mapping.Section,
			Severity:      mapping.Severity,
			URL:           mapping.URL,
		})
	}
	return converted
}

func toComplianceCVEReferences(cves []CVE) []compliance.CVEReference {
	converted := make([]compliance.CVEReference, 0, len(cves))
	for _, cve := range cves {
		ref := compliance.CVEReference{
			ID:                 cve.ID,
			URL:                cve.URL,
			NVDUrl:             cve.NVDURL,
			MitreURL:           cve.MitreURL,
			Description:        cve.Description,
			CVSSVector:         cve.CVSSVector,
			CVSSVersion:        cve.CVSSVersion,
			CISAKnownExploited: cve.CISAKnownExploited,
			Published:          parseRFC3339OrZero(cve.Published),
			Modified:           parseRFC3339OrZero(cve.Modified),
		}
		if cve.CVSS != nil {
			ref.CVSS = *cve.CVSS
		}
		if cve.EPSS != nil {
			ref.EPSS = *cve.EPSS
		}
		converted = append(converted, ref)
	}
	return converted
}

func parseRFC3339OrZero(value string) time.Time {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}
	}
	return parsed.UTC()
}

func parseRFC3339Ptr(value string) *time.Time {
	parsed := parseRFC3339OrZero(value)
	if parsed.IsZero() {
		return nil
	}
	return &parsed
}
