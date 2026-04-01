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

const (
	secgraphStartupAdvisoryLockKey int64 = 0x5345434752415048
	secgraphProgressInterval       int   = 5000
)

var secgraphIssueSurfacePersistInterval = 25000

type secgraphPersister interface {
	UpsertFrameworks(ctx context.Context, frameworks []secgraph.FrameworkDefinition) error
	UpsertControls(ctx context.Context, controls []secgraph.Control) error
	UpsertMaterialization(ctx context.Context, result secgraph.MaterializationResult) error
}

type secgraphReconciler interface {
	ReconcileStaleMaterialization(ctx context.Context, tenantID string, activeFindingIDs []string, now time.Time) error
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

type secgraphIssueAssignmentCandidate struct {
	assigneeID string
	priority   int
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
	if !d.autoDispatch {
		return nil
	}

	state, err := d.loadExisting(ctx, issue.ID)
	if err != nil {
		return fmt.Errorf("load existing issue ticket state for %s: %w", issue.ID, err)
	}
	mergeIssueTicketState(issue, state)
	if issue.TicketID != "" || d.provider == nil || d.router == nil {
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
	unlock, acquired, err := acquireSecgraphStartupLock(ctx, db, logger)
	if err != nil {
		return err
	}
	if !acquired {
		if logger != nil {
			logger.Info("Security graph sync already running on another instance, skipping duplicate startup sync")
		}
		return nil
	}
	defer unlock()

	adjacency, err := loadSecgraphAdjacency(ctx, db, logger)
	if err != nil {
		return err
	}
	dispatcher := &secgraphTicketDispatcher{
		provider:     provider,
		router:       router,
		loader:       sqlSecgraphIssueTicketLoader{db: db},
		autoDispatch: secgraphAutoTicketsEnabled(),
		logger:       logger,
	}
	if !secgraphFullSyncEnabledForCorpus(len(findings)) {
		seedCatalog, err := secgraphStartupNeedsCatalogSeed(ctx, db, mgr)
		if err != nil {
			return err
		}
		if logger != nil {
			logger.Warn("Large corpus security graph startup using issue-surface mode",
				zap.Int("findings", len(findings)),
				zap.Int("max_full_sync_findings", secgraphFullSyncMaxFindings()),
				zap.String("deferred_artifacts", "issue graph edges"),
				zap.Bool("seed_catalog", seedCatalog),
			)
		}
		return syncSecurityIssueSurfaceWithStoreAndDispatcherMode(ctx, secgraph.NewStore(db), mgr, findings, defaultSecgraphTenantID, time.Now().UTC(), dispatcher, logger, true, seedCatalog, adjacency)
	}
	return syncSecurityGraphWithStoreAndDispatcherMode(ctx, secgraph.NewStore(db), mgr, findings, defaultSecgraphTenantID, time.Now().UTC(), dispatcher, logger, true, adjacency)
}

func acquireSecgraphStartupLock(ctx context.Context, db *sql.DB, logger *zap.Logger) (func(), bool, error) {
	if db == nil {
		return func() {}, false, nil
	}

	conn, err := db.Conn(ctx)
	if err != nil {
		return nil, false, fmt.Errorf("acquire secgraph lock connection: %w", err)
	}

	var acquired bool
	if err := conn.QueryRowContext(ctx, `SELECT pg_try_advisory_lock($1)`, secgraphStartupAdvisoryLockKey).Scan(&acquired); err != nil {
		_ = conn.Close()
		return nil, false, fmt.Errorf("acquire secgraph advisory lock: %w", err)
	}
	if !acquired {
		_ = conn.Close()
		return func() {}, false, nil
	}

	unlock := func() {
		unlockCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := conn.ExecContext(unlockCtx, `SELECT pg_advisory_unlock($1)`, secgraphStartupAdvisoryLockKey); err != nil && logger != nil {
			logger.Warn("Failed to release secgraph advisory lock", zap.Error(err))
		}
		if err := conn.Close(); err != nil && logger != nil {
			logger.Warn("Failed to close secgraph advisory lock connection", zap.Error(err))
		}
	}

	return unlock, true, nil
}

func secgraphStartupNeedsCatalogSeed(ctx context.Context, db *sql.DB, mgr *compliance.Manager) (bool, error) {
	if db == nil || mgr == nil {
		return true, nil
	}

	expectedFrameworks := len(secgraph.BuildFrameworkDefinitionsFromManager(mgr, time.Now().UTC()))
	expectedControls := len(secgraph.BuildControlsFromManager(mgr, defaultSecgraphTenantID, time.Now().UTC()))

	var existingFrameworks, existingControls int
	if err := db.QueryRowContext(ctx, `
		SELECT
			(SELECT COUNT(*) FROM compliance_frameworks),
			(SELECT COUNT(*) FROM controls)
	`).Scan(&existingFrameworks, &existingControls); err != nil {
		return false, fmt.Errorf("query secgraph catalog counts: %w", err)
	}

	return existingFrameworks < expectedFrameworks || existingControls < expectedControls, nil
}

func syncSecurityGraphWithStore(ctx context.Context, store secgraphPersister, mgr *compliance.Manager, findings []Finding, tenantID string, now time.Time, logger *zap.Logger) error {
	return syncSecurityGraphWithStoreAndDispatcherMode(ctx, store, mgr, findings, tenantID, now, nil, logger, true, nil)
}

func syncSecurityGraphWithStoreAndDispatcher(ctx context.Context, store secgraphPersister, mgr *compliance.Manager, findings []Finding, tenantID string, now time.Time, dispatcher secgraphIssueDispatcher, logger *zap.Logger) error {
	return syncSecurityGraphWithStoreAndDispatcherMode(ctx, store, mgr, findings, tenantID, now, dispatcher, logger, false, nil)
}

func syncSecurityGraphWithStoreAndDispatcherMode(ctx context.Context, store secgraphPersister, mgr *compliance.Manager, findings []Finding, tenantID string, now time.Time, dispatcher secgraphIssueDispatcher, logger *zap.Logger, reconcile bool, adjacency *secgraph.AdjacencySet) error {
	if store == nil || mgr == nil {
		return nil
	}

	frameworks := secgraph.BuildFrameworkDefinitionsFromManager(mgr, now)
	if err := store.UpsertFrameworks(ctx, frameworks); err != nil {
		return fmt.Errorf("seed secgraph frameworks: %w", err)
	}
	controls := secgraph.BuildControlsFromManager(mgr, tenantID, now)
	if err := store.UpsertControls(ctx, controls); err != nil {
		return fmt.Errorf("seed secgraph controls: %w", err)
	}

	seenFrameworks := make(map[string]struct{}, len(frameworks))
	for _, framework := range frameworks {
		seenFrameworks[framework.ID] = struct{}{}
	}
	seenControls := make(map[string]struct{}, len(controls))
	for _, control := range controls {
		seenControls[control.ID] = struct{}{}
	}

	materializedFindings := 0
	materialized := secgraph.MaterializationResult{}
	assignmentCandidates := make(map[string]secgraphIssueAssignmentCandidate)
	for _, finding := range findings {
		complianceFinding := toComplianceFinding(finding)
		if len(complianceFinding.ComplianceMappings) == 0 {
			mapped, err := mgr.MapFinding(ctx, &complianceFinding, compliance.SectorGeneral)
			if err != nil {
				return fmt.Errorf("map finding %s: %w", finding.ID, err)
			}
			complianceFinding = *mapped
		}

		result := secgraph.MaterializeFindingWithOptions(&complianceFinding, tenantID, now, secgraph.MaterializeOptions{
			Adjacency:       adjacency,
			BlastRadiusHops: 2,
		})
		if len(result.Issues) == 0 && len(result.Evaluations) == 0 && len(result.Edges) == 0 {
			continue
		}

		extraFrameworks := missingFrameworkDefinitions(seenFrameworks, frameworkDefinitionsFromMappings(complianceFinding.ComplianceMappings, now))
		if len(extraFrameworks) > 0 {
			if err := store.UpsertFrameworks(ctx, extraFrameworks); err != nil {
				return fmt.Errorf("seed materialized frameworks for finding %s: %w", finding.ID, err)
			}
			for _, framework := range extraFrameworks {
				seenFrameworks[framework.ID] = struct{}{}
			}
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
		if candidate := deriveIssueAssignmentCandidate(&complianceFinding); candidate.assigneeID != "" {
			for _, issue := range result.Issues {
				assignmentCandidates[issue.ID] = betterIssueAssignmentCandidate(assignmentCandidates[issue.ID], candidate)
			}
		}
		materialized = secgraph.MergeMaterializationResults(materialized, result)
		materializedFindings++
	}

	for idx := range materialized.Issues {
		if candidate := assignmentCandidates[materialized.Issues[idx].ID]; candidate.assigneeID != "" && strings.TrimSpace(materialized.Issues[idx].AssigneeID) == "" {
			materialized.Issues[idx].AssigneeID = candidate.assigneeID
		}
		if dispatcher == nil {
			continue
		}
		if err := dispatcher.Dispatch(ctx, &materialized.Issues[idx]); err != nil {
			return fmt.Errorf("dispatch issue ticket for issue %s: %w", materialized.Issues[idx].ID, err)
		}
	}
	if len(materialized.Issues) > 0 || len(materialized.Evaluations) > 0 || len(materialized.Edges) > 0 || len(materialized.IssueFindings) > 0 {
		if err := store.UpsertMaterialization(ctx, materialized); err != nil {
			return fmt.Errorf("persist secgraph artifacts: %w", err)
		}
	}
	if reconcile {
		if reconciler, ok := store.(secgraphReconciler); ok {
			if err := reconciler.ReconcileStaleMaterialization(ctx, tenantID, activeFindingIDs(findings), now); err != nil {
				return fmt.Errorf("reconcile stale secgraph materialization: %w", err)
			}
		}
	}

	if logger != nil {
		logger.Info("Security graph sync complete",
			zap.Int("frameworks_seeded", len(frameworks)),
			zap.Int("controls_seeded", len(controls)),
			zap.Int("findings_materialized", materializedFindings),
			zap.Int("issues_materialized", len(materialized.Issues)),
		)
	}

	return nil
}

func syncSecurityIssueSurfaceWithStoreAndDispatcherMode(ctx context.Context, store secgraphPersister, mgr *compliance.Manager, findings []Finding, tenantID string, now time.Time, dispatcher secgraphIssueDispatcher, logger *zap.Logger, reconcile bool, seedCatalog bool, adjacency *secgraph.AdjacencySet) error {
	if store == nil || mgr == nil {
		return nil
	}

	frameworks := secgraph.BuildFrameworkDefinitionsFromManager(mgr, now)
	controls := secgraph.BuildControlsFromManager(mgr, tenantID, now)
	if seedCatalog {
		if err := store.UpsertFrameworks(ctx, frameworks); err != nil {
			return fmt.Errorf("seed secgraph frameworks: %w", err)
		}
		if err := store.UpsertControls(ctx, controls); err != nil {
			return fmt.Errorf("seed secgraph controls: %w", err)
		}
	}

	seenFrameworks := make(map[string]struct{}, len(frameworks))
	for _, framework := range frameworks {
		seenFrameworks[framework.ID] = struct{}{}
	}
	seenControls := make(map[string]struct{}, len(controls))
	for _, control := range controls {
		seenControls[control.ID] = struct{}{}
	}

	materializedFindings := 0
	deferredEdges := 0
	issueSurface := secgraph.NewIssueSurfaceAccumulator(len(findings))
	assignmentCandidates := make(map[string]secgraphIssueAssignmentCandidate)
	persistedIssues := 0
	persistedEvaluations := 0
	persistedIssueFindings := 0
	flushIssueSurface := func(reason string) error {
		issueSurfaceResult := issueSurface.Snapshot()
		if len(issueSurfaceResult.Issues) == 0 && len(issueSurfaceResult.Evaluations) == 0 && len(issueSurfaceResult.IssueFindings) == 0 {
			return nil
		}
		for idx := range issueSurfaceResult.Issues {
			if candidate := assignmentCandidates[issueSurfaceResult.Issues[idx].ID]; candidate.assigneeID != "" && strings.TrimSpace(issueSurfaceResult.Issues[idx].AssigneeID) == "" {
				issueSurfaceResult.Issues[idx].AssigneeID = candidate.assigneeID
			}
			if dispatcher == nil {
				continue
			}
			if err := dispatcher.Dispatch(ctx, &issueSurfaceResult.Issues[idx]); err != nil {
				return fmt.Errorf("dispatch issue ticket for issue %s: %w", issueSurfaceResult.Issues[idx].ID, err)
			}
		}
		if err := store.UpsertMaterialization(ctx, issueSurfaceResult); err != nil {
			return fmt.Errorf("persist secgraph issue surface batch: %w", err)
		}
		persistedIssues += len(issueSurfaceResult.Issues)
		persistedEvaluations += len(issueSurfaceResult.Evaluations)
		persistedIssueFindings += len(issueSurfaceResult.IssueFindings)
		if logger != nil {
			logger.Info("Security graph issue-surface batch persisted",
				zap.String("reason", reason),
				zap.Int("batch_issues", len(issueSurfaceResult.Issues)),
				zap.Int("batch_evaluations", len(issueSurfaceResult.Evaluations)),
				zap.Int("batch_issue_findings", len(issueSurfaceResult.IssueFindings)),
				zap.Int("persisted_issues", persistedIssues),
				zap.Int("persisted_evaluations", persistedEvaluations),
				zap.Int("persisted_issue_findings", persistedIssueFindings),
			)
		}
		issueSurface = secgraph.NewIssueSurfaceAccumulator(secgraphIssueSurfacePersistInterval)
		clear(assignmentCandidates)
		return nil
	}
	for idx, finding := range findings {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("security issue surface context canceled after %d findings: %w", idx, err)
		}

		complianceFinding := toComplianceFinding(finding)
		if len(complianceFinding.ComplianceMappings) == 0 {
			mapped, err := mgr.MapFinding(ctx, &complianceFinding, compliance.SectorGeneral)
			if err != nil {
				return fmt.Errorf("map finding %s: %w", finding.ID, err)
			}
			complianceFinding = *mapped
		}

		result := secgraph.MaterializeFindingWithOptions(&complianceFinding, tenantID, now, secgraph.MaterializeOptions{
			Adjacency:       adjacency,
			BlastRadiusHops: 2,
		})
		if len(result.Issues) == 0 && len(result.Evaluations) == 0 && len(result.IssueFindings) == 0 {
			continue
		}

		extraFrameworks := missingFrameworkDefinitions(seenFrameworks, frameworkDefinitionsFromMappings(complianceFinding.ComplianceMappings, now))
		if len(extraFrameworks) > 0 {
			if err := store.UpsertFrameworks(ctx, extraFrameworks); err != nil {
				return fmt.Errorf("seed materialized frameworks for finding %s: %w", finding.ID, err)
			}
			for _, framework := range extraFrameworks {
				seenFrameworks[framework.ID] = struct{}{}
			}
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
		if candidate := deriveIssueAssignmentCandidate(&complianceFinding); candidate.assigneeID != "" {
			for _, issue := range result.Issues {
				assignmentCandidates[issue.ID] = betterIssueAssignmentCandidate(assignmentCandidates[issue.ID], candidate)
			}
		}

		deferredEdges += len(result.Edges)
		result.Controls = nil
		result.Edges = nil
		issueSurface.Add(result)
		materializedFindings++

		if logger != nil && materializedFindings%secgraphProgressInterval == 0 {
			evaluationsBuffered, issuesBuffered, issueFindingsBuffered := issueSurface.Counts()
			logger.Info("Security graph issue-surface sync progress",
				zap.Int("processed_findings", idx+1),
				zap.Int("findings_materialized", materializedFindings),
				zap.Int("issues_buffered", issuesBuffered),
				zap.Int("evaluations_buffered", evaluationsBuffered),
				zap.Int("issue_findings_buffered", issueFindingsBuffered),
				zap.Int("persisted_issues", persistedIssues),
				zap.Int("persisted_evaluations", persistedEvaluations),
				zap.Int("persisted_issue_findings", persistedIssueFindings),
				zap.Int("edges_deferred", deferredEdges),
			)
		}
		if materializedFindings%secgraphIssueSurfacePersistInterval == 0 {
			if err := flushIssueSurface("interval"); err != nil {
				return err
			}
		}
	}

	if err := flushIssueSurface("final"); err != nil {
		return err
	}
	if reconcile {
		if reconciler, ok := store.(secgraphReconciler); ok {
			if err := reconciler.ReconcileStaleMaterialization(ctx, tenantID, activeFindingIDs(findings), now); err != nil {
				return fmt.Errorf("reconcile stale secgraph materialization: %w", err)
			}
		}
	}

	if logger != nil {
		logger.Info("Security graph issue-surface sync complete",
			zap.Int("frameworks_seeded", len(frameworks)),
			zap.Int("controls_seeded", len(controls)),
			zap.Int("findings_materialized", materializedFindings),
			zap.Int("issues_materialized", persistedIssues),
			zap.Int("evaluations_materialized", persistedEvaluations),
			zap.Int("issue_findings_materialized", persistedIssueFindings),
			zap.Int("edges_deferred", deferredEdges),
		)
	}

	return nil
}

func loadSecgraphAdjacency(ctx context.Context, db *sql.DB, logger *zap.Logger) (*secgraph.AdjacencySet, error) {
	if db == nil {
		return nil, nil
	}
	adjacency, err := secgraph.LoadAdjacencyFromDB(ctx, db)
	if err != nil {
		if logger != nil {
			logger.Warn("Failed to load secgraph adjacency for issue scoring (using heuristic blast radius)", zap.Error(err))
		}
		return nil, nil
	}
	return adjacency, nil
}

func activeFindingIDs(findings []Finding) []string {
	seen := make(map[string]struct{}, len(findings))
	active := make([]string, 0, len(findings))
	for _, finding := range findings {
		id := strings.TrimSpace(finding.ID)
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		active = append(active, id)
	}
	return active
}

func frameworkDefinitionsFromMappings(mappings []compliance.ComplianceMapping, now time.Time) []secgraph.FrameworkDefinition {
	if len(mappings) == 0 {
		return nil
	}

	byID := make(map[string]secgraph.FrameworkDefinition, len(mappings))
	controlSets := make(map[string]map[string]struct{}, len(mappings))
	for _, mapping := range mappings {
		frameworkID := strings.TrimSpace(mapping.FrameworkID)
		if frameworkID == "" {
			continue
		}
		definition, exists := byID[frameworkID]
		if !exists {
			name := strings.TrimSpace(mapping.FrameworkName)
			if name == "" {
				name = frameworkID
			}
			definition = secgraph.FrameworkDefinition{
				ID:          frameworkID,
				Name:        name,
				Description: "Framework referenced by persisted finding mappings",
				Category:    "custom",
				CreatedAt:   now.UTC(),
				UpdatedAt:   now.UTC(),
			}
		}
		if definition.Name == "" {
			definition.Name = frameworkID
		}
		byID[frameworkID] = definition
		if _, ok := controlSets[frameworkID]; !ok {
			controlSets[frameworkID] = make(map[string]struct{})
		}
		controlID := strings.TrimSpace(mapping.ControlID)
		if controlID != "" {
			controlSets[frameworkID][controlID] = struct{}{}
		}
	}

	definitions := make([]secgraph.FrameworkDefinition, 0, len(byID))
	for frameworkID, definition := range byID {
		definition.TotalControls = len(controlSets[frameworkID])
		definitions = append(definitions, definition)
	}
	return definitions
}

func missingFrameworkDefinitions(seen map[string]struct{}, frameworks []secgraph.FrameworkDefinition) []secgraph.FrameworkDefinition {
	if len(frameworks) == 0 {
		return nil
	}

	missing := make([]secgraph.FrameworkDefinition, 0, len(frameworks))
	for _, framework := range frameworks {
		if _, ok := seen[framework.ID]; ok {
			continue
		}
		missing = append(missing, framework)
	}
	return missing
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
	if state.AssigneeID != "" {
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
		Assignee:            toComplianceAssignee(f.Assignee),
		TechnicalContact:    toComplianceContact(f.TechnicalContact),
		BusinessOwner:       toComplianceContact(f.BusinessOwner),
		ServiceName:         f.ServiceName,
		LineOfBusiness:      f.LineOfBusiness,
		Team:                f.Team,
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

func toComplianceAssignee(assignee *FindingAssignee) *compliance.AssigneeInfo {
	if assignee == nil {
		return nil
	}

	converted := &compliance.AssigneeInfo{
		UserID:      strings.TrimSpace(assignee.UserID),
		UserEmail:   strings.TrimSpace(assignee.UserEmail),
		UserName:    strings.TrimSpace(assignee.UserName),
		Team:        strings.TrimSpace(assignee.Team),
		AssignedAt:  parseRFC3339OrZero(assignee.AssignedAt),
		AssignedBy:  strings.TrimSpace(assignee.AssignedBy),
		Escalated:   assignee.Escalated,
		EscalatedTo: strings.TrimSpace(assignee.EscalatedTo),
	}
	if dueDate := parseRFC3339Ptr(assignee.DueDate); dueDate != nil {
		converted.DueDate = dueDate
	}
	if escalatedAt := parseRFC3339Ptr(assignee.EscalatedAt); escalatedAt != nil {
		converted.EscalatedAt = escalatedAt
	}
	if converted.UserID == "" && converted.UserEmail == "" && converted.UserName == "" &&
		converted.Team == "" && converted.AssignedAt.IsZero() && converted.AssignedBy == "" &&
		converted.DueDate == nil && !converted.Escalated && converted.EscalatedTo == "" && converted.EscalatedAt == nil {
		return nil
	}
	return converted
}

func toComplianceContact(contact *FindingContact) *compliance.Contact {
	if contact == nil {
		return nil
	}
	converted := &compliance.Contact{
		Name:      strings.TrimSpace(contact.Name),
		Email:     strings.TrimSpace(contact.Email),
		Team:      strings.TrimSpace(contact.Team),
		Phone:     strings.TrimSpace(contact.Phone),
		SlackID:   strings.TrimSpace(contact.SlackID),
		OnCallURL: strings.TrimSpace(contact.OnCallURL),
	}
	if converted.Name == "" && converted.Email == "" && converted.Team == "" &&
		converted.Phone == "" && converted.SlackID == "" && converted.OnCallURL == "" {
		return nil
	}
	return converted
}

func deriveIssueAssignmentCandidate(finding *compliance.Finding) secgraphIssueAssignmentCandidate {
	if finding == nil {
		return secgraphIssueAssignmentCandidate{}
	}
	if finding.Assignee != nil {
		if userID := strings.TrimSpace(finding.Assignee.UserID); userID != "" {
			return secgraphIssueAssignmentCandidate{assigneeID: userID, priority: 4}
		}
		if userEmail := strings.TrimSpace(finding.Assignee.UserEmail); userEmail != "" {
			return secgraphIssueAssignmentCandidate{assigneeID: userEmail, priority: 3}
		}
	}
	if finding.TechnicalContact != nil {
		if email := strings.TrimSpace(finding.TechnicalContact.Email); email != "" {
			return secgraphIssueAssignmentCandidate{assigneeID: email, priority: 2}
		}
	}
	if finding.BusinessOwner != nil {
		if email := strings.TrimSpace(finding.BusinessOwner.Email); email != "" {
			return secgraphIssueAssignmentCandidate{assigneeID: email, priority: 1}
		}
	}
	return secgraphIssueAssignmentCandidate{}
}

func betterIssueAssignmentCandidate(existing, incoming secgraphIssueAssignmentCandidate) secgraphIssueAssignmentCandidate {
	if incoming.assigneeID == "" {
		return existing
	}
	if existing.assigneeID == "" {
		return incoming
	}
	if incoming.priority > existing.priority {
		return incoming
	}
	if incoming.priority < existing.priority {
		return existing
	}
	if incoming.assigneeID < existing.assigneeID {
		return incoming
	}
	return existing
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
