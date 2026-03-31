package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"aegis/internal/compliance"
	"aegis/internal/integrations"
	"aegis/internal/secgraph"

	"go.uber.org/zap"
)

type recordingSecgraphStore struct {
	frameworksCalls      [][]secgraph.FrameworkDefinition
	controlsCalls        [][]secgraph.Control
	materializationCalls []secgraph.MaterializationResult
	reconcileCalls       int
	reconcileTenantID    string
	reconcileFindingIDs  []string
	reconcileAt          time.Time
	frameworksErr        error
	controlsErr          error
	materializationErr   error
	reconcileErr         error
}

func (s *recordingSecgraphStore) UpsertFrameworks(_ context.Context, frameworks []secgraph.FrameworkDefinition) error {
	if s.frameworksErr != nil {
		return s.frameworksErr
	}
	copied := append([]secgraph.FrameworkDefinition(nil), frameworks...)
	s.frameworksCalls = append(s.frameworksCalls, copied)
	return nil
}

func (s *recordingSecgraphStore) UpsertControls(_ context.Context, controls []secgraph.Control) error {
	if s.controlsErr != nil {
		return s.controlsErr
	}
	copied := append([]secgraph.Control(nil), controls...)
	s.controlsCalls = append(s.controlsCalls, copied)
	return nil
}

func (s *recordingSecgraphStore) UpsertMaterialization(_ context.Context, result secgraph.MaterializationResult) error {
	if s.materializationErr != nil {
		return s.materializationErr
	}
	s.materializationCalls = append(s.materializationCalls, result)
	return nil
}

func (s *recordingSecgraphStore) ReconcileStaleMaterialization(_ context.Context, tenantID string, activeFindingIDs []string, now time.Time) error {
	if s.reconcileErr != nil {
		return s.reconcileErr
	}
	s.reconcileCalls++
	s.reconcileTenantID = tenantID
	s.reconcileFindingIDs = append([]string(nil), activeFindingIDs...)
	s.reconcileAt = now
	return nil
}

type mutatingIssueDispatcher struct {
	calls int
}

func (d *mutatingIssueDispatcher) Dispatch(_ context.Context, issue *secgraph.Issue) error {
	d.calls++
	issue.TicketID = "TICKET-" + issue.ID
	issue.TicketURL = "https://tickets.local/" + issue.ID
	return nil
}

type staticIssueTicketLoader struct {
	state secgraphIssueTicketState
	err   error
}

func (l staticIssueTicketLoader) LoadIssueTicketState(_ context.Context, _ string) (secgraphIssueTicketState, error) {
	return l.state, l.err
}

func TestSyncSecurityGraphWithStore_SeedsAndMaterializesMappedFindings(t *testing.T) {
	manager := compliance.NewManager(zap.NewNop())
	store := &recordingSecgraphStore{}
	now := time.Date(2026, 3, 31, 12, 0, 0, 0, time.UTC)

	finding := Finding{
		ID:               "finding-1",
		Title:            "S3 bucket has public read access enabled",
		Description:      "The S3 bucket allows public read access which could expose sensitive data",
		ResourceType:     "storage",
		ResourceID:       "arn:aws:s3:::demo-bucket",
		ResourceName:     "demo-bucket",
		Type:             "misconfiguration",
		Severity:         "high",
		CloudProvider:    "aws",
		AccountID:        "123456789012",
		Category:         "MISCONFIGURATION",
		FirstFoundAt:     now.Format(time.RFC3339),
		ExploitAvailable: true,
	}

	if err := syncSecurityGraphWithStore(context.Background(), store, manager, []Finding{finding}, "tenant-a", now, zap.NewNop()); err != nil {
		t.Fatalf("syncSecurityGraphWithStore() error = %v", err)
	}

	if len(store.frameworksCalls) != 1 {
		t.Fatalf("framework upserts = %d, want 1", len(store.frameworksCalls))
	}
	if len(store.frameworksCalls[0]) == 0 {
		t.Fatal("expected seeded frameworks from compliance manager")
	}
	if len(store.controlsCalls) != 1 {
		t.Fatalf("controls upserts = %d, want 1", len(store.controlsCalls))
	}
	if len(store.controlsCalls[0]) == 0 {
		t.Fatal("expected seeded controls from compliance manager")
	}
	if len(store.materializationCalls) != 1 {
		t.Fatalf("materialization upserts = %d, want 1", len(store.materializationCalls))
	}

	result := store.materializationCalls[0]
	if len(result.Issues) == 0 {
		t.Fatal("expected one or more issues to be materialized")
	}
	if len(result.Evaluations) != len(result.Issues) {
		t.Fatalf("evaluations = %d, want %d", len(result.Evaluations), len(result.Issues))
	}
	if len(result.Edges) == 0 {
		t.Fatal("expected graph edges to be materialized")
	}
	if result.Issues[0].TenantID != "tenant-a" {
		t.Fatalf("issue tenant_id = %q, want tenant-a", result.Issues[0].TenantID)
	}
}

func TestSyncSecurityGraphWithStore_SeedsExtraControlsForPreMappedFindings(t *testing.T) {
	manager := compliance.NewManager(zap.NewNop())
	store := &recordingSecgraphStore{}
	now := time.Date(2026, 3, 31, 13, 0, 0, 0, time.UTC)

	finding := Finding{
		ID:           "finding-2",
		Title:        "Custom control violation",
		Description:  "This finding already carries a persisted custom mapping",
		ResourceType: "database",
		ResourceID:   "db-123",
		ResourceName: "db-123",
		Type:         "compliance_violation",
		Severity:     "medium",
		AccountID:    "acct-1",
		Category:     "COMPLIANCE",
		ComplianceMappings: []ComplianceMapping{
			{
				FrameworkID:   "custom-fw",
				FrameworkName: "Custom Framework",
				ControlID:     "CTRL-001",
				ControlTitle:  "Custom Database Guardrail",
				Severity:      "HIGH",
			},
		},
	}

	if err := syncSecurityGraphWithStore(context.Background(), store, manager, []Finding{finding}, "tenant-a", now, zap.NewNop()); err != nil {
		t.Fatalf("syncSecurityGraphWithStore() error = %v", err)
	}

	if len(store.frameworksCalls) != 2 {
		t.Fatalf("framework upserts = %d, want 2 (manager seed + custom framework)", len(store.frameworksCalls))
	}
	if len(store.frameworksCalls[1]) != 1 {
		t.Fatalf("extra framework upsert size = %d, want 1", len(store.frameworksCalls[1]))
	}
	if got := store.frameworksCalls[1][0].ID; got != "custom-fw" {
		t.Fatalf("extra framework id = %q, want custom-fw", got)
	}
	if len(store.controlsCalls) != 2 {
		t.Fatalf("controls upserts = %d, want 2 (manager seed + custom control)", len(store.controlsCalls))
	}
	if len(store.controlsCalls[1]) != 1 {
		t.Fatalf("extra controls upsert size = %d, want 1", len(store.controlsCalls[1]))
	}
	if got := store.controlsCalls[1][0].ID; got != "custom-fw:CTRL-001" {
		t.Fatalf("extra control id = %q, want custom-fw:CTRL-001", got)
	}
	if len(store.materializationCalls) != 1 || len(store.materializationCalls[0].Issues) != 1 {
		t.Fatal("expected one materialized issue for the pre-mapped finding")
	}
}

func TestSyncSecurityGraphWithStore_DerivesIssueLifecycleFromFindingWorkflow(t *testing.T) {
	manager := compliance.NewManager(zap.NewNop())
	store := &recordingSecgraphStore{}
	now := time.Date(2026, 3, 31, 13, 30, 0, 0, time.UTC)
	lastSeenAt := now.Add(-45 * time.Minute)
	slaBreachAt := now.Add(-90 * time.Minute)

	finding := Finding{
		ID:             "finding-lifecycle",
		Title:          "Suppressed inherited finding",
		Description:    "Already accepted upstream and should not rematerialize as open",
		ResourceType:   "database",
		ResourceID:     "db-accepted",
		ResourceName:   "db-accepted",
		Type:           "misconfiguration",
		Severity:       "medium",
		AccountID:      "acct-1",
		Category:       "COMPLIANCE",
		Status:         "suppressed",
		WorkflowStatus: "risk_accepted",
		Suppressed:     true,
		LastSeenAt:     lastSeenAt.Format(time.RFC3339),
		SLABreachDate:  slaBreachAt.Format(time.RFC3339),
		ComplianceMappings: []ComplianceMapping{
			{
				FrameworkID:   "custom-fw",
				FrameworkName: "Custom Framework",
				ControlID:     "CTRL-LIFECYCLE",
				ControlTitle:  "Lifecycle fidelity control",
				Severity:      "MEDIUM",
			},
		},
	}

	if err := syncSecurityGraphWithStore(context.Background(), store, manager, []Finding{finding}, "tenant-a", now, zap.NewNop()); err != nil {
		t.Fatalf("syncSecurityGraphWithStore() error = %v", err)
	}

	if len(store.materializationCalls) != 1 || len(store.materializationCalls[0].Issues) != 1 {
		t.Fatal("expected one materialized issue")
	}

	result := store.materializationCalls[0]
	issue := result.Issues[0]
	if issue.Status != secgraph.IssueSuppressed {
		t.Fatalf("issue status = %q, want %q", issue.Status, secgraph.IssueSuppressed)
	}
	if issue.ResolvedAt == nil || !issue.ResolvedAt.Equal(lastSeenAt) {
		t.Fatalf("resolved_at = %v, want %v", issue.ResolvedAt, lastSeenAt)
	}
	if issue.SLABreachAt == nil || !issue.SLABreachAt.Equal(slaBreachAt) {
		t.Fatalf("sla_breach_at = %v, want %v", issue.SLABreachAt, slaBreachAt)
	}
	if len(result.Evaluations) != 1 || result.Evaluations[0].Status != secgraph.EvalNotApplicable {
		t.Fatalf("evaluation status = %+v, want %q", result.Evaluations, secgraph.EvalNotApplicable)
	}
}

func TestSyncSecurityGraphWithStore_MergesSharedIssueAcrossFindings(t *testing.T) {
	manager := compliance.NewManager(zap.NewNop())
	store := &recordingSecgraphStore{}
	now := time.Date(2026, 3, 31, 13, 45, 0, 0, time.UTC)

	findings := []Finding{
		{
			ID:               "finding-merge-open",
			Title:            "Active shared issue source",
			Description:      "Still failing",
			ResourceType:     "database",
			ResourceID:       "db-shared",
			ResourceName:     "db-shared",
			Type:             "misconfiguration",
			Severity:         "high",
			AccountID:        "acct-1",
			Category:         "NETWORK",
			ExploitAvailable: true,
			ComplianceMappings: []ComplianceMapping{
				{FrameworkID: "custom-fw", FrameworkName: "Custom Framework", ControlID: "CTRL-MERGE", ControlTitle: "Shared merge control", Severity: "HIGH"},
			},
		},
		{
			ID:             "finding-merge-resolved",
			Title:          "Resolved shared issue source",
			Description:    "No longer failing",
			ResourceType:   "database",
			ResourceID:     "db-shared",
			ResourceName:   "db-shared",
			Type:           "misconfiguration",
			Severity:       "medium",
			AccountID:      "acct-1",
			Category:       "COMPLIANCE",
			Status:         "resolved",
			WorkflowStatus: "remediated",
			LastSeenAt:     now.Add(-20 * time.Minute).Format(time.RFC3339),
			ComplianceMappings: []ComplianceMapping{
				{FrameworkID: "custom-fw", FrameworkName: "Custom Framework", ControlID: "CTRL-MERGE", ControlTitle: "Shared merge control", Severity: "MEDIUM"},
			},
		},
	}

	if err := syncSecurityGraphWithStore(context.Background(), store, manager, findings, "tenant-a", now, zap.NewNop()); err != nil {
		t.Fatalf("syncSecurityGraphWithStore() error = %v", err)
	}

	if len(store.materializationCalls) != 1 {
		t.Fatalf("materialization upserts = %d, want 1 aggregated batch", len(store.materializationCalls))
	}

	result := store.materializationCalls[0]
	if len(result.Issues) != 1 {
		t.Fatalf("issues = %d, want 1", len(result.Issues))
	}
	if len(result.Evaluations) != 1 {
		t.Fatalf("evaluations = %d, want 1", len(result.Evaluations))
	}
	if len(result.IssueFindings) != 2 {
		t.Fatalf("issue_findings = %d, want 2", len(result.IssueFindings))
	}
	if result.Issues[0].Status != secgraph.IssueOpen {
		t.Fatalf("issue status = %q, want %q", result.Issues[0].Status, secgraph.IssueOpen)
	}
	if result.Evaluations[0].Status != secgraph.EvalFail {
		t.Fatalf("evaluation status = %q, want %q", result.Evaluations[0].Status, secgraph.EvalFail)
	}
	if len(result.Evaluations[0].Evidence) != 2 {
		t.Fatalf("evaluation evidence = %+v, want 2 finding ids", result.Evaluations[0].Evidence)
	}
	if store.reconcileCalls != 1 {
		t.Fatalf("reconcile calls = %d, want 1", store.reconcileCalls)
	}
	if store.reconcileTenantID != "tenant-a" {
		t.Fatalf("reconcile tenant_id = %q, want tenant-a", store.reconcileTenantID)
	}
	if len(store.reconcileFindingIDs) != 2 {
		t.Fatalf("reconcile finding ids = %+v, want 2 ids", store.reconcileFindingIDs)
	}
}

func TestSyncSecurityGraphWithStore_UsesAdjacencyBlastRadiusWhenProvided(t *testing.T) {
	manager := compliance.NewManager(zap.NewNop())
	store := &recordingSecgraphStore{}
	now := time.Date(2026, 3, 31, 13, 55, 0, 0, time.UTC)
	adjacency := secgraph.NewAdjacencySet()
	adjacency.Add("db-graph-sync", "svc-a", secgraph.EdgeSameRegion)
	adjacency.Add("svc-a", "svc-b", secgraph.EdgeSameAccount)

	finding := Finding{
		ID:           "finding-graph-radius",
		Title:        "Shared service blast radius",
		Description:  "Should use graph adjacency instead of empty impacted_resources",
		ResourceType: "database",
		ResourceID:   "db-graph-sync",
		ResourceName: "db-graph-sync",
		Type:         "misconfiguration",
		Severity:     "high",
		AccountID:    "acct-1",
		Category:     "COMPLIANCE",
		ComplianceMappings: []ComplianceMapping{
			{FrameworkID: "custom-fw", FrameworkName: "Custom Framework", ControlID: "CTRL-GRAPH", ControlTitle: "Graph blast radius control", Severity: "HIGH"},
		},
	}

	if err := syncSecurityGraphWithStoreAndDispatcherMode(context.Background(), store, manager, []Finding{finding}, "tenant-a", now, nil, zap.NewNop(), true, adjacency); err != nil {
		t.Fatalf("syncSecurityGraphWithStoreAndDispatcherMode() error = %v", err)
	}

	if len(store.materializationCalls) != 1 || len(store.materializationCalls[0].Issues) != 1 {
		t.Fatal("expected one materialized issue")
	}
	issue := store.materializationCalls[0].Issues[0]
	if issue.BlastRadius != 2 {
		t.Fatalf("blast_radius = %d, want 2", issue.BlastRadius)
	}
	if issue.RiskScore != 82.5 {
		t.Fatalf("risk_score = %.2f, want 82.50", issue.RiskScore)
	}
}

func TestSyncSecurityGraphWithStore_PicksBestIssueAssigneeFromFindingMetadata(t *testing.T) {
	manager := compliance.NewManager(zap.NewNop())
	store := &recordingSecgraphStore{}
	now := time.Date(2026, 3, 31, 13, 50, 0, 0, time.UTC)

	findings := []Finding{
		{
			ID:           "finding-owner-fallback",
			Title:        "Shared issue from ownership fallback",
			ResourceType: "database",
			ResourceID:   "db-shared-owner",
			ResourceName: "db-shared-owner",
			Type:         "misconfiguration",
			Severity:     "medium",
			AccountID:    "acct-1",
			Category:     "COMPLIANCE",
			BusinessOwner: &FindingContact{
				Email: "owner@example.com",
			},
			ComplianceMappings: []ComplianceMapping{
				{FrameworkID: "custom-fw", FrameworkName: "Custom Framework", ControlID: "CTRL-ASSIGNEE", ControlTitle: "Assignment control", Severity: "MEDIUM"},
			},
		},
		{
			ID:           "finding-explicit-assignee",
			Title:        "Shared issue from explicit assignee",
			ResourceType: "database",
			ResourceID:   "db-shared-owner",
			ResourceName: "db-shared-owner",
			Type:         "misconfiguration",
			Severity:     "high",
			AccountID:    "acct-1",
			Category:     "COMPLIANCE",
			Assignee: &FindingAssignee{
				UserID: "user-123",
			},
			ComplianceMappings: []ComplianceMapping{
				{FrameworkID: "custom-fw", FrameworkName: "Custom Framework", ControlID: "CTRL-ASSIGNEE", ControlTitle: "Assignment control", Severity: "HIGH"},
			},
		},
	}

	if err := syncSecurityGraphWithStore(context.Background(), store, manager, findings, "tenant-a", now, zap.NewNop()); err != nil {
		t.Fatalf("syncSecurityGraphWithStore() error = %v", err)
	}

	if len(store.materializationCalls) != 1 || len(store.materializationCalls[0].Issues) != 1 {
		t.Fatal("expected one aggregated issue")
	}
	if got := store.materializationCalls[0].Issues[0].AssigneeID; got != "user-123" {
		t.Fatalf("assignee_id = %q, want user-123", got)
	}
}

func TestSyncSecurityGraphWithStoreAndDispatcher_DoesNotReconcileIncrementalBatch(t *testing.T) {
	manager := compliance.NewManager(zap.NewNop())
	store := &recordingSecgraphStore{}
	now := time.Date(2026, 3, 31, 14, 5, 0, 0, time.UTC)

	finding := Finding{
		ID:           "finding-incremental",
		Title:        "Incremental batch finding",
		Description:  "Should materialize without global reconciliation",
		ResourceType: "database",
		ResourceID:   "db-incremental",
		ResourceName: "db-incremental",
		Type:         "misconfiguration",
		Severity:     "medium",
		AccountID:    "acct-1",
		Category:     "COMPLIANCE",
		ComplianceMappings: []ComplianceMapping{
			{FrameworkID: "custom-fw", FrameworkName: "Custom Framework", ControlID: "CTRL-INCR", ControlTitle: "Incremental control", Severity: "MEDIUM"},
		},
	}

	if err := syncSecurityGraphWithStoreAndDispatcher(context.Background(), store, manager, []Finding{finding}, "tenant-a", now, nil, zap.NewNop()); err != nil {
		t.Fatalf("syncSecurityGraphWithStoreAndDispatcher() error = %v", err)
	}
	if store.reconcileCalls != 0 {
		t.Fatalf("reconcile calls = %d, want 0 for incremental batch", store.reconcileCalls)
	}
}

func TestSyncSecurityGraphWithStore_PropagatesStoreErrors(t *testing.T) {
	manager := compliance.NewManager(zap.NewNop())
	now := time.Date(2026, 3, 31, 14, 0, 0, 0, time.UTC)
	finding := Finding{
		ID:            "finding-3",
		Title:         "S3 bucket has public read access enabled",
		Description:   "The S3 bucket allows public read access which could expose sensitive data",
		ResourceType:  "storage",
		ResourceID:    "arn:aws:s3:::demo-bucket",
		ResourceName:  "demo-bucket",
		Type:          "misconfiguration",
		Severity:      "high",
		CloudProvider: "aws",
		AccountID:     "123456789012",
		Category:      "MISCONFIGURATION",
	}

	controlsErr := errors.New("controls failed")
	if err := syncSecurityGraphWithStore(context.Background(), &recordingSecgraphStore{controlsErr: controlsErr}, manager, []Finding{finding}, "tenant-a", now, zap.NewNop()); !errors.Is(err, controlsErr) {
		t.Fatalf("controls error = %v, want %v", err, controlsErr)
	}

	frameworksErr := errors.New("frameworks failed")
	if err := syncSecurityGraphWithStore(context.Background(), &recordingSecgraphStore{frameworksErr: frameworksErr}, manager, []Finding{finding}, "tenant-a", now, zap.NewNop()); !errors.Is(err, frameworksErr) {
		t.Fatalf("frameworks error = %v, want %v", err, frameworksErr)
	}

	materializationErr := errors.New("materialization failed")
	if err := syncSecurityGraphWithStore(context.Background(), &recordingSecgraphStore{materializationErr: materializationErr}, manager, []Finding{finding}, "tenant-a", now, zap.NewNop()); !errors.Is(err, materializationErr) {
		t.Fatalf("materialization error = %v, want %v", err, materializationErr)
	}
}

func TestSyncSecurityGraphWithStoreAndDispatcher_PersistsTicketMetadata(t *testing.T) {
	manager := compliance.NewManager(zap.NewNop())
	store := &recordingSecgraphStore{}
	dispatcher := &mutatingIssueDispatcher{}
	now := time.Date(2026, 3, 31, 14, 30, 0, 0, time.UTC)

	finding := Finding{
		ID:           "finding-5",
		Title:        "Custom control violation",
		Description:  "This finding already carries a persisted custom mapping",
		ResourceType: "database",
		ResourceID:   "db-123",
		ResourceName: "db-123",
		Type:         "compliance_violation",
		Severity:     "medium",
		AccountID:    "acct-1",
		Category:     "COMPLIANCE",
		ComplianceMappings: []ComplianceMapping{
			{
				FrameworkID:   "custom-fw",
				FrameworkName: "Custom Framework",
				ControlID:     "CTRL-001",
				ControlTitle:  "Custom Database Guardrail",
				Severity:      "HIGH",
			},
		},
	}

	if err := syncSecurityGraphWithStoreAndDispatcher(context.Background(), store, manager, []Finding{finding}, "tenant-a", now, dispatcher, zap.NewNop()); err != nil {
		t.Fatalf("syncSecurityGraphWithStoreAndDispatcher() error = %v", err)
	}

	if dispatcher.calls != 1 {
		t.Fatalf("dispatcher calls = %d, want 1", dispatcher.calls)
	}
	if len(store.materializationCalls) != 1 || len(store.materializationCalls[0].Issues) != 1 {
		t.Fatal("expected one persisted materialization batch with one issue")
	}
	issue := store.materializationCalls[0].Issues[0]
	if issue.TicketID == "" || issue.TicketURL == "" {
		t.Fatal("expected dispatched ticket metadata to be persisted with the issue")
	}
}

func TestSecgraphTicketDispatcher_PreservesExistingTicketState(t *testing.T) {
	provider := integrations.NewMockProvider(zap.NewNop())
	existingDue := time.Date(2026, 4, 2, 12, 0, 0, 0, time.UTC)
	dispatcher := &secgraphTicketDispatcher{
		provider:     provider,
		router:       integrations.NewRoutingEngine(integrations.DefaultRules()),
		loader:       staticIssueTicketLoader{state: secgraphIssueTicketState{TicketID: "JIRA-123", TicketURL: "https://jira.local/JIRA-123", AssigneeID: "alice", SLABreachAt: &existingDue}},
		autoDispatch: true,
		logger:       zap.NewNop(),
	}
	issue := &secgraph.Issue{
		ID:         "ISS-EXISTING",
		Severity:   "HIGH",
		ControlID:  "ctrl-1",
		ResourceID: "res-1",
		AssigneeID: "owner@example.com",
		TenantID:   "tenant-a",
	}

	if err := dispatcher.Dispatch(context.Background(), issue); err != nil {
		t.Fatalf("Dispatch() error = %v", err)
	}

	if issue.TicketID != "JIRA-123" || issue.TicketURL != "https://jira.local/JIRA-123" {
		t.Fatalf("issue ticket state = %#v, want preserved existing ticket", issue)
	}
	if issue.AssigneeID != "alice" {
		t.Fatalf("assignee = %q, want alice", issue.AssigneeID)
	}
	if issue.SLABreachAt == nil || !issue.SLABreachAt.Equal(existingDue) {
		t.Fatal("expected existing SLA breach timestamp to be preserved")
	}
	if _, found := provider.GetTicketByFindingID(issue.ID); found {
		t.Fatal("did not expect a new provider ticket when one already exists")
	}
}

func TestSecgraphTicketDispatcher_CreatesTicketForUnticketedIssue(t *testing.T) {
	provider := integrations.NewMockProvider(zap.NewNop())
	dispatcher := &secgraphTicketDispatcher{
		provider:     provider,
		router:       integrations.NewRoutingEngine(integrations.DefaultRules()),
		autoDispatch: true,
		logger:       zap.NewNop(),
	}
	issue := &secgraph.Issue{
		ID:            "ISS-NEW",
		Title:         "Critical issue",
		Description:   "Internet-exposed resource with critical control failure",
		Severity:      "CRITICAL",
		RiskScore:     9.7,
		BlastRadius:   3,
		ExposurePaths: 2,
		ControlID:     "pci:REQ.1.2",
		ResourceID:    "db-1",
		AccountID:     "acct-1",
		Provider:      "aws",
		AssigneeID:    "user-123",
		TenantID:      "tenant-a",
	}

	if err := dispatcher.Dispatch(context.Background(), issue); err != nil {
		t.Fatalf("Dispatch() error = %v", err)
	}

	if issue.TicketID == "" || issue.TicketURL == "" {
		t.Fatal("expected a ticket to be created for the unticketed issue")
	}
	if issue.SLABreachAt == nil {
		t.Fatal("expected SLA breach deadline to be set from routing")
	}
	ticket, found := provider.GetTicketByFindingID(issue.ID)
	if !found {
		t.Fatal("expected provider to create a ticket keyed by the issue id")
	}
	if ticket.Priority != integrations.PriorityUrgent {
		t.Fatalf("ticket priority = %q, want %q", ticket.Priority, integrations.PriorityUrgent)
	}
	if ticket.Assignee != "user-123" {
		t.Fatalf("ticket assignee = %q, want user-123", ticket.Assignee)
	}
}

func TestSecgraphAutoTicketsEnabled(t *testing.T) {
	t.Setenv("SECGRAPH_AUTO_TICKETS", "true")
	if !secgraphAutoTicketsEnabled() {
		t.Fatal("expected SECGRAPH_AUTO_TICKETS=true to enable auto ticket dispatch")
	}

	t.Setenv("SECGRAPH_AUTO_TICKETS", "false")
	if secgraphAutoTicketsEnabled() {
		t.Fatal("expected SECGRAPH_AUTO_TICKETS=false to disable auto ticket dispatch")
	}
}

func TestSecgraphTicketDispatcher_SkipsLoaderWhenAutoDispatchDisabled(t *testing.T) {
	dispatcher := &secgraphTicketDispatcher{
		loader:       staticIssueTicketLoader{err: errors.New("loader should not be called")},
		autoDispatch: false,
		logger:       zap.NewNop(),
	}
	issue := &secgraph.Issue{
		ID:       "ISS-SKIP",
		Severity: "HIGH",
		TenantID: "tenant-a",
	}

	if err := dispatcher.Dispatch(context.Background(), issue); err != nil {
		t.Fatalf("Dispatch() error = %v, want nil when auto dispatch is disabled", err)
	}
}

func TestSyncSecurityIssueSurfaceWithStoreAndDispatcherMode_DefersEdges(t *testing.T) {
	manager := compliance.NewManager(zap.NewNop())
	store := &recordingSecgraphStore{}
	now := time.Date(2026, 3, 31, 14, 30, 0, 0, time.UTC)

	finding := Finding{
		ID:            "finding-large",
		Title:         "Shared database exposed to the internet",
		Description:   "Issue surface sync should materialize operator issues without buffering graph edges",
		ResourceType:  "database",
		ResourceID:    "db-shared",
		ResourceName:  "db-shared",
		Type:          "misconfiguration",
		Severity:      "high",
		CloudProvider: "aws",
		AccountID:     "123456789012",
		Category:      "NETWORK",
		ComplianceMappings: []ComplianceMapping{
			{
				FrameworkID:   "pci-dss",
				FrameworkName: "PCI-DSS",
				ControlID:     "REQ.1",
				ControlTitle:  "Restrict public exposure",
				Severity:      "HIGH",
			},
		},
	}

	if err := syncSecurityIssueSurfaceWithStoreAndDispatcherMode(context.Background(), store, manager, []Finding{finding}, "tenant-a", now, nil, zap.NewNop(), true, true, nil); err != nil {
		t.Fatalf("syncSecurityIssueSurfaceWithStoreAndDispatcherMode() error = %v", err)
	}

	if len(store.materializationCalls) != 1 {
		t.Fatalf("materialization upserts = %d, want 1", len(store.materializationCalls))
	}
	result := store.materializationCalls[0]
	if len(result.Edges) != 0 {
		t.Fatalf("edges = %d, want 0", len(result.Edges))
	}
	if len(result.Issues) != 1 {
		t.Fatalf("issues = %d, want 1", len(result.Issues))
	}
	if len(result.Evaluations) != 1 {
		t.Fatalf("evaluations = %d, want 1", len(result.Evaluations))
	}
	if len(result.IssueFindings) != 1 {
		t.Fatalf("issue_findings = %d, want 1", len(result.IssueFindings))
	}
	if len(result.Controls) != 0 {
		t.Fatalf("controls = %d, want 0 in deferred-edge issue-surface write", len(result.Controls))
	}
	if store.reconcileCalls != 1 {
		t.Fatalf("reconcile calls = %d, want 1", store.reconcileCalls)
	}
}

func TestSyncSecurityIssueSurfaceWithStoreAndDispatcherMode_FlushesIncrementalBatches(t *testing.T) {
	manager := compliance.NewManager(zap.NewNop())
	store := &recordingSecgraphStore{}
	now := time.Date(2026, 3, 31, 14, 45, 0, 0, time.UTC)
	originalInterval := secgraphIssueSurfacePersistInterval
	secgraphIssueSurfacePersistInterval = 2
	defer func() { secgraphIssueSurfacePersistInterval = originalInterval }()

	findings := []Finding{
		{
			ID:            "finding-batch-1",
			Title:         "Batch issue 1",
			ResourceType:  "database",
			ResourceID:    "db-batch-1",
			ResourceName:  "db-batch-1",
			Type:          "misconfiguration",
			Severity:      "high",
			CloudProvider: "aws",
			AccountID:     "123456789012",
			Category:      "NETWORK",
			ComplianceMappings: []ComplianceMapping{{
				FrameworkID:   "pci-dss",
				FrameworkName: "PCI-DSS",
				ControlID:     "REQ.1",
				ControlTitle:  "Restrict public exposure",
				Severity:      "HIGH",
			}},
		},
		{
			ID:            "finding-batch-2",
			Title:         "Batch issue 2",
			ResourceType:  "database",
			ResourceID:    "db-batch-2",
			ResourceName:  "db-batch-2",
			Type:          "misconfiguration",
			Severity:      "high",
			CloudProvider: "aws",
			AccountID:     "123456789012",
			Category:      "NETWORK",
			ComplianceMappings: []ComplianceMapping{{
				FrameworkID:   "pci-dss",
				FrameworkName: "PCI-DSS",
				ControlID:     "REQ.1",
				ControlTitle:  "Restrict public exposure",
				Severity:      "HIGH",
			}},
		},
		{
			ID:            "finding-batch-3",
			Title:         "Batch issue 3",
			ResourceType:  "database",
			ResourceID:    "db-batch-3",
			ResourceName:  "db-batch-3",
			Type:          "misconfiguration",
			Severity:      "high",
			CloudProvider: "aws",
			AccountID:     "123456789012",
			Category:      "NETWORK",
			ComplianceMappings: []ComplianceMapping{{
				FrameworkID:   "pci-dss",
				FrameworkName: "PCI-DSS",
				ControlID:     "REQ.1",
				ControlTitle:  "Restrict public exposure",
				Severity:      "HIGH",
			}},
		},
	}

	if err := syncSecurityIssueSurfaceWithStoreAndDispatcherMode(context.Background(), store, manager, findings, "tenant-a", now, nil, zap.NewNop(), true, true, nil); err != nil {
		t.Fatalf("syncSecurityIssueSurfaceWithStoreAndDispatcherMode() error = %v", err)
	}

	if len(store.materializationCalls) != 2 {
		t.Fatalf("materialization upserts = %d, want 2 incremental batches", len(store.materializationCalls))
	}
	if len(store.materializationCalls[0].Issues) == 0 || len(store.materializationCalls[1].Issues) == 0 {
		t.Fatal("expected both incremental batches to persist issues")
	}
}

func TestToComplianceFinding_ParsesOptionalFields(t *testing.T) {
	now := time.Date(2026, 3, 31, 15, 0, 0, 0, time.UTC)
	cvss := 9.8
	epss := 0.91
	assigneeDue := now.Add(12 * time.Hour)
	finding := Finding{
		ID:              "finding-4",
		Type:            "vulnerability",
		ResourceType:    "compute",
		CloudProvider:   "aws",
		EnvironmentType: "production",
		Category:        "THREAT",
		WorkflowStatus:  "in_progress",
		Assignee: &FindingAssignee{
			UserID:     "user-42",
			UserEmail:  "user-42@example.com",
			AssignedAt: now.Format(time.RFC3339),
			DueDate:    assigneeDue.Format(time.RFC3339),
		},
		TechnicalContact: &FindingContact{
			Name:  "Tech Owner",
			Email: "tech-owner@example.com",
		},
		BusinessOwner: &FindingContact{
			Name:  "Biz Owner",
			Email: "biz-owner@example.com",
		},
		Team:         "platform-security",
		CVSS:         &cvss,
		EPSS:         &epss,
		FirstFoundAt: now.Format(time.RFC3339),
		DueDate:      now.Add(24 * time.Hour).Format(time.RFC3339),
		CVEs: []CVE{
			{
				ID:                 "CVE-2026-0001",
				URL:                "https://nvd.nist.gov/vuln/detail/CVE-2026-0001",
				CVSS:               &cvss,
				EPSS:               &epss,
				CISAKnownExploited: true,
			},
		},
	}

	converted := toComplianceFinding(finding)
	if converted.Type != compliance.FindingTypeVulnerability {
		t.Fatalf("type = %q, want %q", converted.Type, compliance.FindingTypeVulnerability)
	}
	if converted.ResourceType != compliance.ResourceTypeCompute {
		t.Fatalf("resource_type = %q, want %q", converted.ResourceType, compliance.ResourceTypeCompute)
	}
	if converted.CloudProvider != compliance.CloudProviderAWS {
		t.Fatalf("cloud_provider = %q, want %q", converted.CloudProvider, compliance.CloudProviderAWS)
	}
	if converted.EnvironmentType != compliance.EnvProduction {
		t.Fatalf("environment_type = %q, want %q", converted.EnvironmentType, compliance.EnvProduction)
	}
	if converted.Category != compliance.CategoryThreat {
		t.Fatalf("category = %q, want %q", converted.Category, compliance.CategoryThreat)
	}
	if converted.WorkflowStatus != compliance.StatusInProgress {
		t.Fatalf("workflow_status = %q, want %q", converted.WorkflowStatus, compliance.StatusInProgress)
	}
	if converted.CVSS != cvss {
		t.Fatalf("cvss = %v, want %v", converted.CVSS, cvss)
	}
	if converted.EPSS != epss {
		t.Fatalf("epss = %v, want %v", converted.EPSS, epss)
	}
	if converted.DueDate == nil || !converted.DueDate.Equal(now.Add(24*time.Hour)) {
		t.Fatal("expected due date to be parsed")
	}
	if len(converted.CVEs) != 1 || converted.CVEs[0].ID != "CVE-2026-0001" {
		t.Fatal("expected CVE references to be converted")
	}
	if converted.Assignee == nil || converted.Assignee.UserID != "user-42" {
		t.Fatalf("assignee = %+v, want propagated user-42", converted.Assignee)
	}
	if converted.Assignee.DueDate == nil || !converted.Assignee.DueDate.Equal(assigneeDue) {
		t.Fatalf("assignee due date = %v, want %v", converted.Assignee.DueDate, assigneeDue)
	}
	if converted.TechnicalContact == nil || converted.TechnicalContact.Email != "tech-owner@example.com" {
		t.Fatalf("technical_contact = %+v, want propagated email", converted.TechnicalContact)
	}
	if converted.BusinessOwner == nil || converted.BusinessOwner.Email != "biz-owner@example.com" {
		t.Fatalf("business_owner = %+v, want propagated email", converted.BusinessOwner)
	}
	if converted.Team != "platform-security" {
		t.Fatalf("team = %q, want platform-security", converted.Team)
	}
}
