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
	controlsCalls        [][]secgraph.Control
	materializationCalls []secgraph.MaterializationResult
	controlsErr          error
	materializationErr   error
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

func TestToComplianceFinding_ParsesOptionalFields(t *testing.T) {
	now := time.Date(2026, 3, 31, 15, 0, 0, 0, time.UTC)
	cvss := 9.8
	epss := 0.91
	finding := Finding{
		ID:              "finding-4",
		Type:            "vulnerability",
		ResourceType:    "compute",
		CloudProvider:   "aws",
		EnvironmentType: "production",
		Category:        "THREAT",
		WorkflowStatus:  "in_progress",
		CVSS:            &cvss,
		EPSS:            &epss,
		FirstFoundAt:    now.Format(time.RFC3339),
		DueDate:         now.Add(24 * time.Hour).Format(time.RFC3339),
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
}
