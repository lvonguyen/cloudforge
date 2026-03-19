package integrations

import (
	"context"
	"testing"
)

func TestMockProvider_CreateAndGet(t *testing.T) {
	p := NewMockProvider(nil)
	ctx := context.Background()

	ticket, err := p.CreateTicket(ctx, CreateTicketRequest{
		FindingID:   "finding-001",
		Title:       "Fix S3 public access",
		Description: "S3 bucket is publicly accessible",
		Priority:    PriorityHigh,
		Assignee:    "alice@example.com",
	})
	if err != nil {
		t.Fatalf("CreateTicket: %v", err)
	}
	if ticket.ExternalID == "" {
		t.Fatal("expected non-empty external ID")
	}
	if ticket.Status != TicketStatusOpen {
		t.Fatalf("expected status %q, got %q", TicketStatusOpen, ticket.Status)
	}
	if ticket.Provider != "mock" {
		t.Fatalf("expected provider %q, got %q", "mock", ticket.Provider)
	}

	got, err := p.GetTicket(ctx, ticket.ExternalID)
	if err != nil {
		t.Fatalf("GetTicket: %v", err)
	}
	if got.FindingID != "finding-001" {
		t.Fatalf("expected finding_id %q, got %q", "finding-001", got.FindingID)
	}
}

func TestMockProvider_AddComment(t *testing.T) {
	p := NewMockProvider(nil)
	ctx := context.Background()

	ticket, _ := p.CreateTicket(ctx, CreateTicketRequest{
		FindingID: "f-002",
		Title:     "test",
		Priority:  PriorityNormal,
	})

	comment, err := p.AddComment(ctx, ticket.ExternalID, "Remediation in progress")
	if err != nil {
		t.Fatalf("AddComment: %v", err)
	}
	if comment.Body != "Remediation in progress" {
		t.Fatalf("unexpected comment body: %q", comment.Body)
	}
}

func TestMockProvider_SyncStatus(t *testing.T) {
	p := NewMockProvider(nil)
	ctx := context.Background()

	ticket, _ := p.CreateTicket(ctx, CreateTicketRequest{
		FindingID: "f-003",
		Title:     "test",
		Priority:  PriorityLow,
	})

	status, err := p.SyncStatus(ctx, ticket.ExternalID)
	if err != nil {
		t.Fatalf("SyncStatus: %v", err)
	}
	if status != TicketStatusOpen {
		t.Fatalf("expected %q, got %q", TicketStatusOpen, status)
	}
}

func TestMockProvider_NotFound(t *testing.T) {
	p := NewMockProvider(nil)
	ctx := context.Background()

	_, err := p.GetTicket(ctx, "nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent ticket")
	}
}

func TestMockProvider_GetByFindingID(t *testing.T) {
	p := NewMockProvider(nil)
	ctx := context.Background()

	p.CreateTicket(ctx, CreateTicketRequest{
		FindingID: "f-lookup",
		Title:     "test",
		Priority:  PriorityNormal,
	})

	ticket, found := p.GetTicketByFindingID("f-lookup")
	if !found {
		t.Fatal("expected ticket to be found by finding ID")
	}
	if ticket.FindingID != "f-lookup" {
		t.Fatalf("expected finding_id %q, got %q", "f-lookup", ticket.FindingID)
	}
}

func TestRoutingEngine_CriticalChokePoint(t *testing.T) {
	engine := NewRoutingEngine(DefaultRules())
	ctx := context.Background()

	d, err := engine.Route(ctx, RoutingInput{
		Severity:     "CRITICAL",
		IsChokePoint: true,
	})
	if err != nil {
		t.Fatalf("Route: %v", err)
	}
	if d.Priority != PriorityUrgent {
		t.Fatalf("expected priority %q, got %q", PriorityUrgent, d.Priority)
	}
	if d.SLAHours != 4 {
		t.Fatalf("expected SLA 4h, got %d", d.SLAHours)
	}
	if d.Team != "incident-response" {
		t.Fatalf("expected team %q, got %q", "incident-response", d.Team)
	}
}

func TestRoutingEngine_Critical(t *testing.T) {
	engine := NewRoutingEngine(DefaultRules())
	ctx := context.Background()

	d, _ := engine.Route(ctx, RoutingInput{Severity: "CRITICAL"})
	if d.SLAHours != 24 {
		t.Fatalf("expected SLA 24h, got %d", d.SLAHours)
	}
}

func TestRoutingEngine_High(t *testing.T) {
	engine := NewRoutingEngine(DefaultRules())
	ctx := context.Background()

	d, _ := engine.Route(ctx, RoutingInput{Severity: "HIGH"})
	if d.Priority != PriorityHigh {
		t.Fatalf("expected priority %q, got %q", PriorityHigh, d.Priority)
	}
	if d.SLAHours != 72 {
		t.Fatalf("expected SLA 72h, got %d", d.SLAHours)
	}
}

func TestRoutingEngine_Medium(t *testing.T) {
	engine := NewRoutingEngine(DefaultRules())
	ctx := context.Background()

	d, _ := engine.Route(ctx, RoutingInput{Severity: "MEDIUM"})
	if d.SLAHours != 7*24 {
		t.Fatalf("expected SLA 168h, got %d", d.SLAHours)
	}
}

func TestRoutingEngine_Low(t *testing.T) {
	engine := NewRoutingEngine(DefaultRules())
	ctx := context.Background()

	d, _ := engine.Route(ctx, RoutingInput{Severity: "LOW"})
	if d.SLAHours != 30*24 {
		t.Fatalf("expected SLA 720h, got %d", d.SLAHours)
	}
}

func TestRoutingEngine_Fallback(t *testing.T) {
	engine := NewRoutingEngine(DefaultRules())
	ctx := context.Background()

	d, _ := engine.Route(ctx, RoutingInput{Severity: "UNKNOWN"})
	if d.Priority != PriorityLow {
		t.Fatalf("expected fallback priority %q, got %q", PriorityLow, d.Priority)
	}
	if d.Reason != "default-fallback" {
		t.Fatalf("expected fallback reason, got %q", d.Reason)
	}
}
