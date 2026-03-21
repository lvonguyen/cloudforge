package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"aegis/internal/audit"
	"aegis/internal/integrations"
	"aegis/internal/workflow"

	"github.com/gorilla/mux"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.uber.org/zap"
)

// IntegrationHandler mirrors the GRCHandler pattern — owns provider, router,
// workflow ref, and audit logger as self-contained fields.
type IntegrationHandler struct {
	provider    integrations.TicketProvider
	router      integrations.RoutingEngine
	workflow    workflow.Engine
	auditLogger audit.AuditLogger
	logger      *zap.Logger
}

// RemediateFinding creates a ticket and starts a remediation workflow.
// POST /api/v1/findings/{id}/remediate
func (h *IntegrationHandler) RemediateFinding(w http.ResponseWriter, r *http.Request) {
	ctx, span := otel.Tracer("aegis.api").Start(r.Context(), "handler.RemediateFinding")
	defer span.End()
	r = r.WithContext(ctx)

	findingID := mux.Vars(r)["id"]
	span.SetAttributes(attribute.String("finding.id", findingID))
	if findingID == "" {
		writeErrorResponse(w, "finding id required", http.StatusBadRequest)
		return
	}

	// Decode optional request body for routing hints
	var body struct {
		Severity     string `json:"severity"`
		IsChokePoint bool   `json:"is_choke_point"`
		Assignee     string `json:"assignee,omitempty"`
	}
	if r.Body != nil && r.ContentLength > 0 {
		r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeErrorResponse(w, "invalid request body", http.StatusBadRequest)
			return
		}
	}

	if body.Severity == "" {
		body.Severity = "MEDIUM"
	}

	// Route the finding
	decision, err := h.router.Route(r.Context(), integrations.RoutingInput{
		Severity:     strings.ToUpper(body.Severity),
		IsChokePoint: body.IsChokePoint,
	})
	if err != nil {
		h.logger.Error("routing failed", zap.String("finding_id", findingID), zap.Error(err))
		writeErrorResponse(w, "routing failed", http.StatusInternalServerError)
		return
	}

	// Compute SLA deadline
	dueDate := decision.SLADeadline(time.Now().UTC())

	// Create ticket in external system
	ticket, err := h.provider.CreateTicket(r.Context(), integrations.CreateTicketRequest{
		FindingID:   findingID,
		Title:       fmt.Sprintf("[Cloud Aegis] Remediate finding %s", findingID),
		Description: fmt.Sprintf("Priority: %s | Team: %s | SLA: %dh", decision.Priority, decision.Team, decision.SLAHours),
		Priority:    decision.Priority,
		Assignee:    body.Assignee,
		DueDate:     &dueDate,
		Metadata: map[string]string{
			"team":     decision.Team,
			"sla_rule": decision.Reason,
		},
	})
	if err != nil {
		h.logger.Error("ticket creation failed", zap.String("finding_id", findingID), zap.Error(err))
		writeErrorResponse(w, "ticket creation failed", http.StatusInternalServerError)
		return
	}

	// Start a remediation workflow
	wf, err := h.workflow.StartWorkflow(r.Context(), &workflow.Workflow{
		Name:        "Remediate " + findingID,
		Type:        workflow.TypeRemediation,
		Priority:    priorityToInt(decision.Priority),
		Initiator:   "integration-handler",
		Description: fmt.Sprintf("Ticket %s created in %s", ticket.ExternalID, ticket.Provider),
		Metadata: map[string]string{
			"finding_id":  findingID,
			"external_id": ticket.ExternalID,
			"provider":    ticket.Provider,
		},
	})
	if err != nil {
		h.logger.Warn("workflow start failed (ticket was created)", zap.Error(err))
	}

	// Audit log
	_ = h.auditLogger.Log(r.Context(), audit.AuditEntry{
		Action:   "remediation.created",
		Resource: "finding/" + findingID,
	})

	resp := struct {
		Ticket   *integrations.Ticket          `json:"ticket"`
		Routing  *integrations.RoutingDecision `json:"routing"`
		Workflow string                        `json:"workflow_id,omitempty"`
	}{
		Ticket:   ticket,
		Routing:  decision,
		Workflow: safeWorkflowID(wf),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(resp)
}

// GetFindingTicket returns the ticket associated with a finding.
// GET /api/v1/findings/{id}/ticket
func (h *IntegrationHandler) GetFindingTicket(w http.ResponseWriter, r *http.Request) {
	ctx, span := otel.Tracer("aegis.api").Start(r.Context(), "handler.GetFindingTicket")
	defer span.End()
	r = r.WithContext(ctx)

	findingID := mux.Vars(r)["id"]
	span.SetAttributes(attribute.String("finding.id", findingID))
	if findingID == "" {
		writeErrorResponse(w, "finding id required", http.StatusBadRequest)
		return
	}

	// For the mock provider, look up by finding ID.
	// Real providers would use a mapping table.
	if mp, ok := h.provider.(*integrations.MockProvider); ok {
		ticket, found := mp.GetTicketByFindingID(findingID)
		if !found {
			writeErrorResponse(w, "no ticket for this finding", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(ticket)
		return
	}

	// For non-mock providers, this would query a mapping store.
	writeErrorResponse(w, "no ticket for this finding", http.StatusNotFound)
}

// AsanaWebhook handles Asana webhook handshake and event delivery.
// POST /api/v1/webhooks/asana
func (h *IntegrationHandler) AsanaWebhook(w http.ResponseWriter, r *http.Request) {
	// Asana webhook handshake: respond with X-Hook-Secret header
	hookSecret := r.Header.Get("X-Hook-Secret")
	if hookSecret != "" {
		w.Header().Set("X-Hook-Secret", hookSecret)
		w.WriteHeader(http.StatusOK)
		return
	}

	// Event delivery — for now, just acknowledge
	h.logger.Info("asana webhook event received")
	w.WriteHeader(http.StatusOK)
}

func priorityToInt(p integrations.TicketPriority) int {
	switch p {
	case integrations.PriorityUrgent:
		return 1
	case integrations.PriorityHigh:
		return 2
	case integrations.PriorityNormal:
		return 3
	case integrations.PriorityLow:
		return 4
	default:
		return 3
	}
}

func safeWorkflowID(wf *workflow.Workflow) string {
	if wf == nil {
		return ""
	}
	return wf.ID
}
