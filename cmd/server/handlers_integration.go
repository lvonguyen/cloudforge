package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
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
	provider    integrations.TicketProvider            // default provider (first available: asana > jira > mock)
	providers   map[string]integrations.TicketProvider // all available providers keyed by name
	router      integrations.RoutingEngine
	workflow    workflow.Engine
	auditLogger audit.AuditLogger
	logger      *zap.Logger

	ticketMu    sync.RWMutex
	ticketStore map[string]*integrations.Ticket // finding ID → ticket (in-memory mapping)

	mu                 sync.RWMutex
	asanaWebhookSecret string // persisted from handshake for event signature validation
	asanaWebhookToken  string // pre-shared token from ASANA_WEBHOOK_TOKEN for handshake auth
}

// selectProvider returns the named provider or the default.
func (h *IntegrationHandler) selectProvider(name string) integrations.TicketProvider {
	if name != "" && h.providers != nil {
		if p, ok := h.providers[name]; ok {
			return p
		}
	}
	return h.provider
}

// providerForFinding returns the provider that created the ticket for a finding.
func (h *IntegrationHandler) providerForFinding(findingID string) integrations.TicketProvider {
	h.ticketMu.RLock()
	ticket, ok := h.ticketStore[findingID]
	h.ticketMu.RUnlock()
	if ok && h.providers != nil {
		if p, exists := h.providers[ticket.Provider]; exists {
			return p
		}
	}
	return h.provider
}

// storeTicket persists the finding→ticket mapping in memory.
func (h *IntegrationHandler) storeTicket(findingID string, ticket *integrations.Ticket) {
	h.ticketMu.Lock()
	h.ticketStore[findingID] = ticket
	h.ticketMu.Unlock()
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
		Provider     string `json:"provider,omitempty"` // "asana", "jira" — overrides default
	}
	if r.Body != nil && r.ContentLength != 0 {
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

	// Create ticket in external system (use requested provider or default)
	provider := h.selectProvider(body.Provider)
	ticket, err := provider.CreateTicket(r.Context(), integrations.CreateTicketRequest{
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

	// Persist finding→ticket mapping for later lookups
	h.storeTicket(findingID, ticket)

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
		Action:   audit.ActionRemediationCreate,
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

	// Look up from ticket store (works for all providers: real and mock)
	h.ticketMu.RLock()
	ticket, ok := h.ticketStore[findingID]
	h.ticketMu.RUnlock()
	if ok {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(ticket)
		return
	}

	// Fallback: mock provider's internal index (for tests that bypass storeTicket)
	if mp, ok := h.provider.(*integrations.MockProvider); ok {
		if t, found := mp.GetTicketByFindingID(findingID); found {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(t)
			return
		}
	}

	writeErrorResponse(w, "no ticket for this finding", http.StatusNotFound)
}

// GetTicketComments returns comments on the ticket linked to a finding.
// GET /api/v1/findings/{id}/ticket/comments
func (h *IntegrationHandler) GetTicketComments(w http.ResponseWriter, r *http.Request) {
	ctx, span := otel.Tracer("aegis.api").Start(r.Context(), "handler.GetTicketComments")
	defer span.End()

	findingID := mux.Vars(r)["id"]
	span.SetAttributes(attribute.String("finding.id", findingID))
	if findingID == "" {
		writeErrorResponse(w, "finding id required", http.StatusBadRequest)
		return
	}

	externalID, err := h.resolveExternalID(findingID)
	if err != nil {
		writeErrorResponse(w, "no ticket for this finding", http.StatusNotFound)
		return
	}

	type commenter interface {
		ListComments(ctx context.Context, externalID string) ([]integrations.CommentSync, error)
	}
	lc, ok := h.providerForFinding(findingID).(commenter)
	if !ok {
		writeErrorResponse(w, "provider does not support listing comments", http.StatusNotImplemented)
		return
	}

	comments, err := lc.ListComments(ctx, externalID)
	if err != nil {
		h.logger.Error("listing ticket comments failed", zap.String("finding_id", findingID), zap.Error(err))
		writeErrorResponse(w, "failed to list comments", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(comments)
}

// AddTicketComment adds a comment to the ticket linked to a finding.
// POST /api/v1/findings/{id}/ticket/comments
func (h *IntegrationHandler) AddTicketComment(w http.ResponseWriter, r *http.Request) {
	ctx, span := otel.Tracer("aegis.api").Start(r.Context(), "handler.AddTicketComment")
	defer span.End()

	findingID := mux.Vars(r)["id"]
	span.SetAttributes(attribute.String("finding.id", findingID))
	if findingID == "" {
		writeErrorResponse(w, "finding id required", http.StatusBadRequest)
		return
	}

	var body struct {
		Body string `json:"body"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Body == "" {
		writeErrorResponse(w, "body field is required", http.StatusBadRequest)
		return
	}

	externalID, err := h.resolveExternalID(findingID)
	if err != nil {
		writeErrorResponse(w, "no ticket for this finding", http.StatusNotFound)
		return
	}

	comment, err := h.providerForFinding(findingID).AddComment(ctx, externalID, body.Body)
	if err != nil {
		h.logger.Error("adding ticket comment failed", zap.String("finding_id", findingID), zap.Error(err))
		writeErrorResponse(w, "failed to add comment", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(comment)
}

// SyncTicketStatus force-refreshes the ticket status from the external provider.
// POST /api/v1/findings/{id}/ticket/sync
func (h *IntegrationHandler) SyncTicketStatus(w http.ResponseWriter, r *http.Request) {
	ctx, span := otel.Tracer("aegis.api").Start(r.Context(), "handler.SyncTicketStatus")
	defer span.End()

	findingID := mux.Vars(r)["id"]
	span.SetAttributes(attribute.String("finding.id", findingID))
	if findingID == "" {
		writeErrorResponse(w, "finding id required", http.StatusBadRequest)
		return
	}

	externalID, err := h.resolveExternalID(findingID)
	if err != nil {
		writeErrorResponse(w, "no ticket for this finding", http.StatusNotFound)
		return
	}

	prov := h.providerForFinding(findingID)
	status, err := prov.SyncStatus(ctx, externalID)
	if err != nil {
		h.logger.Error("syncing ticket status failed", zap.String("finding_id", findingID), zap.Error(err))
		writeErrorResponse(w, "failed to sync status", http.StatusInternalServerError)
		return
	}

	ticket, err := prov.GetTicket(ctx, externalID)
	if err != nil {
		h.logger.Error("getting ticket after sync failed", zap.String("finding_id", findingID), zap.Error(err))
		writeErrorResponse(w, "failed to fetch ticket", http.StatusInternalServerError)
		return
	}
	ticket.Status = status

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(ticket)
}

// resolveExternalID maps a finding ID to its external ticket ID.
func (h *IntegrationHandler) resolveExternalID(findingID string) (string, error) {
	// Primary: ticket store (works for all providers)
	h.ticketMu.RLock()
	ticket, ok := h.ticketStore[findingID]
	h.ticketMu.RUnlock()
	if ok {
		return ticket.ExternalID, nil
	}

	// Fallback: mock provider's internal index (for tests)
	if mp, ok := h.provider.(*integrations.MockProvider); ok {
		t, found := mp.GetTicketByFindingID(findingID)
		if found {
			return t.ExternalID, nil
		}
	}

	return "", fmt.Errorf("no ticket mapping for finding %s", findingID)
}

// AsanaWebhook handles Asana webhook handshake and event delivery.
// POST /api/v1/webhooks/asana
//
// The handshake is unauthenticated per Asana's protocol, but protected by a
// pre-shared token (ASANA_WEBHOOK_TOKEN env var) when configured. This prevents
// arbitrary callers from injecting a webhook secret.
func (h *IntegrationHandler) AsanaWebhook(w http.ResponseWriter, r *http.Request) {
	// Asana webhook handshake: respond with X-Hook-Secret header and persist it
	hookSecret := r.Header.Get("X-Hook-Secret")
	if hookSecret != "" {
		// When ASANA_WEBHOOK_TOKEN is set, require it as a query param to
		// prevent unauthenticated secret injection (SA-001).
		if h.asanaWebhookToken != "" {
			if r.URL.Query().Get("token") != h.asanaWebhookToken {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
		}
		h.mu.Lock()
		h.asanaWebhookSecret = hookSecret
		h.mu.Unlock()
		w.Header().Set("X-Hook-Secret", hookSecret)
		w.WriteHeader(http.StatusOK)
		return
	}

	// Validate X-Hook-Signature on event delivery
	h.mu.RLock()
	secret := h.asanaWebhookSecret
	h.mu.RUnlock()
	if secret == "" {
		h.logger.Warn("asana webhook event received before handshake")
		http.Error(w, "webhook not configured", http.StatusServiceUnavailable)
		return
	}
	sig := r.Header.Get("X-Hook-Signature")
	if sig == "" {
		http.Error(w, "missing X-Hook-Signature", http.StatusUnauthorized)
		return
	}

	// Read body and validate HMAC-SHA256 signature
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20)) // 1MB cap
	if err != nil {
		http.Error(w, "failed to read body", http.StatusBadRequest)
		return
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	expected := hex.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(sig), []byte(expected)) {
		http.Error(w, "invalid signature", http.StatusUnauthorized)
		return
	}

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
