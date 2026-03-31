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
	ticketRepo  findingTicketStore

	ticketMu    sync.RWMutex
	ticketStore map[string]*integrations.Ticket // tenant-scoped finding ticket cache

	mu                 sync.RWMutex
	asanaWebhookSecret string // persisted from handshake for event signature validation
	asanaWebhookToken  string // pre-shared token from ASANA_WEBHOOK_TOKEN for handshake auth
}

type cachedTicketRef struct {
	tenantID  string
	findingID string
	ticket    *integrations.Ticket
}

type asanaWebhookPayload struct {
	Events []struct {
		Action   string `json:"action"`
		Resource struct {
			GID          string `json:"gid"`
			ResourceType string `json:"resource_type"`
		} `json:"resource"`
		Parent *struct {
			GID          string `json:"gid"`
			ResourceType string `json:"resource_type"`
		} `json:"parent,omitempty"`
	} `json:"events"`
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
func (h *IntegrationHandler) providerForFinding(ctx context.Context, tenantID, findingID string) integrations.TicketProvider {
	if ticket, ok := h.loadTicket(ctx, tenantID, findingID); ok && h.providers != nil {
		if p, exists := h.providers[ticket.Provider]; exists {
			return p
		}
	}
	return h.provider
}

func (h *IntegrationHandler) providerForTicket(ticket *integrations.Ticket) integrations.TicketProvider {
	if ticket != nil && h.providers != nil {
		if p, ok := h.providers[ticket.Provider]; ok {
			return p
		}
	}
	return h.provider
}

func (h *IntegrationHandler) cacheTicket(tenantID, findingID string, ticket *integrations.Ticket) {
	if h == nil || ticket == nil {
		return
	}
	tenantID = normalizeTicketTenantID(tenantID)
	h.ticketMu.Lock()
	if h.ticketStore == nil {
		h.ticketStore = make(map[string]*integrations.Ticket)
	}
	h.ticketStore[ticketCacheKey(tenantID, findingID)] = ticket
	h.ticketMu.Unlock()
}

func (h *IntegrationHandler) loadMemoryTicket(tenantID, findingID string) (*integrations.Ticket, bool) {
	if h == nil {
		return nil, false
	}
	tenantID = normalizeTicketTenantID(tenantID)
	h.ticketMu.RLock()
	ticket, ok := h.ticketStore[ticketCacheKey(tenantID, findingID)]
	h.ticketMu.RUnlock()
	return ticket, ok
}

// storeTicket persists the finding→ticket mapping in the in-memory cache and optional durable store.
func (h *IntegrationHandler) storeTicket(ctx context.Context, tenantID, findingID string, ticket *integrations.Ticket) {
	if h == nil || ticket == nil {
		return
	}
	if findingID != "" {
		ticket.FindingID = findingID
	}
	h.cacheTicket(tenantID, findingID, ticket)
	if h.ticketRepo != nil {
		if err := h.ticketRepo.PutTicket(ctx, tenantID, ticket); err != nil && h.logger != nil {
			h.logger.Warn("persisting finding ticket failed",
				zap.String("tenant_id", normalizeTicketTenantID(tenantID)),
				zap.String("finding_id", findingID),
				zap.Error(err),
			)
		}
	}
}

func (h *IntegrationHandler) loadTicket(ctx context.Context, tenantID, findingID string) (*integrations.Ticket, bool) {
	if ticket, ok := h.loadMemoryTicket(tenantID, findingID); ok {
		return ticket, true
	}
	if h != nil && h.ticketRepo != nil {
		ticket, err := h.ticketRepo.GetTicket(ctx, tenantID, findingID)
		if err != nil {
			if h.logger != nil {
				h.logger.Warn("loading finding ticket from durable store failed",
					zap.String("tenant_id", normalizeTicketTenantID(tenantID)),
					zap.String("finding_id", findingID),
					zap.Error(err),
				)
			}
		} else if ticket != nil {
			h.cacheTicket(tenantID, findingID, ticket)
			return ticket, true
		}
	}
	return nil, false
}

func ticketCacheKey(tenantID, findingID string) string {
	return normalizeTicketTenantID(tenantID) + ":" + strings.TrimSpace(findingID)
}

func splitTicketCacheKey(key string) (tenantID, findingID string) {
	parts := strings.SplitN(key, ":", 2)
	if len(parts) != 2 {
		return normalizeTicketTenantID(""), strings.TrimSpace(key)
	}
	return normalizeTicketTenantID(parts[0]), strings.TrimSpace(parts[1])
}

func (h *IntegrationHandler) refreshTicketFromProvider(ctx context.Context, tenantID, findingID string, ticket *integrations.Ticket) (*integrations.Ticket, error) {
	if h == nil || ticket == nil {
		return ticket, nil
	}
	prov := h.providerForTicket(ticket)
	if prov == nil || strings.TrimSpace(ticket.ExternalID) == "" {
		return ticket, nil
	}

	refreshed, err := prov.GetTicket(ctx, ticket.ExternalID)
	if err != nil {
		return nil, err
	}
	if refreshed == nil {
		return nil, fmt.Errorf("provider %q returned nil ticket for %s", ticket.Provider, ticket.ExternalID)
	}

	if refreshed.ID == "" {
		refreshed.ID = ticket.ID
		if refreshed.ID == "" {
			refreshed.ID = ticket.ExternalID
		}
	}
	if refreshed.ExternalID == "" {
		refreshed.ExternalID = ticket.ExternalID
	}
	if refreshed.Provider == "" {
		refreshed.Provider = ticket.Provider
	}
	if refreshed.FindingID == "" {
		refreshed.FindingID = findingID
	}
	if refreshed.Title == "" {
		refreshed.Title = ticket.Title
	}
	if refreshed.Priority == "" {
		refreshed.Priority = ticket.Priority
	}
	if refreshed.Assignee == "" {
		refreshed.Assignee = ticket.Assignee
	}
	if refreshed.URL == "" {
		refreshed.URL = ticket.URL
	}
	if refreshed.CreatedAt.IsZero() {
		refreshed.CreatedAt = ticket.CreatedAt
	}
	if refreshed.UpdatedAt.IsZero() {
		refreshed.UpdatedAt = ticket.UpdatedAt
	}
	if len(refreshed.Metadata) == 0 && len(ticket.Metadata) != 0 {
		refreshed.Metadata = ticket.Metadata
	}

	h.storeTicket(ctx, tenantID, findingID, refreshed)
	return refreshed, nil
}

func (h *IntegrationHandler) matchingCachedTickets(providerName, externalID string) []cachedTicketRef {
	if h == nil || providerName == "" || externalID == "" {
		return nil
	}

	h.ticketMu.RLock()
	defer h.ticketMu.RUnlock()

	matches := make([]cachedTicketRef, 0)
	for key, ticket := range h.ticketStore {
		if ticket == nil || !strings.EqualFold(ticket.Provider, providerName) || ticket.ExternalID != externalID {
			continue
		}
		tenantID, findingID := splitTicketCacheKey(key)
		matches = append(matches, cachedTicketRef{
			tenantID:  tenantID,
			findingID: findingID,
			ticket:    ticket,
		})
	}
	return matches
}

func (h *IntegrationHandler) refreshCachedTicketsByExternalID(ctx context.Context, providerName, externalID string) int {
	matches := h.matchingCachedTickets(providerName, externalID)
	refreshed := 0
	for _, match := range matches {
		if _, err := h.refreshTicketFromProvider(ctx, match.tenantID, match.findingID, match.ticket); err != nil {
			if h.logger != nil {
				h.logger.Warn("refreshing cached ticket from webhook failed",
					zap.String("provider", providerName),
					zap.String("tenant_id", match.tenantID),
					zap.String("finding_id", match.findingID),
					zap.String("external_id", externalID),
					zap.Error(err),
				)
			}
			continue
		}
		refreshed++
	}
	return refreshed
}

func asanaTaskGIDs(payload asanaWebhookPayload) []string {
	seen := make(map[string]struct{})
	gids := make([]string, 0, len(payload.Events))
	add := func(resourceType, gid string) {
		if !strings.EqualFold(resourceType, "task") || strings.TrimSpace(gid) == "" {
			return
		}
		if _, ok := seen[gid]; ok {
			return
		}
		seen[gid] = struct{}{}
		gids = append(gids, gid)
	}
	for _, event := range payload.Events {
		add(event.Resource.ResourceType, event.Resource.GID)
		if event.Parent != nil {
			add(event.Parent.ResourceType, event.Parent.GID)
		}
	}
	return gids
}

// RemediateFinding creates a ticket and starts a remediation workflow.
// POST /api/v1/findings/{id}/remediate
func (h *IntegrationHandler) RemediateFinding(w http.ResponseWriter, r *http.Request) {
	ctx, span := otel.Tracer("aegis.api").Start(r.Context(), "handler.RemediateFinding")
	defer span.End()
	r = r.WithContext(ctx)

	findingID := mux.Vars(r)["id"]
	tenantID := issueTenantID(r)
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
	h.storeTicket(ctx, tenantID, findingID, ticket)

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
	tenantID := issueTenantID(r)
	span.SetAttributes(attribute.String("finding.id", findingID))
	if findingID == "" {
		writeErrorResponse(w, "finding id required", http.StatusBadRequest)
		return
	}

	// Look up from the durable store / cache first.
	if ticket, ok := h.loadTicket(ctx, tenantID, findingID); ok {
		refreshed := ticket
		if latest, err := h.refreshTicketFromProvider(ctx, tenantID, findingID, ticket); err != nil {
			h.logger.Warn("refreshing finding ticket failed",
				zap.String("tenant_id", normalizeTicketTenantID(tenantID)),
				zap.String("finding_id", findingID),
				zap.String("provider", ticket.Provider),
				zap.String("external_id", ticket.ExternalID),
				zap.Error(err),
			)
		} else if latest != nil {
			refreshed = latest
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(refreshed)
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

	externalID, err := h.resolveExternalID(ctx, issueTenantID(r), findingID)
	if err != nil {
		writeErrorResponse(w, "no ticket for this finding", http.StatusNotFound)
		return
	}

	type commenter interface {
		ListComments(ctx context.Context, externalID string) ([]integrations.CommentSync, error)
	}
	lc, ok := h.providerForFinding(ctx, issueTenantID(r), findingID).(commenter)
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

	externalID, err := h.resolveExternalID(ctx, issueTenantID(r), findingID)
	if err != nil {
		writeErrorResponse(w, "no ticket for this finding", http.StatusNotFound)
		return
	}

	comment, err := h.providerForFinding(ctx, issueTenantID(r), findingID).AddComment(ctx, externalID, body.Body)
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
	tenantID := issueTenantID(r)
	span.SetAttributes(attribute.String("finding.id", findingID))
	if findingID == "" {
		writeErrorResponse(w, "finding id required", http.StatusBadRequest)
		return
	}

	externalID, err := h.resolveExternalID(ctx, tenantID, findingID)
	if err != nil {
		writeErrorResponse(w, "no ticket for this finding", http.StatusNotFound)
		return
	}

	prov := h.providerForFinding(ctx, tenantID, findingID)
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
	h.storeTicket(ctx, tenantID, findingID, ticket)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(ticket)
}

// resolveExternalID maps a tenant-scoped finding ID to its external ticket ID.
func (h *IntegrationHandler) resolveExternalID(ctx context.Context, tenantID, findingID string) (string, error) {
	// Primary: durable store + cache (works for all providers)
	ticket, ok := h.loadTicket(ctx, tenantID, findingID)
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

	var payload asanaWebhookPayload
	if err := json.Unmarshal(body, &payload); err != nil {
		http.Error(w, "invalid webhook payload", http.StatusBadRequest)
		return
	}

	refreshed := 0
	for _, gid := range asanaTaskGIDs(payload) {
		refreshed += h.refreshCachedTicketsByExternalID(r.Context(), "asana", gid)
	}

	h.logger.Info("asana webhook event received",
		zap.Int("events", len(payload.Events)),
		zap.Int("tickets_refreshed", refreshed),
	)
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
