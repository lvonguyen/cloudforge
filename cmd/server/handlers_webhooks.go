package main

import (
	"encoding/json"
	"net/http"

	"aegis/internal/webhooks"

	"github.com/gorilla/mux"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
)

// registerWebhook creates a new webhook endpoint.
// POST /api/v1/webhooks
func (s *Server) registerWebhook(w http.ResponseWriter, r *http.Request) {
	ctx, span := otel.Tracer("aegis.api").Start(r.Context(), "handler.registerWebhook")
	defer span.End()
	r = r.WithContext(ctx)

	var req webhooks.RegisterEndpointRequest
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErrorResponse(w, "invalid request body", http.StatusBadRequest)
		return
	}

	ep, err := s.webhookEngine.RegisterEndpoint(r.Context(), req)
	if err != nil {
		writeErrorResponse(w, "webhook registration failed", http.StatusBadRequest)
		return
	}

	span.SetAttributes(attribute.Bool("webhook.registered", true))

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(ep)
}

// listWebhooks returns all registered webhook endpoints.
// GET /api/v1/webhooks
func (s *Server) listWebhooks(w http.ResponseWriter, r *http.Request) {
	_, span := otel.Tracer("aegis.api").Start(r.Context(), "handler.listWebhooks")
	defer span.End()

	endpoints, err := s.webhookEngine.ListEndpoints(r.Context())
	if err != nil {
		writeErrorResponse(w, "listing webhooks", http.StatusInternalServerError)
		return
	}

	span.SetAttributes(attribute.Int("webhooks.count", len(endpoints)))

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(endpoints)
}

// deleteWebhook removes a webhook endpoint.
// DELETE /api/v1/webhooks/{id}
func (s *Server) deleteWebhook(w http.ResponseWriter, r *http.Request) {
	ctx, span := otel.Tracer("aegis.api").Start(r.Context(), "handler.deleteWebhook")
	defer span.End()
	r = r.WithContext(ctx)

	id := mux.Vars(r)["id"]
	span.SetAttributes(attribute.String("webhook.id", id))

	if err := s.webhookEngine.DeleteEndpoint(r.Context(), id); err != nil {
		writeErrorResponse(w, "webhook endpoint not found", http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// listWebhookDeliveries returns delivery history for an endpoint.
// GET /api/v1/webhooks/{id}/deliveries
func (s *Server) listWebhookDeliveries(w http.ResponseWriter, r *http.Request) {
	ctx, span := otel.Tracer("aegis.api").Start(r.Context(), "handler.listWebhookDeliveries")
	defer span.End()
	r = r.WithContext(ctx)

	id := mux.Vars(r)["id"]
	span.SetAttributes(attribute.String("webhook.id", id))

	deliveries, err := s.webhookEngine.ListDeliveries(r.Context(), id)
	if err != nil {
		writeErrorResponse(w, "listing deliveries", http.StatusInternalServerError)
		return
	}
	if deliveries == nil {
		deliveries = make([]webhooks.Delivery, 0)
	}

	span.SetAttributes(attribute.Int("webhook.deliveries_count", len(deliveries)))

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(deliveries)
}
