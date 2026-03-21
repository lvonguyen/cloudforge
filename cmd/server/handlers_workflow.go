package main

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
)

func (s *Server) listWorkflows(w http.ResponseWriter, r *http.Request) {
	ctx, span := otel.Tracer("aegis.api").Start(r.Context(), "handler.listWorkflows")
	defer span.End()
	r = r.WithContext(ctx)

	engine := s.workflowEngine
	workflows, err := engine.ListWorkflows(r.Context())
	if err != nil {
		s.writeInternalError(w, err, "list workflows")
		return
	}

	span.SetAttributes(attribute.Int("workflows.count", len(workflows)))

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"workflows": workflows,
		"count":     len(workflows),
	})
}

func (s *Server) getWorkflow(w http.ResponseWriter, r *http.Request) {
	ctx, span := otel.Tracer("aegis.api").Start(r.Context(), "handler.getWorkflow")
	defer span.End()
	r = r.WithContext(ctx)

	vars := mux.Vars(r)
	id := vars["id"]
	span.SetAttributes(attribute.String("workflow.id", id))

	engine := s.workflowEngine
	wf, err := engine.GetWorkflow(r.Context(), id)
	if err != nil {
		writeErrorResponse(w, "workflow not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(wf)
}

func (s *Server) approveWorkflow(w http.ResponseWriter, r *http.Request) {
	ctx, span := otel.Tracer("aegis.api").Start(r.Context(), "handler.approveWorkflow")
	defer span.End()
	r = r.WithContext(ctx)

	vars := mux.Vars(r)
	id := vars["id"]
	span.SetAttributes(attribute.String("workflow.id", id))

	var body struct {
		Approver string `json:"approver"`
	}
	if !s.decodeJSONBody(w, r, &body) {
		return
	}
	if body.Approver == "" {
		writeErrorResponse(w, "approver is required", http.StatusBadRequest)
		return
	}

	engine := s.workflowEngine
	wf, err := engine.ApproveWorkflow(r.Context(), id, body.Approver)
	if err != nil {
		writeErrorResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(wf)
}
