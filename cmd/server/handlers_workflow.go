package main

import (
	"encoding/json"
	"net/http"

	"cloudforge/internal/workflow"

	"github.com/gorilla/mux"
)

func (s *Server) listWorkflows(w http.ResponseWriter, r *http.Request) {
	engine, err := workflow.NewEngine("memory")
	if err != nil {
		s.writeInternalError(w, err, "create workflow engine")
		return
	}
	workflows, err := engine.ListWorkflows(r.Context())
	if err != nil {
		s.writeInternalError(w, err, "list workflows")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"workflows": workflows,
		"count":     len(workflows),
	})
}

func (s *Server) getWorkflow(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	engine, err := workflow.NewEngine("memory")
	if err != nil {
		s.writeInternalError(w, err, "create workflow engine")
		return
	}
	wf, err := engine.GetWorkflow(r.Context(), id)
	if err != nil {
		writeErrorResponse(w, "workflow not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(wf)
}

func (s *Server) approveWorkflow(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

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

	engine, err := workflow.NewEngine("memory")
	if err != nil {
		s.writeInternalError(w, err, "create workflow engine")
		return
	}
	wf, err := engine.ApproveWorkflow(r.Context(), id, body.Approver)
	if err != nil {
		writeErrorResponse(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(wf)
}
