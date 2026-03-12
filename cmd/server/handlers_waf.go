package main

import (
	"encoding/json"
	"net/http"

	"cloudforge/internal/waf"

	"github.com/gorilla/mux"
)

func (s *Server) listWAFTemplates(w http.ResponseWriter, r *http.Request) {
	mgr, err := waf.NewTemplateManager("memory")
	if err != nil {
		s.writeInternalError(w, err, "create waf template manager")
		return
	}
	templates, err := mgr.ListTemplates(r.Context())
	if err != nil {
		s.writeInternalError(w, err, "list waf templates")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"templates": templates,
		"count":     len(templates),
	})
}

func (s *Server) validateWAFCompliance(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	templateID := vars["templateId"]
	resourceID := r.URL.Query().Get("resource")
	if resourceID == "" {
		resourceID = "resource-" + templateID
	}

	mgr, err := waf.NewTemplateManager("memory")
	if err != nil {
		s.writeInternalError(w, err, "create waf template manager")
		return
	}
	result, err := mgr.ValidateCompliance(r.Context(), templateID, resourceID)
	if err != nil {
		writeErrorResponse(w, "template not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(result)
}
