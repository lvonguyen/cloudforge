package main

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
)

func (s *Server) listWAFTemplates(w http.ResponseWriter, r *http.Request) {
	ctx, span := otel.Tracer("aegis.api").Start(r.Context(), "handler.listWAFTemplates")
	defer span.End()
	r = r.WithContext(ctx)

	mgr := s.wafManager
	templates, err := mgr.ListTemplates(r.Context())
	if err != nil {
		s.writeInternalError(w, err, "list waf templates")
		return
	}

	span.SetAttributes(attribute.Int("waf.templates_count", len(templates)))

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"templates": templates,
		"count":     len(templates),
	})
}

func (s *Server) validateWAFCompliance(w http.ResponseWriter, r *http.Request) {
	ctx, span := otel.Tracer("aegis.api").Start(r.Context(), "handler.validateWAFCompliance")
	defer span.End()
	r = r.WithContext(ctx)

	vars := mux.Vars(r)
	templateID := vars["templateId"]
	resourceID := r.URL.Query().Get("resource")
	if resourceID == "" {
		resourceID = "resource-" + templateID
	}

	span.SetAttributes(
		attribute.String("waf.template_id", templateID),
		attribute.String("waf.resource_id", resourceID),
	)

	mgr := s.wafManager
	result, err := mgr.ValidateCompliance(r.Context(), templateID, resourceID)
	if err != nil {
		writeErrorResponse(w, "template not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(result)
}
