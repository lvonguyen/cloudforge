package main

import (
	"encoding/json"
	"net/http"

	"aegis/internal/secrets"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
)

// handleOrgScan runs an org-wide secrets scan.
// POST /api/v1/secrets/org-scan
func (s *Server) handleOrgScan(w http.ResponseWriter, r *http.Request) {
	ctx, span := otel.Tracer("aegis.api").Start(r.Context(), "handler.handleOrgScan")
	defer span.End()
	r = r.WithContext(ctx)

	var cfg secrets.OrgConfig
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		writeErrorResponse(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if cfg.OrgName == "" {
		writeErrorResponse(w, "org_name is required", http.StatusBadRequest)
		return
	}

	span.SetAttributes(attribute.String("secrets.org_name", cfg.OrgName))

	result, err := s.orgScanner.ScanOrg(r.Context(), cfg)
	if err != nil {
		writeErrorResponse(w, "org scan failed", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(result)
}
