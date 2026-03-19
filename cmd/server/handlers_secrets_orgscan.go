package main

import (
	"encoding/json"
	"net/http"

	"cloudforge/internal/secrets"
)

// handleOrgScan runs an org-wide secrets scan.
// POST /api/v1/secrets/org-scan
func (s *Server) handleOrgScan(w http.ResponseWriter, r *http.Request) {
	var cfg secrets.OrgConfig
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}

	if cfg.OrgName == "" {
		http.Error(w, `{"error":"org_name is required"}`, http.StatusBadRequest)
		return
	}

	result, err := s.orgScanner.ScanOrg(r.Context(), cfg)
	if err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(result)
}
