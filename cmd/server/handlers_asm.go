package main

import (
	"encoding/json"
	"net/http"

	"cloudforge/internal/asm"
)

// asmService encapsulates ASM scanning state (mirrors finopsService pattern).
type asmService struct {
	scanner asm.ASMScanner
	assets  []asm.Asset // cached from last scan
}

// handleASMScan runs an ASM scan for a domain.
// POST /api/v1/asm/scan
func (s *Server) handleASMScan(w http.ResponseWriter, r *http.Request) {
	var req asm.ScanRequest
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}

	if req.Domain == "" {
		http.Error(w, `{"error":"domain is required"}`, http.StatusBadRequest)
		return
	}

	result, err := s.asmSvc.scanner.ScanDomain(r.Context(), req.Domain)
	if err != nil {
		http.Error(w, `{"error":"`+err.Error()+`"}`, http.StatusInternalServerError)
		return
	}

	// Cache assets from the latest scan
	s.asmSvc.assets = result.Assets

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(result)
}

// handleASMAssets returns cached assets from the most recent scan.
// GET /api/v1/asm/assets
func (s *Server) handleASMAssets(w http.ResponseWriter, r *http.Request) {
	assets := s.asmSvc.assets
	if assets == nil {
		assets = make([]asm.Asset, 0)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(assets)
}
