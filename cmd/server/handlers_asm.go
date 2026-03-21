package main

import (
	"encoding/json"
	"net/http"
	"sync"

	"aegis/internal/asm"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
)

// asmService encapsulates ASM scanning state (mirrors finopsService pattern).
type asmService struct {
	mu      sync.RWMutex
	scanner asm.ASMScanner
	assets  []asm.Asset // cached from last scan
}

// handleASMScan runs an ASM scan for a domain.
// POST /api/v1/asm/scan
func (s *Server) handleASMScan(w http.ResponseWriter, r *http.Request) {
	ctx, span := otel.Tracer("aegis.api").Start(r.Context(), "handler.handleASMScan")
	defer span.End()
	r = r.WithContext(ctx)

	var req asm.ScanRequest
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErrorResponse(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if req.Domain == "" {
		writeErrorResponse(w, "domain is required", http.StatusBadRequest)
		return
	}

	span.SetAttributes(attribute.String("asm.domain", req.Domain))

	result, err := s.asmSvc.scanner.ScanDomain(r.Context(), req.Domain)
	if err != nil {
		writeErrorResponse(w, "ASM scan failed", http.StatusInternalServerError)
		return
	}

	// Cache assets from the latest scan
	s.asmSvc.mu.Lock()
	s.asmSvc.assets = result.Assets
	s.asmSvc.mu.Unlock()

	span.SetAttributes(attribute.Int("asm.assets_found", len(result.Assets)))

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(result)
}

// handleASMAssets returns cached assets from the most recent scan.
// GET /api/v1/asm/assets
func (s *Server) handleASMAssets(w http.ResponseWriter, r *http.Request) {
	_, span := otel.Tracer("aegis.api").Start(r.Context(), "handler.handleASMAssets")
	defer span.End()

	s.asmSvc.mu.RLock()
	assets := s.asmSvc.assets
	s.asmSvc.mu.RUnlock()
	if assets == nil {
		assets = make([]asm.Asset, 0)
	}

	span.SetAttributes(attribute.Int("asm.assets_count", len(assets)))

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(assets)
}
