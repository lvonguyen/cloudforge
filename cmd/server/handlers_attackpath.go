package main

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
)

func (s *Server) listAttackPaths(w http.ResponseWriter, r *http.Request) {
	_, span := otel.Tracer("cloudforge.api").Start(r.Context(), "handler.listAttackPaths")
	defer span.End()

	s.attackPathMu.RLock()
	paths := s.attackPaths
	s.attackPathMu.RUnlock()

	span.SetAttributes(attribute.Int("attack_paths.count", len(paths)))

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(paths)
}

func (s *Server) getAttackPath(w http.ResponseWriter, r *http.Request) {
	ctx, span := otel.Tracer("cloudforge.api").Start(r.Context(), "handler.getAttackPath")
	defer span.End()
	r = r.WithContext(ctx)

	id := mux.Vars(r)["id"]
	span.SetAttributes(attribute.String("attack_path.id", id))

	s.attackPathMu.RLock()
	var found *AttackPath
	for i := range s.attackPaths {
		if s.attackPaths[i].ID == id {
			p := s.attackPaths[i]
			found = &p
			break
		}
	}
	s.attackPathMu.RUnlock()

	if found != nil {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(found)
		return
	}

	writeErrorResponse(w, "attack path not found", http.StatusNotFound)
}

func (s *Server) getAttackPathStats(w http.ResponseWriter, r *http.Request) {
	_, span := otel.Tracer("cloudforge.api").Start(r.Context(), "handler.getAttackPathStats")
	defer span.End()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(s.attackPathStats)
}
