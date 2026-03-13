package main

import (
	"encoding/json"
	"net/http"

	"cloudforge/internal/api"

	"github.com/gorilla/mux"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
)

// attackPathInScope returns true if all nodes in the path fall within the scope.
func attackPathInScope(scope *api.ResourceScope, path *AttackPath) bool {
	if scope == nil {
		return true
	}
	for i := range path.Nodes {
		n := &path.Nodes[i]
		if !api.MatchesDimension(scope.AccountIDs, n.AccountID) ||
			!api.MatchesDimension(scope.Regions, n.Region) {
			return false
		}
	}
	return true
}

func (s *Server) listAttackPaths(w http.ResponseWriter, r *http.Request) {
	_, span := otel.Tracer("cloudforge.api").Start(r.Context(), "handler.listAttackPaths")
	defer span.End()

	claims, _ := api.GetClaimsFromContext(r.Context())
	scope := api.ScopeFromContext(claims)

	s.attackPathMu.RLock()
	src := s.attackPaths
	s.attackPathMu.RUnlock()

	// Apply scope filter
	all := make([]AttackPath, 0, len(src))
	for i := range src {
		if attackPathInScope(scope, &src[i]) {
			all = append(all, src[i])
		}
	}

	page, perPage := parsePagination(r, 20)
	total := len(all)
	totalPages := (total + perPage - 1) / perPage
	if totalPages == 0 {
		totalPages = 1
	}
	if page > totalPages {
		page = totalPages
	}

	start := (page - 1) * perPage
	end := start + perPage
	if start >= total {
		start = total
		end = total
	} else if end > total {
		end = total
	}

	span.SetAttributes(
		attribute.Int("attack_paths.total", total),
		attribute.Int("attack_paths.page", page),
	)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(paginatedResponse{
		Data:       all[start:end],
		Page:       page,
		PerPage:    perPage,
		Total:      total,
		TotalPages: totalPages,
	})
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

	s.attackPathMu.RLock()
	stats := s.attackPathStats
	s.attackPathMu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(stats)
}
