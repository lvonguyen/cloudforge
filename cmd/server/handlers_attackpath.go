package main

import (
	"encoding/json"
	"net/http"
	"sync"

	"cloudforge/internal/api"

	"github.com/gorilla/mux"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
)

// AttackPathService encapsulates attack path data and the mutex protecting it.
// Extracted from Server to reduce the God Object surface area.
type AttackPathService struct {
	Paths []AttackPath
	Stats *AttackPathStats
	Mu    sync.RWMutex
}

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

func (svc *AttackPathService) listAttackPaths(w http.ResponseWriter, r *http.Request) {
	_, span := otel.Tracer("cloudforge.api").Start(r.Context(), "handler.listAttackPaths")
	defer span.End()

	claims, _ := api.GetClaimsFromContext(r.Context())
	scope := api.ScopeFromContext(claims)

	svc.Mu.RLock()
	src := svc.Paths
	// Apply scope filter
	all := make([]AttackPath, 0, len(src))
	for i := range src {
		if attackPathInScope(scope, &src[i]) {
			all = append(all, src[i])
		}
	}
	svc.Mu.RUnlock()

	page, perPage := parsePagination(r, 20, 100)
	resp := paginateResult(all, page, perPage)

	span.SetAttributes(
		attribute.Int("attack_paths.total", resp.Total),
		attribute.Int("attack_paths.page", resp.Page),
	)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (svc *AttackPathService) getAttackPath(w http.ResponseWriter, r *http.Request) {
	ctx, span := otel.Tracer("cloudforge.api").Start(r.Context(), "handler.getAttackPath")
	defer span.End()
	r = r.WithContext(ctx)

	id := mux.Vars(r)["id"]
	span.SetAttributes(attribute.String("attack_path.id", id))

	svc.Mu.RLock()
	var found *AttackPath
	for i := range svc.Paths {
		if svc.Paths[i].ID == id {
			p := svc.Paths[i]
			found = &p
			break
		}
	}
	svc.Mu.RUnlock()

	if found != nil {
		claims, _ := api.GetClaimsFromContext(r.Context())
		scope := api.ScopeFromContext(claims)
		if scope != nil && !attackPathInScope(scope, found) {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(found)
		return
	}

	writeErrorResponse(w, "attack path not found", http.StatusNotFound)
}

func (svc *AttackPathService) getAttackPathStats(w http.ResponseWriter, r *http.Request) {
	_, span := otel.Tracer("cloudforge.api").Start(r.Context(), "handler.getAttackPathStats")
	defer span.End()

	claims, _ := api.GetClaimsFromContext(r.Context())
	scope := api.ScopeFromContext(claims)

	svc.Mu.RLock()
	defer svc.Mu.RUnlock()

	// Fast path: no scope restriction — return pre-computed stats.
	if scope == nil {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(svc.Stats)
		return
	}

	// Scoped path: compute stats on the fly for the caller's scope.
	scoped := &AttackPathStats{
		TotalFindings:    svc.Stats.TotalFindings,
		FindingsInPaths:  svc.Stats.FindingsInPaths,
		IsolatedFindings: svc.Stats.IsolatedFindings,
		CoveragePercent:  svc.Stats.CoveragePercent,
		ByProvider:       make(map[string]int),
	}
	for i := range svc.Paths {
		if !attackPathInScope(scope, &svc.Paths[i]) {
			continue
		}
		scoped.TotalPaths++
		switch svc.Paths[i].Severity {
		case "CRITICAL":
			scoped.CriticalPaths++
		case "HIGH":
			scoped.HighPaths++
		default:
			scoped.MediumPaths++
		}
		if len(svc.Paths[i].Nodes) > 0 {
			scoped.ByProvider[svc.Paths[i].Nodes[0].Provider]++
		}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(scoped)
}
