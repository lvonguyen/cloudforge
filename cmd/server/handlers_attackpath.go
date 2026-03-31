package main

import (
	"context"
	"encoding/json"
	"net/http"
	"regexp"
	"strconv"
	"sync"

	"aegis/internal/api"
	"aegis/internal/graph"

	"github.com/gorilla/mux"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.uber.org/zap"
)

// AttackPathService encapsulates attack path data and the mutex protecting it.
// Extracted from Server to reduce the God Object surface area.
type AttackPathService struct {
	Paths     []AttackPath
	PathsByID map[string]*AttackPath // O(1) lookup by ID
	Stats     *AttackPathStats
	Mu        sync.RWMutex
}

// buildPathIndex populates PathsByID from the Paths slice.
func (svc *AttackPathService) buildPathIndex() {
	svc.PathsByID = make(map[string]*AttackPath, len(svc.Paths))
	for i := range svc.Paths {
		svc.PathsByID[svc.Paths[i].ID] = &svc.Paths[i]
	}
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
	_, span := otel.Tracer("aegis.api").Start(r.Context(), "handler.listAttackPaths")
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
	ctx, span := otel.Tracer("aegis.api").Start(r.Context(), "handler.getAttackPath")
	defer span.End()
	r = r.WithContext(ctx)

	id := mux.Vars(r)["id"]
	span.SetAttributes(attribute.String("attack_path.id", id))

	svc.Mu.RLock()
	src := svc.PathsByID[id]
	var found *AttackPath
	if src != nil {
		p := *src
		found = &p
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

// attackPathAnalysis is the response shape for GET /api/v1/attack-paths/{id}/analysis.
type attackPathAnalysis struct {
	Analysis         string            `json:"analysis"`
	RemediationSteps []string          `json:"remediation_steps"`
	RiskFactors      []string          `json:"risk_factors"`
	BlastRadius      blastRadiusDetail `json:"blast_radius"`
}

type blastRadiusDetail struct {
	Direct   int `json:"direct"`
	Indirect int `json:"indirect"`
	Total    int `json:"total"`
}

// getAttackPathAnalysis returns AI-enriched analysis for a single attack path.
// When graphClient is configured, it queries PuppyGraph for connected resources
// to build richer context. Otherwise it returns mock analysis data.
func (s *Server) getAttackPathAnalysis(w http.ResponseWriter, r *http.Request) {
	ctx, span := otel.Tracer("aegis.api").Start(r.Context(), "handler.getAttackPathAnalysis")
	defer span.End()

	id := mux.Vars(r)["id"]
	span.SetAttributes(attribute.String("attack_path.id", id))

	// Verify the attack path exists and is in scope.
	s.attackPathSvc.Mu.RLock()
	src := s.attackPathSvc.PathsByID[id]
	var path *AttackPath
	if src != nil {
		p := *src
		path = &p
	}
	s.attackPathSvc.Mu.RUnlock()

	if path == nil {
		writeErrorResponse(w, "attack path not found", http.StatusNotFound)
		return
	}

	claims, _ := api.GetClaimsFromContext(ctx)
	scope := api.ScopeFromContext(claims)
	if scope != nil && !attackPathInScope(scope, path) {
		writeErrorResponse(w, "attack path not found", http.StatusNotFound)
		return
	}

	// Build analysis -- use graph context when PuppyGraph is available,
	// otherwise return mock analysis seeded from path metadata.
	analysis := s.buildAttackPathAnalysis(ctx, path)

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(analysis); err != nil {
		s.logger.Warn("encoding attack path analysis", zap.Error(err))
	}
}

// buildAttackPathAnalysis constructs the analysis response.
// When graphClient is non-nil, it queries for connected resources to enrich
// the blast radius. When nil, it derives data from the path's node/edge metadata.
func (s *Server) buildAttackPathAnalysis(ctx context.Context, path *AttackPath) attackPathAnalysis {
	direct := len(path.Nodes)
	indirect := direct * 2 // heuristic: 2x connected resources per node
	if indirect > 50 {
		indirect = 50
	}

	// If PuppyGraph is available and ID is safe, query for real connected resource counts.
	// Safe: path.ID is validated by safeGraphID (alphanumeric, hyphens, underscores only),
	// preventing Gremlin injection in the string concatenation below.
	if s.graphClient != nil && safeGraphID.MatchString(path.ID) {
		query := "g.V().has('id', '" + path.ID + "').both().both().dedup().count()"
		result, err := s.graphClient.Query(ctx, graph.QueryRequest{
			Language: "gremlin",
			Query:    query,
		})
		if err != nil {
			s.logger.Warn("graph query for blast radius failed, using heuristic",
				zap.String("path_id", path.ID),
				zap.Error(err),
			)
		} else {
			var count int
			if err := json.Unmarshal(result.Data, &count); err == nil && count > 0 {
				indirect = count - direct
				if indirect < 0 {
					indirect = 0
				}
			}
		}
	}

	// Build severity-aware analysis text from path metadata.
	analysisText := "This " + path.Severity + "-severity attack path spans " +
		strconv.Itoa(len(path.Nodes)) + " resources across " +
		strconv.Itoa(len(path.Edges)) + " lateral movement steps. "
	if len(path.Nodes) > 0 {
		entry := path.Nodes[0]
		analysisText += "The entry point is a " + entry.ResourceType +
			" resource (" + entry.Provider + "/" + entry.Region + "). "
	}
	if len(path.Nodes) > 1 {
		target := path.Nodes[len(path.Nodes)-1]
		analysisText += "The target is a " + target.ResourceType +
			" resource that could be compromised through privilege escalation or lateral movement."
	}

	return attackPathAnalysis{
		Analysis: analysisText,
		RemediationSteps: []string{
			"Restrict network segmentation between entry-point and target resources",
			"Apply least-privilege IAM policies to reduce lateral movement surface",
			"Enable GuardDuty or equivalent runtime threat detection on affected accounts",
			"Rotate credentials for identities with cross-account access in this path",
		},
		RiskFactors: []string{
			"Path traverses " + strconv.Itoa(len(path.Nodes)) + " resources with escalation potential",
			"Entry point has public-facing exposure",
			path.Severity + " severity indicates high exploitability",
		},
		BlastRadius: blastRadiusDetail{
			Direct:   direct,
			Indirect: indirect,
			Total:    direct + indirect,
		},
	}
}

// safeGraphID allows only alphanumeric characters, hyphens, and underscores in graph IDs.
var safeGraphID = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

func (svc *AttackPathService) getAttackPathStats(w http.ResponseWriter, r *http.Request) {
	_, span := otel.Tracer("aegis.api").Start(r.Context(), "handler.getAttackPathStats")
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
		ByProvider: make(map[string]int),
	}
	scopedFindingIDs := make(map[string]bool)
	for i := range svc.Paths {
		if !attackPathInScope(scope, &svc.Paths[i]) {
			continue
		}
		scoped.TotalPaths++
		switch svc.Paths[i].Severity {
		case "CRITICAL": //nolint:goconst // severity literals used across package as domain values
			scoped.CriticalPaths++
		case "HIGH":
			scoped.HighPaths++
		default:
			scoped.MediumPaths++
		}
		if len(svc.Paths[i].Nodes) > 0 {
			scoped.ByProvider[svc.Paths[i].Nodes[0].Provider]++
		}
		for _, fid := range svc.Paths[i].FindingIDs {
			scopedFindingIDs[fid] = true
		}
	}
	// Compute scoped finding-level stats from filtered paths
	scoped.FindingsInPaths = len(scopedFindingIDs)
	// TotalFindings for scope = findings in paths + isolated (approximate: use global ratio)
	if svc.Stats.TotalFindings > 0 && svc.Stats.FindingsInPaths > 0 {
		ratio := float64(svc.Stats.TotalFindings) / float64(svc.Stats.FindingsInPaths)
		scoped.TotalFindings = int(float64(scoped.FindingsInPaths) * ratio)
	}
	scoped.IsolatedFindings = scoped.TotalFindings - scoped.FindingsInPaths
	if scoped.IsolatedFindings < 0 {
		scoped.IsolatedFindings = 0
	}
	if scoped.TotalFindings > 0 {
		scoped.CoveragePercent = float64(scoped.FindingsInPaths) / float64(scoped.TotalFindings) * 100
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(scoped)
}
