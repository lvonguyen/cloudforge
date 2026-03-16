package main

import (
	"encoding/json"
	"fmt"
	"net/http"

	"cloudforge/internal/ingestion"

	"go.uber.org/zap"
)

// ingestRequest represents a finding submitted via the ingest endpoint.
type ingestRequest struct {
	Source          string `json:"source"`
	SourceFindingID string `json:"source_finding_id"`
	ResourceID      string `json:"resource_id"`
	AccountID       string `json:"account_id"`
	Severity        string `json:"severity"`
	FindingType     string `json:"finding_type"`
	Title           string `json:"title"`
	Description     string `json:"description"`
}

// ingestResponse confirms acceptance or duplicate detection.
type ingestResponse struct {
	Status    string                `json:"status"`
	FindingID string                `json:"finding_id"`
	DedupKey  string                `json:"dedup_key"`
	Entry     *ingestion.DedupEntry `json:"existing_entry,omitempty"`
}

// ingestFinding handles POST /api/v1/findings/ingest (admin-only).
// It deduplicates incoming findings by generating a SHA-256 key from
// the canonical identity fields (source, source_finding_id, resource_id, account_id).
func (s *Server) ingestFinding(w http.ResponseWriter, r *http.Request) {
	if r.Body == nil || r.Body == http.NoBody {
		writeErrorResponse(w, "request body is required", http.StatusBadRequest)
		return
	}

	var req ingestRequest
	if !s.decodeJSONBody(w, r, &req) {
		return
	}

	if req.Source == "" || req.SourceFindingID == "" || req.ResourceID == "" || req.AccountID == "" {
		writeErrorResponse(w, "source, source_finding_id, resource_id, and account_id are required", http.StatusBadRequest)
		return
	}

	// Validate enum fields
	switch req.Severity {
	case "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO":
		// valid
	default:
		writeErrorResponse(w, "severity must be one of: CRITICAL, HIGH, MEDIUM, LOW, INFO", http.StatusBadRequest)
		return
	}

	key := ingestion.GenerateDedupKey(req.Source, req.SourceFindingID, req.ResourceID, req.AccountID)
	findingID := fmt.Sprintf("ING-%s", key[:12])

	isDuplicate, entry := s.dedupCache.CheckOrInsert(key, findingID)

	if isDuplicate {
		s.logger.Info("duplicate finding rejected",
			zap.String("dedup_key", key),
			zap.String("existing_finding_id", entry.FindingID),
		)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(ingestResponse{
			Status:    "duplicate",
			FindingID: entry.FindingID,
			DedupKey:  key,
			Entry:     &entry,
		})
		return
	}

	s.logger.Info("finding ingested",
		zap.String("finding_id", findingID),
		zap.String("source", req.Source),
		zap.String("dedup_key", key),
	)
	s.logAuditEvent(r, "finding.ingest", "finding", findingID, "accepted")

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(ingestResponse{
		Status:    "accepted",
		FindingID: findingID,
		DedupKey:  key,
	})
}
