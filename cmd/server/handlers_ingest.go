package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"aegis/internal/ingestion"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
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
	ctx, span := otel.Tracer("aegis.api").Start(r.Context(), "handler.ingestFinding")
	defer span.End()
	r = r.WithContext(ctx)

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

	span.SetAttributes(
		attribute.String("finding.id", findingID),
		attribute.String("finding.source", req.Source),
		attribute.String("finding.dedup_key", key),
	)
	s.logger.Info("finding ingested",
		zap.String("finding_id", findingID),
		zap.String("source", req.Source),
		zap.String("dedup_key", key),
	)
	s.logAuditEvent(r, "finding.ingest", "finding", findingID, "accepted")

	if s.secgraphSync != nil {
		syncCtx, syncCancel := context.WithTimeout(ctx, 5*time.Second)
		if err := s.secgraphSync(syncCtx, req.toFinding(findingID, time.Now().UTC())); err != nil {
			s.logger.Warn("incremental secgraph sync failed after finding ingest",
				zap.String("finding_id", findingID),
				zap.Error(err),
			)
		}
		syncCancel()
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(ingestResponse{
		Status:    "accepted",
		FindingID: findingID,
		DedupKey:  key,
	})
}

func (r ingestRequest) toFinding(findingID string, now time.Time) Finding {
	return Finding{
		ID:              findingID,
		Source:          r.Source,
		SourceFindingID: r.SourceFindingID,
		Type:            strings.TrimSpace(r.FindingType),
		Title:           r.Title,
		Description:     r.Description,
		ResourceType:    inferIngestResourceType(r.ResourceID),
		ResourceID:      r.ResourceID,
		ResourceName:    r.ResourceID,
		CloudProvider:   inferIngestCloudProvider(r.Source, r.ResourceID),
		AccountID:       r.AccountID,
		StaticSeverity:  strings.ToUpper(strings.TrimSpace(r.Severity)),
		Severity:        strings.ToUpper(strings.TrimSpace(r.Severity)),
		Category:        inferIngestCategory(r.FindingType, r.Title),
		Status:          "open",
		FirstFoundAt:    now.Format(time.RFC3339),
	}
}

func inferIngestCloudProvider(source, resourceID string) string {
	lower := strings.ToLower(strings.TrimSpace(source + " " + resourceID))
	switch {
	case strings.Contains(lower, "aws"), strings.Contains(strings.ToLower(resourceID), "arn:aws:"):
		return "aws"
	case strings.Contains(lower, "azure"), strings.Contains(lower, "/subscriptions/"):
		return "azure"
	case strings.Contains(lower, "gcp"), strings.Contains(lower, "projects/"):
		return "gcp"
	default:
		return ""
	}
}

func inferIngestResourceType(resourceID string) string {
	lower := strings.ToLower(strings.TrimSpace(resourceID))
	switch {
	case strings.Contains(lower, ":s3:"), strings.Contains(lower, "bucket"):
		return "storage"
	case strings.Contains(lower, ":rds:"), strings.Contains(lower, ":db:"), strings.Contains(lower, "database"):
		return "database"
	case strings.Contains(lower, ":iam:"), strings.Contains(lower, "role"), strings.Contains(lower, "user"):
		return "identity"
	case strings.Contains(lower, ":ec2:"), strings.Contains(lower, "instance"):
		return "compute"
	case strings.Contains(lower, ":lambda:"), strings.Contains(lower, "function"):
		return "serverless"
	case strings.Contains(lower, ":ecr:"), strings.Contains(lower, "image"), strings.Contains(lower, "container"):
		return "container"
	default:
		return "other"
	}
}

func inferIngestCategory(findingType, title string) string {
	lower := strings.ToLower(strings.TrimSpace(findingType + " " + title))
	switch {
	case strings.Contains(lower, "cve"), strings.Contains(lower, "vuln"):
		return "VULNERABILITY"
	case strings.Contains(lower, "iam"), strings.Contains(lower, "role"), strings.Contains(lower, "credential"):
		return "IDENTITY"
	case strings.Contains(lower, "public"), strings.Contains(lower, "network"), strings.Contains(lower, "exposed"):
		return "NETWORK"
	case strings.Contains(lower, "compliance"):
		return "COMPLIANCE"
	default:
		return "MISCONFIGURATION"
	}
}
