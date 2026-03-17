package main

import (
	"encoding/json"
	"net/http"
	"strings"

	"cloudforge/internal/ai"
)

// NLQRequest is the request body for the NLQ endpoint.
type NLQRequest struct {
	Query string `json:"query"`
}

// NLQResponse is the structured filter response from NLQ parsing.
type NLQResponse struct {
	Severity    []string `json:"severity,omitempty"`
	Provider    []string `json:"provider,omitempty"`
	Category    []string `json:"category,omitempty"`
	Status      []string `json:"status,omitempty"`
	Environment []string `json:"environment,omitempty"`
	Text        string   `json:"text,omitempty"`
}

const nlqSystemPrompt = `You are a security query parser. Convert the user's natural language query into a structured JSON filter for a CSPM findings dashboard.

Return ONLY valid JSON with these optional fields:
- "severity": array of "CRITICAL", "HIGH", "MEDIUM", "LOW"
- "provider": array of "aws", "azure", "gcp"
- "category": array of "VULNERABILITY", "MISCONFIGURATION", "DATA_PROTECTION", "IDENTITY", "NETWORK"
- "status": array of "open", "in_progress", "resolved"
- "environment": array of "production", "staging", "development", "sandbox"
- "text": free text search term if nothing else matches

Examples:
- "critical AWS misconfigs" -> {"severity":["CRITICAL"],"provider":["aws"],"category":["MISCONFIGURATION"]}
- "all open high vulns in prod" -> {"severity":["HIGH"],"category":["VULNERABILITY"],"status":["open"],"environment":["production"]}
- "S3 bucket" -> {"text":"S3 bucket"}

Only include fields that are clearly specified. Return {} for ambiguous queries.`

func (s *Server) queryNLQ(w http.ResponseWriter, r *http.Request) {
	if s.enrichmentSvc == nil || s.enrichmentSvc.AI == nil {
		http.Error(w, `{"error":"AI provider not configured"}`, http.StatusServiceUnavailable)
		return
	}

	var req NLQRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}

	query := strings.TrimSpace(req.Query)
	if query == "" {
		http.Error(w, `{"error":"query is required"}`, http.StatusBadRequest)
		return
	}
	if len(query) > 500 {
		http.Error(w, `{"error":"query too long (max 500 chars)"}`, http.StatusBadRequest)
		return
	}

	// Use TierFast for NLQ parsing — cost-optimized
	var result string
	var err error
	if rp, ok := s.enrichmentSvc.AI.(*ai.RoutingProvider); ok {
		result, err = rp.CompleteWithTier(r.Context(), ai.TierFast, nlqSystemPrompt, query)
	} else {
		result, err = s.enrichmentSvc.AI.CompleteWithSystem(r.Context(), nlqSystemPrompt, query)
	}

	if err != nil {
		// Fallback: return query as text search
		resp := NLQResponse{Text: query}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
		return
	}

	// Parse AI response into structured filter
	var resp NLQResponse
	if err := json.Unmarshal([]byte(result), &resp); err != nil {
		// AI returned unparseable output — fall back to text search
		resp = NLQResponse{Text: query}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}
