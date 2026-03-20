package main

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"aegis/internal/ai"
	"aegis/internal/cspm/threatintel"

	"go.uber.org/zap"
	"golang.org/x/sync/singleflight"
)

// FindingEnrichment holds cached AI analysis and threat intel for a single finding.
type FindingEnrichment struct {
	FindingID       string                             `json:"finding_id"`
	RootCause       string                             `json:"root_cause"`
	Impact          string                             `json:"impact"`
	Remediation     string                             `json:"remediation"`
	RelatedControls []string                           `json:"related_controls"`
	ThreatIntel     *threatintel.ThreatIntelEnrichment `json:"threat_intel,omitempty"`
	EnrichedAt      string                             `json:"enriched_at"`
	CreatedAt       time.Time                          `json:"-"` // cache eviction timestamp
}

const findingEnrichSystemPrompt = `You are a cloud security analyst. Given a security finding, provide:
1. Root cause analysis
2. Business impact assessment
3. Step-by-step remediation
4. Related CIS/NIST controls

Respond ONLY with valid JSON matching this schema:
{"root_cause":"...","impact":"...","remediation":"...","related_controls":["CIS x.y","NIST SC-z"]}`

func parseFindingEnrichment(findingID, response string) (*FindingEnrichment, error) {
	type aiResponse struct {
		RootCause       string   `json:"root_cause"`
		Impact          string   `json:"impact"`
		Remediation     string   `json:"remediation"`
		RelatedControls []string `json:"related_controls"`
	}

	var parsed aiResponse

	// Try direct parse
	if err := json.Unmarshal([]byte(response), &parsed); err != nil {
		// Extract JSON from surrounding text
		start := strings.Index(response, "{")
		end := strings.LastIndex(response, "}")
		if start == -1 || end == -1 || end <= start {
			return nil, fmt.Errorf("no JSON in response")
		}
		if err := json.Unmarshal([]byte(response[start:end+1]), &parsed); err != nil {
			return nil, fmt.Errorf("parsing extracted JSON: %w", err)
		}
	}

	if parsed.RootCause == "" {
		return nil, fmt.Errorf("missing root_cause in response")
	}

	now := time.Now().UTC()
	return &FindingEnrichment{
		FindingID:       findingID,
		RootCause:       parsed.RootCause,
		Impact:          parsed.Impact,
		Remediation:     parsed.Remediation,
		RelatedControls: parsed.RelatedControls,
		EnrichedAt:      now.Format(time.RFC3339),
		CreatedAt:       now,
	}, nil
}

const (
	// enrichmentCacheTTL is how long enrichment results are cached.
	enrichmentCacheTTL = 30 * time.Minute
	// enrichmentCacheMaxSize caps the number of cached enrichments to bound memory.
	enrichmentCacheMaxSize = 5000
)

// EnrichmentService encapsulates AI-powered finding enrichment with a
// thread-safe cache. Extracted from Server to isolate the AI provider,
// cache map, and mutex into a cohesive unit.
type EnrichmentService struct {
	AI          ai.Provider
	ThreatIntel *threatintel.Enricher // nil = threat intel disabled
	Cache       map[string]*FindingEnrichment
	Mu          sync.RWMutex
	Logger      *zap.Logger
	group       singleflight.Group
}

// Enabled returns true when AI or threat intel enrichment is available.
func (svc *EnrichmentService) Enabled() bool {
	return svc.AI != nil || svc.ThreatIntel != nil
}

// GetCached returns a cached enrichment if available and not expired.
func (svc *EnrichmentService) GetCached(id string) (*FindingEnrichment, bool) {
	svc.Mu.RLock()
	defer svc.Mu.RUnlock()
	cached, ok := svc.Cache[id]
	if ok && time.Since(cached.CreatedAt) >= enrichmentCacheTTL {
		return nil, false
	}
	return cached, ok
}

// Enrich calls AI and/or threat intel providers to analyze a finding, caching the result.
// Returns the cached result if already enriched. Concurrent calls for the
// same finding ID are deduplicated via singleflight.
func (svc *EnrichmentService) Enrich(ctx context.Context, finding *Finding) (*FindingEnrichment, error) {
	// Check cache first
	if cached, ok := svc.GetCached(finding.ID); ok {
		return cached, nil
	}

	if svc.AI == nil && svc.ThreatIntel == nil {
		return nil, fmt.Errorf("enrichment is not enabled (no AI provider or threat intel)")
	}

	// Deduplicate concurrent requests for the same finding
	result, err, _ := svc.group.Do(finding.ID, func() (interface{}, error) {
		// Re-check cache inside singleflight (another caller may have populated it)
		if cached, ok := svc.GetCached(finding.ID); ok {
			return cached, nil
		}

		now := time.Now().UTC()
		enrichment := &FindingEnrichment{
			FindingID:  finding.ID,
			EnrichedAt: now.Format(time.RFC3339),
			CreatedAt:  now,
		}

		// AI enrichment (optional — skipped when AI provider is nil)
		if svc.AI != nil {
			callCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
			defer cancel()

			prompt := fmt.Sprintf(`Finding: %s
Severity: %s | Category: %s | Provider: %s
Resource: %s (%s) in %s
Status: %s
Description: %s`,
				finding.Title,
				finding.Severity, finding.Category, finding.CloudProvider,
				finding.ResourceName, finding.ResourceType, finding.Region,
				finding.Status,
				finding.Remediation,
			)

			response, err := svc.AI.CompleteWithSystem(callCtx, findingEnrichSystemPrompt, prompt)
			if err != nil {
				svc.Logger.Warn("AI enrichment failed, continuing with threat intel only",
					zap.String("finding_id", finding.ID), zap.Error(err))
			} else {
				parsed, err := parseFindingEnrichment(finding.ID, response)
				if err != nil {
					svc.Logger.Warn("parsing AI response failed",
						zap.String("finding_id", finding.ID), zap.Error(err))
				} else {
					enrichment.RootCause = parsed.RootCause
					enrichment.Impact = parsed.Impact
					enrichment.Remediation = parsed.Remediation
					enrichment.RelatedControls = parsed.RelatedControls
				}
			}
		}

		// Threat intel enrichment (optional — skipped when enricher is nil)
		if svc.ThreatIntel != nil {
			cves := make([]string, 0, len(finding.CVEs))
			for _, cve := range finding.CVEs {
				cves = append(cves, cve.ID)
			}
			enrichment.ThreatIntel = svc.ThreatIntel.Enrich(ctx, cves, nil, nil)
		}

		// Cache the result
		svc.Mu.Lock()
		svc.Cache[finding.ID] = enrichment
		svc.Mu.Unlock()

		return enrichment, nil
	})

	if err != nil {
		return nil, err
	}
	return result.(*FindingEnrichment), nil
}

// StartEviction launches a background goroutine that periodically removes
// stale enrichment cache entries (older than enrichmentCacheTTL) and evicts
// oldest entries when the cache exceeds enrichmentCacheMaxSize.
func (svc *EnrichmentService) StartEviction(ctx context.Context, interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				svc.evictExpired()
			}
		}
	}()
}

func (svc *EnrichmentService) evictExpired() {
	svc.Mu.Lock()
	defer svc.Mu.Unlock()

	now := time.Now()

	// Pass 1: remove entries older than TTL
	for key, entry := range svc.Cache {
		if now.Sub(entry.CreatedAt) >= enrichmentCacheTTL {
			delete(svc.Cache, key)
		}
	}

	// Pass 2: if still over max size, evict oldest until at cap
	if len(svc.Cache) > enrichmentCacheMaxSize {
		type kv struct {
			key string
			ts  time.Time
		}
		items := make([]kv, 0, len(svc.Cache))
		for k, v := range svc.Cache {
			items = append(items, kv{k, v.CreatedAt})
		}
		sort.Slice(items, func(i, j int) bool { return items[i].ts.Before(items[j].ts) })
		excess := len(svc.Cache) - enrichmentCacheMaxSize
		for i := 0; i < excess; i++ {
			delete(svc.Cache, items[i].key)
		}
	}
}
