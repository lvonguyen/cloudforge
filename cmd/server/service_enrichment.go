package main

import (
	"context"
	"fmt"
	"sync"
	"time"

	"cloudforge/internal/ai"

	"go.uber.org/zap"
	"golang.org/x/sync/singleflight"
)

// EnrichmentService encapsulates AI-powered finding enrichment with a
// thread-safe cache. Extracted from Server to isolate the AI provider,
// cache map, and mutex into a cohesive unit.
type EnrichmentService struct {
	AI     ai.Provider
	Cache  map[string]*FindingEnrichment
	Mu     sync.Mutex
	Logger *zap.Logger
	group  singleflight.Group
}

// Enabled returns true when an AI provider is configured.
func (svc *EnrichmentService) Enabled() bool {
	return svc.AI != nil
}

// GetCached returns a cached enrichment if available.
func (svc *EnrichmentService) GetCached(id string) (*FindingEnrichment, bool) {
	svc.Mu.Lock()
	defer svc.Mu.Unlock()
	cached, ok := svc.Cache[id]
	return cached, ok
}

// Enrich calls the AI provider to analyze a finding, caching the result.
// Returns the cached result if already enriched. Concurrent calls for the
// same finding ID are deduplicated via singleflight.
func (svc *EnrichmentService) Enrich(ctx context.Context, finding *Finding) (*FindingEnrichment, error) {
	// Check cache first
	if cached, ok := svc.GetCached(finding.ID); ok {
		return cached, nil
	}

	if svc.AI == nil {
		return nil, fmt.Errorf("AI enrichment is not enabled")
	}

	// Deduplicate concurrent requests for the same finding
	result, err, _ := svc.group.Do(finding.ID, func() (interface{}, error) {
		// Re-check cache inside singleflight (another caller may have populated it)
		if cached, ok := svc.GetCached(finding.ID); ok {
			return cached, nil
		}

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
			return nil, fmt.Errorf("AI call failed: %w", err)
		}

		enrichment, err := parseFindingEnrichment(finding.ID, response)
		if err != nil {
			return nil, fmt.Errorf("parsing AI response: %w", err)
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
