package ai

import (
	"context"
	"fmt"
	"sync/atomic"
)

// ModelTier represents a routing tier controlling cost vs quality tradeoffs.
type ModelTier int

const (
	// TierFast routes to cost-optimized Sonnet models (~80% of calls).
	TierFast ModelTier = iota
	// TierPremium routes to high-quality Opus models for complex analysis.
	TierPremium
	// TierLocal routes to air-gapped/offline local models (LM Studio, Ollama).
	TierLocal
)

// tierUsage tracks per-tier call counts and estimated token usage.
type tierUsage struct {
	callCount     atomic.Int64
	tokenEstimate atomic.Int64
}

// UsageStats is a snapshot of per-tier usage for cost estimation.
type UsageStats struct {
	Tier          ModelTier
	CallCount     int64
	TokenEstimate int64
}

// RoutingProvider implements Provider with tier-based model selection and a fallback chain.
type RoutingProvider struct {
	tiers         map[ModelTier]Provider
	defaultTier   ModelTier
	fallbackChain []Provider
	usage         map[ModelTier]*tierUsage
}

// NewRoutingProvider constructs a RoutingProvider.
// tiers maps each ModelTier to its primary provider.
// defaultTier is used for calls to Complete/CompleteWithSystem.
// fallbackChain is tried in order when the tier's primary provider fails.
func NewRoutingProvider(tiers map[ModelTier]Provider, defaultTier ModelTier, fallbackChain []Provider) *RoutingProvider {
	usage := make(map[ModelTier]*tierUsage, len(tiers))
	for t := range tiers {
		usage[t] = &tierUsage{}
	}
	return &RoutingProvider{
		tiers:         tiers,
		defaultTier:   defaultTier,
		fallbackChain: fallbackChain,
		usage:         usage,
	}
}

// CompleteWithTier routes to the provider for the given tier, falling back on failure.
func (r *RoutingProvider) CompleteWithTier(ctx context.Context, tier ModelTier, systemPrompt, userPrompt string) (string, error) {
	primary, ok := r.tiers[tier]
	if ok {
		result, err := primary.CompleteWithSystem(ctx, systemPrompt, userPrompt)
		if err == nil {
			r.recordUsage(tier, userPrompt)
			return result, nil
		}
	}

	// Attempt fallback chain.
	for _, fb := range r.fallbackChain {
		result, err := fb.CompleteWithSystem(ctx, systemPrompt, userPrompt)
		if err == nil {
			r.recordUsage(tier, userPrompt)
			return result, nil
		}
	}

	return "", fmt.Errorf("all providers failed for tier %d (and %d fallbacks exhausted)", tier, len(r.fallbackChain))
}

// Complete satisfies Provider using the defaultTier.
func (r *RoutingProvider) Complete(ctx context.Context, prompt string) (string, error) {
	return r.CompleteWithTier(ctx, r.defaultTier, "", prompt)
}

// CompleteWithSystem satisfies Provider using the defaultTier.
func (r *RoutingProvider) CompleteWithSystem(ctx context.Context, systemPrompt, userPrompt string) (string, error) {
	return r.CompleteWithTier(ctx, r.defaultTier, systemPrompt, userPrompt)
}

// GetUsageStats returns a snapshot of per-tier call counts and token estimates.
func (r *RoutingProvider) GetUsageStats() []UsageStats {
	stats := make([]UsageStats, 0, len(r.usage))
	for tier, u := range r.usage {
		stats = append(stats, UsageStats{
			Tier:          tier,
			CallCount:     u.callCount.Load(),
			TokenEstimate: u.tokenEstimate.Load(),
		})
	}
	return stats
}

// recordUsage increments counters for the given tier.
// Token estimate: rough heuristic of 4 chars per token for user prompt.
func (r *RoutingProvider) recordUsage(tier ModelTier, userPrompt string) {
	u, ok := r.usage[tier]
	if !ok {
		return
	}
	u.callCount.Add(1)
	u.tokenEstimate.Add(int64(len(userPrompt) / 4))
}
