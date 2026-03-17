package ai

import (
	"context"
	"errors"
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

// ErrBudgetExhausted is returned when the monthly cost budget has been reached.
var ErrBudgetExhausted = errors.New("monthly AI cost budget exhausted")

// Per-tier cost rates in microdollars per token (input).
// Output tokens cost ~5x input; we estimate output as 3x input tokens for budgeting.
var tierCostMicrodollars = map[ModelTier]int64{
	TierFast:    3,  // Sonnet 4.6: ~$3/MTok input
	TierPremium: 15, // Opus 4.6: ~$15/MTok input
	TierLocal:   0,  // Local models: free
}

// tierUsage tracks per-tier call counts and estimated cost.
type tierUsage struct {
	callCount     atomic.Int64
	tokenEstimate atomic.Int64
	costMicros    atomic.Int64 // accumulated cost in microdollars
}

// UsageStats is a snapshot of per-tier usage for cost estimation.
type UsageStats struct {
	Tier          ModelTier `json:"tier"`
	CallCount     int64     `json:"call_count"`
	TokenEstimate int64     `json:"token_estimate"`
	CostCents     int64     `json:"cost_cents"`
}

// BudgetStatus reports current spend vs budget.
type BudgetStatus struct {
	MonthlyBudgetCents int64        `json:"monthly_budget_cents"`
	SpentCents         int64        `json:"spent_cents"`
	RemainingCents     int64        `json:"remaining_cents"`
	Exhausted          bool         `json:"exhausted"`
	Tiers              []UsageStats `json:"tiers"`
}

// RoutingProvider implements Provider with tier-based model selection, a fallback chain,
// and a monthly cost budget guard.
type RoutingProvider struct {
	tiers              map[ModelTier]Provider
	defaultTier        ModelTier
	fallbackChain      []Provider
	usage              map[ModelTier]*tierUsage
	monthlyBudgetCents int64 // 0 = unlimited
}

// RoutingOption configures a RoutingProvider.
type RoutingOption func(*RoutingProvider)

// WithMonthlyBudget sets the monthly cost cap in cents (e.g., 1500 = $15.00).
func WithMonthlyBudget(cents int64) RoutingOption {
	return func(r *RoutingProvider) {
		r.monthlyBudgetCents = cents
	}
}

// NewRoutingProvider constructs a RoutingProvider.
// tiers maps each ModelTier to its primary provider.
// defaultTier is used for calls to Complete/CompleteWithSystem.
// fallbackChain is tried in order when the tier's primary provider fails.
func NewRoutingProvider(tiers map[ModelTier]Provider, defaultTier ModelTier, fallbackChain []Provider, opts ...RoutingOption) *RoutingProvider {
	usage := make(map[ModelTier]*tierUsage, len(tiers))
	for t := range tiers {
		usage[t] = &tierUsage{}
	}
	r := &RoutingProvider{
		tiers:         tiers,
		defaultTier:   defaultTier,
		fallbackChain: fallbackChain,
		usage:         usage,
	}
	for _, opt := range opts {
		opt(r)
	}
	return r
}

// CompleteWithTier routes to the provider for the given tier, falling back on failure.
// Returns ErrBudgetExhausted if the monthly budget has been reached.
func (r *RoutingProvider) CompleteWithTier(ctx context.Context, tier ModelTier, systemPrompt, userPrompt string) (string, error) {
	if r.monthlyBudgetCents > 0 && r.totalSpentCents() >= r.monthlyBudgetCents {
		return "", ErrBudgetExhausted
	}

	primary, ok := r.tiers[tier]
	if ok {
		result, err := primary.CompleteWithSystem(ctx, systemPrompt, userPrompt)
		if err == nil {
			r.recordUsage(tier, userPrompt, result)
			return result, nil
		}
	}

	// Attempt fallback chain.
	for _, fb := range r.fallbackChain {
		result, err := fb.CompleteWithSystem(ctx, systemPrompt, userPrompt)
		if err == nil {
			r.recordUsage(tier, userPrompt, result)
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

// GetUsageStats returns a snapshot of per-tier call counts and cost estimates.
func (r *RoutingProvider) GetUsageStats() []UsageStats {
	stats := make([]UsageStats, 0, len(r.usage))
	for tier, u := range r.usage {
		stats = append(stats, UsageStats{
			Tier:          tier,
			CallCount:     u.callCount.Load(),
			TokenEstimate: u.tokenEstimate.Load(),
			CostCents:     u.costMicros.Load() / 10_000,
		})
	}
	return stats
}

// GetBudgetStatus returns current spend vs budget for the /api/v1/ai/usage endpoint.
func (r *RoutingProvider) GetBudgetStatus() BudgetStatus {
	spent := r.totalSpentCents()
	budget := r.monthlyBudgetCents
	remaining := budget - spent
	if remaining < 0 {
		remaining = 0
	}
	return BudgetStatus{
		MonthlyBudgetCents: budget,
		SpentCents:         spent,
		RemainingCents:     remaining,
		Exhausted:          budget > 0 && spent >= budget,
		Tiers:              r.GetUsageStats(),
	}
}

// totalSpentCents returns accumulated cost across all tiers in cents.
// Sums raw microdollar values first, then divides once to avoid per-tier truncation.
func (r *RoutingProvider) totalSpentCents() int64 {
	var totalMicros int64
	for _, u := range r.usage {
		totalMicros += u.costMicros.Load()
	}
	return totalMicros / 10_000
}

// recordUsage increments counters and estimates cost for the given tier.
// Token estimate: ~4 chars per token. Cost: input + output (output estimated as 3x input length).
func (r *RoutingProvider) recordUsage(tier ModelTier, userPrompt, response string) {
	u, ok := r.usage[tier]
	if !ok {
		return
	}
	inputTokens := int64(len(userPrompt) / 4)
	outputTokens := int64(len(response) / 4)
	u.callCount.Add(1)
	u.tokenEstimate.Add(inputTokens + outputTokens)

	// Estimate cost in microdollars
	rate := tierCostMicrodollars[tier]
	// Input cost + output cost (output is ~5x input rate)
	costMicros := inputTokens*rate + outputTokens*rate*5
	u.costMicros.Add(costMicros)
}
