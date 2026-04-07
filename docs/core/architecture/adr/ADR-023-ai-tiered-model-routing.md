# ADR-023: AI Tiered Model Routing

**Status:** Accepted
**Date:** 2026-04-06
**Deciders:** Liem Vo-Nguyen
**Supersedes:** None
**Extends:** ADR-004 (AI Provider Selection)

## Context

CloudForge integrates AI across multiple features — attack path narrative generation, natural language queries (NLQ), compliance analysis, toxic combination explanation, and remediation guidance. These features vary dramatically in their quality requirements, latency tolerance, and data sensitivity:

| Feature | Quality Need | Latency Target | Sensitivity |
|---------|-------------|----------------|-------------|
| Attack path AI narrative | High (reasoning chains) | <10s (async) | Contains finding details |
| NLQ-to-SQL translation | High (correctness critical) | <5s (interactive) | Contains schema, no findings |
| Compliance gap analysis | Medium (summaries) | <15s (batch) | Framework metadata only |
| Remediation suggestions | Medium | <8s (interactive) | Generic cloud patterns |
| Toxic combo explanation | High (security reasoning) | <10s (async) | Contains finding combinations |

Without routing, all calls go to a single provider (originally Anthropic Claude direct API). This creates three problems:

1. **Cost:** Opus-quality models at $15/MTok input are unnecessary for simple summarization tasks that Sonnet handles equally well at $3/MTok.
2. **Availability:** A single provider outage blocks all AI features. No degradation path.
3. **Sensitivity:** Some enterprise deployments (HAEA) require air-gapped inference for data containing finding details, IAM configurations, or account identifiers — cloud API calls are prohibited for these workloads.

## Decision

Implement a **three-tier routing provider** (`RoutingProvider`) that wraps the existing `Provider` interface, adding tier selection, a fallback chain, and a monthly cost budget guard.

## Implementation Status

As of 2026-04-06, this ADR is **accepted and partially wired**:

- `internal/ai/router.go`, `internal/ai/config.go`, and tier-aware handler call sites exist
- `cmd/server/handlers_nlq.go` and attack-path enrichment can use `RoutingProvider` when one is supplied
- the default server bootstrap still initializes a single provider via `initAIProvider`, so tiered routing is not yet the runtime default

Treat this ADR as the accepted routing design plus supporting implementation pieces, not as proof that all live AI calls already flow through the tiered router.

### Tier Definitions

| Tier | Constant | Models | Cost | Use Case |
|------|----------|--------|------|----------|
| **Fast** | `TierFast` | Sonnet 4.6, GPT-4o-mini | ~$3/MTok | ~80% of calls: summaries, formatting, simple analysis |
| **Premium** | `TierPremium` | Opus 4.6, GPT-4o | ~$15/MTok | ~15% of calls: reasoning chains, NLQ, toxic combos |
| **Local** | `TierLocal` | Qwen-32B (LM Studio), Ollama | $0 | ~5% of calls: air-gapped, sensitive data, offline |

Callers select a tier via `CompleteWithTier(ctx, tier, system, user)`. The default tier (for `Complete`/`CompleteWithSystem` calls that don't specify) is `TierFast`.

### Provider Registration

Providers are registered by name in YAML configuration (`configs/ai.yaml`):

```yaml
default_tier: fast
providers:
  anthropic-sonnet:
    type: anthropic
    api_key_env_var: ANTHROPIC_API_KEY
    model: claude-sonnet-4-6
  anthropic-opus:
    type: anthropic
    api_key_env_var: ANTHROPIC_API_KEY
    model: claude-opus-4-6
  bedrock-sonnet:
    type: bedrock
    region: us-east-1
    model: us.anthropic.claude-sonnet-4-6-v1
  local-qwen:
    type: local
    base_url: http://localhost:1234/v1/chat/completions
    model: qwen-32b
fallback_order:
  - anthropic-sonnet
  - bedrock-sonnet
  - local-qwen
```

Provider names are mapped to tiers by convention: names containing "fast" or "sonnet" → `TierFast`; "premium" or "opus" → `TierPremium`; "local" → `TierLocal`. First provider registered for a tier wins.

### Fallback Chain

When the primary provider for a tier fails, the `fallback_order` list is tried sequentially:

```
TierPremium request → anthropic-opus
    ↓ (fails: 429 rate limit)
Fallback[0] → anthropic-sonnet
    ↓ (fails: network timeout)
Fallback[1] → bedrock-sonnet
    ↓ (succeeds)
Return result, record at TierPremium cost rate
```

Fallback usage is always billed at `TierPremium` rate for conservative budgeting — fallbacks typically serve requests that needed higher quality.

### Cost Budget Guardrail

`RoutingProvider` tracks estimated cost per tier using atomic counters:

```go
type tierUsage struct {
    callCount     atomic.Int64
    tokenEstimate atomic.Int64  // ~4 chars/token heuristic
    costMicros    atomic.Int64  // microdollars (input + 5x output rate)
}
```

A configurable `monthlyBudgetCents` cap (e.g., 1500 = $15.00) gates all calls — `CompleteWithTier` returns `ErrBudgetExhausted` when the cap is reached. This prevents runaway costs from retry loops or misconfigured batch jobs.

The `/api/v1/ai/usage` endpoint exposes `BudgetStatus` (spent, remaining, per-tier breakdown) for FinOps dashboards.

### Sensitivity-Based Routing

For enterprise deployments with data classification requirements:

| Sensitivity Tag | Routing Rule | Rationale |
|-----------------|-------------|-----------|
| `sensitivity:general` | Any tier | No restriction |
| `sensitivity:internal` | TierFast or TierPremium (cloud OK) | Finding metadata but no PII |
| `sensitivity:restricted` | TierLocal only | Contains IAM configs, account IDs, finding details |
| `sensitivity:bounty` | TierLocal only | Bug bounty / red team — zero cloud exfiltration |
| `project:HAEA-*` | TierLocal only | HAEA compliance mandate — all inference local |

Sensitivity routing is enforced at the caller site (feature handlers specify the tier), not in the `RoutingProvider` itself. The routing provider is tier-aware, not sensitivity-aware — this keeps the abstraction clean and avoids coupling business rules into infrastructure.

### Provider Interface

The routing layer wraps the existing `Provider` interface without changing it:

```go
type Provider interface {
    Complete(ctx context.Context, prompt string) (string, error)
    CompleteWithSystem(ctx context.Context, systemPrompt, userPrompt string) (string, error)
}
```

`RoutingProvider` satisfies `Provider` (its `Complete` and `CompleteWithSystem` delegate to `CompleteWithTier` with the default tier), so any code expecting a `Provider` works transparently. Tier-aware callers import `RoutingProvider` directly for `CompleteWithTier`.

## Consequences

### Positive

- **~60% cost reduction** on AI spend — 80% of calls at Sonnet rate ($3/MTok) instead of Opus rate ($15/MTok)
- **Zero-downtime degradation** — fallback chain ensures AI features survive single-provider outages
- **Air-gapped compliance** — `TierLocal` satisfies enterprise mandates for on-premise inference
- **Budget visibility** — per-tier usage tracking and hard cap prevent cost surprises
- **Transparent adoption** — existing `Provider` consumers work unchanged; tier selection is opt-in

### Negative

- **Token estimation is approximate** — `len(prompt)/4` is a heuristic, not tokenizer output. Cost tracking may drift ±20% from actual billing.
- **Fallback latency** — sequential fallback adds wall time on provider failures (each attempt has its own timeout). No parallel racing of providers.
- **Tier selection is manual** — callers must choose the right tier. No automatic quality/cost optimization based on prompt complexity.

### Risks

| Risk | Impact | Mitigation |
|------|--------|-----------|
| Sonnet produces incorrect NLQ-to-SQL | Wrong query results shown to user | NLQ explicitly routes to TierPremium; Sonnet only for summarization |
| Budget exhausted mid-month | All AI features disabled | Budget status exposed on dashboard; alerts at 80% threshold; TierLocal as unlimited fallback |
| Local model quality gap | Degraded narratives in air-gapped mode | Qwen-32B benchmarked on CloudForge-specific prompts; acceptable for summarization, not for complex reasoning |
| Provider API key rotation | Outage until env vars updated | Keys read from 1Password via `op read` at container start; rotation is env var swap + restart |

## Alternatives Considered

### 1. Single Provider with Model Parameter

Pass model name as a parameter to `Complete()`, let the provider handle routing internally.

**Rejected because:** Leaks model knowledge into feature code. Callers shouldn't know that "claude-sonnet-4-6" exists — they should express intent ("fast", "premium") and let infrastructure handle mapping. Also cannot abstract across provider boundaries (Anthropic Sonnet → Bedrock Sonnet fallback requires different client code).

### 2. Sidecar Routing Proxy (LiteLLM)

Run LiteLLM as a sidecar that presents a unified OpenAI-compatible API and handles provider failover.

**Evaluated but deferred:** Adds container dependency, configuration surface, and network hop. Appropriate at scale (>10 providers, >100 RPS) but overengineered for CloudForge's 5-provider, <10 RPS profile. The in-process `RoutingProvider` achieves the same routing with zero latency overhead.

### 3. Two Tiers Only (Cloud + Local)

Collapse Fast and Premium into a single "Cloud" tier.

**Rejected because:** 5x cost difference between Sonnet and Opus is too large to ignore. Summarization tasks consuming Opus tokens wastes ~$12/MTok. Three tiers map naturally to the three distinct quality/cost/sensitivity profiles in the feature set.

## References

- ADR-004: AI Provider Selection (original single-provider design)
- `internal/ai/provider.go` — Provider interface, AnthropicProvider, OpenAIProvider
- `internal/ai/router.go` — RoutingProvider, ModelTier, fallback chain, budget tracking
- `internal/ai/config.go` — AIConfig YAML loading, NewRoutingProviderFromConfig
- `internal/ai/bedrock.go` — BedrockProvider (AWS Bedrock)
- `internal/ai/vertex.go` — VertexProvider (GCP Vertex AI)
- `internal/ai/openai.go` — OpenAIProvider (also used for local LM Studio)
- `cmd/server/bootstrap_startup.go` — Provider initialization at server start
