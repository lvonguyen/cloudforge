# ADR-018: Threat Intelligence Feed Integration

## Status

Accepted

## Date

2026-03-20

## Deciders

Liem Vo-Nguyen

## Context

Cloud Aegis performs AI-powered severity re-scoring on CSPM findings. To produce accurate risk assessments, the enrichment pipeline needs real-time threat intelligence from multiple external feeds:

1. **EPSS** (Exploit Prediction Scoring System) — probability that a CVE will be exploited in the next 30 days
2. **CISA KEV** (Known Exploited Vulnerabilities) — authoritative catalog of actively exploited CVEs
3. **GreyNoise** — IP reputation and internet-wide scanning classification
4. **HIBP** (Have I Been Pwned) — breach exposure for email addresses
5. **OTX** (AlienVault Open Threat Exchange) — IoC intelligence (IPs, domains, hashes)

Each feed has different data models, rate limits, authentication requirements, and freshness guarantees. The platform needs a unified integration pattern.

## Decision

Adopt a **client-per-feed architecture** with shared caching and rate limiting.

### Architecture

Each threat intel feed gets a dedicated Go client in `internal/cspm/threatintel/`:

| Client | File | Cache TTL | Rate Limit | Auth |
|--------|------|-----------|------------|------|
| EPSS | `epss.go` | 12h | None (bulk CSV) | None |
| CISA KEV | `kev.go` | 12h (singleflight refresh) | None (bulk JSON) | None |
| GreyNoise | `greynoise.go` | 12h | 100/day (Community) | API key |
| HIBP | `hibp.go` | 12h | 10/min (sliding window) | API key |
| OTX | `otx.go` | 12h | 100/day | API key |

### Shared Patterns

All clients follow these conventions:

1. **Cache-first lookup** — `GetCached()` checks in-memory cache with TTL validation (TTL check fix: Sprint J QA)
2. **HTTP client with timeout** — 30s default, configurable per client
3. **URL path escaping** — `url.PathEscape()` on all user-supplied values (email, IP) before URL construction (Sprint J security fix)
4. **Rate limiter** — Per-client rate limiting with slot reservation before unlock to prevent TOCTOU races (Sprint J HIBP fix)
5. **Singleflight dedup** — `sync/singleflight` on refresh operations to prevent thundering herd (Sprint J KEV fix)
6. **Error logging** — All errors logged with context; never silently discarded (Sprint J KEV fix)

### Enrichment Pipeline Integration

The `EnrichmentService` in `cmd/server/service_enrichment.go` orchestrates feed lookups:

```
Finding → [EPSS] → [KEV] → [GreyNoise] → [HIBP] → [OTX] → AI Scoring → Enriched Finding
```

Current limitation: feeds are called sequentially. When Finding has IP/email fields wired (P3), switch to `errgroup` for parallel execution.

### Cache Implementation

```go
type CachedResult struct {
    Data      interface{}
    FetchedAt time.Time
    TTL       time.Duration
}

func (c *CachedResult) IsExpired() bool {
    return time.Since(c.FetchedAt) > c.TTL
}
```

## Consequences

### Positive

- Each feed is independently deployable and testable
- Shared caching reduces API calls by 90%+ for repeated CVE/IP lookups
- Singleflight prevents cache stampede on TTL expiry
- URL escaping prevents injection via crafted email/IP values

### Negative

- Sequential enrichment adds latency (~200ms per feed, ~1s total for 5 feeds)
- GreyNoise/HIBP community tier rate limits constrain throughput for large finding volumes
- IP and email fields not yet wired on Finding type (P3) — GreyNoise/HIBP/OTX return nil until then

### Risks

- Feed API changes or deprecation require per-client updates
- Rate limit exhaustion during bulk enrichment (mitigated by cache + backoff)
- Community API key rate limits may be insufficient for production volumes (upgrade to paid tiers)

## References

- ADR-008 (Attack Path Computation) — attack paths benefit from IP reputation context
- ADR-011 (Toxic Combo Detection) — threat intel feeds into toxic combination scoring
- ADR-014 (Event-Driven Ingestion) — newly ingested findings trigger enrichment
- Sprint J implementation: `a15764d`, QA fixes: `fd6e4eb`

---

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2026-03-20 | Liem Vo-Nguyen | Initial ADR |
