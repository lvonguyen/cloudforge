# ADR-005: Rate Limiting Implementation

## Status

Accepted

## Date

2026-01-05

## Context

We need rate limiting to:
- Protect backend services from overload
- Enforce fair usage across API tiers
- Prevent abuse and DoS attacks
- Control costs for expensive operations (AI analysis)

### Requirements

- Per-client and per-endpoint limits
- Multiple time windows (second, minute, hour, day)
- Tier-based limits (free, basic, professional, enterprise)
- Cost multipliers for expensive endpoints
- Distributed enforcement (multi-instance)

## Decision

We will implement **Redis-based sliding window rate limiting** with tier and endpoint configuration.

## Algorithm Selection

### Options

1. **Fixed Window** - Simple, but allows bursts at window boundaries
2. **Sliding Window Log** - Accurate, but memory-intensive
3. **Sliding Window Counter** - Good balance of accuracy and efficiency
4. **Token Bucket** - Allows controlled bursts
5. **Leaky Bucket** - Smooth rate, no bursts

### Decision: Sliding Window Counter

- Accurate rate calculation without boundary issues
- Efficient Redis storage (single key per window)
- Atomic increment with TTL using Lua script

## Implementation

### Redis Lua Script

```lua
local current = redis.call('INCR', KEYS[1])
if current == 1 then
    redis.call('PEXPIRE', KEYS[1], ARGV[1])
end
return current
```

### Key Structure

```
ratelimit:{tier}:{client_id}:{endpoint}:{window}
```

Example: `ratelimit:professional:user123:/api/v1/findings:minute`

### Tier Limits

| Tier | /sec | /min | /hour | /day |
|------|------|------|-------|------|
| anonymous | 2 | 20 | 100 | 500 |
| free | 5 | 60 | 500 | 5,000 |
| basic | 20 | 200 | 2,000 | 20,000 |
| professional | 50 | 500 | 5,000 | 50,000 |
| enterprise | 200 | 2,000 | 20,000 | 200,000 |

### Endpoint Cost Multipliers

| Endpoint | Multiplier | Effective Limit (pro) |
|----------|------------|----------------------|
| POST /findings | 1x | 50/sec |
| POST /findings/analyze | 5x | 10/sec |
| POST /findings/bulk | 10x | 5/sec |
| POST /reports/generate | 20x | 2.5/sec |

## Response Headers

```http
X-RateLimit-Limit: 500
X-RateLimit-Remaining: 423
X-RateLimit-Reset: 1704456789
X-RateLimit-Tier: professional
Retry-After: 45  # Only on 429
```

## Consequences

### Positive
- Prevents service overload
- Fair usage across clients
- Cost control for AI operations
- Standard headers for client integration

### Negative
- Redis dependency for rate limiting
- Slightly increased latency (~1ms)
- Configuration complexity

### Mitigations
- Redis cluster for high availability
- Local fallback if Redis unavailable
- Clear documentation for tier limits

## Monitoring

- `rate_limit_hits_total{tier, endpoint}` - Track violations
- `rate_limit_remaining{tier}` - Capacity monitoring
- Alert on sustained high limit hits

## Related Decisions

- ADR-003: Caching Strategy (Redis selection)
- ADR-007: Error Handling Strategy

