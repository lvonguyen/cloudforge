# ADR-003: Caching Strategy

## Status

Accepted

## Date

2026-01-05

## Context

We need a caching layer to:
- Reduce database load for frequently accessed data
- Store session and rate limit data
- Provide pub/sub for real-time notifications
- Implement distributed locks for workflow coordination

### Options Considered

1. **Redis** - In-memory, data structures, pub/sub
2. **Memcached** - Simple key-value, high performance
3. **Application-level caching** - In-process, no network

## Decision

We will use **Redis 7** for caching and coordination.

## Rationale

### Data Structures
- Hashes for session objects
- Sorted sets for rate limiting windows
- Lists for queues
- Streams for event processing

### Features
- Pub/sub for real-time finding notifications
- Lua scripting for atomic operations (rate limiting)
- TTL support with millisecond precision
- Cluster mode for horizontal scaling

### Persistence
- Optional RDB/AOF persistence for recovery
- Not required for pure caching, but useful for sessions

### Why Not Memcached
- No pub/sub support
- Limited data structures
- No persistence option
- No Lua scripting

## Cache Strategy

### TTL by Data Type

| Data Type | TTL | Reason |
|-----------|-----|--------|
| Compliance frameworks | 24h | Rarely changes |
| Finding by ID | 1h | May be updated |
| Deduplication keys | 7d | Long-term lookup |
| User sessions | 8h | Security policy |
| Rate limit counters | 1min | Per-window |
| AI responses | 30min | Cost optimization |

### Cache Invalidation

1. **Write-through**: Update cache on write
2. **Event-driven**: Invalidate on compliance framework updates
3. **TTL-based**: Automatic expiration for most data

## Consequences

### Positive
- Reduced database queries by 80%+
- Sub-millisecond cache reads
- Built-in rate limiting support
- Real-time notifications via pub/sub

### Negative
- Additional infrastructure to manage
- Cache invalidation complexity
- Memory costs (~$0.017/GB/hour on ElastiCache)

### Mitigations
- Use ElastiCache Serverless for auto-scaling
- Implement cache-aside pattern with fallback
- Monitor cache hit rates

## Related Decisions

- ADR-002: Database Selection
- ADR-004: Rate Limiting Implementation

