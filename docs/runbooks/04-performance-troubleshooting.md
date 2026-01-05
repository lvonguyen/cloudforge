# Runbook: Performance Troubleshooting

## Overview

This runbook covers diagnosing and resolving performance issues in CloudForge, including slow API responses, high latency, and resource exhaustion.

## Prerequisites

- [ ] Access to Grafana dashboards
- [ ] kubectl access to production
- [ ] pprof endpoint access (internal network only)

## Performance Baselines

| Metric | Normal | Warning | Critical |
|--------|--------|---------|----------|
| API P50 latency | <50ms | <200ms | >500ms |
| API P99 latency | <200ms | <500ms | >2s |
| Error rate | <0.1% | <1% | >5% |
| CPU usage | <60% | <80% | >90% |
| Memory usage | <70% | <85% | >95% |
| DB query time | <50ms | <200ms | >1s |

## Diagnosis Workflow

### Step 1: Identify the Bottleneck

```bash
# Check overall latency
curl -s 'http://prometheus:9090/api/v1/query?query=histogram_quantile(0.99,rate(cloudforge_http_request_duration_seconds_bucket[5m]))'

# Check by endpoint
curl -s 'http://prometheus:9090/api/v1/query?query=topk(10,histogram_quantile(0.99,rate(cloudforge_http_request_duration_seconds_bucket[5m]))by(path))'

# Check resource usage
kubectl top pods -n cloudforge
```

### Step 2: CPU Profiling

```bash
# Enable CPU profile (30 seconds)
curl -s http://cloudforge-api:6060/debug/pprof/profile?seconds=30 > cpu.prof

# Analyze locally
go tool pprof -http=:8080 cpu.prof
```

**Common CPU issues**:
- JSON serialization (use sonic or jsoniter)
- Regex compilation (compile once, reuse)
- Excessive logging
- Inefficient algorithms

### Step 3: Memory Profiling

```bash
# Capture heap profile
curl -s http://cloudforge-api:6060/debug/pprof/heap > heap.prof

# Analyze
go tool pprof heap.prof
> top10
> list <function>
```

**Common memory issues**:
- Unbounded slice growth
- String concatenation in loops
- Holding references preventing GC
- Large object pools

### Step 4: Database Analysis

```bash
# Check slow queries
kubectl exec -n cloudforge deployment/cloudforge-api -- \
  psql $DATABASE_URL -c "SELECT query, calls, mean_time, total_time FROM pg_stat_statements ORDER BY mean_time DESC LIMIT 10;"

# Check active connections
kubectl exec -n cloudforge deployment/cloudforge-api -- \
  psql $DATABASE_URL -c "SELECT count(*), state FROM pg_stat_activity GROUP BY state;"

# Check table sizes
kubectl exec -n cloudforge deployment/cloudforge-api -- \
  psql $DATABASE_URL -c "SELECT relname, pg_size_pretty(pg_total_relation_size(relid)) FROM pg_catalog.pg_statio_user_tables ORDER BY pg_total_relation_size(relid) DESC LIMIT 10;"
```

### Step 5: Goroutine Analysis

```bash
# Check goroutine count
curl -s http://cloudforge-api:6060/debug/pprof/goroutine?debug=1 | head -50

# Full goroutine dump
curl -s http://cloudforge-api:6060/debug/pprof/goroutine?debug=2 > goroutines.txt
```

**Common goroutine issues**:
- Goroutine leaks (missing context cancellation)
- Blocking on channels
- Mutex contention

## Common Issues and Fixes

### Slow Database Queries

**Symptoms**: High P99 latency, increasing query times

**Quick fixes**:
```sql
-- Add missing index
CREATE INDEX CONCURRENTLY idx_findings_created 
ON findings(created_at DESC) 
WHERE status = 'open';

-- Vacuum and analyze
VACUUM ANALYZE findings;

-- Check for lock contention
SELECT * FROM pg_locks WHERE NOT granted;
```

**Long-term fixes**:
- Add query timeouts
- Implement query result caching
- Partition large tables by date
- Add read replicas for reporting queries

### Memory Exhaustion

**Symptoms**: OOMKilled, gradual memory increase

**Quick fixes**:
```bash
# Increase memory limit (temporary)
kubectl patch deployment cloudforge-api -n cloudforge \
  --type='json' \
  -p='[{"op": "replace", "path": "/spec/template/spec/containers/0/resources/limits/memory", "value": "4Gi"}]'
```

**Long-term fixes**:
- Implement streaming for large responses
- Use generators for batch processing
- Add memory limits to goroutines
- Profile and fix memory leaks

### High CPU Usage

**Symptoms**: Throttled pods, slow responses

**Quick fixes**:
```bash
# Scale horizontally
kubectl scale deployment cloudforge-api -n cloudforge --replicas=5
```

**Long-term fixes**:
- Cache computed results
- Optimize hot code paths
- Use worker pools for CPU-intensive work
- Add batch processing for bulk operations

### Connection Pool Exhaustion

**Symptoms**: "connection pool exhausted", intermittent failures

**Quick fixes**:
```bash
# Check and increase pool size
kubectl edit configmap cloudforge-config -n cloudforge
# Update: database.max_connections: 100
```

**Long-term fixes**:
- Add PgBouncer for connection pooling
- Reduce connection hold times
- Implement connection health checking
- Add circuit breaker for downstream services

## Optimization Checklist

### API Layer
- [ ] Response compression enabled (gzip)
- [ ] Connection keep-alive configured
- [ ] Request timeout limits set
- [ ] Rate limiting prevents overload

### Database Layer
- [ ] Connection pooling configured
- [ ] Query timeouts set
- [ ] Slow query logging enabled
- [ ] Indexes optimized for common queries

### Caching Layer
- [ ] Redis caching for hot data
- [ ] Cache hit rate >80%
- [ ] TTL configured appropriately
- [ ] Cache invalidation working

### Application Layer
- [ ] Goroutine limits configured
- [ ] Memory limits enforced
- [ ] Profiling endpoints enabled
- [ ] Structured logging (not excessive)

## Monitoring Queries

### Grafana Dashboard Queries

```promql
# Request rate by endpoint
sum(rate(cloudforge_http_requests_total[5m])) by (path)

# Latency heatmap
histogram_quantile(0.5, rate(cloudforge_http_request_duration_seconds_bucket[5m])) by (path)
histogram_quantile(0.95, rate(cloudforge_http_request_duration_seconds_bucket[5m])) by (path)
histogram_quantile(0.99, rate(cloudforge_http_request_duration_seconds_bucket[5m])) by (path)

# Error rate
sum(rate(cloudforge_http_requests_total{status=~"5.."}[5m])) / sum(rate(cloudforge_http_requests_total[5m]))

# Memory usage
container_memory_usage_bytes{container="cloudforge-api"} / container_spec_memory_limit_bytes{container="cloudforge-api"}

# CPU usage
rate(container_cpu_usage_seconds_total{container="cloudforge-api"}[5m]) / container_spec_cpu_quota{container="cloudforge-api"} * 100000
```

## Escalation

| Condition | Action |
|-----------|--------|
| P99 > 2s for >5 min | Page on-call |
| CPU/Memory >90% | Scale and page on-call |
| Error rate >5% | Page on-call immediately |
| DB query >30s | Kill query, investigate |

