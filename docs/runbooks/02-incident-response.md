# Runbook: Incident Response

## Overview

This runbook covers incident detection, triage, mitigation, and resolution for CloudForge production issues.

## Incident Classification

| Severity | Description | Response Time | Examples |
|----------|-------------|---------------|----------|
| SEV1 | Service down, data loss risk | 15 min | API unreachable, DB corruption |
| SEV2 | Major degradation | 30 min | 50% error rate, major feature broken |
| SEV3 | Minor degradation | 2 hours | Single endpoint slow, non-critical bug |
| SEV4 | Low impact | 1 business day | UI cosmetic issue, minor inconvenience |

## Detection

### Alert Sources

1. **PagerDuty** - Critical alerts
2. **Grafana** - Metric-based alerts
3. **Datadog/CloudWatch** - Log-based alerts
4. **Customer Reports** - Support tickets

### Key Metrics to Monitor

```promql
# Error rate (should be <0.1%)
sum(rate(cloudforge_http_requests_total{status=~"5.."}[5m])) 
/ sum(rate(cloudforge_http_requests_total[5m]))

# Latency P99 (should be <500ms)
histogram_quantile(0.99, rate(cloudforge_http_request_duration_seconds_bucket[5m]))

# Active findings (trend)
cloudforge_findings_active

# AI provider availability
cloudforge_health_status{component="ai_provider"}
```

## Triage Procedure

### Step 1: Initial Assessment (5 min)

```bash
# Check overall status
kubectl get pods -n cloudforge
kubectl top pods -n cloudforge

# Check recent deployments
kubectl rollout history deployment/cloudforge-api -n cloudforge

# Check logs for errors
kubectl logs -n cloudforge -l app=cloudforge-api --tail=100 | grep -i error
```

### Step 2: Impact Assessment

- How many users affected?
- Which features impacted?
- Is data at risk?
- When did it start?

### Step 3: Classification

Based on impact, classify severity and engage appropriate responders.

## Common Issues and Remediation

### Issue: High API Error Rate

**Symptoms**: 5xx errors, timeouts

**Diagnosis**:
```bash
# Check API logs
kubectl logs -n cloudforge -l app=cloudforge-api --tail=500 | grep "ERROR\|FATAL"

# Check resource usage
kubectl top pods -n cloudforge

# Check database connectivity
kubectl exec -n cloudforge deployment/cloudforge-api -- ./cloudforge health
```

**Remediation**:
1. If OOM: Increase memory limits, then investigate memory leak
2. If CPU: Scale horizontally, then optimize hot paths
3. If DB connection: Check connection pool, DB health
4. If external dependency: Check provider status, enable fallback

### Issue: Database Connection Failures

**Symptoms**: "connection refused", "too many connections"

**Diagnosis**:
```bash
# Check connection count
kubectl exec -n cloudforge deployment/cloudforge-api -- \
  psql $DATABASE_URL -c "SELECT count(*) FROM pg_stat_activity;"

# Check max connections
kubectl exec -n cloudforge deployment/cloudforge-api -- \
  psql $DATABASE_URL -c "SHOW max_connections;"
```

**Remediation**:
1. Kill idle connections: `SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE state = 'idle' AND query_start < now() - interval '10 minutes';`
2. Increase connection pool size in config
3. Add PgBouncer if not already present
4. Scale up DB instance if connection limit reached

### Issue: AI Provider Timeouts

**Symptoms**: Slow analysis, AI-powered features fail

**Diagnosis**:
```bash
# Check AI provider status
curl -s https://status.anthropic.com/api/v2/status.json | jq .
curl -s https://status.openai.com/api/v2/status.json | jq .

# Check rate limit status
kubectl logs -n cloudforge -l app=cloudforge-api | grep "rate_limit"
```

**Remediation**:
1. Enable fallback provider in config
2. Increase timeout if provider slow but working
3. Enable cached responses for repeat queries
4. Gracefully degrade to static analysis

### Issue: High Memory Usage

**Symptoms**: OOMKilled pods, increasing memory trend

**Diagnosis**:
```bash
# Check memory usage
kubectl top pods -n cloudforge

# Enable profiling
curl -s http://localhost:6060/debug/pprof/heap > heap.prof
go tool pprof heap.prof
```

**Remediation**:
1. Restart affected pods (temporary)
2. Reduce batch sizes for processing
3. Add memory limits enforcement
4. Investigate and fix memory leak

## Communication

### Internal Communication

1. Create incident channel: `#incident-YYYYMMDD-XX`
2. Post initial update with:
   - What's happening
   - Who is investigating
   - Current impact
3. Update every 15 minutes for SEV1-2

### External Communication (if customer-facing)

1. Update status page
2. Prepare customer communication
3. Coordinate with support team

## Post-Incident

### Immediate (within 24h)

- [ ] Document timeline
- [ ] Confirm service restored
- [ ] Remove any temporary mitigations
- [ ] Update monitoring if gap identified

### Post-Mortem (within 5 days)

1. Schedule blameless post-mortem
2. Document root cause
3. Create action items
4. Share learnings

## Escalation Matrix

| Severity | Primary | Escalation (30 min) | Escalation (1h) |
|----------|---------|---------------------|-----------------|
| SEV1 | On-Call | Engineering Manager | VP Engineering |
| SEV2 | On-Call | Tech Lead | Engineering Manager |
| SEV3 | On-Call | Tech Lead | - |
| SEV4 | Assigned Engineer | - | - |

## Contact Information

- On-Call: PagerDuty
- Engineering Manager: @eng-manager
- Security: #security-ops
- Customer Success: #customer-success

