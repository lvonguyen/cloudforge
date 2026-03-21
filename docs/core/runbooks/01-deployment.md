# Runbook: Cloud Aegis Deployment

## Overview

This runbook covers deploying Cloud Aegis to production, including:
- Container image builds
- Database migrations
- Service rollout
- Verification procedures

## Prerequisites

- [ ] Access to CI/CD pipeline (GitHub Actions)
- [ ] kubectl access to production cluster
- [ ] Database migration permissions
- [ ] Approval from change management (if required)

## Pre-Deployment Checklist

```bash
# 1. Verify current service health
kubectl get pods -n aegis
kubectl top pods -n aegis

# 2. Check pending database migrations
./aegis migrate status

# 3. Verify no active incidents
open https://status.aegis.io/admin

# 4. Backup current config
kubectl get configmap aegis-config -n aegis -o yaml > backup-config.yaml
```

## Deployment Procedure

### Option A: Fly.io Deployment (Primary)

```bash
# 1. Deploy to Fly.io (uses fly.toml at repo root)
fly deploy

# 2. Monitor deployment
fly status -a cloudforge-api
fly logs -a cloudforge-api

# 3. Verify health
curl -s https://aegis-api.fly.dev/health | jq .
```

### Option B: Standard CI/CD (Alternative — Kubernetes)

```bash
# 1. Create release tag
git tag v1.2.3
git push origin v1.2.3

# 2. Monitor pipeline
# GitHub Actions will:
# - Run tests
# - Build container image
# - Push to registry
# - Apply Kubernetes manifests
# - Run smoke tests

# 3. Verify deployment
kubectl rollout status deployment/aegis-api -n aegis
```

### Option C: Manual Deployment (Emergency — Kubernetes)

```bash
# 1. Build and push image
docker build -t aegis:v1.2.3 .
docker tag aegis:v1.2.3 123456789.dkr.ecr.us-west-2.amazonaws.com/aegis:v1.2.3
docker push 123456789.dkr.ecr.us-west-2.amazonaws.com/aegis:v1.2.3

# 2. Update deployment
kubectl set image deployment/aegis-api \
  api=123456789.dkr.ecr.us-west-2.amazonaws.com/aegis:v1.2.3 \
  -n aegis

# 3. Wait for rollout
kubectl rollout status deployment/aegis-api -n aegis --timeout=300s
```

### Database Migration

```bash
# 1. Run migrations in dry-run mode first
./aegis migrate --dry-run

# 2. Apply migrations
./aegis migrate up

# 3. Verify migrations
./aegis migrate status
```

## Verification

### API Health Check

```bash
# Check health endpoint
curl -s https://api.aegis.io/health | jq .

# Expected response:
# {
#   "status": "healthy",
#   "version": "1.2.3",
#   "components": { ... }
# }
```

### Functional Verification

```bash
# Test finding creation
curl -X POST https://api.aegis.io/api/v1/findings \
  -H "Authorization: Bearer $API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"title": "Test Finding", "severity": "low"}'

# Verify in UI
open https://app.aegis.io/findings
```

### Metrics Verification

```bash
# Check Prometheus targets
curl -s http://prometheus:9090/api/v1/targets | jq '.data.activeTargets[] | select(.labels.job=="aegis")'

# Check error rate
curl -s 'http://prometheus:9090/api/v1/query?query=rate(aegis_http_requests_total{status=~"5.."}[5m])'
```

## Rollback Procedure

### Automatic Rollback (Kubernetes)

```bash
# Rollback to previous version
kubectl rollout undo deployment/aegis-api -n aegis

# Verify rollback
kubectl rollout status deployment/aegis-api -n aegis
```

### Database Rollback

```bash
# Rollback last migration
./aegis migrate down 1

# Rollback to specific version
./aegis migrate goto 20260103120000
```

## Post-Deployment

1. [ ] Verify all pods healthy
2. [ ] Check error rate in Grafana
3. [ ] Verify log shipping working
4. [ ] Update deployment ticket
5. [ ] Notify stakeholders

## Escalation

| Condition | Action |
|-----------|--------|
| Deployment fails | Rollback, then investigate |
| Error rate >1% | Rollback immediately |
| Performance degradation >20% | Consider rollback |
| Security vulnerability | Emergency rollback |

## Contact

- On-Call: PagerDuty
- Platform Team: #platform-support (Slack)
- Security Team: #security-ops (Slack)

