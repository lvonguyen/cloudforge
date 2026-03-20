# Runbook: DR Failover

## Overview

This runbook covers disaster recovery failover procedures for CloudForge, including:
- Pre-failover readiness checks
- Automated and manual failover triggers
- Per-CSP failover specifics (AWS, Azure, GCP)
- Post-failover verification
- Failback to primary
- Stakeholder communication templates

## Prerequisites

- [ ] Access to all three CSP consoles (AWS, Azure, GCP)
- [ ] kubectl access to primary and DR clusters
- [ ] DNS management access (Route 53, Traffic Manager, Cloud DNS)
- [ ] PagerDuty incident created for tracking
- [ ] Runbook 02-incident-response.md reviewed if triggered by incident

## Incident Classification

| Condition | Failover Type | RTO Target | RPO Target |
|-----------|---------------|------------|------------|
| Region outage | Full failover | 30 min | 5 min |
| Database corruption | DB-only failover | 15 min | 1 min |
| Network partition | Routing failover | 10 min | 0 |
| Compute failure | Cluster failover | 20 min | 2 min |

## Pre-Failover Checklist

Run these checks before initiating any failover.

```bash
# 1. Verify DR environment is healthy
kubectl get nodes --context=dr-cluster
kubectl get pods -n cloudforge --context=dr-cluster

# 2. Check database replication lag
# AWS RDS
aws rds describe-db-instances \
  --db-instance-identifier cloudforge-db-replica \
  --query 'DBInstances[0].StatusInfos' \
  --region us-west-2

# 3. Verify last successful backup
aws rds describe-db-snapshots \
  --db-instance-identifier cloudforge-db \
  --query 'reverse(sort_by(DBSnapshots, &SnapshotCreateTime))[0]' \
  --region us-east-1

# 4. Check DNS TTL (must be <=60s before failover)
dig +short SOA cloudforge.io
dig cloudforge.io | grep TTL

# 5. Verify DR application config is current
kubectl get configmap cloudforge-config -n cloudforge --context=dr-cluster -o yaml | \
  diff - <(kubectl get configmap cloudforge-config -n cloudforge --context=primary-cluster -o yaml)

# 6. Check DR health endpoint
curl -sf https://dr.cloudforge.io/health | jq .
```

- [ ] DR cluster nodes all Ready
- [ ] Database replication lag <30s
- [ ] Last backup <6h old
- [ ] DNS TTL reduced to 60s
- [ ] DR config matches primary
- [ ] DR health endpoint returns 200

## Automated Failover Triggers

CloudForge monitors the following conditions and triggers automated failover via the DR controller:

```promql
# Primary region health score (triggers failover at <0.3)
avg(cloudforge_health_status) by (region) < 0.3

# Consecutive health check failures (triggers at >5)
increase(cloudforge_health_check_failures_total[5m]) > 5

# Database replication lag (triggers at >120s)
cloudforge_db_replication_lag_seconds > 120
```

To check current DR controller status:

```bash
kubectl get deployment cloudforge-dr-controller -n cloudforge-system
kubectl logs -n cloudforge-system -l app=dr-controller --tail=50
```

## Manual Failover Procedure

### Step 1: Declare Failover

```bash
# Announce in incident channel
# #incident-YYYYMMDD-XX: "Initiating manual DR failover to [region]. ETA: 30 min."

# Disable new writes to primary (prevents split-brain)
kubectl annotate deployment cloudforge-api \
  cloudforge.io/drain="true" \
  --context=primary-cluster \
  -n cloudforge
```

### Step 2: Verify In-Flight Requests Drained

```bash
# Watch connection count drop to zero
watch -n 5 'kubectl exec -n cloudforge deployment/cloudforge-api \
  --context=primary-cluster -- \
  curl -s localhost:8080/debug/connections | jq .active'
```

### Step 3: Initiate Database Failover

See per-CSP sections below for database-specific commands.

### Step 4: Update DNS

```bash
# Route 53 (AWS)
aws route53 change-resource-record-sets \
  --hosted-zone-id Z1234567890ABC \
  --change-batch '{
    "Changes": [{
      "Action": "UPSERT",
      "ResourceRecordSet": {
        "Name": "api.cloudforge.io",
        "Type": "CNAME",
        "TTL": 60,
        "ResourceRecords": [{"Value": "dr-nlb.us-west-2.elb.amazonaws.com"}]
      }
    }]
  }'

# Verify propagation
watch -n 10 'dig +short api.cloudforge.io'
```

### Step 5: Scale DR Cluster

```bash
# Scale to production capacity
kubectl scale deployment cloudforge-api \
  --replicas=6 \
  --context=dr-cluster \
  -n cloudforge

kubectl rollout status deployment/cloudforge-api \
  --context=dr-cluster \
  -n cloudforge
```

### Step 6: Verify Failover Complete

```bash
curl -sf https://api.cloudforge.io/health | jq '{status, region}'
# Expected: {"status": "healthy", "region": "dr"}
```

## Per-CSP Failover Specifics

### AWS

#### RDS Multi-AZ Failover

```bash
# Force failover for Multi-AZ (60-120s downtime)
aws rds reboot-db-instance \
  --db-instance-identifier cloudforge-db \
  --force-failover \
  --region us-east-1

# Monitor failover event
aws rds describe-events \
  --source-identifier cloudforge-db \
  --source-type db-instance \
  --duration 60
```

#### Route 53 Health Check Management

```bash
# Disable primary health check (force failover routing)
aws route53 update-health-check \
  --health-check-id hc-1234567890abcdef0 \
  --disabled

# Verify traffic routing
aws route53 get-health-check-status \
  --health-check-id hc-1234567890abcdef0
```

#### EKS Node Scaling

```bash
# Scale node group in DR region
aws eks update-nodegroup-config \
  --cluster-name cloudforge-dr \
  --nodegroup-name primary \
  --scaling-config minSize=3,maxSize=10,desiredSize=6 \
  --region us-west-2

# Wait for nodes ready
kubectl wait nodes \
  --for=condition=Ready \
  --all \
  --timeout=300s \
  --context=dr-cluster
```

### Azure

#### SQL Failover Groups

```bash
# Initiate planned failover
az sql failover-group set-primary \
  --name cloudforge-fog \
  --resource-group cloudforge-dr-rg \
  --server cloudforge-dr-sql

# Check failover group status
az sql failover-group show \
  --name cloudforge-fog \
  --resource-group cloudforge-dr-rg \
  --server cloudforge-dr-sql \
  --query 'replicationState'
```

#### Traffic Manager

```bash
# Disable primary endpoint
az network traffic-manager endpoint update \
  --resource-group cloudforge-rg \
  --profile-name cloudforge-tm \
  --name primary-endpoint \
  --type azureEndpoints \
  --endpoint-status Disabled

# Verify routing
az network traffic-manager profile show \
  --resource-group cloudforge-rg \
  --name cloudforge-tm \
  --query 'endpoints[].{name:name,status:endpointStatus}'
```

#### AKS Scaling

```bash
# Scale AKS node pool in DR region
az aks nodepool scale \
  --resource-group cloudforge-dr-rg \
  --cluster-name cloudforge-dr-aks \
  --name agentpool \
  --node-count 6

# Verify nodes
kubectl get nodes --context=aks-dr-cluster
```

### GCP

#### Cloud SQL HA Failover

```bash
# Initiate failover to standby
gcloud sql instances failover cloudforge-db \
  --failover-replica-name=cloudforge-db-failover \
  --project=cloudforge-prod

# Check instance status
gcloud sql instances describe cloudforge-db \
  --project=cloudforge-prod \
  --format='value(state,failoverReplica.available)'
```

#### Cloud DNS

```bash
# Update DNS record to DR endpoint
gcloud dns record-sets update api.cloudforge.io. \
  --type=CNAME \
  --ttl=60 \
  --rrdatas=dr-lb.cloudforge.io. \
  --zone=cloudforge-zone \
  --project=cloudforge-prod

# Verify propagation
gcloud dns record-sets list \
  --zone=cloudforge-zone \
  --filter="name=api.cloudforge.io." \
  --project=cloudforge-prod
```

#### GKE Node Pools

```bash
# Resize GKE node pool in DR region
gcloud container clusters resize cloudforge-dr \
  --node-pool primary-pool \
  --num-nodes 6 \
  --region us-central1 \
  --project=cloudforge-prod

# Watch nodes come up
kubectl get nodes -w --context=gke-dr-cluster
```

## Post-Failover Verification

Run all checks before closing the incident.

```bash
# 1. API health
curl -sf https://api.cloudforge.io/health | jq .
# Expected: status=healthy, region=dr

# 2. Verify all deployments running
kubectl get deployment -n cloudforge --context=dr-cluster

# 3. Check error rate (allow 5-min window to settle)
curl -s 'http://prometheus-dr:9090/api/v1/query?query=rate(cloudforge_http_requests_total{status=~"5.."}[5m])' | jq '.data.result'

# 4. Data integrity check
kubectl exec -n cloudforge deployment/cloudforge-api \
  --context=dr-cluster -- \
  ./cloudforge db check-integrity

# 5. Verify OPA policy engine loaded
curl -sf https://api.cloudforge.io/api/v1/policies/health | jq .
# Expected: {"opa_external": "ok", "opa_embedded": "ok"}

# 6. Test end-to-end scan
curl -sf -X POST https://api.cloudforge.io/api/v1/scans \
  -H "Authorization: Bearer $API_TOKEN" \
  -d '{"scope": "test", "providers": ["aws"]}' | jq '{id, status}'
```

- [ ] API health returns healthy
- [ ] Error rate <1% for 5 consecutive minutes
- [ ] Database writes succeeding
- [ ] Policy engine loaded and evaluating
- [ ] End-to-end scan completes

## Failback Procedure

Return to primary after primary region is confirmed stable (minimum 2h post-recovery).

```bash
# 1. Verify primary region recovered
kubectl get nodes --context=primary-cluster

# 2. Sync any data written during failover (if not using synchronous replication)
./cloudforge dr sync-from-dr --dry-run
./cloudforge dr sync-from-dr --execute

# 3. Reduce DNS TTL to 60s (if not already)
# Run appropriate DNS command from Step 4 above pointing back to primary NLB

# 4. Scale primary cluster back up
kubectl scale deployment cloudforge-api \
  --replicas=6 \
  --context=primary-cluster \
  -n cloudforge

# 5. Redirect DNS back to primary
# Reverse the DNS change from Step 4 of the failover procedure

# 6. Verify traffic on primary
watch -n 10 'curl -sf https://api.cloudforge.io/health | jq .region'

# 7. Scale down DR cluster to standby capacity
kubectl scale deployment cloudforge-api \
  --replicas=2 \
  --context=dr-cluster \
  -n cloudforge
```

- [ ] Primary cluster healthy for >2h
- [ ] Data sync completed with zero conflicts
- [ ] DNS propagated to primary
- [ ] DR cluster scaled back to standby

## Communication Templates

### Initial Notification (T+0)

```
Subject: [INCIDENT] CloudForge DR Failover Initiated

Severity: SEV1
Started: YYYY-MM-DD HH:MM UTC
Incident Channel: #incident-YYYYMMDD-XX

We are initiating a DR failover for CloudForge due to [reason].
Estimated completion: 30 minutes.
Expected impact: API unavailable for up to 5 minutes during DNS propagation.

Next update: T+15 min
```

### Progress Update (T+15)

```
Update [T+15]:
- Database failover: COMPLETE
- DNS update: IN PROGRESS (propagating)
- DR cluster: SCALED (6/6 pods running)
- ETA to full recovery: 15 minutes
```

### Resolution Notice

```
Subject: [RESOLVED] CloudForge DR Failover Complete

Resolved: YYYY-MM-DD HH:MM UTC
Duration: XX minutes
Region: [primary -> DR]

All systems operational. Post-mortem scheduled for YYYY-MM-DD.
```

## Escalation

| Condition | Action |
|-----------|--------|
| Failover takes >30 min | Escalate to VP Engineering |
| Data integrity failure | Stop failover, engage DBA + Security |
| DR environment unhealthy | Contact Platform Team immediately |
| Two-region simultaneous failure | Engage executive team, activate BCP |

## Contact Information

- On-Call: PagerDuty
- Platform Team: #platform-support (Slack)
- Security Team: #security-ops (Slack)
- DBA On-Call: PagerDuty escalation policy `cloudforge-dba`
