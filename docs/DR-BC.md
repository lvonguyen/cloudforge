# CloudForge - Disaster Recovery & Business Continuity

**Version:** 1.0
**Author:** Liem Vo-Nguyen
**Last Updated:** January 2026

---

## Executive Summary

This document outlines the DR/BC strategy for CloudForge Internal Developer Platform (IDP) across AWS, Azure, and GCP deployments.

---

## Recovery Objectives

| Metric | Target | Description |
|--------|--------|-------------|
| **RTO** | 2 hours | Maximum acceptable downtime |
| **RPO** | 5 minutes | Maximum acceptable data loss |
| **MTTR** | 1 hour | Average time to restore |

---

## Service Criticality

| Component | Criticality | RTO | RPO | Notes |
|-----------|-------------|-----|-----|-------|
| Policy Engine (OPA) | Critical | 30 min | N/A | Stateless, fast recovery |
| GRC Integration | High | 1 hour | 5 min | State in external GRC |
| Template Engine | Critical | 30 min | N/A | Templates in Git |
| API Gateway | Critical | 15 min | N/A | Stateless |
| Request Workflow | High | 1 hour | 5 min | State in database |
| Temporal Orchestration | High | 1 hour | 5 min | Temporal cluster |
| PostgreSQL | Critical | 30 min | 5 min | Main data store |

---

## Multi-Cloud DR Architecture

### AWS Primary

```
AWS Primary (us-west-2)
├── EKS Cluster (3 nodes)
├── RDS PostgreSQL (Multi-AZ)
├── S3 (Versioned)
└── Secrets Manager

        Cross-Region Replication
                │
                ▼
AWS DR (us-east-1)
├── EKS Cluster (0 nodes - cold standby)
├── RDS Read Replica
└── S3 Replica
```

### Azure Primary

```
Azure Primary (West US 2)
├── AKS Cluster (3 nodes)
├── Azure SQL (Geo-Replicated)
├── Blob Storage (GRS)
└── Key Vault

        Geo-Replication
                │
                ▼
Azure DR (East US)
├── AKS Cluster (0 nodes)
├── SQL Failover Group
└── Blob GRS Secondary
```

### GCP Primary

```
GCP Primary (us-west1)
├── GKE Cluster (3 nodes)
├── Cloud SQL (Regional HA)
├── GCS (Dual-region)
└── Secret Manager

        Regional Replication
                │
                ▼
GCP DR (us-east1)
├── GKE Cluster (0 nodes)
├── SQL Regional Replica
└── GCS Dual-region
```

---

## Backup Strategy

### Database Backups

| Database | Method | Frequency | Retention | Location |
|----------|--------|-----------|-----------|----------|
| PostgreSQL | Point-in-time | Continuous | 7 days | Same region |
| PostgreSQL | Daily snapshot | Daily | 30 days | Cross-region |
| Policy configs | GitOps | Real-time | Infinite | Git |

### Application State

| Component | Method | Frequency | Retention |
|-----------|--------|-----------|-----------|
| Kubernetes state | Velero | Every 4 hours | 7 days |
| OPA policies | Git sync | Real-time | Infinite |
| Templates | Git sync | Real-time | Infinite |
| Temporal state | Native backup | Hourly | 48 hours |

---

## Failover Procedures

### Automated Failover (RTO: 30 min)

**Triggers:**
- Primary region health check fails 3 consecutive times
- Database connection failure > 5 minutes
- Kubernetes API unavailable > 5 minutes

**Automated Steps:**
1. Traffic Manager/Route 53 switches to DR
2. Database replica promoted
3. K8s pods scaled up in DR
4. On-call notified

### Manual Failover (RTO: 2 hours)

1. Notify stakeholders
2. Drain primary gracefully
3. Verify DR database sync
4. Promote DR database
5. Scale up DR Kubernetes
6. Update DNS/load balancer
7. Verify OPA policies loaded
8. Resume traffic
9. Document in incident log

---

## Quarterly DR Testing

| Quarter | Test Type | Scope |
|---------|-----------|-------|
| Q1 | Tabletop | Full |
| Q2 | Database failover | DB only |
| Q3 | Full failover | Complete |
| Q4 | Chaos engineering | Random |

### Success Criteria

- [ ] RTO met (< 2 hours)
- [ ] RPO met (< 5 min data loss)
- [ ] OPA policies functional in DR
- [ ] GRC integrations restored
- [ ] Template deployments working
- [ ] Rollback successful

---

## SLA Targets

| Tier | Uptime | Monthly Downtime |
|------|--------|------------------|
| Gold | 99.9% | 43.8 minutes |

**CloudForge Target:** Gold (99.9%)

---

## DR Cost Summary (Monthly)

| Component | AWS | Azure | GCP |
|-----------|-----|-------|-----|
| K8s standby | $75 | $0 | $75 |
| Database replica | $150 | $140 | $130 |
| Storage replication | $25 | $25 | $20 |
| **Total** | **$250** | **$165** | **$225** |

---

## Author

**Liem Vo-Nguyen**
- LinkedIn: linkedin.com/in/liemvonguyen

