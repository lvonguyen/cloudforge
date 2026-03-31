# ADR-020: Security Graph Architecture

**Status:** Accepted
**Date:** 2026-03-30
**Deciders:** Liem Vo-Nguyen
**Supersedes:** None
**Extends:** ADR-008 (Attack Path Computation), ADR-015 (Graph Query Engine)

## Context

Cloud Aegis today has three disconnected layers that each touch "graph" concepts:

1. **Heuristic attack paths** (`cmd/server/attackpath.go`) — in-memory BFS over flat finding lists. Edges are inferred from co-location (same account + region/resource-type = reachable). No actual infrastructure topology.
2. **PuppyGraph query proxy** (`internal/graph/client.go`, `handlers_graph.go`) — generic read-only Gremlin/Cypher pass-through. Schema has 3 vertex types (finding, resource, compliance_framework) and 2 edge types (affects, maps_to).
3. **Compliance mapping** (`internal/compliance/`) — keyword-based control matching. Controls exist as in-memory structs but have no evaluation state, no per-resource pass/fail, no persistence.

The target is a **graph-native security pipeline** where:

- A live **Security Graph** models resources, their relationships, and security posture
- **Controls** are evaluable rules with per-resource pass/fail state and evidence
- **Issues** are materialized, prioritized entities derived from control failures and finding aggregation
- **Attack paths** and blast radius views are projections over the graph, not heuristic computations

## Decision

### System Roles

| Component | Role | Rationale |
|-----------|------|-----------|
| **PostgreSQL** | System of record | All entities (findings, resources, controls, issues, edges) are persisted in Postgres. Single source of truth. Transactional writes, ACID guarantees. |
| **PuppyGraph** | Query/federation layer | Zero-ETL graph projection over Postgres via JDBC. Ad-hoc Gremlin/Cypher traversal for exploration, investigation, and attack path queries. No data duplication. |
| **Neptune** | Deferred (production) | Native graph store for scale (>100K nodes, deep multi-hop traversal, graph algorithms). Migration path: ETL from Postgres edge tables. Decision revisited when traversal depth or latency demands exceed PuppyGraph/Postgres capabilities. |
| **Go BFS engine** | Fallback / offline computation | Retained for environments without PuppyGraph (CI, local dev, demo). Uses same edge data but computes in-memory. Feature-flagged via `PUPPYGRAPH_URL`. |

### Node Taxonomy (Vertex Types)

| Label | Source Table | Description | Key Properties |
|-------|-------------|-------------|----------------|
| `finding` | `findings` | Security finding from scanner | severity, category, status, exploit_available |
| `resource` | `resources` | Cloud resource (S3, EC2, RDS, etc.) | resource_type, region, account_id, cloud_provider |
| `control` | `controls` (new) | Evaluable security rule (CIS check, FSBP rule) | framework_id, category, severity, eval_logic_ref |
| `issue` | `issues` (new) | Materialized prioritized security issue | severity, risk_score, status, blast_radius |
| `account` | `accounts` (new) | Cloud account / project / subscription | cloud_provider, environment_type, tenant_id |
| `compliance_framework` | `compliance_frameworks` | Compliance standard (CIS, NIST, SOC2) | version, category, score |

**Deferred vertex types** (require infrastructure discovery integration):
- `identity` — IAM principal (role, user, service account)
- `network_zone` — VPC, subnet, security group
- `service_endpoint` — API Gateway, Load Balancer, CDN

### Edge Taxonomy (Relationship Types)

| Label | From → To | Source | Description |
|-------|-----------|--------|-------------|
| `affects` | finding → resource | `findings.resource_id` FK | Finding affects this resource |
| `violates` | finding → control | `control_evaluations` | Finding violates this control |
| `maps_to` | control → compliance_framework | `controls.framework_id` FK | Control belongs to framework |
| `evaluated_by` | resource → control | `control_evaluations` | Resource evaluated against control |
| `materializes_to` | finding → issue | `issue_findings` junction | Finding(s) materialized into issue |
| `belongs_to` | resource → account | `resources.account_id` FK | Resource lives in account |
| `same_account` | resource → resource | Derived (same `account_id`) | Resources in same account |
| `same_region` | resource → resource | Derived (same `account_id` + `region`) | Resources co-located in region |

**Deferred edge types** (require infrastructure discovery):
- `accesses` (resource → resource) — IAM permission grants
- `exposes` (resource → resource) — Network exposure (public, cross-VPC)
- `depends_on` (resource → resource) — Service dependency
- `can_assume` (identity → identity) — IAM role assumption chain
- `has_permission` (identity → resource) — IAM permission to resource

### Edge Storage Strategy

A single `graph_edges` table stores all explicit edges:

```sql
CREATE TABLE graph_edges (
    id          UUID PRIMARY KEY,
    source_type VARCHAR(30) NOT NULL,  -- vertex label
    source_id   TEXT NOT NULL,         -- vertex PK
    target_type VARCHAR(30) NOT NULL,
    target_id   TEXT NOT NULL,
    edge_type   VARCHAR(50) NOT NULL,  -- relationship label
    properties  JSONB DEFAULT '{}',    -- weight, confidence, metadata
    tenant_id   VARCHAR(50) NOT NULL DEFAULT 'default',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (source_type, source_id, target_type, target_id, edge_type)
);
```

This design is intentionally generic — PuppyGraph maps each `edge_type` value as a separate edge label in its schema. Neptune migration requires only SELECT → batch INSERT.

Co-location edges (`same_account`, `same_region`) are materialized by a backfill query rather than maintained per-row, keeping the edge table bounded.

### Control Schema

```
Control {
    id              -- "CIS-AWS-2.1.1", "FSBP-S3.8", etc.
    framework_id    -- FK to compliance_frameworks
    title
    description
    category        -- IAM, Network, Encryption, Logging, Data, Compute
    severity        -- CRITICAL | HIGH | MEDIUM | LOW
    provider        -- aws | azure | gcp | * (universal)
    resource_types  -- ["storage", "database"] — what this control applies to
    eval_logic_ref  -- Reference to evaluation rule (OPA policy ID or built-in)
    auto_remediable -- Can this be auto-fixed?
    remediation_ref -- Link to remediation handler ID
    keywords        -- For finding-to-control matching (existing pattern)
    status          -- ACTIVE | DISABLED | DEPRECATED
}
```

**Evaluation model:** `ControlEvaluation` records per-resource, per-control pass/fail:

```
ControlEvaluation {
    control_id    -- FK to controls
    resource_id   -- FK to resources
    status        -- PASS | FAIL | ERROR | NOT_APPLICABLE
    evidence      -- Finding IDs that triggered FAIL
    evaluated_at  -- Timestamp of last evaluation
    tenant_id
}
```

Controls are seeded from the existing `internal/compliance` framework definitions (20+ frameworks, hundreds of controls). The `compliance.Manager.MapFinding()` method becomes the bridge — when it finds a matching control, it writes a `ControlEvaluation` with status=FAIL and links the finding.

### Issue Entity and Lifecycle

An Issue is a materialized, prioritized artifact aggregating one or more findings that violate the same control on the same resource:

```
Issue {
    id
    title
    description
    severity            -- Inherited from worst finding or control
    risk_score          -- Composite: severity × blast_radius × exposure_paths
    blast_radius        -- Count of downstream resources (graph-derived)
    status              -- OPEN | ACKNOWLEDGED | IN_PROGRESS | RESOLVED | SUPPRESSED
    control_id          -- Violated control (nullable — some issues are finding-only)
    resource_id         -- Primary affected resource
    finding_ids         -- Source findings (via junction table)
    attack_path_ids     -- Related attack paths
    assignee_id
    ticket_id           -- External ticket (Asana/Jira/ADO)
    sla_breach_at
    tenant_id
    created_at
    updated_at
    resolved_at
}
```

**Lifecycle:**

```
Scanner produces Finding
  → Ingestion pipeline deduplicates
  → Control evaluation: MapFinding() → ControlEvaluation(FAIL)
  → Issue materialization: dedup by (control_id, resource_id)
    - New issue if no existing open issue for this (control, resource)
    - Append finding to existing issue if one exists
  → Scoring: risk_score = severity_weight × blast_radius × exposure_factor
  → Assignment: auto-assign based on resource ownership or manual
  → Ticket creation: dispatch to Asana/Jira/ADO via existing IntegrationHandler
  → Resolution tracking: mark resolved when all source findings are resolved
  → Re-evaluation: next scan cycle re-evaluates controls, may reopen
```

**Dedup key:** `(control_id, resource_id, tenant_id)` — one open issue per control violation per resource per tenant.

### Attack Path Migration: Heuristic → Graph-Native

Current heuristic logic and its graph-native replacement:

| Heuristic (attackpath.go) | Graph-Native Equivalent |
|---------------------------|------------------------|
| `isEntryPoint(f)`: category=NETWORK, or VULNERABILITY+exploit, or compute/container CRIT/HIGH | `g.V().hasLabel('finding').or(has('category','NETWORK'), and(has('category','VULNERABILITY'), has('exploit_available',true)))` |
| `isTarget(f)`: resource_type in (storage, database, secret, encryption) | `g.V().hasLabel('resource').has('resource_type', within('storage','database','secret','encryption'))` |
| `canConnect(a,b)`: same account AND (same region OR same type) | Explicit `same_account` + `same_region` edges in `graph_edges`, plus future `accesses`/`exposes` edges |
| `buildChain(entry, intermediates, target)`: direct or 1-intermediate bridge | `g.V(entryFinding).out('affects').repeat(out('same_region','accesses','exposes').simplePath()).until(hasId(targetResource)).path().limit(10)` |
| `inferEdgeType(from, to)`: heuristic based on resource type/category | Replaced by explicit `edge_type` from `graph_edges` — no inference needed |
| Lateral movement: CRIT/HIGH pairs in same account | `g.V().hasLabel('finding').has('severity', within('CRITICAL','HIGH')).out('affects').out('same_account').in('affects').has('severity', within('CRITICAL','HIGH')).path()` |
| Blast radius: count of findings in path | `g.V(issueId).out('materializes_to').out('affects').out('same_region','accesses').dedup().count()` |

**Migration strategy:** Both engines coexist behind a feature flag. The Go BFS engine reads from `graph_edges` (replacing heuristic inference) for consistency, while PuppyGraph serves the same edges as native Gremlin traversals. The heuristic `canConnect()` is replaced by edge lookup, not removed — it becomes the edge materializer.

### Phase Plan

| Phase | Scope | Deliverables |
|-------|-------|-------------|
| **1 — Schema** (this PR) | Data model + types | Migration 007, Go types, PuppyGraph schema update, this ADR |
| **2 — Edge Materialization** | Populate graph_edges from existing data | Backfill script, ingestion pipeline writes edges on finding import, control evaluation writes edges |
| **3 — Issue Pipeline** | Materialization engine | Issue creation from control failures, dedup, scoring, lifecycle management |
| **4 — Graph-Native Paths** | Replace heuristic BFS | Gremlin query templates for path computation, blast radius, exposure analysis |
| **5 — Infrastructure Discovery** | Real topology edges | IAM analysis, network topology, dependency scanning → `accesses`, `exposes`, `depends_on` edges |

## Consequences

### Positive

- **Single data model** serves both relational queries (Postgres) and graph traversal (PuppyGraph/Neptune)
- **Explicit edges** replace heuristic inference — attack paths become evidence-based, not co-location guesses
- **Controls as first-class entities** enable compliance posture tracking per-resource, not just per-framework
- **Issues aggregate findings** — operators see 50 issues instead of 500 findings (noise reduction)
- **Clean migration path** to Neptune — edge table maps directly to property graph bulk load format

### Negative

- **Edge table growth** — O(findings × controls) evaluations, O(resources²) co-location edges. Mitigated by tenant scoping and materialization batching.
- **Two execution paths** (Go BFS + PuppyGraph Gremlin) during migration. Mitigated by shared edge data source.
- **PuppyGraph trial dependency** — expires 2026-04-18. Mitigated by Go BFS fallback and generic edge table design.

### Risks

| Risk | Impact | Mitigation |
|------|--------|-----------|
| PuppyGraph JDBC performance on deep traversal (>4 hops) | Slow attack path queries | Materialized co-location edges reduce hop depth; Neptune migration for production |
| Edge table bloat at 300K findings | Storage, query performance | Tenant-scoped indexes, periodic edge compaction, partition by tenant_id |
| Control evaluation latency on full scan | Ingestion pipeline slows | Async evaluation via goroutine pool, batch control evaluation |

## References

- ADR-008: Attack Path Computation Strategy
- ADR-015: Graph Query Engine (PuppyGraph)
- `cmd/server/attackpath.go` — current heuristic BFS engine
- `internal/graph/client.go` — PuppyGraph Gremlin/Cypher client
- `internal/compliance/framework.go` — existing Control struct and matching logic
- `internal/compliance/finding.go` — comprehensive Finding domain model
- `deploy/docker/puppygraph/schema.json` — current PuppyGraph vertex/edge schema
- `migrations/002_findings_and_compliance.sql` — findings + compliance tables
- `migrations/006_graph_support.sql` — resources table (PuppyGraph vertex source)
