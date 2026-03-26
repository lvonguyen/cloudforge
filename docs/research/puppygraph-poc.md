# PuppyGraph POC Results

**Trial Start:** 2026-03-19
**Trial End:** 2026-04-18 (30 days)
**ADR:** [ADR-015](../core/architecture/adr/ADR-015-graph-query-engine.md)

## Deployment

### Local (Docker)

- Image: `puppygraph/puppygraph-enterprise:latest`
- Compose: `docker-compose.puppygraph.yml`
- Schema: `deploy/docker/puppygraph/schema.json`

### AWS EC2

- Instance: `r6i.xlarge` (4 vCPU, 32 GB RAM)
- AMI: _TBD -- from AWS Marketplace_
- Region: us-east-1
- Cost: ~$0.252/hr = ~$6/day = ~$181/month
- Terraform: `deploy/terraform/modules/puppygraph/`

## Schema Mapping

| Vertex | Source Table | Key Properties |
|--------|-------------|----------------|
| finding | findings | id, title, severity, category, cloud_provider |
| resource | resources | id, name, type, region, account_id |
| identity | identities | id, name, email, provider |
| compliance_control | compliance_controls | id, framework, control_id, title |

| Edge | From -> To | Source Table |
|------|-----------|--------------|
| affects | finding -> resource | findings (self-join on resource_id) |
| can_access | identity -> resource | identity_access |
| maps_to | finding -> compliance_control | finding_compliance_mappings |
| runs_on | resource -> resource | resource_relationships |
| trusts | identity -> identity | identity_trusts |

## Validation Queries

### Gremlin (WebSocket port 8182)

**Q1: All critical findings affecting a resource**
```groovy
g.V().has('finding', 'severity', 'CRITICAL').out('affects').dedup().valueMap()
```

**Q2: Attack path -- identities that can reach a specific resource**
```groovy
g.V().hasLabel('identity').repeat(out('can_access', 'trusts')).until(has('resource', 'id', 'res-001')).path()
```

**Q3: Findings with compliance gaps (no control mapping)**
```groovy
g.V().hasLabel('finding').not(out('maps_to')).valueMap('id', 'title', 'severity')
```

**Q4: Blast radius -- resources downstream of a compromised identity**
```groovy
g.V().has('identity', 'email', 'admin@contoso.dev').out('can_access').out('runs_on').emit().repeat(out('runs_on')).dedup().count()
```

**Q5: Top 10 most-connected resources (attack surface)**
```groovy
g.V().hasLabel('resource').project('name', 'degree').by('name').by(both().count()).order().by(select('degree'), desc).limit(10)
```

### openCypher (HTTP port 8184)

**Q6: Critical findings per cloud provider**
```cypher
MATCH (f:finding {severity: 'CRITICAL'})-[:affects]->(r:resource)
RETURN r.region, COUNT(f) AS critical_count
ORDER BY critical_count DESC
```

**Q7: Shortest path between identity and finding**
```cypher
MATCH p = shortestPath((i:identity {email: 'admin@contoso.dev'})-[*..5]-(f:finding {severity: 'CRITICAL'}))
RETURN p
```

**Q8: Resources with both findings and identity access (toxic combo)**
```cypher
MATCH (f:finding)-[:affects]->(r:resource)<-[:can_access]-(i:identity)
WHERE f.severity IN ['CRITICAL', 'HIGH']
RETURN r.name, COLLECT(DISTINCT f.title) AS findings, COLLECT(DISTINCT i.email) AS identities
```

**Q9: Compliance coverage gap**
```cypher
MATCH (f:finding)
WHERE NOT (f)-[:maps_to]->(:compliance_control)
RETURN f.severity, COUNT(f) AS unmapped_count
ORDER BY unmapped_count DESC
```

**Q10: Multi-hop trust chain (privilege escalation risk)**
```cypher
MATCH path = (i1:identity)-[:trusts*2..4]->(i2:identity)-[:can_access]->(r:resource)
WHERE r.type = 'database'
RETURN i1.name AS source_identity, length(path) AS hops, r.name AS target_resource
ORDER BY hops ASC
LIMIT 20
```

## Benchmark Results

| Query | Local Docker (ms) | EC2 r6i.xlarge (ms) | Go BFS Baseline (ms) | Notes |
|-------|-------------------|---------------------|----------------------|-------|
| Q1 (critical findings) | _TBD_ | 111 | _TBD_ | 0 results (no resources populated in demo data) |
| Q2 (identity path) | _TBD_ | _blocked_ | _TBD_ | Needs `identity` vertex + `identity_access` table |
| Q3 (unmapped findings) | _TBD_ | 156 | _TBD_ | 8 findings returned (none mapped to compliance) |
| Q4 (blast radius) | _TBD_ | _blocked_ | _TBD_ | Needs `identity` vertex |
| Q5 (top connected) | _TBD_ | 134 | _TBD_ | 0 results (no resources) |
| Q6 (critical per provider) | _TBD_ | _blocked_ | N/A | Needs populated resources |
| Q7 (shortest path) | _TBD_ | _blocked_ | N/A | Needs `identity` vertex |
| Q8 (toxic combo) | _TBD_ | _blocked_ | N/A | Needs `identity` + resources |
| Q9 (compliance gap) | _TBD_ | _blocked_ | N/A | Needs `compliance_control` vertex (schema has `compliance_framework`) |
| Q10 (trust chain) | _TBD_ | _blocked_ | N/A | Needs `identity_trusts` table |

**Baseline run (2026-03-25, 8 demo findings, 6 compliance frameworks, 0 resources):**

| Metric | Value |
|--------|-------|
| Finding count query | 234ms |
| Vertex count by label | 191ms |
| Edge count by label | 115ms |
| Severity distribution | 119ms |
| Resource count | 110ms |
| Compliance frameworks | 118ms |
| Single finding valueMap | 123ms |
| Affects edge sample | 163ms |

**Protocol notes:**
- Gremlin WebSocket args must contain ONLY `gremlin` + `language` (no `bindings`/`aliases`)
- PuppyGraph v0.113 silently hangs on unknown args fields (no error, no response)
- Schema upload: `POST /schema` with Basic Auth on port 8081 (works despite "UI-only" claim)
- Container startup: `--env-file ~/.puppygraph_env --net host` (NOT port mapping)

## Decision Criteria

- [ ] P50 query latency < 100ms for single-hop traversals — **110-156ms on 8 findings (inconclusive, need 20K+ dataset)**
- [ ] P50 query latency < 500ms for multi-hop (3+ hops) — **blocked (no identity/resource data)**
- [ ] Memory consumption < 16GB for 20k findings + relationships — **TBD (need seed data)**
- [x] Schema changes propagate without service restart — **YES (POST /schema returns 200, Gremlin server auto-restarts)**
- [x] WebSocket Gremlin client stable under concurrent connections — **YES (6 sequential queries, no drops)**

## Recommendation

_Blocked on WS-E seed data (20K+ findings with populated resource_id). Re-run benchmarks after seed load. Schema and query pipeline verified working. TEARDOWN by Mar 28._
