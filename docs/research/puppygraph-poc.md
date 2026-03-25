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

| Query | Local Docker (ms) | EC2 r6i.xlarge (ms) | Go BFS Baseline (ms) |
|-------|-------------------|---------------------|----------------------|
| Q1 (critical findings) | _TBD_ | _TBD_ | _TBD_ |
| Q2 (identity path) | _TBD_ | _TBD_ | _TBD_ |
| Q3 (unmapped findings) | _TBD_ | _TBD_ | _TBD_ |
| Q4 (blast radius) | _TBD_ | _TBD_ | _TBD_ |
| Q5 (top connected) | _TBD_ | _TBD_ | _TBD_ |
| Q6 (critical per provider) | _TBD_ | _TBD_ | N/A |
| Q7 (shortest path) | _TBD_ | _TBD_ | N/A |
| Q8 (toxic combo) | _TBD_ | _TBD_ | N/A |
| Q9 (compliance gap) | _TBD_ | _TBD_ | N/A |
| Q10 (trust chain) | _TBD_ | _TBD_ | N/A |

## Decision Criteria

- [ ] P50 query latency < 100ms for single-hop traversals
- [ ] P50 query latency < 500ms for multi-hop (3+ hops)
- [ ] Memory consumption < 16GB for 20k findings + relationships
- [ ] Schema changes propagate without service restart
- [ ] WebSocket Gremlin client stable under concurrent connections

## Recommendation

_To be filled after benchmarks._
