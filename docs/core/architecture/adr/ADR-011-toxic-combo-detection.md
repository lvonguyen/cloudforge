# ADR-011: Toxic Combination Detection Strategy

## Status

Accepted

## Date

2026-03-04

## Context

Individual security findings often appear low-severity in isolation but become critical when combined. For example, a public S3 bucket (medium) combined with sensitive data classification (low) creates a data breach risk (critical). Industry leaders (Wiz, Orca, GCP SCC v2) have adopted "toxic combination" detection as a core differentiator.

CloudForge already has:
- Finding normalization across AWS/Azure/GCP
- Attack path computation with BFS traversal
- Per-finding severity scoring with AI enrichment

The question is: how to detect and surface toxic combinations efficiently within the existing architecture.

### Requirements

- Detect combinations across findings within the same account
- Support configurable pattern definitions (not hardcoded)
- Integrate with attack path computation (toxic combos as graph edges)
- Produce actionable output (which findings combine, what the composite risk is)

## Decision

**Pattern-based toxic combination detection** was selected, implemented in `internal/cspm/scoring/toxic_combos.go` with 4 initial patterns:

### Pattern Definitions

| ID | Pattern | Component A | Component B | Composite Severity |
|----|---------|------------|------------|-------------------|
| TC-001 | Public Storage + Sensitive Data | Public S3/Blob/GCS | Data classification finding | CRITICAL |
| TC-002 | IAM Escalation + No MFA | IAM privilege escalation | MFA not enforced | CRITICAL |
| TC-003 | Internet Exposure + Known CVE | Network exposure finding | CVE with EPSS > 0.5 | CRITICAL |
| TC-004 | Security Group Gap + Database | Permissive SG (0.0.0.0/0) | Database resource | HIGH |

### Detection Algorithm

```
FOR each finding F in account:
  FOR each pattern P:
    IF F matches P.componentA:
      SCAN remaining findings in same account for P.componentB match
      IF match found:
        CREATE ToxicCombo{PatternID, FindingA, FindingB, CompositeSeverity}
        ANNOTATE both findings with ToxicComboFlag=true
```

### Integration Points

1. **Attack Path Engine**: Toxic combos create weighted edges in the BFS graph
2. **Risk Scorer**: `ToxicComboDetails` struct on Finding includes pattern ID, related findings, and composite severity
3. **Frontend**: Toxic combo badge displayed on affected findings and attack paths

## Consequences

### Positive

- **Noise reduction**: Collapses multiple medium findings into one critical action item
- **Aligns with industry**: Matches Wiz/Orca/GCP SCC v2 toxic combination features
- **Configurable**: New patterns added by defining component matchers, no code changes to detection engine
- **Sub-millisecond**: Pattern matching is O(n*p) where n=findings, p=patterns (4) — negligible overhead

### Negative

- **False positives**: Heuristic matching may flag unrelated findings in the same account
- **Limited to same-account**: Cross-account toxic combos not detected (requires trust chain data)
- **Pattern maintenance**: New attack techniques require new pattern definitions

### Mitigations

- FP suppression rules in `fp_rules.go` can whitelist specific resource+pattern combinations
- Cross-account detection deferred to production (requires organizational trust chain graph)
- Pattern library designed for easy extension

## Alternatives Considered

### 1. AI-Only Detection

Use LLM to analyze all findings in an account and identify dangerous combinations.

**Rejected because**: Too expensive for real-time detection (requires sending all findings to LLM per account). Pattern-based detection runs in microseconds; AI is used for enrichment after detection.

### 2. Graph Database Queries (Neo4j)

Store all findings as nodes with relationship edges, use Cypher queries for pattern matching.

**Deferred because**: Adds Neo4j dependency for a pattern that works efficiently in-memory. The same patterns can be expressed as Cypher queries when the graph database is introduced at production scale.

## References

- `internal/cspm/scoring/toxic_combos.go` — Pattern definitions and detection engine
- `internal/cspm/scoring/toxic_combos_test.go` — Test cases for all 4 patterns
- `internal/cspm/scoring/blast_radius.go` — Account/VPC/transit reachability computation
- `internal/cspm/scoring/fp_rules.go` — False positive suppression rules
- [ADR-008](ADR-008-attack-path-computation.md) — Attack path computation strategy
