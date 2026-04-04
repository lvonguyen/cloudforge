# ADR-016: Container Security Scanning Architecture

## Status

Accepted

## Date

2026-03-20

## Deciders

Liem Vo-Nguyen

## Context

CloudForge manages infrastructure across AWS, Azure, and GCP where containerized workloads (EKS, AKS, GKE) constitute a significant attack surface. Container images may contain:

- Known CVEs in base images or application dependencies
- Misconfigured K8s RBAC or pod security standards
- Leaked secrets embedded in image layers
- Outdated packages with public exploits

The platform needs a container scanning strategy that integrates with the existing findings pipeline, remediation dispatcher, and compliance framework engine.

### Requirements

1. Scan container images for CVE, secret, and misconfiguration findings
2. Parse scan results into the unified Finding type for dashboard display
3. Support both registry-level scanning (pre-deploy) and runtime topology inspection
4. Integrate with the existing remediation handler interface for automated patching guidance
5. Present K8s cluster topology (namespaces, deployments, pods) in the portal

## Decision

Adopt a **Trivy-based scanning pipeline** with a Go scanner interface abstraction.

### Architecture

- `internal/container/scanner.go` — `Scanner` interface with `ScanImage(ref string) ([]Finding, error)` method
- `internal/container/trivy.go` — Trivy JSON output parser (reads from `TRIVY_OUTPUT_PATH` env var or executes `trivy image --format json`)
- `internal/container/topology.go` — K8s cluster topology model (Cluster > Namespace > Deployment > Pod)
- `GET /api/v1/containers` — returns cluster topology with vulnerability summary per node
- Findings from container scans are normalized into the standard `Finding` type and flow through the same enrichment, dedup, and compliance mapping pipeline

### Scanner Interface

```go
type Scanner interface {
    ScanImage(ctx context.Context, ref string) ([]finding.Finding, error)
    ListClusters(ctx context.Context) ([]Cluster, error)
}
```

### Image Reference Validation

Container image references are validated against a regex allowlist before being passed to the scanner binary to prevent command injection:

```
^[a-zA-Z0-9][a-zA-Z0-9._/-]*:[a-zA-Z0-9._-]+$
```

## Consequences

### Positive

- Trivy is open-source, well-maintained, and covers CVE + secret + misconfiguration scanning in a single tool
- The Scanner interface allows swapping to Grype, Snyk, or cloud-native scanners (ECR scanning, Azure Defender) without changing the handler layer
- Container findings flow through the same pipeline as cloud findings — no separate dashboard or data model needed

### Negative

- Trivy binary must be available in the deployment environment (added to Dockerfile)
- Large image scans can be slow (>30s for images with many layers) — need timeout handling
- Runtime topology requires K8s API access (RBAC permissions for listing pods, deployments)

### Risks

- Trivy database update lag may miss zero-day CVEs (mitigated by CISA KEV cross-reference)
- K8s API permissions must be scoped carefully (read-only service account)

## References

- ADR-009 (Remediation Dispatcher) — container findings feed into remediation pipeline
- ADR-014 (Event-Driven Ingestion) — container scan results can be ingested via the same endpoint
- `internal/container/` package implementation

---

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2026-03-20 | Liem Vo-Nguyen | Initial ADR |
