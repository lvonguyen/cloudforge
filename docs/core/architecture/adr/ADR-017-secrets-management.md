# ADR-017: Secrets Management Architecture

## Status

Accepted

## Date

2026-03-20

## Deciders

Liem Vo-Nguyen

## Context

CloudForge handles multiple categories of secrets across its operational lifecycle:

1. **Platform secrets** — JWT signing keys, database credentials, API keys for AI providers (Anthropic, OpenAI), cloud provider credentials (AWS/Azure/GCP)
2. **Customer secrets** — API keys, OAuth tokens, and service account credentials discovered during CSPM scanning
3. **Remediation secrets** — Rollback state encryption keys, temporary credentials for executing remediations
4. **Operational secrets** — 1Password service account tokens, Fly.io deploy tokens, CI/CD pipeline secrets

The platform needs a secrets management strategy that:

- Abstracts secret storage behind an interface (Vault, AWS Secrets Manager, Azure Key Vault, 1Password)
- Supports automatic rotation with zero-downtime key rollover
- Encrypts sensitive state at rest (rollback snapshots, audit logs)
- Never exposes secrets in logs, API responses, or error messages

## Decision

Adopt a **provider-abstracted secrets interface** with encrypted state storage.

### Architecture

```go
type SecretsProvider interface {
    GetSecret(ctx context.Context, key string) (string, error)
    SetSecret(ctx context.Context, key, value string) error
    RotateSecret(ctx context.Context, key string) error
    ListSecrets(ctx context.Context, prefix string) ([]SecretMetadata, error)
}
```

### Implementation Layers

1. **SecretsProvider interface** (`internal/secrets/provider.go`) — abstract interface for all secret operations
2. **MemoryProvider** (`internal/secrets/memory_provider.go`) — in-memory implementation for testing (uses `crypto/rand` for UUID generation)
3. **EncryptedStateStore** (`internal/secrets/encrypted_state.go`) — AES-256-GCM encryption for rollback state snapshots with random nonce per operation
4. **Redaction** — `redactSecret()` produces `***REDACTED***` only; no partial prefix/suffix reveal (Sprint A security fix)
5. **POST /api/v1/secrets/scan** — scans request body for exposed credentials (changed from GET with query param, Sprint E)

### Encryption at Rest

Rollback state uses AES-256-GCM with:
- Key sourced from `AEGIS_STATE_ENCRYPTION_KEY` environment variable (32 bytes, hex-encoded)
- Random 12-byte nonce per encryption operation (never reused)
- Authenticated encryption prevents both tampering and information leakage
- Implements STRIDE threat T-02 (rollback state confidentiality)

### Secret Rotation Strategy

| Secret Type | Rotation Period | Method | Downtime |
|------------|----------------|--------|----------|
| JWT signing keys | 90 days | Dual-key overlap (old key valid for 24h after rotation) | Zero |
| Database passwords | 90 days | Blue-green connection pool swap | Zero |
| AI provider API keys | 180 days | Key regeneration via provider portal | < 1 min |
| 1Password SA token | 365 days | Token regeneration + env var update | < 1 min |
| Rollback encryption key | On compromise | Re-encrypt all active states with new key | < 5 min |

See runbook [07-secrets-rotation.md](../../runbooks/07-secrets-rotation.md) for step-by-step procedures.

## Consequences

### Positive

- Provider interface allows swapping between Vault, AWS Secrets Manager, and 1Password without code changes
- AES-256-GCM provides authenticated encryption — detects both tampering and corruption
- Full redaction eliminates partial secret leakage in logs and API responses
- crypto/rand for all random generation (no math/rand in security paths)

### Negative

- MemoryProvider is not suitable for production (secrets lost on restart)
- Vault/cloud KMS integration requires additional infrastructure and IAM configuration
- Dual-key rotation window increases key management complexity

### Risks

- Encryption key loss renders rollback states unrecoverable (mitigated by key backup in 1Password vault)
- In-memory provider in dev mode means secrets are not persisted across server restarts

## References

- ADR-010 (FinOps) — cost data may contain account identifiers requiring redaction
- STRIDE Threat Model T-02 (Rollback State Tampering)
- Runbook 07 (Secrets Rotation)

---

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2026-03-20 | Liem Vo-Nguyen | Initial ADR |
