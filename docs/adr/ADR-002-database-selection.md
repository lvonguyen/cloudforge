# ADR-002: Database Selection

## Status

Accepted

## Date

2026-01-05

## Context

We need to select a database for storing:
- Security findings (millions of records)
- Compliance framework mappings
- Audit logs
- User and configuration data

### Requirements
- Handle millions of findings with complex queries
- Support JSONB for flexible finding schemas
- Strong consistency for compliance data
- Partitioning for time-series finding data
- Full-text search for finding descriptions

### Options Considered

1. **PostgreSQL** - Relational, JSONB support, mature
2. **MySQL** - Relational, widely used, JSON support
3. **MongoDB** - Document store, flexible schema
4. **DynamoDB** - Serverless, key-value/document

## Decision

We will use **PostgreSQL 16** as the primary database.

## Rationale

### JSONB Support
- First-class JSONB with indexing (GIN indexes)
- Query JSONB fields with SQL
- Efficient storage with compression

### Partitioning
- Built-in table partitioning by date range
- Automatic partition pruning for time-based queries
- Easy archival of old partitions

### Full-Text Search
- Built-in tsvector for full-text search
- pg_trgm extension for fuzzy matching
- No need for separate search infrastructure

### Ecosystem
- Extensive extension ecosystem (PostGIS, pg_stat_statements)
- Strong AWS RDS, Azure, GCP support
- Proven at scale (Instagram, Discord, etc.)

### Cost
- Open source with no license fees
- RDS costs ~$0.115/hour for db.t3.medium

## Consequences

### Positive
- Single database for all data types
- SQL familiarity for developers
- Strong consistency and ACID compliance
- Excellent query optimizer

### Negative
- Vertical scaling limits (read replicas help)
- Schema migrations require planning
- Connection pooling needed at scale

### Mitigations
- Use PgBouncer for connection pooling
- Implement read replicas for query scaling
- Use Flyway/golang-migrate for migrations

## Alternatives for Future

If we need >100K TPS or global distribution:
- Add DynamoDB for high-velocity finding ingestion
- Add read replicas for query scaling
- Consider CockroachDB for multi-region active-active

## Related Decisions

- ADR-003: Caching Strategy
- ADR-006: Data Retention Policy

