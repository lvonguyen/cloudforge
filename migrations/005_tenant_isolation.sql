-- Migration 005: Multi-tenant data isolation (ADR-019)
--
-- Adds tenant_id and tenant_name columns to all query-scoped tables to
-- enforce data isolation at the database layer. Previously, tenant filtering
-- was only enforced at the middleware/context level, leaving the data layer
-- vulnerable to cross-tenant access if middleware was bypassed.
--
-- Default value 'default' allows backward-compatible single-tenant operation.
-- tenant_name is denormalized for self-describing records (no join required).

-- Exception management tables
ALTER TABLE exception_requests ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(50) NOT NULL DEFAULT 'default';
ALTER TABLE exception_requests ADD COLUMN IF NOT EXISTS tenant_name VARCHAR(255) NOT NULL DEFAULT '';
ALTER TABLE approval_chain ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(50) NOT NULL DEFAULT 'default';
ALTER TABLE exception_audit_log ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(50) NOT NULL DEFAULT 'default';

-- Risk assessments and compensating controls
ALTER TABLE risk_assessments ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(50) NOT NULL DEFAULT 'default';
ALTER TABLE compensating_controls ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(50) NOT NULL DEFAULT 'default';

-- Findings and compliance
ALTER TABLE findings ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(50) NOT NULL DEFAULT 'default';
ALTER TABLE findings ADD COLUMN IF NOT EXISTS tenant_name VARCHAR(255) NOT NULL DEFAULT '';
ALTER TABLE compliance_frameworks ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(50) NOT NULL DEFAULT 'default';

-- Operations tables
ALTER TABLE ai_agents ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(50) NOT NULL DEFAULT 'default';
ALTER TABLE agent_traces ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(50) NOT NULL DEFAULT 'default';
ALTER TABLE remediations ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(50) NOT NULL DEFAULT 'default';
ALTER TABLE remediations ADD COLUMN IF NOT EXISTS tenant_name VARCHAR(255) NOT NULL DEFAULT '';
ALTER TABLE cost_summaries ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(50) NOT NULL DEFAULT 'default';
ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(50) NOT NULL DEFAULT 'default';
ALTER TABLE audit_log ADD COLUMN IF NOT EXISTS tenant_name VARCHAR(255) NOT NULL DEFAULT '';

-- Indexes for tenant-scoped queries (covering index on tenant_id + created_at
-- for the most common query pattern: list-by-tenant ordered by recency).
CREATE INDEX IF NOT EXISTS idx_exception_requests_tenant ON exception_requests (tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_findings_tenant ON findings (tenant_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_tenant ON audit_log (tenant_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_remediations_tenant ON remediations (tenant_id);
CREATE INDEX IF NOT EXISTS idx_agent_traces_tenant ON agent_traces (tenant_id);
CREATE INDEX IF NOT EXISTS idx_cost_summaries_tenant ON cost_summaries (tenant_id);
