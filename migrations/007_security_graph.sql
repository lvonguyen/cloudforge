-- migrations/007_security_graph.sql
-- Security Graph data model: controls, control evaluations, issues, and explicit graph edges.
-- Extends ADR-020 (Security Graph Architecture).

-- Cloud accounts (vertex source for PuppyGraph)
CREATE TABLE IF NOT EXISTS accounts (
    id              VARCHAR(50) PRIMARY KEY,    -- AWS account ID, GCP project ID, Azure subscription ID
    name            VARCHAR(255),
    cloud_provider  VARCHAR(10) NOT NULL,
    environment_type VARCHAR(20),               -- production, staging, development
    tenant_id       VARCHAR(50) NOT NULL DEFAULT 'default',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_accounts_provider ON accounts(cloud_provider);
CREATE INDEX IF NOT EXISTS idx_accounts_tenant ON accounts(tenant_id);

-- Backfill accounts from existing findings
INSERT INTO accounts (id, name, cloud_provider, environment_type, tenant_id)
SELECT DISTINCT ON (account_id)
    account_id,
    COALESCE(account_name, account_id),
    cloud_provider,
    environment_type,
    COALESCE(tenant_id, 'default')
FROM findings
WHERE account_id IS NOT NULL AND account_id != ''
ON CONFLICT (id) DO NOTHING;

-- Security controls (evaluable rules derived from compliance frameworks)
CREATE TABLE IF NOT EXISTS controls (
    id              VARCHAR(100) PRIMARY KEY,   -- e.g., "CIS-AWS-2.1.1", "FSBP-S3.8"
    framework_id    VARCHAR(50) NOT NULL REFERENCES compliance_frameworks(id) ON DELETE CASCADE,
    title           TEXT NOT NULL,
    description     TEXT,
    category        VARCHAR(30),                -- IAM, Network, Encryption, Logging, Data, Compute
    severity        VARCHAR(10) NOT NULL DEFAULT 'MEDIUM',
    provider        VARCHAR(10) DEFAULT '*',    -- aws, azure, gcp, * (universal)
    resource_types  TEXT[] DEFAULT '{}',         -- resource types this control applies to
    eval_logic_ref  TEXT,                        -- OPA policy ID or built-in evaluator name
    auto_remediable BOOLEAN DEFAULT FALSE,
    remediation_ref TEXT,                        -- remediation handler ID
    keywords        TEXT[] DEFAULT '{}',         -- for finding-to-control matching
    status          VARCHAR(20) NOT NULL DEFAULT 'ACTIVE',
    tenant_id       VARCHAR(50) NOT NULL DEFAULT 'default',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT valid_control_severity CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')),
    CONSTRAINT valid_control_status CHECK (status IN ('ACTIVE', 'DISABLED', 'DEPRECATED'))
);

CREATE INDEX IF NOT EXISTS idx_controls_framework ON controls(framework_id);
CREATE INDEX IF NOT EXISTS idx_controls_category ON controls(category);
CREATE INDEX IF NOT EXISTS idx_controls_provider ON controls(provider);
CREATE INDEX IF NOT EXISTS idx_controls_tenant ON controls(tenant_id);

-- Control evaluations: per-resource, per-control pass/fail state
CREATE TABLE IF NOT EXISTS control_evaluations (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    control_id      VARCHAR(100) NOT NULL REFERENCES controls(id) ON DELETE CASCADE,
    resource_id     TEXT NOT NULL,               -- FK to resources.id (not enforced — resource may not exist yet)
    status          VARCHAR(20) NOT NULL DEFAULT 'FAIL',
    evidence        TEXT[] DEFAULT '{}',         -- finding IDs that triggered FAIL
    evaluated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    tenant_id       VARCHAR(50) NOT NULL DEFAULT 'default',

    CONSTRAINT valid_eval_status CHECK (status IN ('PASS', 'FAIL', 'ERROR', 'NOT_APPLICABLE')),
    CONSTRAINT unique_control_resource UNIQUE (control_id, resource_id, tenant_id)
);

CREATE INDEX IF NOT EXISTS idx_eval_control ON control_evaluations(control_id);
CREATE INDEX IF NOT EXISTS idx_eval_resource ON control_evaluations(resource_id);
CREATE INDEX IF NOT EXISTS idx_eval_status ON control_evaluations(status);
CREATE INDEX IF NOT EXISTS idx_eval_tenant ON control_evaluations(tenant_id);

-- Security issues: materialized prioritized entities from findings + control failures
CREATE TABLE IF NOT EXISTS issues (
    id              VARCHAR(30) PRIMARY KEY,     -- e.g., "ISS-00001"
    title           TEXT NOT NULL,
    description     TEXT,
    severity        VARCHAR(10) NOT NULL DEFAULT 'MEDIUM',
    risk_score      NUMERIC(6,2) DEFAULT 0,      -- composite score
    blast_radius    INT DEFAULT 0,               -- downstream resource count (graph-derived)
    status          VARCHAR(20) NOT NULL DEFAULT 'OPEN',
    control_id      VARCHAR(100) REFERENCES controls(id) ON DELETE SET NULL,
    resource_id     TEXT,                         -- primary affected resource
    account_id      VARCHAR(50),
    provider        VARCHAR(10),
    assignee_id     TEXT,
    ticket_id       TEXT,                         -- external ticket reference (Asana/Jira/ADO)
    ticket_url      TEXT,
    sla_breach_at   TIMESTAMPTZ,
    exposure_paths  INT DEFAULT 0,               -- attack paths through this issue
    tenant_id       VARCHAR(50) NOT NULL DEFAULT 'default',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved_at     TIMESTAMPTZ,

    CONSTRAINT valid_issue_severity CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')),
    CONSTRAINT valid_issue_status CHECK (status IN ('OPEN', 'ACKNOWLEDGED', 'IN_PROGRESS', 'RESOLVED', 'SUPPRESSED'))
);

CREATE INDEX IF NOT EXISTS idx_issues_severity ON issues(severity);
CREATE INDEX IF NOT EXISTS idx_issues_status ON issues(status);
CREATE INDEX IF NOT EXISTS idx_issues_control ON issues(control_id);
CREATE INDEX IF NOT EXISTS idx_issues_resource ON issues(resource_id);
CREATE INDEX IF NOT EXISTS idx_issues_account ON issues(account_id);
CREATE INDEX IF NOT EXISTS idx_issues_tenant ON issues(tenant_id);
CREATE INDEX IF NOT EXISTS idx_issues_sla ON issues(sla_breach_at) WHERE sla_breach_at IS NOT NULL;

-- Junction: findings that contribute to an issue
CREATE TABLE IF NOT EXISTS issue_findings (
    issue_id    VARCHAR(30) NOT NULL REFERENCES issues(id) ON DELETE CASCADE,
    finding_id  VARCHAR(20) NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (issue_id, finding_id)
);

-- Explicit graph edges (generic edge table for PuppyGraph federation)
CREATE TABLE IF NOT EXISTS graph_edges (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source_type VARCHAR(30) NOT NULL,            -- vertex label: finding, resource, control, issue, account
    source_id   TEXT NOT NULL,
    target_type VARCHAR(30) NOT NULL,
    target_id   TEXT NOT NULL,
    edge_type   VARCHAR(50) NOT NULL,            -- affects, violates, belongs_to, same_account, etc.
    properties  JSONB DEFAULT '{}',              -- weight, confidence, metadata
    tenant_id   VARCHAR(50) NOT NULL DEFAULT 'default',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT unique_edge UNIQUE (source_type, source_id, target_type, target_id, edge_type, tenant_id)
);

CREATE INDEX IF NOT EXISTS idx_edges_source ON graph_edges(source_type, source_id);
CREATE INDEX IF NOT EXISTS idx_edges_target ON graph_edges(target_type, target_id);
CREATE INDEX IF NOT EXISTS idx_edges_type ON graph_edges(edge_type);
CREATE INDEX IF NOT EXISTS idx_edges_tenant ON graph_edges(tenant_id);

-- Backfill: finding → resource edges (affects)
INSERT INTO graph_edges (id, source_type, source_id, target_type, target_id, edge_type, tenant_id)
SELECT
    gen_random_uuid(),
    'finding',
    f.id,
    'resource',
    f.resource_id,
    'affects',
    COALESCE(f.tenant_id, 'default')
FROM findings f
WHERE f.resource_id IS NOT NULL AND f.resource_id != ''
ON CONFLICT DO NOTHING;

-- Backfill: resource → account edges (belongs_to)
INSERT INTO graph_edges (id, source_type, source_id, target_type, target_id, edge_type, tenant_id)
SELECT
    gen_random_uuid(),
    'resource',
    r.id,
    'account',
    r.account_id,
    'belongs_to',
    COALESCE(r.tenant_id, 'default')
FROM resources r
WHERE r.account_id IS NOT NULL AND r.account_id != ''
ON CONFLICT DO NOTHING;

-- Backfill: finding → compliance_framework edges (maps_to) from existing junction
INSERT INTO graph_edges (id, source_type, source_id, target_type, target_id, edge_type, tenant_id)
SELECT
    gen_random_uuid(),
    'finding',
    cm.finding_id,
    'compliance_framework',
    cm.framework_id,
    'maps_to',
    'default'
FROM compliance_mappings cm
ON CONFLICT DO NOTHING;

-- Triggers
CREATE TRIGGER accounts_updated_at
    BEFORE UPDATE ON accounts
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER controls_updated_at
    BEFORE UPDATE ON controls
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER issues_updated_at
    BEFORE UPDATE ON issues
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- Comments
COMMENT ON TABLE accounts IS 'Cloud accounts/projects/subscriptions — graph vertex source (ADR-020)';
COMMENT ON TABLE controls IS 'Evaluable security controls derived from compliance frameworks (ADR-020)';
COMMENT ON TABLE control_evaluations IS 'Per-resource, per-control pass/fail evaluation state (ADR-020)';
COMMENT ON TABLE issues IS 'Materialized prioritized security issues aggregating findings + control failures (ADR-020)';
COMMENT ON TABLE issue_findings IS 'Junction linking issues to their source findings (ADR-020)';
COMMENT ON TABLE graph_edges IS 'Explicit typed edges for security graph — PuppyGraph projects each edge_type as a native graph edge (ADR-020)';
