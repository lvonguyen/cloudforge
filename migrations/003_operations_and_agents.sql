-- migrations/003_operations_and_agents.sql
-- AI agent inventory, execution traces, remediation tracking, cost summaries,
-- audit log, and user accounts for CloudForge operational dashboards

-- AI agent registry
CREATE TABLE ai_agents (
    id                  UUID PRIMARY KEY,
    name                VARCHAR(255) NOT NULL,
    description         TEXT,
    framework           VARCHAR(50),
    version             VARCHAR(20),
    owner               VARCHAR(255),
    team                VARCHAR(100),
    environment         VARCHAR(20),
    capabilities        JSONB DEFAULT '[]',
    tools               JSONB DEFAULT '[]',
    policies            TEXT[],
    risk_level          VARCHAR(20),
    status              VARCHAR(20) NOT NULL DEFAULT 'active',
    last_active_at      TIMESTAMPTZ,
    total_invocations   BIGINT DEFAULT 0,
    avg_latency_ms      INT DEFAULT 0,
    error_rate          NUMERIC(5,4) DEFAULT 0,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT valid_agent_status CHECK (status IN ('active', 'inactive', 'suspended', 'deprecated')),
    CONSTRAINT valid_risk_level CHECK (risk_level IN ('low', 'medium', 'high', 'critical'))
);

-- Agent execution traces (OTel-aligned)
CREATE TABLE agent_traces (
    id                  VARCHAR(50) PRIMARY KEY,
    agent_id            UUID NOT NULL REFERENCES ai_agents(id) ON DELETE CASCADE,
    session_id          VARCHAR(100),
    user_id             VARCHAR(255),
    status              VARCHAR(20) NOT NULL,
    started_at          TIMESTAMPTZ NOT NULL,
    completed_at        TIMESTAMPTZ,
    duration_ms         INT,
    token_count         INT DEFAULT 0,
    estimated_cost_usd  NUMERIC(10,4),
    spans               JSONB DEFAULT '[]',
    security_signals    JSONB DEFAULT '[]',
    metrics             JSONB DEFAULT '{}',
    metadata            JSONB DEFAULT '{}',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT valid_trace_status CHECK (status IN ('running', 'completed', 'failed', 'blocked'))
);

-- Remediation actions linked to findings
CREATE TABLE remediations (
    id                  VARCHAR(20) PRIMARY KEY,
    finding_id          VARCHAR(20) NOT NULL,
    domain              VARCHAR(50),
    handler             VARCHAR(100),
    tier                INT NOT NULL,
    status              VARCHAR(20) NOT NULL DEFAULT 'pending',
    result              JSONB,
    validation          JSONB,
    asana_task_url      TEXT,
    executor_email      VARCHAR(255),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT valid_remediation_status CHECK (status IN ('pending', 'in_progress', 'completed', 'failed', 'skipped')),
    CONSTRAINT valid_tier CHECK (tier BETWEEN 1 AND 3)
);

-- Aggregated cloud cost data by provider/service/period
CREATE TABLE cost_summaries (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    period_start        DATE NOT NULL,
    period_end          DATE NOT NULL,
    cloud_provider      VARCHAR(10) NOT NULL,
    account_id          VARCHAR(50),
    service             VARCHAR(100),
    amount              NUMERIC(12,2) NOT NULL,
    currency            VARCHAR(3) DEFAULT 'USD',
    tags                JSONB DEFAULT '{}',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT valid_cost_provider CHECK (cloud_provider IN ('aws', 'azure', 'gcp'))
);

-- Platform-wide audit log (immutable)
CREATE TABLE audit_log (
    id                  VARCHAR(20) PRIMARY KEY,
    action              VARCHAR(50) NOT NULL,
    actor_email         VARCHAR(255) NOT NULL,
    actor_role          VARCHAR(20),
    target_type         VARCHAR(50),
    target_id           VARCHAR(255),
    result              VARCHAR(20) NOT NULL,
    details             JSONB DEFAULT '{}',
    ip_address          INET,
    timestamp           TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT valid_audit_result CHECK (result IN ('success', 'denied', 'error'))
);

-- Platform user accounts
CREATE TABLE users (
    id                  VARCHAR(20) PRIMARY KEY,
    email               VARCHAR(255) NOT NULL UNIQUE,
    name                VARCHAR(255) NOT NULL,
    role                VARCHAR(20) NOT NULL,
    department          VARCHAR(100),
    team                VARCHAR(100),
    last_login          TIMESTAMPTZ,
    status              VARCHAR(20) DEFAULT 'active',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT valid_user_role CHECK (role IN ('admin', 'operator', 'requester')),
    CONSTRAINT valid_user_status CHECK (status IN ('active', 'inactive'))
);

-- Indexes for common queries
CREATE INDEX idx_agents_status ON ai_agents(status);
CREATE INDEX idx_agents_team ON ai_agents(team);
CREATE INDEX idx_agents_risk_level ON ai_agents(risk_level);

CREATE INDEX idx_traces_agent_id ON agent_traces(agent_id);
CREATE INDEX idx_traces_started_at ON agent_traces(started_at);
CREATE INDEX idx_traces_status ON agent_traces(status);

CREATE INDEX idx_remediations_finding ON remediations(finding_id);
CREATE INDEX idx_remediations_status ON remediations(status);
CREATE INDEX idx_remediations_tier ON remediations(tier);
CREATE INDEX idx_remediations_created ON remediations(created_at);

CREATE INDEX idx_costs_provider ON cost_summaries(cloud_provider);
CREATE INDEX idx_costs_period ON cost_summaries(period_start);
CREATE INDEX idx_costs_account ON cost_summaries(account_id);

CREATE INDEX idx_audit_action ON audit_log(action);
CREATE INDEX idx_audit_actor ON audit_log(actor_email);
CREATE INDEX idx_audit_log_timestamp ON audit_log(timestamp);
CREATE INDEX idx_audit_result ON audit_log(result);

CREATE INDEX idx_users_role ON users(role);
CREATE INDEX idx_users_email ON users(email);

-- Auto-update updated_at triggers (reuses update_updated_at() from migration 001)
CREATE TRIGGER ai_agents_updated_at
    BEFORE UPDATE ON ai_agents
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER remediations_updated_at
    BEFORE UPDATE ON remediations
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- Comments for documentation
COMMENT ON TABLE ai_agents IS 'Registry of AI agents deployed across the platform';
COMMENT ON TABLE agent_traces IS 'OTel-aligned execution traces for agent invocations';
COMMENT ON TABLE remediations IS 'Remediation actions linked to security findings';
COMMENT ON TABLE cost_summaries IS 'Aggregated cloud spend by provider, service, and period';
COMMENT ON TABLE audit_log IS 'Immutable platform-wide audit trail for compliance';
COMMENT ON TABLE users IS 'Platform user accounts with RBAC role assignments';
