-- migrations/002_findings_and_compliance.sql
-- Findings and compliance framework schema for CloudForge
-- Core security findings with AI enrichment, plus compliance framework tracking

-- Security findings (the central data model)
CREATE TABLE findings (
    id                  VARCHAR(20) PRIMARY KEY,
    source              VARCHAR(50) NOT NULL,
    source_finding_id   TEXT,
    type                VARCHAR(50) NOT NULL,
    title               TEXT NOT NULL,
    description         TEXT,
    resource_type       VARCHAR(50),
    resource_id         TEXT,
    resource_name       VARCHAR(255),
    resource_arn        TEXT,
    platform            VARCHAR(20) DEFAULT 'cloud',
    cloud_provider      VARCHAR(10) NOT NULL,
    region              VARCHAR(50),
    account_id          VARCHAR(50),
    account_name        VARCHAR(255),
    environment_type    VARCHAR(20),
    static_severity     VARCHAR(10) NOT NULL,
    severity            VARCHAR(10) NOT NULL,
    ai_risk_score       NUMERIC(4,2),
    ai_risk_level       VARCHAR(10),
    ai_risk_rationale   TEXT,
    ai_contextual_factors TEXT[],
    cvss                NUMERIC(4,2),
    cvss_vector         TEXT,
    epss                NUMERIC(6,4),
    exploit_available   BOOLEAN DEFAULT FALSE,
    cves                JSONB DEFAULT '[]',
    mitre_tactics       TEXT[],
    mitre_techniques    TEXT[],
    compliance_mappings JSONB DEFAULT '[]',
    remediation         TEXT,
    auto_remediatable   BOOLEAN DEFAULT FALSE,
    category            VARCHAR(30),
    status              VARCHAR(20) NOT NULL DEFAULT 'open',
    workflow_status      VARCHAR(20) DEFAULT 'new',
    suppressed          BOOLEAN DEFAULT FALSE,
    service_name        VARCHAR(255),
    line_of_business    VARCHAR(100),
    first_found_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at        TIMESTAMPTZ,
    sla_breach_date     TIMESTAMPTZ,
    due_date            TIMESTAMPTZ,
    deduplication_key   TEXT,
    canonical_rule_id   TEXT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT valid_severity CHECK (severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO')),
    CONSTRAINT valid_status CHECK (status IN ('open', 'in_progress', 'resolved', 'suppressed', 'closed')),
    CONSTRAINT valid_provider CHECK (cloud_provider IN ('aws', 'azure', 'gcp'))
);

-- Compliance framework definitions
CREATE TABLE compliance_frameworks (
    id                  VARCHAR(50) PRIMARY KEY,
    name                VARCHAR(255) NOT NULL,
    description         TEXT,
    version             VARCHAR(20),
    category            VARCHAR(50),
    total_controls      INT NOT NULL DEFAULT 0,
    controls_passing    INT NOT NULL DEFAULT 0,
    controls_failing    INT NOT NULL DEFAULT 0,
    score               NUMERIC(5,2),
    relevant_for        TEXT[],
    categories          JSONB DEFAULT '[]',
    last_assessed_at    TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Junction table linking findings to framework controls
CREATE TABLE compliance_mappings (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id          VARCHAR(20) NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    framework_id        VARCHAR(50) NOT NULL REFERENCES compliance_frameworks(id) ON DELETE CASCADE,
    control_id          VARCHAR(50) NOT NULL,
    control_title       TEXT,
    section             VARCHAR(50),
    severity            VARCHAR(10),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT unique_finding_framework_control UNIQUE (finding_id, framework_id, control_id)
);

-- Indexes for common queries
CREATE INDEX idx_findings_severity ON findings(severity);
CREATE INDEX idx_findings_provider ON findings(cloud_provider);
CREATE INDEX idx_findings_status ON findings(status);
CREATE INDEX idx_findings_account ON findings(account_id);
CREATE INDEX idx_findings_due_date ON findings(due_date) WHERE due_date IS NOT NULL;
CREATE INDEX idx_findings_category ON findings(category);
CREATE INDEX idx_findings_environment ON findings(environment_type);
CREATE INDEX idx_mappings_finding ON compliance_mappings(finding_id);
CREATE INDEX idx_mappings_framework ON compliance_mappings(framework_id);

-- Reuse update_updated_at() from migration 001
CREATE TRIGGER findings_updated_at
    BEFORE UPDATE ON findings
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER compliance_frameworks_updated_at
    BEFORE UPDATE ON compliance_frameworks
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- Comments for documentation
COMMENT ON TABLE findings IS 'Security findings from CSPM/CNAPP scanners with AI-enriched risk scoring';
COMMENT ON TABLE compliance_frameworks IS 'Regulatory and industry compliance frameworks with control pass/fail tracking';
COMMENT ON TABLE compliance_mappings IS 'Junction table linking findings to specific compliance framework controls';
