-- migrations/001_exception_management.sql
-- Exception management schema for CloudForge
-- This provides a lightweight GRC alternative to enterprise tools like Archer/ServiceNow

-- Core exception request table
CREATE TABLE exception_requests (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id      VARCHAR(255) NOT NULL,
    requestor_email     VARCHAR(255) NOT NULL,
    request_type        VARCHAR(50) NOT NULL,
    policy_violated     VARCHAR(50) NOT NULL,
    resource_requested  TEXT NOT NULL,
    business_case       TEXT NOT NULL,
    status              VARCHAR(20) NOT NULL DEFAULT 'PENDING',
    expiration_date     TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    metadata            JSONB DEFAULT '{}',
    
    CONSTRAINT valid_status CHECK (status IN ('PENDING', 'APPROVED', 'REJECTED', 'EXPIRED', 'REVOKED')),
    CONSTRAINT valid_request_type CHECK (request_type IN (
        'UNAPPROVED_REGION', 'OVERSIZED_INSTANCE', 'RESTRICTED_SERVICE', 
        'NETWORK_EXPOSURE', 'DATA_RESIDENCY', 'OTHER'
    ))
);

-- Risk assessment (1:1 with exception)
CREATE TABLE risk_assessments (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    exception_id        UUID NOT NULL REFERENCES exception_requests(id) ON DELETE CASCADE,
    risk_level          VARCHAR(20) NOT NULL,
    impact              TEXT,
    likelihood          TEXT,
    residual_risk       TEXT,
    assessed_by         VARCHAR(255) NOT NULL,
    assessed_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    CONSTRAINT valid_risk_level CHECK (risk_level IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    CONSTRAINT one_assessment_per_exception UNIQUE (exception_id)
);

-- Compensating controls (many per exception)
CREATE TABLE compensating_controls (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    exception_id        UUID NOT NULL REFERENCES exception_requests(id) ON DELETE CASCADE,
    control_description TEXT NOT NULL,
    implemented         BOOLEAN DEFAULT FALSE,
    verified_by         VARCHAR(255),
    verified_at         TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Approval chain (ordered approvers)
CREATE TABLE approval_chain (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    exception_id        UUID NOT NULL REFERENCES exception_requests(id) ON DELETE CASCADE,
    sequence_order      INT NOT NULL,
    approver_email      VARCHAR(255) NOT NULL,
    approver_role       VARCHAR(50) NOT NULL,
    decision            VARCHAR(20),
    comments            TEXT,
    decided_at          TIMESTAMPTZ,
    
    CONSTRAINT valid_decision CHECK (decision IS NULL OR decision IN ('APPROVED', 'REJECTED')),
    CONSTRAINT unique_approver_sequence UNIQUE (exception_id, sequence_order)
);

-- Audit log (immutable)
CREATE TABLE exception_audit_log (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    exception_id        UUID NOT NULL REFERENCES exception_requests(id) ON DELETE CASCADE,
    action              VARCHAR(50) NOT NULL,
    actor_email         VARCHAR(255) NOT NULL,
    old_value           JSONB,
    new_value           JSONB,
    timestamp           TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes for common queries
CREATE INDEX idx_exceptions_app_id ON exception_requests(application_id);
CREATE INDEX idx_exceptions_status ON exception_requests(status);
CREATE INDEX idx_exceptions_policy ON exception_requests(policy_violated);
CREATE INDEX idx_exceptions_expiration ON exception_requests(expiration_date) WHERE status = 'APPROVED';
CREATE INDEX idx_approval_pending ON approval_chain(approver_email) WHERE decision IS NULL;
CREATE INDEX idx_audit_exception ON exception_audit_log(exception_id);
CREATE INDEX idx_audit_timestamp ON exception_audit_log(timestamp);

-- Auto-update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER exception_requests_updated_at
    BEFORE UPDATE ON exception_requests
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- View for easy exception validation queries
-- This is what OPA queries to check if an exception is valid
CREATE VIEW valid_exceptions AS
SELECT 
    er.id,
    er.application_id,
    er.policy_violated,
    er.expiration_date,
    er.status
FROM exception_requests er
WHERE er.status = 'APPROVED'
  AND (er.expiration_date IS NULL OR er.expiration_date > NOW());

-- Function to automatically expire exceptions
CREATE OR REPLACE FUNCTION expire_old_exceptions()
RETURNS INTEGER AS $$
DECLARE
    expired_count INTEGER;
BEGIN
    UPDATE exception_requests
    SET status = 'EXPIRED', updated_at = NOW()
    WHERE status = 'APPROVED'
      AND expiration_date IS NOT NULL
      AND expiration_date < NOW();
    
    GET DIAGNOSTICS expired_count = ROW_COUNT;
    RETURN expired_count;
END;
$$ LANGUAGE plpgsql;

-- Comments for documentation
COMMENT ON TABLE exception_requests IS 'Policy exception requests requiring GRC approval';
COMMENT ON TABLE risk_assessments IS 'Security risk assessment for each exception';
COMMENT ON TABLE compensating_controls IS 'Mitigating controls required for exception approval';
COMMENT ON TABLE approval_chain IS 'Multi-level approval workflow for exceptions';
COMMENT ON TABLE exception_audit_log IS 'Immutable audit trail for compliance';
COMMENT ON VIEW valid_exceptions IS 'Active, non-expired approved exceptions for policy validation';
