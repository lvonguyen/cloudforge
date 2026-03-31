-- migrations/008_findings_assignment_context.sql
-- Add explicit assignment / ownership context to findings so secgraph issue
-- materialization can preserve assignees from the source finding pipeline.

ALTER TABLE findings
    ADD COLUMN IF NOT EXISTS assignee JSONB,
    ADD COLUMN IF NOT EXISTS technical_contact JSONB,
    ADD COLUMN IF NOT EXISTS business_owner JSONB,
    ADD COLUMN IF NOT EXISTS team VARCHAR(100);

COMMENT ON COLUMN findings.assignee IS 'Optional source finding assignee metadata (user_id, user_email, user_name, team, escalation)';
COMMENT ON COLUMN findings.technical_contact IS 'Optional technical owner contact metadata for the affected service/resource';
COMMENT ON COLUMN findings.business_owner IS 'Optional business owner contact metadata for the affected service/resource';
COMMENT ON COLUMN findings.team IS 'Owning team for the finding when available from source enrichment or ingestion';
