-- migrations/009_finding_tickets.sql
-- Durable ticket state for finding-level remediation workflows so Jira/Asana
-- integration state survives restarts and can be synced independently of the
-- in-memory demo cache.

CREATE TABLE IF NOT EXISTS finding_tickets (
    finding_id   VARCHAR(20) NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    tenant_id    VARCHAR(50) NOT NULL DEFAULT 'default',
    external_id  TEXT NOT NULL,
    provider     VARCHAR(30) NOT NULL,
    title        TEXT NOT NULL,
    status       VARCHAR(20) NOT NULL,
    priority     VARCHAR(20) NOT NULL,
    assignee     TEXT,
    url          TEXT,
    metadata     JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT finding_tickets_pk PRIMARY KEY (finding_id, tenant_id)
);

CREATE INDEX IF NOT EXISTS idx_finding_tickets_provider_external
    ON finding_tickets(provider, external_id);

CREATE INDEX IF NOT EXISTS idx_finding_tickets_tenant_status
    ON finding_tickets(tenant_id, status);

CREATE TRIGGER finding_tickets_updated_at
    BEFORE UPDATE ON finding_tickets
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

COMMENT ON TABLE finding_tickets IS 'Durable external ticket state for finding remediation workflows';
COMMENT ON COLUMN finding_tickets.external_id IS 'Provider-specific ticket identifier such as Jira issue key or Asana task GID';
COMMENT ON COLUMN finding_tickets.metadata IS 'Opaque provider metadata preserved for follow-up syncs and UI rendering';
