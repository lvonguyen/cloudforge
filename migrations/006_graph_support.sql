-- migrations/006_graph_support.sql
-- Graph support tables for PuppyGraph zero-ETL integration
-- Extracts distinct resources from findings to enable graph vertex/edge modeling

-- Distinct resources extracted from findings (PuppyGraph vertex source)
CREATE TABLE IF NOT EXISTS resources (
    id                  TEXT PRIMARY KEY,
    name                VARCHAR(255),
    resource_type       VARCHAR(50),
    region              VARCHAR(50),
    account_id          VARCHAR(50),
    cloud_provider      VARCHAR(10),
    account_name        VARCHAR(255),
    resource_arn        TEXT,
    tenant_id           VARCHAR(50) NOT NULL DEFAULT 'default',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_resources_type ON resources(resource_type);
CREATE INDEX IF NOT EXISTS idx_resources_account ON resources(account_id);
CREATE INDEX IF NOT EXISTS idx_resources_provider ON resources(cloud_provider);
CREATE INDEX IF NOT EXISTS idx_resources_tenant ON resources(tenant_id);

-- Populate from existing findings
INSERT INTO resources (id, name, resource_type, region, account_id, cloud_provider, account_name, resource_arn, tenant_id)
SELECT DISTINCT ON (resource_id)
    resource_id,
    COALESCE(resource_name, resource_id),
    resource_type,
    region,
    account_id,
    cloud_provider,
    account_name,
    resource_arn,
    tenant_id
FROM findings
WHERE resource_id IS NOT NULL AND resource_id != ''
ON CONFLICT (id) DO NOTHING;

COMMENT ON TABLE resources IS 'Distinct cloud resources extracted from findings for graph vertex modeling (PuppyGraph)';
