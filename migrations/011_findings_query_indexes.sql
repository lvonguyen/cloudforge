-- migrations/011_findings_query_indexes.sql
-- Indexes for serving /api/v1/findings directly from PostgreSQL at demo-scale
-- corpus sizes. These support the allowlisted list/filter/sort path without
-- requiring an in-memory full-corpus scan per request.

CREATE INDEX IF NOT EXISTS idx_findings_list_default
    ON findings (first_found_at DESC, id ASC);

CREATE INDEX IF NOT EXISTS idx_findings_severity_list
    ON findings (severity, first_found_at DESC, id ASC);

CREATE INDEX IF NOT EXISTS idx_findings_provider_list
    ON findings (cloud_provider, first_found_at DESC, id ASC);

CREATE INDEX IF NOT EXISTS idx_findings_status_list
    ON findings (status, first_found_at DESC, id ASC);

CREATE INDEX IF NOT EXISTS idx_findings_account_list
    ON findings (account_id, first_found_at DESC, id ASC);

CREATE INDEX IF NOT EXISTS idx_findings_region_lower
    ON findings (LOWER(COALESCE(region, '')));

CREATE INDEX IF NOT EXISTS idx_findings_environment_lower
    ON findings (LOWER(COALESCE(environment_type, '')));

CREATE INDEX IF NOT EXISTS idx_findings_business_unit_lower
    ON findings (LOWER(COALESCE(line_of_business, '')));
