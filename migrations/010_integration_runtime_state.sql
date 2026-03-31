-- migrations/010_integration_runtime_state.sql
-- Durable provider runtime state for integration webhooks and other
-- provider-scoped secrets learned at runtime.

CREATE TABLE IF NOT EXISTS integration_runtime_state (
    provider    VARCHAR(30) NOT NULL,
    state_key   VARCHAR(100) NOT NULL,
    state_value TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT integration_runtime_state_pk PRIMARY KEY (provider, state_key)
);

CREATE TRIGGER integration_runtime_state_updated_at
    BEFORE UPDATE ON integration_runtime_state
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

COMMENT ON TABLE integration_runtime_state IS 'Durable provider runtime state such as webhook secrets learned during external handshakes';
COMMENT ON COLUMN integration_runtime_state.state_key IS 'Logical provider-scoped state key';
COMMENT ON COLUMN integration_runtime_state.state_value IS 'Opaque state payload stored durably for provider runtime continuity';
