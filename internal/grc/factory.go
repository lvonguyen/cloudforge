package grc

import (
	"database/sql"
	"fmt"
)

// ProviderType represents the type of GRC provider to use.
type ProviderType string

const (
	ProviderTypeMemory     ProviderType = "memory"
	ProviderTypePostgres   ProviderType = "postgres"
	ProviderTypeArcher     ProviderType = "archer"
	ProviderTypeServiceNow ProviderType = "servicenow"
)

// Config contains configuration for creating a GRC provider.
type Config struct {
	Type       ProviderType
	Postgres   *sql.DB
	Archer     *ArcherConfig
	ServiceNow *ServiceNowConfig
}

// NewProvider creates a GRC provider based on the given configuration.
// This factory pattern allows Cloud Aegis to work with different GRC platforms
// without changing the core business logic.
func NewProvider(cfg Config) (GRCProvider, error) {
	switch cfg.Type {
	case ProviderTypeMemory:
		m := NewMemoryGRCProvider()
		m.SeedTestData()
		return m, nil

	case ProviderTypePostgres:
		if cfg.Postgres == nil {
			return nil, fmt.Errorf("postgres db connection required for postgres provider")
		}
		return NewPostgresGRCProvider(cfg.Postgres), nil

	case ProviderTypeArcher:
		return nil, fmt.Errorf("archer provider is not yet implemented")

	case ProviderTypeServiceNow:
		if cfg.ServiceNow == nil {
			return nil, fmt.Errorf("servicenow config required for servicenow provider")
		}
		provider, err := NewServiceNowGRCProvider(*cfg.ServiceNow)
		if err != nil {
			return nil, fmt.Errorf("initializing servicenow provider: %w", err)
		}
		return provider, nil

	default:
		return nil, fmt.Errorf("unknown provider type: %s", cfg.Type)
	}
}

// ProviderFromString converts a string to ProviderType.
func ProviderFromString(s string) (ProviderType, error) {
	switch s {
	case "memory":
		return ProviderTypeMemory, nil
	case "postgres":
		return ProviderTypePostgres, nil
	case "archer":
		return ProviderTypeArcher, nil
	case "servicenow":
		return ProviderTypeServiceNow, nil
	default:
		return "", fmt.Errorf("unknown provider type: %s", s)
	}
}
