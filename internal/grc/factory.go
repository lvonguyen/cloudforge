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
// This factory pattern allows CloudForge to work with different GRC platforms
// without changing the core business logic.
func NewProvider(cfg Config) (GRCProvider, error) {
	switch cfg.Type {
	case ProviderTypeMemory:
		provider := NewMemoryGRCProvider()
		provider.SeedTestData()
		return provider, nil

	case ProviderTypePostgres:
		if cfg.Postgres == nil {
			return nil, fmt.Errorf("postgres db connection required for postgres provider")
		}
		return NewPostgresGRCProvider(cfg.Postgres), nil

	case ProviderTypeArcher:
		if cfg.Archer == nil {
			return nil, fmt.Errorf("archer config required for archer provider")
		}
		return NewArcherGRCProvider(*cfg.Archer), nil

	case ProviderTypeServiceNow:
		if cfg.ServiceNow == nil {
			return nil, fmt.Errorf("servicenow config required for servicenow provider")
		}
		return NewServiceNowGRCProvider(*cfg.ServiceNow), nil

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
