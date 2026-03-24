package secrets

import (
	"fmt"

	"go.uber.org/zap"
)

// ProviderType represents the type of secrets provider.
type ProviderType string

const (
	ProviderTypeMemory ProviderType = "memory"
	ProviderTypeAWS    ProviderType = "aws"
	ProviderTypeAzure  ProviderType = "azure"
	ProviderTypeGCP    ProviderType = "gcp"
)

// ProviderConfig contains configuration for creating a secrets provider.
type ProviderConfig struct {
	Type     ProviderType
	Name     string // Provider display name (default: type value)
	Region   string // AWS region
	VaultURL string // Azure Key Vault URL
	Project  string // GCP project ID
	Logger   *zap.Logger
}

// NewProviderFromConfig creates a secrets provider based on configuration.
func NewProviderFromConfig(cfg ProviderConfig) (Provider, error) {
	logger := cfg.Logger
	if logger == nil {
		logger = zap.NewNop()
	}
	name := cfg.Name
	if name == "" {
		name = string(cfg.Type)
	}

	switch cfg.Type {
	case ProviderTypeMemory, "":
		return NewMemoryProvider(name), nil
	case ProviderTypeAWS:
		return NewAWSSecretsProvider(cfg.Region, logger), nil
	case ProviderTypeAzure:
		return NewAzureKeyVaultProvider(cfg.VaultURL, logger), nil
	case ProviderTypeGCP:
		return NewGCPSecretManagerProvider(cfg.Project, logger), nil
	default:
		return nil, fmt.Errorf("unknown secrets provider type: %s", cfg.Type)
	}
}

// ProviderFromString converts a string to ProviderType.
func ProviderFromString(s string) (ProviderType, error) {
	switch s {
	case "memory", "":
		return ProviderTypeMemory, nil
	case "aws":
		return ProviderTypeAWS, nil
	case "azure":
		return ProviderTypeAzure, nil
	case "gcp":
		return ProviderTypeGCP, nil
	default:
		return "", fmt.Errorf("unknown secrets provider type: %s", s)
	}
}
