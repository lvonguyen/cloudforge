package finops

import (
	"fmt"

	"go.uber.org/zap"
)

// ProviderType represents the type of FinOps data source.
type ProviderType string

const (
	ProviderTypeMemory ProviderType = "memory"
	ProviderTypeAWS    ProviderType = "aws"
	ProviderTypeGCP    ProviderType = "gcp"
	ProviderTypeAzure  ProviderType = "azure"
	ProviderTypeMulti  ProviderType = "multi"
)

// AggregatorConfig contains configuration for creating a cost aggregator.
type AggregatorConfig struct {
	Type      ProviderType
	AWSRegion string // AWS region for Cost Explorer (default: us-east-1)
	Logger    *zap.Logger
}

// NewAggregator creates a cost aggregator based on configuration.
// The anomaly detector and chargeback allocator are provider-agnostic
// and should be constructed separately (see cmd/server for composition).
func NewAggregator(cfg AggregatorConfig) (Aggregator, error) {
	logger := cfg.Logger
	if logger == nil {
		logger = zap.NewNop()
	}

	switch cfg.Type {
	case ProviderTypeMemory, "":
		return NewMemoryAggregator(), nil

	case ProviderTypeAWS:
		region := cfg.AWSRegion
		if region == "" {
			region = "us-east-1"
		}
		return NewAWSAggregator(region, logger)

	case ProviderTypeMulti:
		return nil, fmt.Errorf("multi provider must be composed at the application layer, not via factory")

	case ProviderTypeGCP:
		return nil, fmt.Errorf("gcp finops provider is not yet implemented")

	case ProviderTypeAzure:
		return nil, fmt.Errorf("azure finops provider is not yet implemented")

	default:
		return nil, fmt.Errorf("unknown finops provider type: %s", cfg.Type)
	}
}

// ProviderFromString converts a string to ProviderType.
func ProviderFromString(s string) (ProviderType, error) {
	switch s {
	case "memory", "":
		return ProviderTypeMemory, nil
	case "aws":
		return ProviderTypeAWS, nil
	case "gcp":
		return ProviderTypeGCP, nil
	case "azure":
		return ProviderTypeAzure, nil
	case "multi":
		return ProviderTypeMulti, nil
	default:
		return "", fmt.Errorf("unknown finops provider type: %s", s)
	}
}
