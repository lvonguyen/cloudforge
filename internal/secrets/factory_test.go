package secrets

import (
	"strings"
	"testing"

	"go.uber.org/zap"
)

func TestNewProviderFromConfig_Memory(t *testing.T) {
	provider, err := NewProviderFromConfig(ProviderConfig{
		Type:   ProviderTypeMemory,
		Logger: zap.NewNop(),
	})
	if err != nil {
		t.Fatalf("NewProviderFromConfig(memory) error: %v", err)
	}
	if provider == nil {
		t.Fatal("expected memory provider")
	}
	if provider.Name() != "memory" {
		t.Fatalf("provider.Name() = %q, want memory", provider.Name())
	}
}

func TestNewProviderFromConfig_RealProvidersRequireConfig(t *testing.T) {
	tests := []struct {
		name    string
		cfg     ProviderConfig
		wantErr string
	}{
		{
			name: "aws requires region",
			cfg: ProviderConfig{
				Type:   ProviderTypeAWS,
				Logger: zap.NewNop(),
			},
			wantErr: "requires region",
		},
		{
			name: "azure requires vault url",
			cfg: ProviderConfig{
				Type:   ProviderTypeAzure,
				Logger: zap.NewNop(),
			},
			wantErr: "requires vault URL",
		},
		{
			name: "gcp requires project id",
			cfg: ProviderConfig{
				Type:   ProviderTypeGCP,
				Logger: zap.NewNop(),
			},
			wantErr: "requires project ID",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider, err := NewProviderFromConfig(tt.cfg)
			if err == nil {
				t.Fatal("expected init error, got nil")
			}
			if provider != nil {
				t.Fatal("expected nil provider on init failure")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %q, want substring %q", err.Error(), tt.wantErr)
			}
		})
	}
}
