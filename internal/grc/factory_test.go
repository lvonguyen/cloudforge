package grc

import (
	"testing"
)

func TestNewProvider(t *testing.T) {
	tests := []struct {
		name      string
		config    Config
		wantErr   bool
		errSubstr string
	}{
		{
			name:    "memory provider creates successfully",
			config:  Config{Type: ProviderTypeMemory},
			wantErr: false,
		},
		{
			name:      "postgres provider requires db connection",
			config:    Config{Type: ProviderTypePostgres, Postgres: nil},
			wantErr:   true,
			errSubstr: "postgres db connection required",
		},
		{
			name:      "archer provider is not yet implemented",
			config:    Config{Type: ProviderTypeArcher, Archer: nil},
			wantErr:   true,
			errSubstr: "not yet implemented",
		},
		{
			name:      "servicenow provider requires config",
			config:    Config{Type: ProviderTypeServiceNow, ServiceNow: nil},
			wantErr:   true,
			errSubstr: "servicenow config required",
		},
		{
			name:      "unknown provider type returns error",
			config:    Config{Type: "nonexistent"},
			wantErr:   true,
			errSubstr: "unknown provider type",
		},
		{
			name:    "empty string defaults to unknown",
			config:  Config{Type: ""},
			wantErr: true,
		},
		{
			name: "archer provider with config still not implemented",
			config: Config{
				Type:   ProviderTypeArcher,
				Archer: &ArcherConfig{},
			},
			wantErr:   true,
			errSubstr: "not yet implemented",
		},
		{
			name: "servicenow provider with invalid config returns wrapped error",
			config: Config{
				Type:       ProviderTypeServiceNow,
				ServiceNow: &ServiceNowConfig{},
			},
			wantErr:   true,
			errSubstr: "initializing servicenow provider",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider, err := NewProvider(tt.config)

			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if tt.errSubstr != "" {
					if got := err.Error(); !contains(got, tt.errSubstr) {
						t.Errorf("error %q does not contain %q", got, tt.errSubstr)
					}
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if provider == nil {
				t.Fatal("expected non-nil provider")
			}
		})
	}
}

func TestNewProvider_MemorySeededData(t *testing.T) {
	provider, err := NewProvider(Config{Type: ProviderTypeMemory})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	mem, ok := provider.(*MemoryGRCProvider)
	if !ok {
		t.Fatal("expected *MemoryGRCProvider type")
	}

	mem.mu.RLock()
	count := len(mem.exceptions)
	mem.mu.RUnlock()

	if count == 0 {
		t.Error("expected seeded test data in memory provider")
	}
}

func TestProviderFromString(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    ProviderType
		wantErr bool
	}{
		{name: "memory", input: "memory", want: ProviderTypeMemory},
		{name: "postgres", input: "postgres", want: ProviderTypePostgres},
		{name: "archer", input: "archer", want: ProviderTypeArcher},
		{name: "servicenow", input: "servicenow", want: ProviderTypeServiceNow},
		{name: "unknown returns error", input: "dynamodb", wantErr: true},
		{name: "empty string returns error", input: "", wantErr: true},
		{name: "case sensitive", input: "Memory", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ProviderFromString(tt.input)

			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("got %s, want %s", got, tt.want)
			}
		})
	}
}

func TestGRCProviderInterfaceCompliance(t *testing.T) {
	var _ GRCProvider = (*MemoryGRCProvider)(nil)
	var _ GRCProvider = (*PostgresGRCProvider)(nil)
	var _ GRCProvider = (*ArcherGRCProvider)(nil)
	var _ GRCProvider = (*ServiceNowGRCProvider)(nil)
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchSubstring(s, substr)
}

func searchSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
