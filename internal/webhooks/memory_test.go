package webhooks

import "testing"

func TestValidateWebhookURL(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		wantErr bool
	}{
		{name: "valid https", raw: "https://example.com/hook", wantErr: false},
		{name: "http rejected", raw: "http://example.com/hook", wantErr: true},
		{name: "missing hostname rejected", raw: "https://", wantErr: true},
		{name: "localhost rejected", raw: "https://localhost/hook", wantErr: true},
		{name: "localhost with trailing dot rejected", raw: "https://localhost./hook", wantErr: true},
		{name: "subdomain localhost rejected", raw: "https://api.localhost/hook", wantErr: true},
		{name: "metadata host rejected", raw: "https://metadata.google.internal/path", wantErr: true},
		{name: "loopback ip rejected", raw: "https://127.0.0.1/hook", wantErr: true},
		{name: "private ip rejected", raw: "https://10.0.0.7/hook", wantErr: true},
		{name: "metadata ip rejected", raw: "https://169.254.169.254/latest/meta-data", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateWebhookURL(tt.raw)
			if tt.wantErr && err == nil {
				t.Fatalf("validateWebhookURL(%q) expected error, got nil", tt.raw)
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("validateWebhookURL(%q) unexpected error: %v", tt.raw, err)
			}
		})
	}
}
