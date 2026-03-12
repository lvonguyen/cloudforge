package grc

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// --- Factory tests ---

func TestCovNewProvider_Memory(t *testing.T) {
	p, err := NewProvider(Config{Type: ProviderTypeMemory})
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	if p == nil {
		t.Fatal("expected non-nil provider")
	}
}

func TestCovNewProvider_Postgres_NoDB(t *testing.T) {
	_, err := NewProvider(Config{Type: ProviderTypePostgres})
	if err == nil {
		t.Error("expected error without postgres db")
	}
}

func TestCovNewProvider_Archer(t *testing.T) {
	_, err := NewProvider(Config{Type: ProviderTypeArcher})
	if err == nil {
		t.Error("expected error for unimplemented archer")
	}
}

func TestCovNewProvider_ServiceNow_NoConfig(t *testing.T) {
	_, err := NewProvider(Config{Type: ProviderTypeServiceNow})
	if err == nil {
		t.Error("expected error without servicenow config")
	}
}

func TestCovNewProvider_Unknown(t *testing.T) {
	_, err := NewProvider(Config{Type: "unknown"})
	if err == nil {
		t.Error("expected error for unknown type")
	}
}

func TestCovProviderFromString(t *testing.T) {
	tests := []struct {
		input   string
		want    ProviderType
		wantErr bool
	}{
		{"memory", ProviderTypeMemory, false},
		{"postgres", ProviderTypePostgres, false},
		{"archer", ProviderTypeArcher, false},
		{"servicenow", ProviderTypeServiceNow, false},
		{"invalid", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := ProviderFromString(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ProviderFromString(%q) err=%v, wantErr=%v", tt.input, err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

// --- Memory Provider tests ---

func TestCovMemoryProvider_CRUD(t *testing.T) {
	p := NewMemoryGRCProvider()
	ctx := context.Background()

	// Create
	req := &ExceptionRequest{
		ApplicationID:  "APP-001",
		PolicyViolated: "REGION-001",
		RequestorEmail: "user@example.com",
		BusinessCase:   "testing",
	}
	created, err := p.CreateException(ctx, req)
	if err != nil {
		t.Fatalf("CreateException: %v", err)
	}
	if created.ID == "" {
		t.Error("expected ID to be set")
	}
	if created.Status != StatusPending {
		t.Error("expected PENDING status")
	}

	// Get
	fetched, err := p.GetException(ctx, created.ID)
	if err != nil {
		t.Fatalf("GetException: %v", err)
	}
	if fetched.BusinessCase != "testing" {
		t.Error("expected business case to match")
	}

	// Update
	fetched.BusinessCase = "updated"
	if err := p.UpdateException(ctx, fetched); err != nil {
		t.Fatalf("UpdateException: %v", err)
	}
	updated, _ := p.GetException(ctx, created.ID)
	if updated.BusinessCase != "updated" {
		t.Error("expected updated business case")
	}

	// Get not found
	_, err = p.GetException(ctx, "nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent")
	}

	// Update not found
	err = p.UpdateException(ctx, &ExceptionRequest{ID: "nonexistent"})
	if err == nil {
		t.Error("expected error for nonexistent update")
	}
}

func TestCovMemoryProvider_ValidateException(t *testing.T) {
	p := NewMemoryGRCProvider()
	p.SeedTestData()
	ctx := context.Background()

	// Should find approved exception
	val, err := p.ValidateException(ctx, "APP-001", "REGION-001")
	if err != nil {
		t.Fatalf("ValidateException: %v", err)
	}
	if !val.Valid {
		t.Error("expected valid exception")
	}

	// Should not find for different policy
	val, err = p.ValidateException(ctx, "APP-001", "NONEXISTENT")
	if err != nil {
		t.Fatalf("ValidateException: %v", err)
	}
	if val.Valid {
		t.Error("expected invalid exception")
	}
}

func TestCovMemoryProvider_ValidateException_Expired(t *testing.T) {
	p := NewMemoryGRCProvider()
	ctx := context.Background()

	past := time.Now().Add(-24 * time.Hour)
	req := &ExceptionRequest{
		ApplicationID:  "APP-EXP",
		PolicyViolated: "POL-001",
		RequestorEmail: "user@example.com",
		Status:         StatusApproved,
		ExpirationDate: &past,
	}
	created, _ := p.CreateException(ctx, req)
	// Manually set status to approved
	p.exceptions[created.ID].Status = StatusApproved

	val, err := p.ValidateException(ctx, "APP-EXP", "POL-001")
	if err != nil {
		t.Fatalf("ValidateException: %v", err)
	}
	if val.Valid {
		t.Error("expected expired exception to be invalid")
	}
}

func TestCovMemoryProvider_SubmitApproval(t *testing.T) {
	p := NewMemoryGRCProvider()
	p.SeedTestData()
	ctx := context.Background()

	// Approve for test-exc-002
	err := p.SubmitApproval(ctx, "test-exc-002", Approver{
		Email:    "finance@example.com",
		Decision: StatusApproved,
		Comments: "Approved",
	})
	if err != nil {
		t.Fatalf("SubmitApproval: %v", err)
	}

	// Second approval
	err = p.SubmitApproval(ctx, "test-exc-002", Approver{
		Email:    "platform-lead@example.com",
		Decision: StatusApproved,
		Comments: "Also approved",
	})
	if err != nil {
		t.Fatalf("SubmitApproval: %v", err)
	}

	// Check status
	exc, _ := p.GetException(ctx, "test-exc-002")
	if exc.Status != StatusApproved {
		t.Errorf("expected APPROVED, got %s", exc.Status)
	}
}

func TestCovMemoryProvider_SubmitApproval_Rejected(t *testing.T) {
	p := NewMemoryGRCProvider()
	p.SeedTestData()
	ctx := context.Background()

	err := p.SubmitApproval(ctx, "test-exc-002", Approver{
		Email:    "finance@example.com",
		Decision: StatusRejected,
		Comments: "No budget",
	})
	if err != nil {
		t.Fatalf("SubmitApproval: %v", err)
	}

	exc, _ := p.GetException(ctx, "test-exc-002")
	if exc.Status != StatusRejected {
		t.Errorf("expected REJECTED, got %s", exc.Status)
	}
}

func TestCovMemoryProvider_SubmitApproval_NotFound(t *testing.T) {
	p := NewMemoryGRCProvider()
	ctx := context.Background()

	err := p.SubmitApproval(ctx, "nonexistent", Approver{Email: "a@b.com"})
	if err == nil {
		t.Error("expected error for nonexistent exception")
	}
}

func TestCovMemoryProvider_SubmitApproval_ApproverNotInChain(t *testing.T) {
	p := NewMemoryGRCProvider()
	p.SeedTestData()
	ctx := context.Background()

	err := p.SubmitApproval(ctx, "test-exc-002", Approver{
		Email:    "not-in-chain@example.com",
		Decision: StatusApproved,
	})
	if err == nil {
		t.Error("expected error for approver not in chain")
	}
}

func TestCovMemoryProvider_GetPendingApprovals(t *testing.T) {
	p := NewMemoryGRCProvider()
	p.SeedTestData()
	ctx := context.Background()

	pending, err := p.GetPendingApprovals(ctx, "finance@example.com")
	if err != nil {
		t.Fatalf("GetPendingApprovals: %v", err)
	}
	if len(pending) == 0 {
		t.Error("expected pending approvals for finance")
	}

	// Non-approver
	pending, err = p.GetPendingApprovals(ctx, "nobody@example.com")
	if err != nil {
		t.Fatalf("GetPendingApprovals: %v", err)
	}
	if len(pending) != 0 {
		t.Error("expected no pending approvals for nobody")
	}
}

func TestCovMemoryProvider_GetExceptionsByRequestor(t *testing.T) {
	p := NewMemoryGRCProvider()
	p.SeedTestData()
	ctx := context.Background()

	results, err := p.GetExceptionsByRequestor(ctx, "developer@example.com")
	if err != nil {
		t.Fatalf("GetExceptionsByRequestor: %v", err)
	}
	if len(results) == 0 {
		t.Error("expected exceptions for developer")
	}
}

func TestCovMemoryProvider_GetExceptionsByApplication(t *testing.T) {
	p := NewMemoryGRCProvider()
	p.SeedTestData()
	ctx := context.Background()

	results, err := p.GetExceptionsByApplication(ctx, "APP-001")
	if err != nil {
		t.Fatalf("GetExceptionsByApplication: %v", err)
	}
	if len(results) == 0 {
		t.Error("expected exceptions for APP-001")
	}
}

func TestCovMemoryProvider_GetExpiringExceptions(t *testing.T) {
	p := NewMemoryGRCProvider()
	p.SeedTestData()
	ctx := context.Background()

	expiring, err := p.GetExpiringExceptions(ctx, 120)
	if err != nil {
		t.Fatalf("GetExpiringExceptions: %v", err)
	}
	if len(expiring) == 0 {
		t.Error("expected expiring exceptions within 120 days")
	}

	// Very short window
	expiring, err = p.GetExpiringExceptions(ctx, 0)
	if err != nil {
		t.Fatalf("GetExpiringExceptions: %v", err)
	}
	// Should be 0 or very few
}

// --- ServiceNow Provider tests ---

func TestCovValidateSNOWInput(t *testing.T) {
	tests := []struct {
		field, value string
		wantErr      bool
	}{
		{"field", "valid-input", false},
		{"field", "user@example.com", false},
		{"field", "APP_001", false},
		{"field", "", true},
		{"field", "invalid;chars", true},
		{"field", "sql^injection", true},
	}
	for _, tt := range tests {
		t.Run(tt.value, func(t *testing.T) {
			err := validateSNOWInput(tt.field, tt.value)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateSNOWInput(%q, %q) err=%v, wantErr=%v", tt.field, tt.value, err, tt.wantErr)
			}
		})
	}
}

func TestCovNewServiceNowGRCProvider_Validation(t *testing.T) {
	tests := []struct {
		name    string
		config  ServiceNowConfig
		envVars map[string]string
		wantErr bool
	}{
		{"missing URL", ServiceNowConfig{}, nil, true},
		{"missing username", ServiceNowConfig{InstanceURL: "https://test.service-now.com"}, nil, true},
		{"missing password env", ServiceNowConfig{
			InstanceURL: "https://test.service-now.com",
			Username:    "admin",
		}, nil, true},
		{"missing password value", ServiceNowConfig{
			InstanceURL: "https://test.service-now.com",
			Username:    "admin",
			PasswordEnv: "SNOW_PASS_COV_EMPTY",
		}, nil, true},
		{"valid basic auth", ServiceNowConfig{
			InstanceURL: "https://test.service-now.com",
			Username:    "admin",
			PasswordEnv: "SNOW_PASS_COV",
		}, map[string]string{"SNOW_PASS_COV": "secret"}, false},
		{"oauth missing secret env", ServiceNowConfig{
			InstanceURL: "https://test.service-now.com",
			Username:    "admin",
			PasswordEnv: "SNOW_PASS_COV2",
			ClientID:    "client-id",
		}, map[string]string{"SNOW_PASS_COV2": "secret"}, true},
		{"oauth missing secret value", ServiceNowConfig{
			InstanceURL:     "https://test.service-now.com",
			Username:        "admin",
			PasswordEnv:     "SNOW_PASS_COV3",
			ClientID:        "client-id",
			ClientSecretEnv: "SNOW_SECRET_COV_EMPTY",
		}, map[string]string{"SNOW_PASS_COV3": "secret"}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for k, v := range tt.envVars {
				t.Setenv(k, v)
			}
			_, err := NewServiceNowGRCProvider(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("err=%v, wantErr=%v", err, tt.wantErr)
			}
		})
	}
}

func TestCovServiceNow_CreateException(t *testing.T) {
	// Mock ServiceNow auth and API
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth_token.do" {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"access_token": "test-token",
				"expires_in":   3600,
			})
			return
		}
		w.WriteHeader(http.StatusCreated)
		resp := snowResponse{}
		record := snowExceptionRecord{SysID: "sys-123"}
		data, _ := json.Marshal(record)
		resp.Result = data
		json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	t.Setenv("SNOW_PASS_CREATE", "secret")
	t.Setenv("SNOW_SECRET_CREATE", "client-secret")
	p, err := NewServiceNowGRCProvider(ServiceNowConfig{
		InstanceURL:     srv.URL,
		Username:        "admin",
		PasswordEnv:     "SNOW_PASS_CREATE",
		ClientID:        "cid",
		ClientSecretEnv: "SNOW_SECRET_CREATE",
	})
	if err != nil {
		t.Fatalf("NewServiceNowGRCProvider: %v", err)
	}

	req := &ExceptionRequest{
		ApplicationID:  "APP-001",
		PolicyViolated: "REGION-001",
		RequestorEmail: "user@example.com",
		BusinessCase:   "testing",
	}
	created, err := p.CreateException(context.Background(), req)
	if err != nil {
		t.Fatalf("CreateException: %v", err)
	}
	if created.ID != "sys-123" {
		t.Errorf("expected ID sys-123, got %s", created.ID)
	}
}

func TestCovServiceNow_ValidateException_InputValidation(t *testing.T) {
	t.Setenv("SNOW_PASS_VALIDATE", "secret")
	p, _ := NewServiceNowGRCProvider(ServiceNowConfig{
		InstanceURL: "https://test.service-now.com",
		Username:    "admin",
		PasswordEnv: "SNOW_PASS_VALIDATE",
	})

	_, err := p.ValidateException(context.Background(), "", "POL-001")
	if err == nil {
		t.Error("expected error for empty applicationID")
	}

	_, err = p.ValidateException(context.Background(), "APP-001", "POL;INJECT")
	if err == nil {
		t.Error("expected error for invalid policyCode")
	}
}

func TestCovServiceNow_GetPendingApprovals_InputValidation(t *testing.T) {
	t.Setenv("SNOW_PASS_PENDING", "secret")
	p, _ := NewServiceNowGRCProvider(ServiceNowConfig{
		InstanceURL: "https://test.service-now.com",
		Username:    "admin",
		PasswordEnv: "SNOW_PASS_PENDING",
	})

	_, err := p.GetPendingApprovals(context.Background(), "invalid;chars")
	if err == nil {
		t.Error("expected error for invalid email")
	}
}

func TestCovServiceNow_GetExceptionsByApp_InputValidation(t *testing.T) {
	t.Setenv("SNOW_PASS_APP", "secret")
	p, _ := NewServiceNowGRCProvider(ServiceNowConfig{
		InstanceURL: "https://test.service-now.com",
		Username:    "admin",
		PasswordEnv: "SNOW_PASS_APP",
	})

	_, err := p.GetExceptionsByApplication(context.Background(), "invalid;chars")
	if err == nil {
		t.Error("expected error for invalid appID")
	}
}

func TestCovServiceNow_GetExceptionsByRequestor_InputValidation(t *testing.T) {
	t.Setenv("SNOW_PASS_REQ", "secret")
	p, _ := NewServiceNowGRCProvider(ServiceNowConfig{
		InstanceURL: "https://test.service-now.com",
		Username:    "admin",
		PasswordEnv: "SNOW_PASS_REQ",
	})

	_, err := p.GetExceptionsByRequestor(context.Background(), "invalid;chars")
	if err == nil {
		t.Error("expected error for invalid email")
	}
}
