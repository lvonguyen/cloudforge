package grc

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// ---------- helpers ----------

// snowMux returns an http.ServeMux pre-wired with OAuth and CRUD routes.
// The caller can override individual paths after construction.
func snowMux() *http.ServeMux {
	mux := http.NewServeMux()

	// OAuth endpoint
	mux.HandleFunc("/oauth_token.do", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "test-token",
			"expires_in":   3600,
		})
	})

	// Create exception — POST to table
	mux.HandleFunc("POST /api/now/table/sn_grc_policy_exception", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		record := snowExceptionRecord{
			SysID:            "abc123",
			Number:           "EXC001",
			ShortDescription: "test exception",
			State:            "1",
			ApprovalStatus:   "requested",
		}
		data, _ := json.Marshal(record)
		json.NewEncoder(w).Encode(snowResponse{Result: data})
	})

	// GET single exception — /api/now/table/{table}/{sys_id}
	mux.HandleFunc("GET /api/now/table/sn_grc_policy_exception/abc123", func(w http.ResponseWriter, r *http.Request) {
		record := snowExceptionRecord{
			SysID:           "abc123",
			Number:          "EXC001",
			PolicyReference: "REGION-001",
			BusinessCase:    "testing",
			RequestedFor:    "user@example.com",
			ApprovalStatus:  "approved",
			ExpirationDate:  "2099-12-31",
		}
		data, _ := json.Marshal(record)
		json.NewEncoder(w).Encode(snowResponse{Result: data})
	})

	// GET query — list endpoints (with sysparm_query)
	mux.HandleFunc("GET /api/now/table/sn_grc_policy_exception", func(w http.ResponseWriter, r *http.Request) {
		records := []snowExceptionRecord{
			{
				SysID:           "abc123",
				Number:          "EXC001",
				PolicyReference: "REGION-001",
				BusinessCase:    "testing",
				RequestedFor:    "user@example.com",
				ApprovalStatus:  "approved",
				ExpirationDate:  "2099-12-31",
			},
		}
		data, _ := json.Marshal(records)
		json.NewEncoder(w).Encode(struct {
			Result json.RawMessage `json:"result"`
		}{Result: data})
	})

	// PATCH — update exception
	mux.HandleFunc("PATCH /api/now/table/sn_grc_policy_exception/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})

	return mux
}

// ---------- CreateException ----------

func TestServiceNow_CreateException_Success(t *testing.T) {
	srv := httptest.NewServer(snowMux())
	defer srv.Close()

	p := newServiceNowProviderForTest(srv.URL, srv.Client())
	req := &ExceptionRequest{
		ApplicationID:  "APP-001",
		PolicyViolated: "REGION-001",
		RequestorEmail: "user@example.com",
		BusinessCase:   "testing",
		RequestType:    ExceptionTypeRegion,
	}

	created, err := p.CreateException(context.Background(), req)
	if err != nil {
		t.Fatalf("CreateException: %v", err)
	}
	if created.ID != "abc123" {
		t.Errorf("expected ID abc123, got %s", created.ID)
	}
	if created.Status != StatusPending {
		t.Errorf("expected PENDING status, got %s", created.Status)
	}
}

func TestServiceNow_CreateException_WithExpiration(t *testing.T) {
	srv := httptest.NewServer(snowMux())
	defer srv.Close()

	p := newServiceNowProviderForTest(srv.URL, srv.Client())
	exp := time.Now().Add(30 * 24 * time.Hour)
	req := &ExceptionRequest{
		ApplicationID:  "APP-001",
		PolicyViolated: "REGION-001",
		RequestorEmail: "user@example.com",
		BusinessCase:   "testing",
		ExpirationDate: &exp,
	}

	created, err := p.CreateException(context.Background(), req)
	if err != nil {
		t.Fatalf("CreateException with expiration: %v", err)
	}
	if created.ID == "" {
		t.Error("expected non-empty ID")
	}
}

func TestServiceNow_CreateException_AuthFailure(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth_token.do", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	p := newServiceNowProviderForTest(srv.URL, srv.Client())
	_, err := p.CreateException(context.Background(), &ExceptionRequest{})
	if err == nil {
		t.Fatal("expected auth error")
	}
	if !strings.Contains(err.Error(), "auth failed") {
		t.Errorf("expected auth failure message, got: %v", err)
	}
}

func TestServiceNow_CreateException_Non201(t *testing.T) {
	mux := snowMux()
	// Override the POST handler to return 500
	mux.HandleFunc("POST /api/now/table/sn_grc_policy_exception/error", func(w http.ResponseWriter, r *http.Request) {})
	srvMux := http.NewServeMux()
	srvMux.HandleFunc("/oauth_token.do", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "test-token",
			"expires_in":   3600,
		})
	})
	srvMux.HandleFunc("POST /api/now/table/sn_grc_policy_exception", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	srv := httptest.NewServer(srvMux)
	defer srv.Close()

	p := newServiceNowProviderForTest(srv.URL, srv.Client())
	_, err := p.CreateException(context.Background(), &ExceptionRequest{PolicyViolated: "P1"})
	if err == nil {
		t.Fatal("expected error for non-201 response")
	}
	if !strings.Contains(err.Error(), "status 500") {
		t.Errorf("expected status 500 message, got: %v", err)
	}
}

// ---------- GetException ----------

func TestServiceNow_GetException_Success(t *testing.T) {
	srv := httptest.NewServer(snowMux())
	defer srv.Close()

	p := newServiceNowProviderForTest(srv.URL, srv.Client())
	exc, err := p.GetException(context.Background(), "abc123")
	if err != nil {
		t.Fatalf("GetException: %v", err)
	}
	if exc.ID != "abc123" {
		t.Errorf("expected ID abc123, got %s", exc.ID)
	}
	if exc.Status != StatusApproved {
		t.Errorf("expected APPROVED, got %s", exc.Status)
	}
	if exc.PolicyViolated != "REGION-001" {
		t.Errorf("expected REGION-001, got %s", exc.PolicyViolated)
	}
}

func TestServiceNow_GetException_NotFound(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth_token.do", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "test-token",
			"expires_in":   3600,
		})
	})
	mux.HandleFunc("/api/now/table/sn_grc_policy_exception/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	p := newServiceNowProviderForTest(srv.URL, srv.Client())
	_, err := p.GetException(context.Background(), "nonexistent")
	if err == nil {
		t.Fatal("expected not-found error")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("expected 'not found' message, got: %v", err)
	}
}

func TestServiceNow_GetException_ServerError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth_token.do", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "test-token",
			"expires_in":   3600,
		})
	})
	mux.HandleFunc("/api/now/table/sn_grc_policy_exception/", func(w http.ResponseWriter, r *http.Request) {
		// Return 200 but with invalid JSON to trigger decode error
		w.Write([]byte("not json"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	p := newServiceNowProviderForTest(srv.URL, srv.Client())
	_, err := p.GetException(context.Background(), "abc123")
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestServiceNow_GetException_StatusMapping(t *testing.T) {
	tests := []struct {
		approval string
		want     ApprovalStatus
	}{
		{"approved", StatusApproved},
		{"rejected", StatusRejected},
		{"requested", StatusPending},
		{"", StatusPending},
	}

	for _, tt := range tests {
		t.Run(tt.approval, func(t *testing.T) {
			mux := http.NewServeMux()
			mux.HandleFunc("/oauth_token.do", func(w http.ResponseWriter, r *http.Request) {
				json.NewEncoder(w).Encode(map[string]interface{}{
					"access_token": "test-token",
					"expires_in":   3600,
				})
			})
			mux.HandleFunc("/api/now/table/sn_grc_policy_exception/", func(w http.ResponseWriter, r *http.Request) {
				record := snowExceptionRecord{
					SysID:          "abc123",
					ApprovalStatus: tt.approval,
				}
				data, _ := json.Marshal(record)
				json.NewEncoder(w).Encode(snowResponse{Result: data})
			})
			srv := httptest.NewServer(mux)
			defer srv.Close()

			p := newServiceNowProviderForTest(srv.URL, srv.Client())
			exc, err := p.GetException(context.Background(), "abc123")
			if err != nil {
				t.Fatalf("GetException: %v", err)
			}
			if exc.Status != tt.want {
				t.Errorf("status=%q: expected %s, got %s", tt.approval, tt.want, exc.Status)
			}
		})
	}
}

// ---------- UpdateException ----------

func TestServiceNow_UpdateException_Success(t *testing.T) {
	srv := httptest.NewServer(snowMux())
	defer srv.Close()

	p := newServiceNowProviderForTest(srv.URL, srv.Client())
	exp := time.Now().Add(30 * 24 * time.Hour)
	err := p.UpdateException(context.Background(), &ExceptionRequest{
		ID:             "abc123",
		BusinessCase:   "updated reason",
		ExpirationDate: &exp,
	})
	if err != nil {
		t.Fatalf("UpdateException: %v", err)
	}
}

func TestServiceNow_UpdateException_Error(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth_token.do", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "test-token",
			"expires_in":   3600,
		})
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	p := newServiceNowProviderForTest(srv.URL, srv.Client())
	err := p.UpdateException(context.Background(), &ExceptionRequest{ID: "abc123"})
	if err == nil {
		t.Fatal("expected error for 500 response")
	}
}

// ---------- ValidateException ----------

func TestServiceNow_ValidateException_Found(t *testing.T) {
	srv := httptest.NewServer(snowMux())
	defer srv.Close()

	p := newServiceNowProviderForTest(srv.URL, srv.Client())
	val, err := p.ValidateException(context.Background(), "APP-001", "REGION-001")
	if err != nil {
		t.Fatalf("ValidateException: %v", err)
	}
	if !val.Valid {
		t.Error("expected valid=true")
	}
	if val.ExceptionID != "abc123" {
		t.Errorf("expected exception ID abc123, got %s", val.ExceptionID)
	}
	if val.ExpiresAt == nil {
		t.Error("expected non-nil ExpiresAt")
	}
}

func TestServiceNow_ValidateException_NotFound(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth_token.do", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "test-token",
			"expires_in":   3600,
		})
	})
	mux.HandleFunc("/api/now/table/sn_grc_policy_exception", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(struct {
			Result []snowExceptionRecord `json:"result"`
		}{Result: []snowExceptionRecord{}})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	p := newServiceNowProviderForTest(srv.URL, srv.Client())
	val, err := p.ValidateException(context.Background(), "APP-999", "NONEXIST")
	if err != nil {
		t.Fatalf("ValidateException: %v", err)
	}
	if val.Valid {
		t.Error("expected valid=false for empty results")
	}
}

func TestServiceNow_ValidateException_NoExpirationDate(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth_token.do", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "test-token",
			"expires_in":   3600,
		})
	})
	mux.HandleFunc("/api/now/table/sn_grc_policy_exception", func(w http.ResponseWriter, r *http.Request) {
		records := []snowExceptionRecord{
			{SysID: "abc123", ExpirationDate: ""},
		}
		data, _ := json.Marshal(records)
		json.NewEncoder(w).Encode(struct {
			Result json.RawMessage `json:"result"`
		}{Result: data})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	p := newServiceNowProviderForTest(srv.URL, srv.Client())
	val, err := p.ValidateException(context.Background(), "APP-001", "POL-001")
	if err != nil {
		t.Fatalf("ValidateException: %v", err)
	}
	if !val.Valid {
		t.Error("expected valid=true")
	}
	if val.ExpiresAt != nil {
		t.Error("expected nil ExpiresAt for empty date")
	}
}

func TestServiceNow_ValidateException_InputValidation(t *testing.T) {
	p := newServiceNowProviderForTest("https://unused", &http.Client{})

	_, err := p.ValidateException(context.Background(), "", "POL-001")
	if err == nil {
		t.Error("expected error for empty applicationID")
	}

	_, err = p.ValidateException(context.Background(), "APP-001", "POL;INJECT")
	if err == nil {
		t.Error("expected error for injection chars in policyCode")
	}
}

// ---------- SubmitApproval ----------

func TestServiceNow_SubmitApproval_Approved(t *testing.T) {
	srv := httptest.NewServer(snowMux())
	defer srv.Close()

	p := newServiceNowProviderForTest(srv.URL, srv.Client())
	err := p.SubmitApproval(context.Background(), "abc123", Approver{
		Email:    "approver@example.com",
		Decision: StatusApproved,
		Comments: "Looks good",
	})
	if err != nil {
		t.Fatalf("SubmitApproval: %v", err)
	}
}

func TestServiceNow_SubmitApproval_Rejected(t *testing.T) {
	srv := httptest.NewServer(snowMux())
	defer srv.Close()

	p := newServiceNowProviderForTest(srv.URL, srv.Client())
	err := p.SubmitApproval(context.Background(), "abc123", Approver{
		Email:    "approver@example.com",
		Decision: StatusRejected,
		Comments: "Risk too high",
	})
	if err != nil {
		t.Fatalf("SubmitApproval: %v", err)
	}
}

func TestServiceNow_SubmitApproval_Error(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth_token.do", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "test-token",
			"expires_in":   3600,
		})
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	p := newServiceNowProviderForTest(srv.URL, srv.Client())
	err := p.SubmitApproval(context.Background(), "abc123", Approver{
		Email:    "approver@example.com",
		Decision: StatusApproved,
	})
	if err == nil {
		t.Fatal("expected error for 403 response")
	}
}

// ---------- GetException input validation ----------

func TestServiceNow_GetException_InputValidation(t *testing.T) {
	p := newServiceNowProviderForTest("https://unused", &http.Client{})

	_, err := p.GetException(context.Background(), "")
	if err == nil {
		t.Error("expected error for empty id")
	}
	_, err = p.GetException(context.Background(), "id;inject")
	if err == nil {
		t.Error("expected error for injection chars in id")
	}
}

// ---------- UpdateException input validation ----------

func TestServiceNow_UpdateException_InputValidation(t *testing.T) {
	p := newServiceNowProviderForTest("https://unused", &http.Client{})

	err := p.UpdateException(context.Background(), &ExceptionRequest{ID: ""})
	if err == nil {
		t.Error("expected error for empty id")
	}
	err = p.UpdateException(context.Background(), &ExceptionRequest{ID: "id^inject"})
	if err == nil {
		t.Error("expected error for injection chars in id")
	}
}

// ---------- SubmitApproval input validation ----------

func TestServiceNow_SubmitApproval_InputValidation(t *testing.T) {
	p := newServiceNowProviderForTest("https://unused", &http.Client{})

	err := p.SubmitApproval(context.Background(), "", Approver{Decision: StatusApproved})
	if err == nil {
		t.Error("expected error for empty exceptionID")
	}
	err = p.SubmitApproval(context.Background(), "id;drop", Approver{Decision: StatusApproved})
	if err == nil {
		t.Error("expected error for injection chars in exceptionID")
	}
}

// ---------- GetPendingApprovals ----------

func TestServiceNow_GetPendingApprovals_Found(t *testing.T) {
	srv := httptest.NewServer(snowMux())
	defer srv.Close()

	p := newServiceNowProviderForTest(srv.URL, srv.Client())
	results, err := p.GetPendingApprovals(context.Background(), "user@example.com")
	if err != nil {
		t.Fatalf("GetPendingApprovals: %v", err)
	}
	if len(results) == 0 {
		t.Error("expected non-empty results")
	}
	if results[0].Status != StatusPending {
		t.Errorf("expected PENDING, got %s", results[0].Status)
	}
}

func TestServiceNow_GetPendingApprovals_Empty(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth_token.do", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "test-token",
			"expires_in":   3600,
		})
	})
	mux.HandleFunc("/api/now/table/sn_grc_policy_exception", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(struct {
			Result []snowExceptionRecord `json:"result"`
		}{Result: []snowExceptionRecord{}})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	p := newServiceNowProviderForTest(srv.URL, srv.Client())
	results, err := p.GetPendingApprovals(context.Background(), "nobody@example.com")
	if err != nil {
		t.Fatalf("GetPendingApprovals: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("expected 0 results, got %d", len(results))
	}
}

func TestServiceNow_GetPendingApprovals_InputValidation(t *testing.T) {
	p := newServiceNowProviderForTest("https://unused", &http.Client{})
	_, err := p.GetPendingApprovals(context.Background(), "invalid;chars")
	if err == nil {
		t.Error("expected error for invalid email")
	}
}

// ---------- GetExceptionsByApplication ----------

func TestServiceNow_GetExceptionsByApplication_Found(t *testing.T) {
	srv := httptest.NewServer(snowMux())
	defer srv.Close()

	p := newServiceNowProviderForTest(srv.URL, srv.Client())
	results, err := p.GetExceptionsByApplication(context.Background(), "APP-001")
	if err != nil {
		t.Fatalf("GetExceptionsByApplication: %v", err)
	}
	if len(results) == 0 {
		t.Error("expected non-empty results")
	}
}

func TestServiceNow_GetExceptionsByApplication_Empty(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth_token.do", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "test-token",
			"expires_in":   3600,
		})
	})
	mux.HandleFunc("/api/now/table/sn_grc_policy_exception", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(struct {
			Result []snowExceptionRecord `json:"result"`
		}{Result: []snowExceptionRecord{}})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	p := newServiceNowProviderForTest(srv.URL, srv.Client())
	results, err := p.GetExceptionsByApplication(context.Background(), "APP-999")
	if err != nil {
		t.Fatalf("GetExceptionsByApplication: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("expected 0 results, got %d", len(results))
	}
}

func TestServiceNow_GetExceptionsByApplication_InputValidation(t *testing.T) {
	p := newServiceNowProviderForTest("https://unused", &http.Client{})
	_, err := p.GetExceptionsByApplication(context.Background(), "")
	if err == nil {
		t.Error("expected error for empty appID")
	}
}

// ---------- GetExpiringExceptions ----------

func TestServiceNow_GetExpiringExceptions_Found(t *testing.T) {
	srv := httptest.NewServer(snowMux())
	defer srv.Close()

	p := newServiceNowProviderForTest(srv.URL, srv.Client())
	results, err := p.GetExpiringExceptions(context.Background(), 30)
	if err != nil {
		t.Fatalf("GetExpiringExceptions: %v", err)
	}
	if len(results) == 0 {
		t.Error("expected non-empty results")
	}
	if results[0].Status != StatusApproved {
		t.Errorf("expected APPROVED status, got %s", results[0].Status)
	}
	if results[0].ExpirationDate == nil {
		t.Error("expected non-nil expiration date")
	}
}

func TestServiceNow_GetExpiringExceptions_Empty(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth_token.do", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "test-token",
			"expires_in":   3600,
		})
	})
	mux.HandleFunc("/api/now/table/sn_grc_policy_exception", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(struct {
			Result []snowExceptionRecord `json:"result"`
		}{Result: []snowExceptionRecord{}})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	p := newServiceNowProviderForTest(srv.URL, srv.Client())
	results, err := p.GetExpiringExceptions(context.Background(), 1)
	if err != nil {
		t.Fatalf("GetExpiringExceptions: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("expected 0 results, got %d", len(results))
	}
}

func TestServiceNow_GetExpiringExceptions_NoExpDate(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth_token.do", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "test-token",
			"expires_in":   3600,
		})
	})
	mux.HandleFunc("/api/now/table/sn_grc_policy_exception", func(w http.ResponseWriter, r *http.Request) {
		records := []snowExceptionRecord{
			{SysID: "abc123", PolicyReference: "POL-001", ExpirationDate: ""},
		}
		data, _ := json.Marshal(records)
		json.NewEncoder(w).Encode(struct {
			Result json.RawMessage `json:"result"`
		}{Result: data})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	p := newServiceNowProviderForTest(srv.URL, srv.Client())
	results, err := p.GetExpiringExceptions(context.Background(), 30)
	if err != nil {
		t.Fatalf("GetExpiringExceptions: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].ExpirationDate != nil {
		t.Error("expected nil expiration date for empty string")
	}
}

// ---------- GetExceptionsByRequestor ----------

func TestServiceNow_GetExceptionsByRequestor_Found(t *testing.T) {
	srv := httptest.NewServer(snowMux())
	defer srv.Close()

	p := newServiceNowProviderForTest(srv.URL, srv.Client())
	results, err := p.GetExceptionsByRequestor(context.Background(), "user@example.com")
	if err != nil {
		t.Fatalf("GetExceptionsByRequestor: %v", err)
	}
	if len(results) == 0 {
		t.Error("expected non-empty results")
	}
}

func TestServiceNow_GetExceptionsByRequestor_InputValidation(t *testing.T) {
	p := newServiceNowProviderForTest("https://unused", &http.Client{})
	_, err := p.GetExceptionsByRequestor(context.Background(), "")
	if err == nil {
		t.Error("expected error for empty email")
	}
	_, err = p.GetExceptionsByRequestor(context.Background(), "bad;chars")
	if err == nil {
		t.Error("expected error for injection chars")
	}
}

// ---------- validateSNOWInput ----------

func TestValidateSNOWInput(t *testing.T) {
	tests := []struct {
		name    string
		field   string
		value   string
		wantErr bool
	}{
		{"valid alphanumeric", "f", "ABC123", false},
		{"valid email", "f", "user@example.com", false},
		{"valid with hyphen", "f", "APP-001", false},
		{"valid with underscore", "f", "APP_001", false},
		{"valid with dot", "f", "user.name", false},
		{"empty", "f", "", true},
		{"semicolon injection", "f", "val;drop", true},
		{"caret injection", "f", "val^inject", true},
		{"space", "f", "val ue", true},
		{"equals sign", "f", "val=ue", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateSNOWInput(tt.field, tt.value)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateSNOWInput(%q, %q) err=%v, wantErr=%v", tt.field, tt.value, err, tt.wantErr)
			}
		})
	}
}

// ---------- authenticate edge cases ----------

func TestServiceNow_Authenticate_TokenReuse(t *testing.T) {
	callCount := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth_token.do", func(w http.ResponseWriter, r *http.Request) {
		callCount++
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "test-token",
			"expires_in":   3600,
		})
	})
	mux.HandleFunc("/api/now/table/sn_grc_policy_exception", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(struct {
			Result []snowExceptionRecord `json:"result"`
		}{Result: []snowExceptionRecord{}})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	p := newServiceNowProviderForTest(srv.URL, srv.Client())

	// Two calls should only authenticate once (token caching)
	_, _ = p.GetExceptionsByRequestor(context.Background(), "user@example.com")
	_, _ = p.GetExceptionsByRequestor(context.Background(), "user@example.com")

	if callCount != 1 {
		t.Errorf("expected 1 auth call (token reuse), got %d", callCount)
	}
}

func TestServiceNow_Authenticate_ZeroExpiresIn(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth_token.do", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "test-token",
			"expires_in":   0, // Should default to 3600
		})
	})
	mux.HandleFunc("/api/now/table/sn_grc_policy_exception", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(struct {
			Result []snowExceptionRecord `json:"result"`
		}{Result: []snowExceptionRecord{}})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	p := newServiceNowProviderForTest(srv.URL, srv.Client())
	_, err := p.GetExceptionsByRequestor(context.Background(), "user@example.com")
	if err != nil {
		t.Fatalf("unexpected error with zero expires_in: %v", err)
	}
}

// ---------- HTTP client error paths ----------

func TestServiceNow_CreateException_HTTPClientError(t *testing.T) {
	srv := httptest.NewServer(snowMux())
	p := newServiceNowProviderForTest(srv.URL, srv.Client())
	// Pre-set a valid token to skip auth, then close server
	p.authToken = "pre-set-token"
	p.tokenExp = time.Now().Add(time.Hour)
	srv.Close()

	_, err := p.CreateException(context.Background(), &ExceptionRequest{PolicyViolated: "P1"})
	if err == nil {
		t.Fatal("expected HTTP error for closed server")
	}
}

func TestServiceNow_GetException_HTTPClientError(t *testing.T) {
	srv := httptest.NewServer(snowMux())
	p := newServiceNowProviderForTest(srv.URL, srv.Client())
	p.authToken = "pre-set-token"
	p.tokenExp = time.Now().Add(time.Hour)
	srv.Close()

	_, err := p.GetException(context.Background(), "abc123")
	if err == nil {
		t.Fatal("expected HTTP error for closed server")
	}
}

func TestServiceNow_UpdateException_HTTPClientError(t *testing.T) {
	srv := httptest.NewServer(snowMux())
	p := newServiceNowProviderForTest(srv.URL, srv.Client())
	p.authToken = "pre-set-token"
	p.tokenExp = time.Now().Add(time.Hour)
	srv.Close()

	err := p.UpdateException(context.Background(), &ExceptionRequest{ID: "abc123"})
	if err == nil {
		t.Fatal("expected HTTP error for closed server")
	}
}

func TestServiceNow_SubmitApproval_HTTPClientError(t *testing.T) {
	srv := httptest.NewServer(snowMux())
	p := newServiceNowProviderForTest(srv.URL, srv.Client())
	p.authToken = "pre-set-token"
	p.tokenExp = time.Now().Add(time.Hour)
	srv.Close()

	err := p.SubmitApproval(context.Background(), "abc123", Approver{Decision: StatusApproved})
	if err == nil {
		t.Fatal("expected HTTP error for closed server")
	}
}

func TestServiceNow_GetPendingApprovals_HTTPClientError(t *testing.T) {
	srv := httptest.NewServer(snowMux())
	p := newServiceNowProviderForTest(srv.URL, srv.Client())
	p.authToken = "pre-set-token"
	p.tokenExp = time.Now().Add(time.Hour)
	srv.Close()

	_, err := p.GetPendingApprovals(context.Background(), "user@example.com")
	if err == nil {
		t.Fatal("expected HTTP error for closed server")
	}
}

func TestServiceNow_GetExceptionsByApplication_HTTPClientError(t *testing.T) {
	srv := httptest.NewServer(snowMux())
	p := newServiceNowProviderForTest(srv.URL, srv.Client())
	p.authToken = "pre-set-token"
	p.tokenExp = time.Now().Add(time.Hour)
	srv.Close()

	_, err := p.GetExceptionsByApplication(context.Background(), "APP-001")
	if err == nil {
		t.Fatal("expected HTTP error for closed server")
	}
}

func TestServiceNow_GetExpiringExceptions_HTTPClientError(t *testing.T) {
	srv := httptest.NewServer(snowMux())
	p := newServiceNowProviderForTest(srv.URL, srv.Client())
	p.authToken = "pre-set-token"
	p.tokenExp = time.Now().Add(time.Hour)
	srv.Close()

	_, err := p.GetExpiringExceptions(context.Background(), 30)
	if err == nil {
		t.Fatal("expected HTTP error for closed server")
	}
}

func TestServiceNow_GetExceptionsByRequestor_HTTPClientError(t *testing.T) {
	srv := httptest.NewServer(snowMux())
	p := newServiceNowProviderForTest(srv.URL, srv.Client())
	p.authToken = "pre-set-token"
	p.tokenExp = time.Now().Add(time.Hour)
	srv.Close()

	_, err := p.GetExceptionsByRequestor(context.Background(), "user@example.com")
	if err == nil {
		t.Fatal("expected HTTP error for closed server")
	}
}

func TestServiceNow_Authenticate_HTTPClientError(t *testing.T) {
	srv := httptest.NewServer(snowMux())
	p := newServiceNowProviderForTest(srv.URL, srv.Client())
	srv.Close()

	_, err := p.CreateException(context.Background(), &ExceptionRequest{})
	if err == nil {
		t.Fatal("expected auth HTTP error for closed server")
	}
}

func TestServiceNow_Authenticate_BadJSON(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth_token.do", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("not json"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	p := newServiceNowProviderForTest(srv.URL, srv.Client())
	_, err := p.CreateException(context.Background(), &ExceptionRequest{})
	if err == nil {
		t.Fatal("expected error for bad token JSON")
	}
}

func TestServiceNow_ValidateException_HTTPClientError(t *testing.T) {
	srv := httptest.NewServer(snowMux())
	p := newServiceNowProviderForTest(srv.URL, srv.Client())
	p.authToken = "pre-set-token"
	p.tokenExp = time.Now().Add(time.Hour)
	srv.Close()

	_, err := p.ValidateException(context.Background(), "APP-001", "POL-001")
	if err == nil {
		t.Fatal("expected HTTP error for closed server")
	}
}

// ---------- Archer stub tests ----------

func TestArcher_AllMethods_NotImplemented(t *testing.T) {
	a := newArcherProviderForTest()
	ctx := context.Background()

	// CreateException
	_, err := a.CreateException(ctx, &ExceptionRequest{})
	if err == nil || !strings.Contains(err.Error(), "requires") {
		t.Errorf("CreateException: expected 'requires' error, got: %v", err)
	}

	// GetException
	_, err = a.GetException(ctx, "id")
	if err == nil || !strings.Contains(err.Error(), "not implemented") {
		t.Errorf("GetException: expected 'not implemented', got: %v", err)
	}

	// UpdateException
	err = a.UpdateException(ctx, &ExceptionRequest{})
	if err == nil || !strings.Contains(err.Error(), "not implemented") {
		t.Errorf("UpdateException: expected 'not implemented', got: %v", err)
	}

	// ValidateException
	_, err = a.ValidateException(ctx, "app", "pol")
	if err == nil || !strings.Contains(err.Error(), "not implemented") {
		t.Errorf("ValidateException: expected 'not implemented', got: %v", err)
	}

	// SubmitApproval
	err = a.SubmitApproval(ctx, "id", Approver{})
	if err == nil || !strings.Contains(err.Error(), "not implemented") {
		t.Errorf("SubmitApproval: expected 'not implemented', got: %v", err)
	}

	// GetPendingApprovals
	_, err = a.GetPendingApprovals(ctx, "user@example.com")
	if err == nil || !strings.Contains(err.Error(), "not implemented") {
		t.Errorf("GetPendingApprovals: expected 'not implemented', got: %v", err)
	}

	// GetExceptionsByApplication
	_, err = a.GetExceptionsByApplication(ctx, "app-id")
	if err == nil || !strings.Contains(err.Error(), "not implemented") {
		t.Errorf("GetExceptionsByApplication: expected 'not implemented', got: %v", err)
	}

	// GetExpiringExceptions
	_, err = a.GetExpiringExceptions(ctx, 30)
	if err == nil || !strings.Contains(err.Error(), "not implemented") {
		t.Errorf("GetExpiringExceptions: expected 'not implemented', got: %v", err)
	}

	// GetExceptionsByRequestor
	_, err = a.GetExceptionsByRequestor(ctx, "user@example.com")
	if err == nil || !strings.Contains(err.Error(), "not implemented") {
		t.Errorf("GetExceptionsByRequestor: expected 'not implemented', got: %v", err)
	}
}

func TestNewArcherGRCProvider_Success(t *testing.T) {
	t.Setenv("ARCHER_PASS_SUCCESS_TEST", "secret-password")
	p, err := NewArcherGRCProvider(ArcherConfig{
		BaseURL:     "https://archer.test",
		Username:    "admin",
		PasswordEnv: "ARCHER_PASS_SUCCESS_TEST",
	})
	if err != nil {
		t.Fatalf("NewArcherGRCProvider: %v", err)
	}
	if p == nil {
		t.Fatal("expected non-nil provider")
	}
}

func TestNewArcherGRCProvider_ValidationErrors(t *testing.T) {
	tests := []struct {
		name    string
		config  ArcherConfig
		wantErr string
	}{
		{
			name:    "missing BaseURL",
			config:  ArcherConfig{},
			wantErr: "BaseURL is required",
		},
		{
			name:    "missing Username",
			config:  ArcherConfig{BaseURL: "https://archer.test"},
			wantErr: "Username is required",
		},
		{
			name: "missing PasswordEnv",
			config: ArcherConfig{
				BaseURL:  "https://archer.test",
				Username: "admin",
			},
			wantErr: "PasswordEnv must be specified",
		},
		{
			name: "missing password value",
			config: ArcherConfig{
				BaseURL:     "https://archer.test",
				Username:    "admin",
				PasswordEnv: "ARCHER_PASS_EMPTY_TEST",
			},
			wantErr: "password environment variable",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewArcherGRCProvider(tt.config)
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("expected error containing %q, got: %v", tt.wantErr, err)
			}
		})
	}
}
