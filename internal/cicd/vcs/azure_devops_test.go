package vcs

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.uber.org/zap"
)

// TestAzureDevOps_AuthHeader_UsesStdEncoding verifies that the Authorization
// header value produced by AzureDevOpsProvider.doRequest uses
// base64.StdEncoding (standard alphabet with padding) per RFC 7617.
func TestAzureDevOps_AuthHeader_UsesStdEncoding(t *testing.T) {
	// Use a PAT value whose base64-encoding differs between StdEncoding and
	// RawURLEncoding. A 3-byte suffix forces StdEncoding to append '=' padding
	// and may produce '+' or '/' characters.
	pat := "test-pat-token-abc+/=="

	var capturedAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"value":[]}`))
	}))
	defer srv.Close()

	p := &AzureDevOpsProvider{
		organization: "org",
		project:      "proj",
		token:        pat,
		httpClient:   srv.Client(),
		logger:       zap.NewNop(),
	}

	_ = p.doRequest(t.Context(), "GET", srv.URL, nil, nil)

	// RFC 7617 requires standard base64 (RFC 4648 Section 4).
	expectedCredential := base64.StdEncoding.EncodeToString([]byte(":" + pat))
	expectedHeader := "Basic " + expectedCredential

	// The incorrect value that RawURLEncoding would produce.
	rawCredential := base64.RawURLEncoding.EncodeToString([]byte(":" + pat))
	rawHeader := "Basic " + rawCredential

	if capturedAuth == "" {
		t.Fatal("Authorization header was not set — doRequest may not have been called")
	}

	if capturedAuth == rawHeader && capturedAuth != expectedHeader {
		t.Errorf("Authorization header uses base64.RawURLEncoding:\n  got:  %q\n  want: %q\n  (RawURLEncoding produced: %q)",
			capturedAuth, expectedHeader, rawHeader)
	}

	if capturedAuth != expectedHeader {
		t.Errorf("Authorization header mismatch:\n  got:  %q\n  want: %q",
			capturedAuth, expectedHeader)
	}
}
