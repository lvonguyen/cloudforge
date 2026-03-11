package vcs

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.uber.org/zap"
)

// TestAzureDevOps_AuthHeader_UsesRawURLEncoding verifies that the Authorization
// header value produced by AzureDevOpsProvider.doRequest uses
// base64.RawURLEncoding (no padding, URL-safe alphabet) rather than
// base64.StdEncoding.
//
// PAT tokens may contain bytes that base64.StdEncoding maps to '+', '/', or
// trailing '=' padding characters — all of which are unsafe in URL contexts
// and inconsistent with the rest of the codebase (e.g. auth_middleware.go
// already uses base64.RawURLEncoding for JWT handling). Using StdEncoding
// can corrupt tokens that are subsequently embedded in URLs or compared
// against RawURLEncoding-produced values.
func TestAzureDevOps_AuthHeader_UsesRawURLEncoding(t *testing.T) {
	// Use a PAT value whose base64-encoding differs between StdEncoding and
	// RawURLEncoding. A 3-byte suffix forces StdEncoding to append '=' padding
	// and may produce '+' or '/' characters.
	pat := "test-pat-token-abc+/=="

	var capturedAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		// Minimal valid response for GetRepositories
		_, _ = w.Write([]byte(`{"value":[]}`))
	}))
	defer srv.Close()

	// Directly exercise doRequest by creating a provider with a known token.
	p := &AzureDevOpsProvider{
		organization: "org",
		project:      "proj",
		token:        pat,
		httpClient:   srv.Client(),
		logger:       zap.NewNop(),
	}

	// Build a request to the test server so doRequest populates the header.
	req, _ := http.NewRequest("GET", srv.URL, nil)

	// Call the private helper via the exported path — use a hand-assembled
	// request so we can inspect the Authorization header directly.
	_ = p.doRequest(t.Context(), "GET", srv.URL, nil, nil)

	// The expected value is ":PAT" encoded with RawURLEncoding (no padding).
	expectedCredential := base64.RawURLEncoding.EncodeToString([]byte(":" + pat))
	expectedHeader := "Basic " + expectedCredential

	// The incorrect value that StdEncoding would produce.
	stdCredential := base64.StdEncoding.EncodeToString([]byte(":" + pat))
	stdHeader := "Basic " + stdCredential

	_ = req // silence unused warning

	if capturedAuth == "" {
		t.Fatal("Authorization header was not set — doRequest may not have been called")
	}

	if capturedAuth == stdHeader && capturedAuth != expectedHeader {
		t.Errorf("Authorization header uses base64.StdEncoding:\n  got:  %q\n  want: %q\n  (StdEncoding produced: %q)",
			capturedAuth, expectedHeader, stdHeader)
	}

	if capturedAuth != expectedHeader {
		t.Errorf("Authorization header mismatch:\n  got:  %q\n  want: %q",
			capturedAuth, expectedHeader)
	}
}
