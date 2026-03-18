package main

import (
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.uber.org/zap"
)

// minServer returns the minimal *Server needed to call gzipMiddleware and
// securityHeadersMiddleware — both only use s.logger.
func minServer() *Server {
	return &Server{logger: zap.NewNop()}
}

// echoHandler writes a fixed body so tests can assert on decompressed content.
const echoBody = "hello cloudforge"

func echoHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, echoBody)
	})
}

// --- gzipMiddleware tests ---

func TestGzipMiddleware_Compresses(t *testing.T) {
	srv := minServer()
	handler := srv.gzipMiddleware(echoHandler())

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if got := rr.Header().Get("Content-Encoding"); got != "gzip" {
		t.Fatalf("Content-Encoding = %q, want %q", got, "gzip")
	}

	gr, err := gzip.NewReader(rr.Body)
	if err != nil {
		t.Fatalf("gzip.NewReader: %v", err)
	}
	defer gr.Close()
	body, err := io.ReadAll(gr)
	if err != nil {
		t.Fatalf("reading decompressed body: %v", err)
	}
	if string(body) != echoBody {
		t.Errorf("decompressed body = %q, want %q", string(body), echoBody)
	}
}

func TestGzipMiddleware_BypassSSE(t *testing.T) {
	srv := minServer()
	handler := srv.gzipMiddleware(echoHandler())

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	req.Header.Set("Accept", "text/event-stream")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if got := rr.Header().Get("Content-Encoding"); got != "" {
		t.Errorf("Content-Encoding = %q, want empty (SSE bypass)", got)
	}
	if rr.Body.String() != echoBody {
		t.Errorf("body = %q, want %q", rr.Body.String(), echoBody)
	}
}

func TestGzipMiddleware_BypassWebSocket(t *testing.T) {
	srv := minServer()
	handler := srv.gzipMiddleware(echoHandler())

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	req.Header.Set("Upgrade", "websocket")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if got := rr.Header().Get("Content-Encoding"); got != "" {
		t.Errorf("Content-Encoding = %q, want empty (WebSocket bypass)", got)
	}
	if rr.Body.String() != echoBody {
		t.Errorf("body = %q, want %q", rr.Body.String(), echoBody)
	}
}

func TestGzipMiddleware_NoAcceptEncoding(t *testing.T) {
	srv := minServer()
	handler := srv.gzipMiddleware(echoHandler())

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if got := rr.Header().Get("Content-Encoding"); got != "" {
		t.Errorf("Content-Encoding = %q, want empty (no Accept-Encoding)", got)
	}
	if rr.Body.String() != echoBody {
		t.Errorf("body = %q, want %q", rr.Body.String(), echoBody)
	}
}

// --- securityHeadersMiddleware tests ---

func TestSecurityHeaders_AllPresent(t *testing.T) {
	srv := minServer()
	handler := srv.securityHeadersMiddleware(echoHandler())

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	checks := map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
	}
	for header, want := range checks {
		if got := rr.Header().Get(header); got != want {
			t.Errorf("%s = %q, want %q", header, got, want)
		}
	}
	if got := rr.Header().Get("X-XSS-Protection"); got == "" {
		t.Error("X-XSS-Protection header missing")
	}
	if got := rr.Header().Get("Content-Security-Policy"); got == "" {
		t.Error("Content-Security-Policy header missing")
	}
}

func TestSecurityHeaders_HSTS_OnlyHTTPS(t *testing.T) {
	srv := minServer()
	handler := srv.securityHeadersMiddleware(echoHandler())

	// HTTPS via X-Forwarded-Proto — HSTS must be present.
	reqHTTPS := httptest.NewRequest(http.MethodGet, "/", nil)
	reqHTTPS.Header.Set("X-Forwarded-Proto", "https")
	rrHTTPS := httptest.NewRecorder()
	handler.ServeHTTP(rrHTTPS, reqHTTPS)

	if got := rrHTTPS.Header().Get("Strict-Transport-Security"); got == "" {
		t.Error("HSTS header missing when X-Forwarded-Proto: https")
	}

	// Plain HTTP — HSTS must be absent.
	reqHTTP := httptest.NewRequest(http.MethodGet, "/", nil)
	rrHTTP := httptest.NewRecorder()
	handler.ServeHTTP(rrHTTP, reqHTTP)

	if got := rrHTTP.Header().Get("Strict-Transport-Security"); got != "" {
		t.Errorf("HSTS header = %q, want empty on plain HTTP", got)
	}
}

func TestSecurityHeaders_CSP_ContainsNonce(t *testing.T) {
	srv := minServer()
	handler := srv.securityHeadersMiddleware(echoHandler())

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	csp := rr.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "nonce-") {
		t.Errorf("CSP = %q, want it to contain 'nonce-'", csp)
	}
}

func TestCSPNonceFromContext(t *testing.T) {
	srv := minServer()

	var capturedNonce string
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedNonce = CSPNonceFromContext(r.Context())
	})
	handler := srv.securityHeadersMiddleware(inner)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if capturedNonce == "" {
		t.Fatal("CSPNonceFromContext returned empty string; nonce not threaded into context")
	}

	csp := rr.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, capturedNonce) {
		t.Errorf("CSP header does not contain the nonce %q that was threaded into context", capturedNonce)
	}
}

// --- generateCSPNonce tests ---

func TestGenerateCSPNonce_Format(t *testing.T) {
	// base64.StdEncoding of 16 bytes is always 24 characters (16 * 4/3 rounded up).
	const wantLen = 24
	for i := range 100 {
		n := generateCSPNonce()
		if n == "" {
			t.Fatalf("iteration %d: generateCSPNonce returned empty string", i)
		}
		if len(n) != wantLen {
			t.Fatalf("iteration %d: nonce length = %d, want %d (got %q)", i, len(n), wantLen, n)
		}
	}
}

func TestGenerateCSPNonce_Unique(t *testing.T) {
	a := generateCSPNonce()
	b := generateCSPNonce()
	if a == b {
		t.Errorf("two consecutive nonces are identical (%q); crypto/rand collision is astronomically unlikely", a)
	}
}
