package main

import (
	"bufio"
	"compress/gzip"
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"strings"

	"go.uber.org/zap"
)

// gzipMiddleware compresses responses for clients that accept gzip encoding.
// Applied at the http.Server level so all routes benefit (44MB findings -> ~4MB).
func (s *Server) gzipMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Bypass gzip for SSE and WebSocket — compression defeats low-latency streaming
		// and buffered writes prevent event delivery to the client.
		if r.Header.Get("Accept") == "text/event-stream" ||
			strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
			next.ServeHTTP(w, r)
			return
		}

		if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			next.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Vary", "Accept-Encoding")
		w.Header().Del("Content-Length")
		gz := gzip.NewWriter(w)
		defer func() {
			if err := gz.Close(); err != nil {
				s.logger.Warn("gzip close failed", zap.Error(err))
			}
		}()
		next.ServeHTTP(&gzipResponseWriter{ResponseWriter: w, gw: gz}, r)
	})
}

type gzipResponseWriter struct {
	http.ResponseWriter
	gw *gzip.Writer
}

func (w *gzipResponseWriter) Write(b []byte) (int, error) {
	return w.gw.Write(b)
}

// Flush flushes both the gzip buffer and the underlying ResponseWriter.
// Required for SSE handlers that call http.Flusher after writing each event.
func (w *gzipResponseWriter) Flush() {
	_ = w.gw.Flush()
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Hijack delegates to the underlying ResponseWriter for WebSocket upgrades.
func (w *gzipResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h, ok := w.ResponseWriter.(http.Hijacker); ok {
		return h.Hijack()
	}
	return nil, nil, fmt.Errorf("underlying ResponseWriter does not support Hijack")
}

type contextKey string

const cspNonceKey contextKey = "csp-nonce"

// generateCSPNonce produces a cryptographically random base64-encoded nonce
// for Content-Security-Policy headers. Returns empty string on failure (rare).
func generateCSPNonce() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(b)
}

// CSPNonceFromContext extracts the per-request CSP nonce for use in templates.
//
// SEC-004 status: The nonce infrastructure is in place, but style-src still
// requires 'unsafe-inline' because Vite-built SPAs inject inline styles
// (Tailwind reset, Radix UI) that cannot reference a server-generated nonce
// without a Vite plugin + HTML template nonce injection pipeline. Removing
// 'unsafe-inline' is a single CSP directive change once the frontend is ready.
func CSPNonceFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(cspNonceKey).(string); ok {
		return v
	}
	return ""
}

// securityHeadersMiddleware adds security headers and generates a per-request
// CSP nonce threaded through the request context.
// HSTS is only set on TLS connections or when the request was forwarded over HTTPS
// (X-Forwarded-Proto: https). Setting HSTS on plain HTTP causes browser lockout in dev.
func (s *Server) securityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		isTLS := r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
		if isTLS {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}

		nonce := generateCSPNonce()
		r = r.WithContext(context.WithValue(r.Context(), cspNonceKey, nonce))

		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Content-Security-Policy", fmt.Sprintf(
			"default-src 'self'; script-src 'self' 'nonce-%s'; style-src 'self' 'unsafe-inline' 'nonce-%s'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
			nonce, nonce,
		))
		next.ServeHTTP(w, r)
	})
}
