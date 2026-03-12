package main

import (
	"compress/gzip"
	"net/http"
	"strings"

	"go.uber.org/zap"
)

// gzipMiddleware compresses responses for clients that accept gzip encoding.
// Applied at the http.Server level so all routes benefit (44MB findings -> ~4MB).
func (s *Server) gzipMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			next.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Vary", "Accept-Encoding")
		w.Header().Del("Content-Length")
		gz := gzip.NewWriter(w)
		next.ServeHTTP(&gzipResponseWriter{ResponseWriter: w, gw: gz}, r)
		if err := gz.Close(); err != nil {
			s.logger.Warn("gzip close failed", zap.Error(err))
		}
	})
}

type gzipResponseWriter struct {
	http.ResponseWriter
	gw *gzip.Writer
}

func (w *gzipResponseWriter) Write(b []byte) (int, error) {
	return w.gw.Write(b)
}

// securityHeadersMiddleware adds security headers.
// HSTS is only set on TLS connections or when the request was forwarded over HTTPS
// (X-Forwarded-Proto: https). Setting HSTS on plain HTTP causes browser lockout in dev.
func (s *Server) securityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		isTLS := r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
		if isTLS {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		next.ServeHTTP(w, r)
	})
}
