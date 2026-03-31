package threatintel

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestThreatFoxClient_SearchIOC(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST, got %s", r.Method)
		}
		if r.Header.Get("Auth-Key") != "test-key" {
			t.Fatalf("expected Auth-Key header, got %q", r.Header.Get("Auth-Key"))
		}
		if got := r.Header.Get("Content-Type"); !strings.Contains(got, "application/json") {
			t.Fatalf("expected JSON content type, got %q", got)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		if !strings.Contains(string(body), `"search_term":"1.2.3.4"`) {
			t.Fatalf("expected search_term in body, got %s", string(body))
		}
		_, _ = w.Write([]byte(`{"query_status":"ok","data":[{"ioc":"1.2.3.4:443","ioc_type":"ip:port","threat_type":"botnet_cc","malware":"win.test","malware_printable":"Test Malware","confidence_level":60,"tags":["c2","botnet","c2"]},{"ioc":"1.2.3.4:8443","ioc_type":"ip:port","threat_type":"botnet_cc","malware":"win.alt","malware_printable":"Alt Malware","confidence_level":75,"tags":["loader"]}]}`))
	}))
	defer srv.Close()

	client := NewThreatFoxClient("test-key", WithThreatFoxBaseURL(srv.URL), WithThreatFoxHTTPClient(srv.Client()))
	match, err := client.SearchIOC(context.Background(), "1.2.3.4")
	if err != nil {
		t.Fatalf("SearchIOC returned error: %v", err)
	}
	if match == nil {
		t.Fatal("expected non-nil match")
	}
	if match.IOC != "1.2.3.4:8443" {
		t.Fatalf("expected highest-confidence IOC, got %q", match.IOC)
	}
	if match.MalwarePrintable != "Alt Malware" {
		t.Fatalf("expected malware_printable, got %q", match.MalwarePrintable)
	}
}

func TestThreatFoxClient_Caching(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		_, _ = w.Write([]byte(`{"query_status":"ok","data":[{"ioc":"8.8.8.8:53","ioc_type":"ip:port","threat_type":"botnet_cc","malware":"win.test","malware_printable":"Test","confidence_level":40}]}`))
	}))
	defer srv.Close()

	client := NewThreatFoxClient("test-key", WithThreatFoxBaseURL(srv.URL), WithThreatFoxHTTPClient(srv.Client()))
	if _, err := client.SearchIOC(context.Background(), "8.8.8.8"); err != nil {
		t.Fatalf("first SearchIOC error: %v", err)
	}
	if _, err := client.SearchIOC(context.Background(), "8.8.8.8"); err != nil {
		t.Fatalf("second SearchIOC error: %v", err)
	}
	if hits != 1 {
		t.Fatalf("expected one upstream hit, got %d", hits)
	}
}

func TestThreatFoxClient_NoResult(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"query_status":"no_result","data":[]}`))
	}))
	defer srv.Close()

	client := NewThreatFoxClient("test-key", WithThreatFoxBaseURL(srv.URL), WithThreatFoxHTTPClient(srv.Client()))
	match, err := client.SearchIOC(context.Background(), "9.9.9.9")
	if err != nil {
		t.Fatalf("SearchIOC error: %v", err)
	}
	if match != nil {
		t.Fatalf("expected nil match, got %+v", match)
	}
}

func TestThreatFoxClient_RateLimitFallback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "too many requests", http.StatusTooManyRequests)
	}))
	defer srv.Close()

	client := NewThreatFoxClient("test-key", WithThreatFoxBaseURL(srv.URL), WithThreatFoxHTTPClient(srv.Client()))
	client.cache["5.5.5.5"] = threatFoxEntry{
		match:    &ThreatFoxMatch{IOC: "5.5.5.5:443", ConfidenceLevel: 99},
		cachedAt: time.Now(),
	}

	match, err := client.SearchIOC(context.Background(), "5.5.5.5")
	if err != nil {
		t.Fatalf("SearchIOC error: %v", err)
	}
	if match == nil || match.IOC != "5.5.5.5:443" {
		t.Fatalf("expected cached match on rate limit, got %+v", match)
	}
}

func TestThreatFoxClient_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusBadGateway)
	}))
	defer srv.Close()

	client := NewThreatFoxClient("test-key", WithThreatFoxBaseURL(srv.URL), WithThreatFoxHTTPClient(srv.Client()))
	if _, err := client.SearchIOC(context.Background(), "4.4.4.4"); err == nil {
		t.Fatal("expected error for non-200 response")
	}
}

func TestThreatFoxClient_InvalidateCache(t *testing.T) {
	client := NewThreatFoxClient("test-key")
	client.cache["1.1.1.1"] = threatFoxEntry{
		match:    &ThreatFoxMatch{IOC: "1.1.1.1:443"},
		cachedAt: time.Now(),
	}
	client.InvalidateCache()
	if len(client.cache) != 0 {
		t.Fatalf("expected empty cache, got %d entries", len(client.cache))
	}
}
