package threatintel

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const sampleGreyNoiseResponse = `{
  "ip": "8.8.8.8",
  "noise": false,
  "riot": true,
  "classification": "benign",
  "name": "Google Public DNS",
  "last_seen": "2024-01-15"
}`

func newGreyNoiseTestServer(handler http.HandlerFunc) *httptest.Server {
	return httptest.NewServer(handler)
}

func TestClassifyIP_Success(t *testing.T) {
	srv := newGreyNoiseTestServer(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/8.8.8.8") {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Header.Get("key") == "" {
			t.Error("expected API key header")
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(sampleGreyNoiseResponse))
	})
	defer srv.Close()

	client := NewGreyNoiseClient("test-api-key", WithBaseURL(srv.URL+"/"))
	result, err := client.ClassifyIP(context.Background(), "8.8.8.8")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IP != "8.8.8.8" {
		t.Errorf("expected IP 8.8.8.8, got %s", result.IP)
	}
	if result.Classification != "benign" {
		t.Errorf("expected classification benign, got %s", result.Classification)
	}
	if !result.Riot {
		t.Error("expected Riot to be true")
	}
	if result.Name != "Google Public DNS" {
		t.Errorf("expected name Google Public DNS, got %s", result.Name)
	}
}

func TestClassifyIP_CacheHit(t *testing.T) {
	callCount := 0
	srv := newGreyNoiseTestServer(func(w http.ResponseWriter, _ *http.Request) {
		callCount++
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(sampleGreyNoiseResponse))
	})
	defer srv.Close()

	client := NewGreyNoiseClient("test-api-key", WithBaseURL(srv.URL+"/"))

	// First call — hits server
	_, err := client.ClassifyIP(context.Background(), "8.8.8.8")
	if err != nil {
		t.Fatalf("first call failed: %v", err)
	}

	// Second call — should use cache
	_, err = client.ClassifyIP(context.Background(), "8.8.8.8")
	if err != nil {
		t.Fatalf("second call failed: %v", err)
	}

	if callCount != 1 {
		t.Errorf("expected 1 HTTP call, got %d (caching not working)", callCount)
	}
}

func TestClassifyIP_CacheExpiry(t *testing.T) {
	callCount := 0
	srv := newGreyNoiseTestServer(func(w http.ResponseWriter, _ *http.Request) {
		callCount++
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(sampleGreyNoiseResponse))
	})
	defer srv.Close()

	client := NewGreyNoiseClient("test-api-key", WithBaseURL(srv.URL+"/"))

	// Seed cache with an expired entry
	client.mu.Lock()
	client.cache["8.8.8.8"] = greynoiseEntry{
		result:   &GreyNoiseResult{IP: "8.8.8.8", Classification: "unknown"},
		cachedAt: time.Now().Add(-25 * time.Hour), // expired
	}
	client.mu.Unlock()

	result, err := client.ClassifyIP(context.Background(), "8.8.8.8")
	if err != nil {
		t.Fatalf("call failed: %v", err)
	}

	if callCount != 1 {
		t.Errorf("expected 1 HTTP call for expired entry, got %d", callCount)
	}
	if result.Classification != "benign" {
		t.Errorf("expected refreshed classification benign, got %s", result.Classification)
	}
}

func TestClassifyIP_RateLimit429(t *testing.T) {
	srv := newGreyNoiseTestServer(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	})
	defer srv.Close()

	client := NewGreyNoiseClient("test-api-key", WithBaseURL(srv.URL+"/"))

	// No cached data — should return zero-value result, not error
	result, err := client.ClassifyIP(context.Background(), "1.2.3.4")
	if err != nil {
		t.Fatalf("expected no error on 429, got: %v", err)
	}
	if result.Classification != "unknown" {
		t.Errorf("expected unknown classification on 429, got %s", result.Classification)
	}
	if result.IP != "1.2.3.4" {
		t.Errorf("expected IP 1.2.3.4, got %s", result.IP)
	}
}

func TestClassifyIP_RateLimit429_WithCache(t *testing.T) {
	srv := newGreyNoiseTestServer(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	})
	defer srv.Close()

	client := NewGreyNoiseClient("test-api-key", WithBaseURL(srv.URL+"/"))

	// Seed cache with existing (even expired) entry
	client.mu.Lock()
	client.cache["1.2.3.4"] = greynoiseEntry{
		result:   &GreyNoiseResult{IP: "1.2.3.4", Classification: "malicious", Noise: true},
		cachedAt: time.Now().Add(-25 * time.Hour),
	}
	client.mu.Unlock()

	result, err := client.ClassifyIP(context.Background(), "1.2.3.4")
	if err != nil {
		t.Fatalf("expected no error on 429 with cache, got: %v", err)
	}
	if result.Classification != "malicious" {
		t.Errorf("expected cached classification malicious on 429, got %s", result.Classification)
	}
}

func TestClassifyIP_HTTPError(t *testing.T) {
	srv := newGreyNoiseTestServer(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	defer srv.Close()

	client := NewGreyNoiseClient("test-api-key", WithBaseURL(srv.URL+"/"))
	_, err := client.ClassifyIP(context.Background(), "8.8.8.8")
	if err == nil {
		t.Error("expected error for 500 response, got nil")
	}
}

func TestBatchClassify_Success(t *testing.T) {
	responses := map[string]string{
		"8.8.8.8": `{"ip":"8.8.8.8","noise":false,"riot":true,"classification":"benign","name":"Google DNS","last_seen":"2024-01-15"}`,
		"1.1.1.1": `{"ip":"1.1.1.1","noise":false,"riot":true,"classification":"benign","name":"Cloudflare DNS","last_seen":"2024-01-15"}`,
	}
	srv := newGreyNoiseTestServer(func(w http.ResponseWriter, r *http.Request) {
		// Extract IP from path (last segment)
		parts := strings.Split(r.URL.Path, "/")
		ip := parts[len(parts)-1]
		if body, ok := responses[ip]; ok {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(body))
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	})
	defer srv.Close()

	client := NewGreyNoiseClient("test-api-key", WithBaseURL(srv.URL+"/"))
	results, err := client.BatchClassify(context.Background(), []string{"8.8.8.8", "1.1.1.1"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 2 {
		t.Errorf("expected 2 results, got %d", len(results))
	}
	if results["8.8.8.8"].Name != "Google DNS" {
		t.Errorf("expected Google DNS, got %s", results["8.8.8.8"].Name)
	}
	if results["1.1.1.1"].Name != "Cloudflare DNS" {
		t.Errorf("expected Cloudflare DNS, got %s", results["1.1.1.1"].Name)
	}
}

func TestBatchClassify_EmptyInput(t *testing.T) {
	client := NewGreyNoiseClient("test-api-key")
	results, err := client.BatchClassify(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("expected empty map for nil input, got %v", results)
	}
}
