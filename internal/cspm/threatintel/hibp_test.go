package threatintel

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestHIBPClient_GetBreachCount(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("hibp-api-key") != "test-key" {
			t.Error("missing or wrong API key header")
		}
		if r.Header.Get("User-Agent") != "CloudAegis-ThreatIntel" {
			t.Error("missing User-Agent header")
		}

		switch r.URL.Path {
		case "/breachedaccount/breached@example.com":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`[{"Name":"Breach1","Domain":"example.com","BreachDate":"2023-01-01"},{"Name":"Breach2","Domain":"other.com","BreachDate":"2024-06-15"}]`))
		case "/breachedaccount/clean@example.com":
			w.WriteHeader(http.StatusNotFound)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	client := NewHIBPClient("test-key",
		WithHIBPBaseURL(srv.URL+"/"),
		WithHIBPHTTPClient(srv.Client()),
	)

	ctx := context.Background()

	t.Run("breached email returns count", func(t *testing.T) {
		count, err := client.GetBreachCount(ctx, "breached@example.com")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if count != 2 {
			t.Errorf("expected 2 breaches, got %d", count)
		}
	})

	t.Run("clean email returns zero", func(t *testing.T) {
		count, err := client.GetBreachCount(ctx, "clean@example.com")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if count != 0 {
			t.Errorf("expected 0 breaches, got %d", count)
		}
	})
}

func TestHIBPClient_Caching(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`[{"Name":"B1","Domain":"d.com","BreachDate":"2024-01-01"}]`))
	}))
	defer srv.Close()

	client := NewHIBPClient("test-key",
		WithHIBPBaseURL(srv.URL+"/"),
		WithHIBPHTTPClient(srv.Client()),
	)

	ctx := context.Background()

	// First call hits the server
	count1, err := client.GetBreachCount(ctx, "user@d.com")
	if err != nil {
		t.Fatal(err)
	}
	if count1 != 1 {
		t.Errorf("expected 1, got %d", count1)
	}
	if calls != 1 {
		t.Errorf("expected 1 API call, got %d", calls)
	}

	// Second call should be cached
	count2, err := client.GetBreachCount(ctx, "user@d.com")
	if err != nil {
		t.Fatal(err)
	}
	if count2 != 1 {
		t.Errorf("expected 1, got %d", count2)
	}
	if calls != 1 {
		t.Errorf("expected 1 API call (cached), got %d", calls)
	}
}

func TestHIBPClient_CacheExpiry(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`[{"Name":"B1","Domain":"d.com","BreachDate":"2024-01-01"}]`))
	}))
	defer srv.Close()

	client := NewHIBPClient("test-key",
		WithHIBPBaseURL(srv.URL+"/"),
		WithHIBPHTTPClient(srv.Client()),
	)

	ctx := context.Background()

	// Seed cache with expired entry
	client.mu.Lock()
	client.cache["expired@d.com"] = hibpEntry{
		breachCount: 5,
		cachedAt:    time.Now().Add(-25 * time.Hour),
	}
	client.mu.Unlock()

	count, err := client.GetBreachCount(ctx, "expired@d.com")
	if err != nil {
		t.Fatal(err)
	}
	// Should have refetched (server returns 1)
	if count != 1 {
		t.Errorf("expected 1 after expiry, got %d", count)
	}
	if calls != 1 {
		t.Errorf("expected 1 API call after expiry, got %d", calls)
	}
}

func TestHIBPClient_RateLimitFallback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	client := NewHIBPClient("test-key",
		WithHIBPBaseURL(srv.URL+"/"),
		WithHIBPHTTPClient(srv.Client()),
	)

	// Seed cache so 429 can fall back
	client.mu.Lock()
	client.cache["throttled@d.com"] = hibpEntry{breachCount: 3, cachedAt: time.Now()}
	client.mu.Unlock()

	// Invalidate the cache for the test email to force a fetch
	client.mu.Lock()
	delete(client.cache, "throttled@d.com")
	// But seed fresh for the fallback check
	client.cache["throttled@d.com"] = hibpEntry{breachCount: 3, cachedAt: time.Now()}
	client.mu.Unlock()

	// Force a fresh fetch by using an email that's not in cache
	count, err := client.GetBreachCount(context.Background(), "unknown@d.com")
	if err != nil {
		t.Fatal(err)
	}
	// 429 with no cache = 0
	if count != 0 {
		t.Errorf("expected 0 on 429 without cache, got %d", count)
	}
}

func TestHIBPClient_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	client := NewHIBPClient("test-key",
		WithHIBPBaseURL(srv.URL+"/"),
		WithHIBPHTTPClient(srv.Client()),
	)

	_, err := client.GetBreachCount(context.Background(), "user@d.com")
	if err == nil {
		t.Error("expected error on 500")
	}
}

func TestHIBPClient_InvalidateCache(t *testing.T) {
	client := NewHIBPClient("test-key")

	client.mu.Lock()
	client.cache["a@b.com"] = hibpEntry{breachCount: 1, cachedAt: time.Now()}
	client.mu.Unlock()

	client.InvalidateCache()

	client.mu.RLock()
	if len(client.cache) != 0 {
		t.Errorf("expected empty cache after invalidate, got %d entries", len(client.cache))
	}
	client.mu.RUnlock()
}
