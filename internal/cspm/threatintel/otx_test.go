package threatintel

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestOTXClient_GetIndicator(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-OTX-API-KEY") != "test-key" {
			t.Error("missing or wrong API key header")
		}

		switch r.URL.Path {
		case "/indicators/IPv4/1.2.3.4/general":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{
				"pulse_info": {
					"count": 5,
					"pulses": [
						{"tags": ["malware", "botnet"]},
						{"tags": ["botnet", "c2"]}
					]
				}
			}`))
		case "/indicators/domain/clean.example.com/general":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"pulse_info": {"count": 0, "pulses": []}}`))
		case "/indicators/IPv4/10.0.0.1/general":
			w.WriteHeader(http.StatusNotFound)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	client := NewOTXClient("test-key",
		WithOTXBaseURL(srv.URL+"/"),
		WithOTXHTTPClient(srv.Client()),
	)

	ctx := context.Background()

	t.Run("malicious IP returns pulses and tags", func(t *testing.T) {
		indicator, err := client.GetIndicator(ctx, OTXTypeIPv4, "1.2.3.4")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if indicator.PulseCount != 5 {
			t.Errorf("expected 5 pulses, got %d", indicator.PulseCount)
		}
		// Tags should be deduplicated and sorted
		expectedTags := []string{"botnet", "c2", "malware"}
		if len(indicator.Tags) != len(expectedTags) {
			t.Fatalf("expected %d tags, got %d: %v", len(expectedTags), len(indicator.Tags), indicator.Tags)
		}
		for i, tag := range expectedTags {
			if indicator.Tags[i] != tag {
				t.Errorf("tag[%d]: expected %q, got %q", i, tag, indicator.Tags[i])
			}
		}
	})

	t.Run("clean domain returns zero pulses", func(t *testing.T) {
		indicator, err := client.GetIndicator(ctx, OTXTypeDomain, "clean.example.com")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if indicator.PulseCount != 0 {
			t.Errorf("expected 0 pulses, got %d", indicator.PulseCount)
		}
	})

	t.Run("not found returns empty indicator", func(t *testing.T) {
		indicator, err := client.GetIndicator(ctx, OTXTypeIPv4, "10.0.0.1")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if indicator.PulseCount != 0 {
			t.Errorf("expected 0 pulses for 404, got %d", indicator.PulseCount)
		}
	})
}

func TestOTXClient_Caching(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"pulse_info": {"count": 3, "pulses": [{"tags": ["scan"]}]}}`))
	}))
	defer srv.Close()

	client := NewOTXClient("test-key",
		WithOTXBaseURL(srv.URL+"/"),
		WithOTXHTTPClient(srv.Client()),
	)

	ctx := context.Background()

	ind1, _ := client.GetIndicator(ctx, OTXTypeIPv4, "8.8.8.8")
	if calls != 1 {
		t.Errorf("expected 1 API call, got %d", calls)
	}
	if ind1.PulseCount != 3 {
		t.Errorf("expected 3 pulses, got %d", ind1.PulseCount)
	}

	// Second call should be cached
	ind2, _ := client.GetIndicator(ctx, OTXTypeIPv4, "8.8.8.8")
	if calls != 1 {
		t.Errorf("expected 1 API call (cached), got %d", calls)
	}
	if ind2.PulseCount != 3 {
		t.Errorf("expected 3 pulses (cached), got %d", ind2.PulseCount)
	}
}

func TestOTXClient_CacheExpiry(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"pulse_info": {"count": 1, "pulses": []}}`))
	}))
	defer srv.Close()

	client := NewOTXClient("test-key",
		WithOTXBaseURL(srv.URL+"/"),
		WithOTXHTTPClient(srv.Client()),
	)

	// Seed expired cache entry
	client.mu.Lock()
	client.cache["IPv4:9.9.9.9"] = otxEntry{
		indicator: &OTXIndicator{PulseCount: 99},
		cachedAt:  time.Now().Add(-13 * time.Hour),
	}
	client.mu.Unlock()

	ind, err := client.GetIndicator(context.Background(), OTXTypeIPv4, "9.9.9.9")
	if err != nil {
		t.Fatal(err)
	}
	if ind.PulseCount != 1 {
		t.Errorf("expected 1 after expiry refresh, got %d", ind.PulseCount)
	}
	if calls != 1 {
		t.Errorf("expected 1 API call after expiry, got %d", calls)
	}
}

func TestOTXClient_RateLimitFallback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	client := NewOTXClient("test-key",
		WithOTXBaseURL(srv.URL+"/"),
		WithOTXHTTPClient(srv.Client()),
	)

	// 429 without cache returns empty indicator
	ind, err := client.GetIndicator(context.Background(), OTXTypeIPv4, "5.5.5.5")
	if err != nil {
		t.Fatal(err)
	}
	if ind.PulseCount != 0 {
		t.Errorf("expected 0 on 429 without cache, got %d", ind.PulseCount)
	}
}

func TestOTXClient_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	client := NewOTXClient("test-key",
		WithOTXBaseURL(srv.URL+"/"),
		WithOTXHTTPClient(srv.Client()),
	)

	_, err := client.GetIndicator(context.Background(), OTXTypeIPv4, "1.1.1.1")
	if err == nil {
		t.Error("expected error on 500")
	}
}

func TestOTXClient_InvalidateCache(t *testing.T) {
	client := NewOTXClient("test-key")

	client.mu.Lock()
	client.cache["IPv4:1.1.1.1"] = otxEntry{
		indicator: &OTXIndicator{PulseCount: 1},
		cachedAt:  time.Now(),
	}
	client.mu.Unlock()

	client.InvalidateCache()

	client.mu.RLock()
	if len(client.cache) != 0 {
		t.Errorf("expected empty cache after invalidate, got %d entries", len(client.cache))
	}
	client.mu.RUnlock()
}
