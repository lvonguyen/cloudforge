package graph

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.uber.org/zap/zaptest"
)

func TestQuery_Gremlin(t *testing.T) {
	want := `{"result":{"data":[{"id":"v1","label":"Finding"}]}}`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/gremlin" {
			t.Errorf("unexpected path: %s", r.URL.Path)
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("expected Content-Type application/json, got %s", ct)
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("reading request body: %v", err)
		}

		var req gremlinRequest
		if err := json.Unmarshal(body, &req); err != nil {
			t.Fatalf("unmarshalling gremlin request: %v", err)
		}
		if req.Gremlin != "g.V().limit(10)" {
			t.Errorf("unexpected gremlin query: %s", req.Gremlin)
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(want))
	}))
	defer srv.Close()

	c := NewClient(srv.URL, zaptest.NewLogger(t))
	result, err := c.Query(context.Background(), QueryRequest{
		Language: "gremlin",
		Query:    "g.V().limit(10)",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(result.Data) != want {
		t.Errorf("data mismatch:\n  got:  %s\n  want: %s", string(result.Data), want)
	}
	if result.Elapsed <= 0 {
		t.Error("elapsed duration should be positive")
	}
}

func TestQuery_Cypher(t *testing.T) {
	want := `{"results":[{"n":{"id":"v1"}}]}`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/cypher" {
			t.Errorf("unexpected path: %s", r.URL.Path)
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("expected Content-Type application/json, got %s", ct)
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("reading request body: %v", err)
		}

		var req cypherRequest
		if err := json.Unmarshal(body, &req); err != nil {
			t.Fatalf("unmarshalling cypher request: %v", err)
		}
		if req.Statement != "MATCH (n) RETURN n LIMIT 10" {
			t.Errorf("unexpected cypher statement: %s", req.Statement)
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(want))
	}))
	defer srv.Close()

	c := NewClient(srv.URL, zaptest.NewLogger(t))
	result, err := c.Query(context.Background(), QueryRequest{
		Language: "cypher",
		Query:    "MATCH (n) RETURN n LIMIT 10",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(result.Data) != want {
		t.Errorf("data mismatch:\n  got:  %s\n  want: %s", string(result.Data), want)
	}
	if result.Elapsed <= 0 {
		t.Error("elapsed duration should be positive")
	}
}

func TestQuery_UnsupportedLanguage(t *testing.T) {
	tests := []struct {
		name     string
		language string
	}{
		{name: "empty string", language: ""},
		{name: "sql", language: "sql"},
		{name: "sparql", language: "sparql"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewClient("http://localhost:0", zaptest.NewLogger(t))
			result, err := c.Query(context.Background(), QueryRequest{
				Language: tt.language,
				Query:    "SELECT 1",
			})
			if err == nil {
				t.Fatal("expected error for unsupported language, got nil")
			}
			if result != nil {
				t.Errorf("expected nil result, got %+v", result)
			}
			wantSubstr := "unsupported query language"
			if !strings.Contains(err.Error(), wantSubstr) {
				t.Errorf("error %q should contain %q", err.Error(), wantSubstr)
			}
		})
	}
}

func TestQuery_ServerError(t *testing.T) {
	tests := []struct {
		name       string
		language   string
		path       string
		statusCode int
		body       string
	}{
		{
			name:       "gremlin 500",
			language:   "gremlin",
			path:       "/gremlin",
			statusCode: http.StatusInternalServerError,
			body:       `{"error":"internal server error"}`,
		},
		{
			name:       "cypher 500",
			language:   "cypher",
			path:       "/cypher",
			statusCode: http.StatusInternalServerError,
			body:       `{"error":"query execution failed"}`,
		},
		{
			name:       "gremlin 502",
			language:   "gremlin",
			path:       "/gremlin",
			statusCode: http.StatusBadGateway,
			body:       "bad gateway",
		},
		{
			name:       "cypher 400",
			language:   "cypher",
			path:       "/cypher",
			statusCode: http.StatusBadRequest,
			body:       `{"error":"syntax error"}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != tt.path {
					t.Errorf("unexpected path: got %s, want %s", r.URL.Path, tt.path)
				}
				w.WriteHeader(tt.statusCode)
				_, _ = w.Write([]byte(tt.body))
			}))
			defer srv.Close()

			c := NewClient(srv.URL, zaptest.NewLogger(t))
			result, err := c.Query(context.Background(), QueryRequest{
				Language: tt.language,
				Query:    "invalid",
			})
			if err == nil {
				t.Fatal("expected error for server error response, got nil")
			}
			if result != nil {
				t.Errorf("expected nil result, got %+v", result)
			}
			if !strings.Contains(err.Error(), tt.body) {
				t.Errorf("error %q should contain response body %q", err.Error(), tt.body)
			}
		})
	}
}

func TestPing_Healthy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/health" {
			t.Errorf("unexpected path: %s", r.URL.Path)
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodGet {
			t.Errorf("expected GET, got %s", r.Method)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer srv.Close()

	c := NewClient(srv.URL, zaptest.NewLogger(t))
	if err := c.Ping(context.Background()); err != nil {
		t.Fatalf("expected healthy ping, got error: %v", err)
	}
}

func TestPing_Unhealthy(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
	}{
		{name: "503 service unavailable", statusCode: http.StatusServiceUnavailable},
		{name: "500 internal error", statusCode: http.StatusInternalServerError},
		{name: "404 not found", statusCode: http.StatusNotFound},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tt.statusCode)
			}))
			defer srv.Close()

			c := NewClient(srv.URL, zaptest.NewLogger(t))
			err := c.Ping(context.Background())
			if err == nil {
				t.Fatalf("expected error for HTTP %d, got nil", tt.statusCode)
			}
			wantSubstr := "health check"
			if !strings.Contains(err.Error(), wantSubstr) {
				t.Errorf("error %q should contain %q", err.Error(), wantSubstr)
			}
		})
	}
}

func TestQuery_ContextCancellation(t *testing.T) {
	tests := []struct {
		name     string
		language string
	}{
		{name: "gremlin cancelled", language: "gremlin"},
		{name: "cypher cancelled", language: "cypher"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{}`))
			}))
			defer srv.Close()

			ctx, cancel := context.WithCancel(context.Background())
			cancel() // cancel immediately

			c := NewClient(srv.URL, zaptest.NewLogger(t))
			result, err := c.Query(ctx, QueryRequest{
				Language: tt.language,
				Query:    "g.V()",
			})
			if err == nil {
				t.Fatal("expected error for cancelled context, got nil")
			}
			if result != nil {
				t.Errorf("expected nil result, got %+v", result)
			}
		})
	}
}

func TestPing_ContextCancellation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	c := NewClient(srv.URL, zaptest.NewLogger(t))
	err := c.Ping(ctx)
	if err == nil {
		t.Fatal("expected error for cancelled context, got nil")
	}
}

func TestNewClient_SetsTimeout(t *testing.T) {
	c := NewClient("http://localhost:8081", zaptest.NewLogger(t))
	if c.client.Timeout.Seconds() != 30 {
		t.Errorf("expected 30s timeout, got %v", c.client.Timeout)
	}
	if c.baseURL != "http://localhost:8081" {
		t.Errorf("expected baseURL http://localhost:8081, got %s", c.baseURL)
	}
}
