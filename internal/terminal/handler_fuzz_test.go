package terminal

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"go.uber.org/zap"
)

func FuzzCheckOrigin(f *testing.F) {
	f.Add("", "", false)
	f.Add("https://app.example.com", "https://app.example.com", false)
	f.Add("http://localhost:3000", "", true)
	f.Add("http://127.0.0.1:5173", "", true)
	f.Add("http://localhost.evil.com", "", true)

	f.Fuzz(func(t *testing.T, origin, allowed string, devMode bool) {
		h := &Handler{
			allowedOrigins: []string{allowed},
			devMode:        devMode,
			logger:         zap.NewNop(),
		}
		req := httptest.NewRequest(http.MethodGet, "http://example.com/ws", nil)
		if origin != "" {
			req.Header.Set("Origin", origin)
		}

		got := h.checkOrigin(req)

		if origin == "" && got {
			t.Fatal("empty Origin header should always be rejected")
		}
		if origin != "" && origin == allowed && !got {
			t.Fatalf("exact allowlist match was rejected: %q", origin)
		}

		u, err := url.Parse(origin)
		if err != nil {
			return
		}
		host := u.Hostname()
		isLocalDevOrigin := host == "localhost" || host == "127.0.0.1"
		if devMode && isLocalDevOrigin && !got {
			t.Fatalf("dev localhost origin was rejected: %q", origin)
		}
		if !devMode && isLocalDevOrigin && origin != allowed && got {
			t.Fatalf("localhost origin was accepted outside dev mode: %q", origin)
		}
	})
}
