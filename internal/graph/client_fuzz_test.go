package graph

import (
	"net/url"
	"testing"
)

func FuzzGremlinWSURL(f *testing.F) {
	for _, seed := range []string{
		"http://localhost:8081",
		"https://graph.example.com:8081",
		"http://10.0.0.1:8081/some/path",
		"localhost:8081",
		"",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, baseURL string) {
		got, err := gremlinWSURL(baseURL)
		if err != nil {
			return
		}

		u, err := url.Parse(got)
		if err != nil {
			t.Fatalf("gremlinWSURL returned an unparseable URL %q: %v", got, err)
		}
		if u.Hostname() == "" {
			t.Fatalf("gremlinWSURL returned an empty host for %q", baseURL)
		}
		if gotPort := u.Port(); gotPort != "8182" {
			t.Fatalf("gremlinWSURL returned port %q, want 8182", gotPort)
		}
		if u.Path != "/gremlin" {
			t.Fatalf("gremlinWSURL returned path %q, want /gremlin", u.Path)
		}
		if u.Scheme != "ws" && u.Scheme != "wss" {
			t.Fatalf("gremlinWSURL returned scheme %q", u.Scheme)
		}
	})
}
