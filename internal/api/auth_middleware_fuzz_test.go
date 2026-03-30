package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.uber.org/zap"
)

func FuzzValidateToken(f *testing.F) {
	header := base64URLEncode([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payload := base64URLEncode([]byte(validClaims("seed-user")))
	signingInput := header + "." + payload
	validHS256 := signingInput + "." + base64URLEncode(computeHS256([]byte(signingInput), []byte("secret")))

	f.Add(validHS256)
	f.Add("not-a-token")
	f.Add(buildRawJWT(`{"alg":"none","typ":"JWT"}`, validClaims("user"), ""))
	f.Add(buildRawJWT(`{"alg":"RS256","typ":"JWT","kid":"missing"}`, validClaims("user"), "sig"))
	f.Add("")

	f.Fuzz(func(t *testing.T, token string) {
		m := &AuthMiddleware{
			jwtSecret:  []byte("secret"),
			skipPaths:  map[string]bool{},
			httpClient: &http.Client{},
			logger:     zap.NewNop(),
		}

		claims, err := m.validateToken(token)
		if err == nil && claims == nil {
			t.Fatal("validateToken returned nil claims without an error")
		}
	})
}

func FuzzExtractToken(f *testing.F) {
	for _, seed := range []string{
		"Bearer token",
		"bearer token",
		"Bearer   token   ",
		"Basic abc",
		"Bearer",
		"",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, authHeader string) {
		m := &AuthMiddleware{
			skipPaths: map[string]bool{},
			logger:    zap.NewNop(),
		}

		req := httptest.NewRequest(http.MethodGet, "http://example.com/api", nil)
		if authHeader != "" {
			req.Header.Set("Authorization", authHeader)
		}

		token, err := m.extractToken(req)
		if err == nil {
			if token == "" {
				t.Fatal("extractToken returned empty token without an error")
			}
			if token != strings.TrimSpace(token) {
				t.Fatalf("extractToken returned untrimmed token %q", token)
			}
		}
	})
}
