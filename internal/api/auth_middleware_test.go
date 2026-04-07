package api

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"
)

// base64URLEncode encodes bytes using base64url without padding (JWT format).
func base64URLEncode(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

// buildJWT constructs a signed JWT from pre-encoded header and payload JSON strings.
// header and payload are plain JSON strings (not yet base64-encoded).
func buildJWT(headerJSON, payloadJSON string, privKey *rsa.PrivateKey) string {
	h := base64URLEncode([]byte(headerJSON))
	p := base64URLEncode([]byte(payloadJSON))
	msg := h + "." + p
	hash := sha256.Sum256([]byte(msg))
	sig, err := rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA256, hash[:])
	if err != nil {
		panic("buildJWT: sign failed: " + err.Error())
	}
	return msg + "." + base64URLEncode(sig)
}

// buildRawJWT builds a JWT with an arbitrary (possibly invalid) signature section.
// Used to construct tokens for algorithm-rejection tests where signature is irrelevant.
func buildRawJWT(headerJSON, payloadJSON, sigPart string) string {
	h := base64URLEncode([]byte(headerJSON))
	p := base64URLEncode([]byte(payloadJSON))
	return h + "." + p + "." + sigPart
}

// makeJWKS returns a JWKS JSON body and the corresponding RSA private key.
func makeJWKS(kid string) ([]byte, *rsa.PrivateKey) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic("makeJWKS: keygen failed: " + err.Error())
	}
	pub := &privKey.PublicKey
	jwk := JWK{
		Kty: "RSA",
		Kid: kid,
		Use: "sig",
		Alg: "RS256",
		N:   base64URLEncode(pub.N.Bytes()),
		E:   base64URLEncode(big.NewInt(int64(pub.E)).Bytes()),
	}
	jwks := JWKS{Keys: []JWK{jwk}}
	body, err := json.Marshal(jwks)
	if err != nil {
		panic("makeJWKS: marshal failed: " + err.Error())
	}
	return body, privKey
}

// validClaims returns a minimal valid claims JSON with exp far in the future.
func validClaims(sub string) string {
	exp := time.Now().Add(1 * time.Hour).Unix()
	iat := time.Now().Unix()
	return `{"sub":"` + sub + `","exp":` + itoa(exp) + `,"iat":` + itoa(iat) + `}`
}

// itoa is a minimal int64-to-string helper to avoid importing strconv.
func itoa(n int64) string {
	b, _ := json.Marshal(n)
	return string(b)
}

// TestValidateToken_RS256_Success verifies a correctly signed RS256 token passes validation.
func TestValidateToken_RS256_Success(t *testing.T) {
	kid := "test-key-1"
	jwksBody, privKey := makeJWKS(kid)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(jwksBody)
	}))
	defer srv.Close()

	m := &AuthMiddleware{
		jwksURL:    srv.URL,
		skipPaths:  map[string]bool{},
		httpClient: srv.Client(),
		logger:     zap.NewNop(),
	}

	headerJSON := `{"alg":"RS256","typ":"JWT","kid":"` + kid + `"}`
	claimsJSON := validClaims("user@example.com")
	token := buildJWT(headerJSON, claimsJSON, privKey)

	claims, err := m.validateToken(token)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if claims.Subject != "user@example.com" {
		t.Errorf("expected sub=user@example.com, got: %s", claims.Subject)
	}
}

func TestValidateToken_RS256_StringAudience_Success(t *testing.T) {
	kid := "test-key-aud-string"
	jwksBody, privKey := makeJWKS(kid)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(jwksBody)
	}))
	defer srv.Close()

	m := &AuthMiddleware{
		config: AuthConfig{
			Audience: "api://default",
		},
		jwksURL:    srv.URL,
		skipPaths:  map[string]bool{},
		httpClient: srv.Client(),
		logger:     zap.NewNop(),
	}

	headerJSON := `{"alg":"RS256","typ":"JWT","kid":"` + kid + `"}`
	exp := time.Now().Add(1 * time.Hour).Unix()
	iat := time.Now().Unix()
	claimsJSON := `{"sub":"user@example.com","aud":"api://default","exp":` + itoa(exp) + `,"iat":` + itoa(iat) + `}`
	token := buildJWT(headerJSON, claimsJSON, privKey)

	claims, err := m.validateToken(token)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if len(claims.Audience) != 1 || claims.Audience[0] != "api://default" {
		t.Fatalf("audience = %#v, want [api://default]", claims.Audience)
	}
}

func TestValidateToken_RS256_ArrayAudience_Success(t *testing.T) {
	kid := "test-key-aud-array"
	jwksBody, privKey := makeJWKS(kid)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(jwksBody)
	}))
	defer srv.Close()

	m := &AuthMiddleware{
		config: AuthConfig{
			Audience: "api://default",
		},
		jwksURL:    srv.URL,
		skipPaths:  map[string]bool{},
		httpClient: srv.Client(),
		logger:     zap.NewNop(),
	}

	headerJSON := `{"alg":"RS256","typ":"JWT","kid":"` + kid + `"}`
	exp := time.Now().Add(1 * time.Hour).Unix()
	iat := time.Now().Unix()
	claimsJSON := `{"sub":"user@example.com","aud":["api://default","other"],"exp":` + itoa(exp) + `,"iat":` + itoa(iat) + `}`
	token := buildJWT(headerJSON, claimsJSON, privKey)

	claims, err := m.validateToken(token)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if len(claims.Audience) != 2 || claims.Audience[0] != "api://default" {
		t.Fatalf("audience = %#v, want [api://default other]", claims.Audience)
	}
}

// TestValidateToken_RS256_NoJWKSURL verifies RS256 tokens are rejected when no JWKS URL is set.
func TestValidateToken_RS256_NoJWKSURL(t *testing.T) {
	kid := "test-key-1"
	_, privKey := makeJWKS(kid)

	m := &AuthMiddleware{
		jwksURL:    "", // deliberately empty
		skipPaths:  map[string]bool{},
		httpClient: &http.Client{},
		logger:     zap.NewNop(),
	}

	headerJSON := `{"alg":"RS256","typ":"JWT","kid":"` + kid + `"}`
	claimsJSON := validClaims("user@example.com")
	token := buildJWT(headerJSON, claimsJSON, privKey)

	_, err := m.validateToken(token)
	if err == nil {
		t.Fatal("expected error for RS256 with no JWKS URL, got nil")
	}
	if !strings.Contains(err.Error(), "no JWKS URL") {
		t.Errorf("expected error to contain 'no JWKS URL', got: %v", err)
	}
}

// TestValidateToken_AlgNone_Rejected verifies tokens with alg="none" are rejected.
func TestValidateToken_AlgNone_Rejected(t *testing.T) {
	m := &AuthMiddleware{
		jwtSecret:  []byte("secret"),
		skipPaths:  map[string]bool{},
		httpClient: &http.Client{},
		logger:     zap.NewNop(),
	}

	token := buildRawJWT(`{"alg":"none","typ":"JWT"}`, validClaims("user"), "")

	_, err := m.validateToken(token)
	if err == nil {
		t.Fatal("expected error for alg=none, got nil")
	}
	errMsg := err.Error()
	if !strings.Contains(errMsg, "insecure") && !strings.Contains(errMsg, "SEC-010") {
		t.Errorf("expected error to contain 'insecure' or 'SEC-010', got: %v", err)
	}
}

// TestValidateToken_AlgEmpty_Rejected verifies tokens with alg="" are rejected.
func TestValidateToken_AlgEmpty_Rejected(t *testing.T) {
	m := &AuthMiddleware{
		jwtSecret:  []byte("secret"),
		skipPaths:  map[string]bool{},
		httpClient: &http.Client{},
		logger:     zap.NewNop(),
	}

	token := buildRawJWT(`{"alg":"","typ":"JWT"}`, validClaims("user"), "")

	_, err := m.validateToken(token)
	if err == nil {
		t.Fatal("expected error for alg='', got nil")
	}
	errMsg := err.Error()
	if !strings.Contains(errMsg, "insecure") && !strings.Contains(errMsg, "SEC-010") {
		t.Errorf("expected error to contain 'insecure' or 'SEC-010', got: %v", err)
	}
}

// TestValidateToken_UnsupportedAlg verifies tokens with unsupported algorithms are rejected.
func TestValidateToken_UnsupportedAlg(t *testing.T) {
	m := &AuthMiddleware{
		jwtSecret:  []byte("secret"),
		skipPaths:  map[string]bool{},
		httpClient: &http.Client{},
		logger:     zap.NewNop(),
	}

	token := buildRawJWT(`{"alg":"ES512","typ":"JWT"}`, validClaims("user"), "fakesig")

	_, err := m.validateToken(token)
	if err == nil {
		t.Fatal("expected error for alg=ES512, got nil")
	}
	if !strings.Contains(err.Error(), "unsupported algorithm") {
		t.Errorf("expected error to contain 'unsupported algorithm', got: %v", err)
	}
}

// TestShouldSkip_ExactMatch verifies an exact skip-path entry is matched.
func TestShouldSkip_ExactMatch(t *testing.T) {
	m := &AuthMiddleware{
		skipPaths: map[string]bool{"/health": true},
		logger:    zap.NewNop(),
	}
	if !m.shouldSkip("/health") {
		t.Error("expected /health to be skipped")
	}
}

// TestShouldSkip_SubPath verifies that a registered prefix also skips sub-paths.
func TestShouldSkip_SubPath(t *testing.T) {
	m := &AuthMiddleware{
		skipPaths: map[string]bool{"/health": true},
		logger:    zap.NewNop(),
	}
	if !m.shouldSkip("/health/ready") {
		t.Error("expected /health/ready to be skipped via prefix match")
	}
}

// TestShouldSkip_NoMatch verifies that a path sharing only a prefix (not followed by "/") is not skipped.
func TestShouldSkip_NoMatch(t *testing.T) {
	m := &AuthMiddleware{
		skipPaths: map[string]bool{"/health": true},
		logger:    zap.NewNop(),
	}
	if m.shouldSkip("/healthcheck") {
		t.Error("/healthcheck should NOT be skipped by /health entry")
	}
}

// TestShouldSkip_NoSkipPaths verifies that an empty skipPaths map never skips.
func TestShouldSkip_NoSkipPaths(t *testing.T) {
	m := &AuthMiddleware{
		skipPaths: map[string]bool{},
		logger:    zap.NewNop(),
	}
	for _, path := range []string{"/health", "/api/v1/findings", "/", ""} {
		if m.shouldSkip(path) {
			t.Errorf("expected %q not to be skipped with empty skipPaths", path)
		}
	}
}

// TestFetchJWKS_CacheHit verifies that a hot cache prevents HTTP calls.
func TestFetchJWKS_CacheHit(t *testing.T) {
	callCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"keys":[]}`))
	}))
	defer srv.Close()

	cachedJWKS := &JWKS{Keys: []JWK{{Kty: "RSA", Kid: "cached", N: "abc", E: "AQAB"}}}
	m := &AuthMiddleware{
		jwksURL:    srv.URL,
		httpClient: srv.Client(),
		logger:     zap.NewNop(),
		jwksCache:  cachedJWKS,
		jwksCacheT: time.Now(), // fresh — well within jwksCacheDuration
	}

	result, err := m.fetchJWKS()
	if err != nil {
		t.Fatalf("fetchJWKS returned error: %v", err)
	}
	if callCount != 0 {
		t.Errorf("expected 0 HTTP calls on cache hit, got %d", callCount)
	}
	if len(result.Keys) != 1 || result.Keys[0].Kid != "cached" {
		t.Errorf("expected cached JWKS to be returned, got: %+v", result)
	}
}
