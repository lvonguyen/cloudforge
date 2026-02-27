// Package api provides API security and middleware components
package api

import (
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

// AuthConfig holds configuration for the authentication middleware.
type AuthConfig struct {
	// JWTSecretEnv is the environment variable name containing the JWT secret.
	// Required for HS256 signature verification.
	JWTSecretEnv string

	// JWKSURLEnv is the environment variable name containing the JWKS endpoint URL.
	// Used for RS256/ES256 signature verification (e.g., Auth0, Okta).
	JWKSURLEnv string

	// Issuer is the expected token issuer (iss claim).
	Issuer string

	// Audience is the expected token audience (aud claim).
	Audience string

	// SkipPaths lists paths that bypass authentication (e.g., /health).
	SkipPaths []string
}

// Claims represents the JWT claims we validate.
type Claims struct {
	Subject   string   `json:"sub"`
	Issuer    string   `json:"iss"`
	Audience  []string `json:"aud"`
	ExpiresAt int64    `json:"exp"`
	NotBefore int64    `json:"nbf"`
	IssuedAt  int64    `json:"iat"`
	Email     string   `json:"email,omitempty"`
	Scope     string   `json:"scope,omitempty"`
}

// contextKey is a custom type for context keys to avoid collisions.
type contextKey string

const (
	// ClaimsContextKey is the context key for storing validated claims.
	ClaimsContextKey contextKey = "auth_claims"

	// jwksCacheDuration is how long to cache JWKS before refreshing
	jwksCacheDuration = 1 * time.Hour
)

// JWK represents a JSON Web Key
type JWK struct {
	Kty string `json:"kty"` // Key type (RSA, EC)
	Kid string `json:"kid"` // Key ID
	Use string `json:"use"` // Usage (sig = signature)
	Alg string `json:"alg"` // Algorithm (RS256, ES256)
	N   string `json:"n"`   // RSA modulus (base64url)
	E   string `json:"e"`   // RSA exponent (base64url)
}

// JWKS represents a JSON Web Key Set
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// AuthMiddleware provides JWT authentication for HTTP handlers.
type AuthMiddleware struct {
	config     AuthConfig
	jwtSecret  []byte
	skipPaths  map[string]bool
	jwksURL    string
	jwksCache  *JWKS
	jwksCacheT time.Time
	jwksMu     sync.RWMutex
	httpClient *http.Client
	logger     *zap.Logger
}

// NewAuthMiddleware creates a new authentication middleware.
// Returns an error if required credentials are missing from environment.
func NewAuthMiddleware(config AuthConfig, logger *zap.Logger) (*AuthMiddleware, error) {
	if logger == nil {
		logger = zap.NewNop()
	}
	m := &AuthMiddleware{
		config:    config,
		skipPaths: make(map[string]bool),
		logger:    logger,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}

	// Build skip paths map for O(1) lookup
	for _, path := range config.SkipPaths {
		m.skipPaths[path] = true
	}

	// Load JWT secret from environment (for HS256)
	if config.JWTSecretEnv != "" {
		secret := os.Getenv(config.JWTSecretEnv)
		if secret != "" {
			m.jwtSecret = []byte(secret)
		}
	}

	// Load JWKS URL from environment (for RS256/ES256)
	if config.JWKSURLEnv != "" {
		jwksURL := os.Getenv(config.JWKSURLEnv)
		if jwksURL != "" {
			m.jwksURL = jwksURL
		}
	}

	// Validate that we have at least one auth method configured
	if len(m.jwtSecret) == 0 && m.jwksURL == "" {
		return nil, fmt.Errorf("creating auth middleware: either JWTSecretEnv or JWKSURLEnv must be configured with valid values")
	}

	return m, nil
}

// Middleware returns an HTTP middleware handler that validates JWT tokens.
func (m *AuthMiddleware) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if path should skip authentication
		if m.shouldSkip(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}

		// Extract token from Authorization header
		token, err := m.extractToken(r)
		if err != nil {
			m.logger.Warn("auth: token extraction failed",
				zap.String("remote_addr", r.RemoteAddr),
				zap.Error(err),
			)
			m.unauthorized(w, "authentication failed")
			return
		}

		// Validate token and extract claims
		claims, err := m.validateToken(token)
		if err != nil {
			m.logger.Warn("auth: token validation failed",
				zap.String("remote_addr", r.RemoteAddr),
				zap.Error(err),
			)
			m.unauthorized(w, "authentication failed")
			return
		}

		// Add claims to request context
		ctx := context.WithValue(r.Context(), ClaimsContextKey, claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// shouldSkip returns true if the path should bypass authentication.
func (m *AuthMiddleware) shouldSkip(path string) bool {
	// Exact match
	if m.skipPaths[path] {
		return true
	}

	// Check for sub-path matches (e.g., /health matches /health/ready but not /healthcare)
	for skipPath := range m.skipPaths {
		if strings.HasPrefix(path, skipPath+"/") {
			return true
		}
	}

	return false
}

// extractToken extracts the Bearer token from the Authorization header.
func (m *AuthMiddleware) extractToken(r *http.Request) (string, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return "", fmt.Errorf("missing Authorization header")
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return "", fmt.Errorf("invalid Authorization header format, expected 'Bearer <token>'")
	}

	token := strings.TrimSpace(parts[1])
	if token == "" {
		return "", fmt.Errorf("empty bearer token")
	}

	return token, nil
}

// validateToken validates a JWT token and returns the claims.
// Supports both HS256 (symmetric) and RS256 (asymmetric via JWKS) algorithms.
func (m *AuthMiddleware) validateToken(token string) (*Claims, error) {
	// Split JWT into parts
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid token format")
	}

	// Decode header to check algorithm and key ID
	headerJSON, err := base64URLDecode(parts[0])
	if err != nil {
		return nil, fmt.Errorf("decoding token header: %w", err)
	}

	var header struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
		Kid string `json:"kid"` // Key ID for JWKS lookup
	}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, fmt.Errorf("parsing token header: %w", err)
	}

	// Verify signature based on algorithm
	switch header.Alg {
	case "HS256":
		if len(m.jwtSecret) == 0 {
			return nil, fmt.Errorf("HS256 token received but no JWT secret configured")
		}
		if err := m.verifyHS256Signature(parts[0], parts[1], parts[2]); err != nil {
			return nil, err
		}
	case "RS256":
		if m.jwksURL == "" {
			return nil, fmt.Errorf("RS256 token received but no JWKS URL configured")
		}
		if err := m.verifyRS256Signature(parts[0], parts[1], parts[2], header.Kid); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s (supported: HS256, RS256)", header.Alg)
	}

	// Decode and parse claims
	claimsJSON, err := base64URLDecode(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decoding token claims: %w", err)
	}

	var claims Claims
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		return nil, fmt.Errorf("parsing token claims: %w", err)
	}

	// Validate standard claims
	if err := m.validateClaims(&claims); err != nil {
		return nil, err
	}

	return &claims, nil
}

// verifyHS256Signature verifies the HMAC-SHA256 signature.
func (m *AuthMiddleware) verifyHS256Signature(header, payload, signature string) error {
	if len(m.jwtSecret) == 0 {
		return fmt.Errorf("JWT secret not configured for HS256 validation")
	}

	// Compute expected signature
	message := header + "." + payload
	expectedSig := computeHS256([]byte(message), m.jwtSecret)

	// Decode provided signature
	providedSig, err := base64URLDecode(signature)
	if err != nil {
		return fmt.Errorf("decoding signature: %w", err)
	}

	// Constant-time comparison to prevent timing attacks
	if subtle.ConstantTimeCompare(expectedSig, providedSig) != 1 {
		return fmt.Errorf("invalid token signature")
	}

	return nil
}

// validateClaims validates the JWT claims.
func (m *AuthMiddleware) validateClaims(claims *Claims) error {
	now := time.Now().Unix()

	// Require expiration claim — tokens without exp are rejected
	if claims.ExpiresAt == 0 {
		return fmt.Errorf("token missing required exp claim")
	}
	if claims.ExpiresAt < now {
		return fmt.Errorf("token expired")
	}

	// Check not-before (reject tokens used too early, with 60s clock skew)
	if claims.NotBefore != 0 && now < claims.NotBefore-60 {
		return fmt.Errorf("token not yet valid")
	}

	// Check issued at (reject tokens from the future)
	if claims.IssuedAt != 0 && claims.IssuedAt > now+60 {
		return fmt.Errorf("token issued in the future")
	}

	// Validate issuer if configured
	if m.config.Issuer != "" && claims.Issuer != m.config.Issuer {
		return fmt.Errorf("invalid token issuer")
	}

	// Validate audience if configured
	if m.config.Audience != "" {
		found := false
		for _, aud := range claims.Audience {
			if aud == m.config.Audience {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("invalid token audience")
		}
	}

	return nil
}

// unauthorized sends a 401 response with the given message.
func (m *AuthMiddleware) unauthorized(w http.ResponseWriter, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("WWW-Authenticate", "Bearer")
	w.WriteHeader(http.StatusUnauthorized)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":   "unauthorized",
		"message": message,
	})
}

// GetClaimsFromContext extracts the validated claims from the request context.
func GetClaimsFromContext(ctx context.Context) (*Claims, bool) {
	claims, ok := ctx.Value(ClaimsContextKey).(*Claims)
	return claims, ok
}

// base64URLDecode decodes a base64url-encoded string (JWT format).
func base64URLDecode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

// computeHS256 computes HMAC-SHA256 signature.
func computeHS256(message, secret []byte) []byte {
	h := hmac.New(sha256.New, secret)
	h.Write(message)
	return h.Sum(nil)
}

// verifyRS256Signature verifies an RSA-SHA256 signature using JWKS.
func (m *AuthMiddleware) verifyRS256Signature(header, payload, signature, kid string) error {
	// Get the public key from JWKS
	pubKey, err := m.getPublicKey(kid)
	if err != nil {
		return fmt.Errorf("getting public key: %w", err)
	}

	// Decode the signature
	sigBytes, err := base64URLDecode(signature)
	if err != nil {
		return fmt.Errorf("decoding signature: %w", err)
	}

	// Compute hash of the message
	message := header + "." + payload
	hash := sha256.Sum256([]byte(message))

	// Verify the signature
	if err := rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hash[:], sigBytes); err != nil {
		return fmt.Errorf("invalid token signature")
	}

	return nil
}

// getPublicKey retrieves and caches the public key from JWKS.
func (m *AuthMiddleware) getPublicKey(kid string) (*rsa.PublicKey, error) {
	jwks, err := m.fetchJWKS()
	if err != nil {
		return nil, err
	}

	// Find the key by ID
	for _, key := range jwks.Keys {
		if key.Kid == kid && key.Kty == "RSA" {
			return jwkToRSAPublicKey(key)
		}
	}

	// If no kid match and only one key, use it (common for simple setups)
	if kid == "" && len(jwks.Keys) == 1 && jwks.Keys[0].Kty == "RSA" {
		return jwkToRSAPublicKey(jwks.Keys[0])
	}

	return nil, fmt.Errorf("no matching key found in JWKS for kid: %s", kid)
}

// fetchJWKS fetches and caches the JWKS from the configured URL.
func (m *AuthMiddleware) fetchJWKS() (*JWKS, error) {
	m.jwksMu.RLock()
	if m.jwksCache != nil && time.Since(m.jwksCacheT) < jwksCacheDuration {
		cached := m.jwksCache
		m.jwksMu.RUnlock()
		return cached, nil
	}
	m.jwksMu.RUnlock()

	// Fetch fresh JWKS
	m.jwksMu.Lock()
	defer m.jwksMu.Unlock()

	// Double-check after acquiring write lock
	if m.jwksCache != nil && time.Since(m.jwksCacheT) < jwksCacheDuration {
		return m.jwksCache, nil
	}

	req, err := http.NewRequest("GET", m.jwksURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating JWKS request: %w", err)
	}

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching JWKS: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JWKS endpoint returned status %d", resp.StatusCode)
	}

	// Cap JWKS response to 64KB to prevent memory exhaustion from compromised endpoints
	var jwks JWKS
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&jwks); err != nil {
		return nil, fmt.Errorf("decoding JWKS: %w", err)
	}

	m.jwksCache = &jwks
	m.jwksCacheT = time.Now()

	return &jwks, nil
}

// jwkToRSAPublicKey converts a JWK to an RSA public key.
func jwkToRSAPublicKey(jwk JWK) (*rsa.PublicKey, error) {
	// Decode modulus
	nBytes, err := base64URLDecode(jwk.N)
	if err != nil {
		return nil, fmt.Errorf("decoding modulus: %w", err)
	}

	// Decode exponent
	eBytes, err := base64URLDecode(jwk.E)
	if err != nil {
		return nil, fmt.Errorf("decoding exponent: %w", err)
	}

	// Convert exponent bytes to int
	var e int
	for _, b := range eBytes {
		e = e<<8 + int(b)
	}

	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: e,
	}, nil
}
