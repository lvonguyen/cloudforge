// Package api provides API security and middleware components
package api

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
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
	IssuedAt  int64    `json:"iat"`
	Email     string   `json:"email,omitempty"`
	Scope     string   `json:"scope,omitempty"`
}

// contextKey is a custom type for context keys to avoid collisions.
type contextKey string

const (
	// ClaimsContextKey is the context key for storing validated claims.
	ClaimsContextKey contextKey = "auth_claims"
)

// AuthMiddleware provides JWT authentication for HTTP handlers.
type AuthMiddleware struct {
	config    AuthConfig
	jwtSecret []byte
	skipPaths map[string]bool
}

// NewAuthMiddleware creates a new authentication middleware.
// Returns an error if required credentials are missing from environment.
func NewAuthMiddleware(config AuthConfig) (*AuthMiddleware, error) {
	m := &AuthMiddleware{
		config:    config,
		skipPaths: make(map[string]bool),
	}

	// Build skip paths map for O(1) lookup
	for _, path := range config.SkipPaths {
		m.skipPaths[path] = true
	}

	// Load JWT secret from environment
	if config.JWTSecretEnv != "" {
		secret := os.Getenv(config.JWTSecretEnv)
		if secret == "" {
			return nil, fmt.Errorf("creating auth middleware: JWT secret environment variable %s is not set", config.JWTSecretEnv)
		}
		m.jwtSecret = []byte(secret)
	}

	// Validate that we have at least one auth method configured
	if len(m.jwtSecret) == 0 && config.JWKSURLEnv == "" {
		return nil, fmt.Errorf("creating auth middleware: either JWTSecretEnv or JWKSURLEnv must be configured")
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
			m.unauthorized(w, err.Error())
			return
		}

		// Validate token and extract claims
		claims, err := m.validateToken(token)
		if err != nil {
			m.unauthorized(w, err.Error())
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

	// Check for prefix matches (e.g., /health matches /health/ready)
	for skipPath := range m.skipPaths {
		if strings.HasPrefix(path, skipPath) {
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
// Currently implements HS256 validation. For production OIDC/JWKS support,
// consider using a library like github.com/golang-jwt/jwt/v5.
func (m *AuthMiddleware) validateToken(token string) (*Claims, error) {
	// Split JWT into parts
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid token format")
	}

	// Decode header to check algorithm
	headerJSON, err := base64URLDecode(parts[0])
	if err != nil {
		return nil, fmt.Errorf("decoding token header: %w", err)
	}

	var header struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
	}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, fmt.Errorf("parsing token header: %w", err)
	}

	// Validate algorithm - only support HS256 for simplicity
	// For RS256/ES256, integrate with JWKS endpoint
	if header.Alg != "HS256" {
		return nil, fmt.Errorf("unsupported algorithm: %s (only HS256 supported)", header.Alg)
	}

	// Verify signature
	if err := m.verifyHS256Signature(parts[0], parts[1], parts[2]); err != nil {
		return nil, err
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

	// Check expiration
	if claims.ExpiresAt != 0 && claims.ExpiresAt < now {
		return fmt.Errorf("token expired")
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
	// Add padding if necessary
	switch len(s) % 4 {
	case 2:
		s += "=="
	case 3:
		s += "="
	}

	return base64.URLEncoding.DecodeString(s)
}

// computeHS256 computes HMAC-SHA256 signature.
func computeHS256(message, secret []byte) []byte {
	h := hmac.New(sha256.New, secret)
	h.Write(message)
	return h.Sum(nil)
}
