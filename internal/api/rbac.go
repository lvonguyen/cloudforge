package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
)

// Role represents a CloudForge authorization role.
type Role string

const (
	RoleAdmin     Role = "admin"
	RoleOperator  Role = "operator"
	RoleRequester Role = "requester"
)

// groupRoleMap maps IdP/CF Access group names to roles (first match wins).
var groupRoleMap = map[string]Role{
	"cloudforge-admin":    RoleAdmin,
	"cloudforge-operator": RoleOperator,
}

// RoleFromClaims extracts the highest-privilege role from JWT group claims.
// First group matching a known role wins; unmatched defaults to requester.
func RoleFromClaims(c *Claims) Role {
	for _, g := range c.Groups {
		if role, ok := groupRoleMap[g]; ok {
			return role
		}
	}
	return RoleRequester
}

// RequireRole returns middleware that enforces the request's role is in the
// allowed set. Must run after AuthMiddleware (claims in context).
// In dev mode, the X-CloudForge-Role header overrides the JWT-derived role
// to support the frontend demo role switcher.
func RequireRole(roles ...Role) func(http.Handler) http.Handler {
	allowed := make(map[Role]bool, len(roles))
	for _, r := range roles {
		allowed[r] = true
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, ok := GetClaimsFromContext(r.Context())
			if !ok {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				_ = json.NewEncoder(w).Encode(map[string]string{
					"error":   "unauthorized",
					"message": "missing authentication claims",
				})
				return
			}

			role := RoleFromClaims(claims)

			// Dev override: allow X-CloudForge-Role header to set role for demo.
			// Gated to non-production environments to prevent privilege escalation.
			env := os.Getenv("APP_ENV")
			if env == "development" || env == "staging" {
				if override := r.Header.Get("X-CloudForge-Role"); override != "" {
					role = Role(strings.ToLower(override))
				}
			}

			if !allowed[role] {
				roleList := make([]string, 0, len(roles))
				for _, ar := range roles {
					roleList = append(roleList, string(ar))
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"error":          "forbidden",
					"message":        fmt.Sprintf("role '%s' cannot access this resource", role),
					"required_roles": roleList,
				})
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
