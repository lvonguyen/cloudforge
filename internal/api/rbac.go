package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"go.uber.org/zap"
)

// Scopeable is implemented by resources that can be filtered by ResourceScope.
type Scopeable interface {
	GetAccountID() string
	GetRegion() string
	GetEnvironmentType() string
	GetLineOfBusiness() string
}

// EnforceScope checks whether a resource falls within the given scope.
// Returns nil if the resource is in scope, or an error describing the denial.
// A nil scope means unrestricted — always allows.
func EnforceScope(scope *ResourceScope, resource Scopeable) error {
	if scope == nil {
		return nil
	}
	if !MatchesDimension(scope.AccountIDs, resource.GetAccountID()) {
		return fmt.Errorf("resource account %q outside scope", resource.GetAccountID())
	}
	if !MatchesDimension(scope.Regions, resource.GetRegion()) {
		return fmt.Errorf("resource region %q outside scope", resource.GetRegion())
	}
	if !MatchesDimension(scope.Environments, resource.GetEnvironmentType()) {
		return fmt.Errorf("resource environment %q outside scope", resource.GetEnvironmentType())
	}
	if !MatchesDimension(scope.BusinessUnits, resource.GetLineOfBusiness()) {
		return fmt.Errorf("resource business unit %q outside scope", resource.GetLineOfBusiness())
	}
	return nil
}

// MatchesDimension returns true if the dimension is empty (allow all) or the value is in the list.
func MatchesDimension(allowed []string, value string) bool {
	if len(allowed) == 0 {
		return true
	}
	for _, a := range allowed {
		if strings.EqualFold(a, value) {
			return true
		}
	}
	return false
}

// LogScopeDenial emits a structured log when a resource access is denied by scope.
func LogScopeDenial(logger *zap.Logger, user, resourceID, resourceAccount, resourceRegion, reason string) {
	logger.Warn("scope_denial",
		zap.String("user", user),
		zap.String("resource_id", resourceID),
		zap.String("resource_account", resourceAccount),
		zap.String("resource_region", resourceRegion),
		zap.String("reason", reason),
	)
}

// ScopeFromContext extracts the ResourceScope from claims in context.
// Returns nil if no claims or no scope restriction.
func ScopeFromContext(claims *Claims) *ResourceScope {
	if claims == nil {
		return nil
	}
	return claims.ResourceScope
}

// Role represents a Cloud Aegis authorization role.
type Role string

const (
	RoleAdmin     Role = "admin"
	RoleOperator  Role = "operator"
	RoleRequester Role = "requester"
	RoleViewer    Role = "viewer"
)

// groupRoleMap maps IdP group names to roles (first match wins).
var groupRoleMap = map[string]Role{
	"aegis-admin":     RoleAdmin,
	"aegis-operator":  RoleOperator,
	"aegis-requester": RoleRequester,
	"aegis-viewer":    RoleViewer,
}

// roleRank defines privilege ordering for highest-privilege-wins resolution.
var roleRank = map[Role]int{
	RoleViewer:    0,
	RoleRequester: 1,
	RoleOperator:  2,
	RoleAdmin:     3,
}

// RoleFromClaims extracts the highest-privilege role from JWT group claims.
// Iterates all groups and returns the role with the highest rank.
// If no group matches, defaults to RoleViewer (least privilege).
func RoleFromClaims(c *Claims) Role {
	best := RoleViewer
	matched := false
	for _, g := range c.Groups {
		if role, ok := groupRoleMap[g]; ok {
			if !matched || roleRank[role] > roleRank[best] {
				best = role
				matched = true
			}
		}
	}
	return best
}

// RoleEnforcer builds role-checking middleware with a startup-captured devMode flag.
// devMode should be computed once from APP_ENV at server init — never re-read at
// request time to prevent runtime env changes from enabling privilege escalation.
type RoleEnforcer struct {
	DevMode bool
}

// Require returns middleware that enforces the request's role is in the allowed set.
// Must run after AuthMiddleware (claims in context).
// In dev mode only, the X-Aegis-Role header overrides the JWT-derived role
// to support the frontend demo role switcher.
func (re *RoleEnforcer) Require(roles ...Role) func(http.Handler) http.Handler {
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

			// Dev override: allow X-Aegis-Role header to set role for demo.
			// Only enabled when APP_ENV=="development" was read at startup.
			// Only valid canonical roles are accepted; invalid values are ignored.
			if re.DevMode {
				if override := r.Header.Get("X-Aegis-Role"); override != "" {
					candidate := Role(strings.ToLower(override))
					if _, valid := roleRank[candidate]; valid {
						role = candidate
					}
				}
			}

			if !allowed[role] {
				roleList := make([]string, 0, len(roles))
				for _, ar := range roles {
					roleList = append(roleList, string(ar))
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)
				_ = json.NewEncoder(w).Encode(map[string]any{
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
