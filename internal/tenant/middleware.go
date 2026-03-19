package tenant

import (
	"net/http"
	"strings"

	"aegis/internal/api"

	"go.uber.org/zap"
)

// Middleware resolves the current tenant from the request and injects it
// into the context. Resolution order:
//
//  1. JWT tenant_id claim (strongest signal, set by IdP)
//  2. X-Tenant-ID header (API clients, testing)
//  3. Subdomain from Host header (browser access)
//
// If the store is nil (single-tenant mode), the middleware is a no-op.
func Middleware(store Store, logger *zap.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Nil store = single-tenant mode, pass through
			if store == nil {
				next.ServeHTTP(w, r)
				return
			}

			var tenantID string

			// 1. JWT tenant_id claim
			if claims, ok := api.GetClaimsFromContext(r.Context()); ok && claims.TenantID != "" {
				tenantID = claims.TenantID
			}

			// 2. X-Tenant-ID header fallback (only when JWT claims are present)
			if tenantID == "" {
				if _, hasClaims := api.GetClaimsFromContext(r.Context()); hasClaims {
					tenantID = r.Header.Get("X-Tenant-ID")
				}
			}

			// 3. Subdomain from Host
			if tenantID == "" {
				tenantID = extractSubdomain(r.Host)
			}

			// Resolve tenant config
			if tenantID != "" {
				cfg, err := store.Get(r.Context(), tenantID)
				if err != nil {
					// Try by domain as fallback
					cfg, err = store.GetByDomain(r.Context(), tenantID)
				}
				if err == nil && cfg != nil {
					r = r.WithContext(WithContext(r.Context(), cfg))
				} else if logger != nil {
					logger.Debug("Tenant not found, proceeding without tenant context",
						zap.String("tenant_id", tenantID),
						zap.Error(err),
					)
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}

// extractSubdomain returns the first subdomain from a host string.
// For example, "haea.aegis.io" returns "haea".
// Returns empty string for bare domains (no subdomain).
func extractSubdomain(host string) string {
	// Strip port
	if idx := strings.LastIndex(host, ":"); idx != -1 {
		host = host[:idx]
	}

	parts := strings.Split(host, ".")
	// Need at least 3 parts for a subdomain (sub.domain.tld)
	if len(parts) < 3 {
		return ""
	}
	// Skip "www"
	if parts[0] == "www" {
		return ""
	}
	return parts[0]
}
