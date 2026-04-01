package main

import (
	"encoding/json"
	"net/http"

	"aegis/internal/tenant"
)

// configResponse matches the frontend RuntimeConfig interface for branding.
type configResponse struct {
	CompanyName    string            `json:"companyName"`
	ProductName    string            `json:"productName"`
	LogoPath       string            `json:"logoPath"`
	EmailDomain    string            `json:"emailDomain"`
	RepoPrefix     string            `json:"repoPrefix"`
	EnabledModules []string          `json:"enabledModules"`
	StoragePrefix  string            `json:"storagePrefix"`
	Theme          map[string]string `json:"theme,omitempty"`
	Features       map[string]bool   `json:"features,omitempty"`
}

// Default Contoso branding (fallback when no tenant is resolved).
var defaultConfigResponse = configResponse{
	CompanyName:    "Contoso Inc.",
	ProductName:    "Aegis",
	LogoPath:       "/logo.svg",
	EmailDomain:    "contoso.com",
	RepoPrefix:     "contoso",
	EnabledModules: []string{"cspm", "grc", "finops", "identity", "attack-paths"},
	StoragePrefix:  "aegis",
	Theme: map[string]string{
		"primaryColor": "#f59e0b",
		"accentColor":  "#f97316",
	},
	Features: map[string]bool{
		"aiEnrichment": true,
		"attackPaths":  true,
		"finops":       true,
	},
}

// handleConfig serves GET /api/v1/config and GET /config.json.
// Unauthenticated — branding must load before auth.
func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	resp := defaultConfigResponse

	// Override with tenant branding if resolved
	if cfg := tenant.FromContext(r.Context()); cfg != nil {
		resp.CompanyName = cfg.Branding.CompanyName
		resp.ProductName = cfg.Branding.ProductName
		if cfg.Branding.LogoPath != "" {
			resp.LogoPath = cfg.Branding.LogoPath
		}
		if cfg.Branding.EmailDomain != "" {
			resp.EmailDomain = cfg.Branding.EmailDomain
		}
		if len(cfg.EnabledModules) > 0 {
			resp.EnabledModules = cfg.EnabledModules
		}
		resp.StoragePrefix = cfg.ID
		resp.RepoPrefix = cfg.ID
		resp.Theme = map[string]string{
			"primaryColor": cfg.Branding.PrimaryColor,
			"accentColor":  cfg.Branding.AccentColor,
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(resp)
}
