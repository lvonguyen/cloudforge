// Package waf provides WAF configuration management and golden templates
package waf

import (
	"context"
	"fmt"
	"strings"

	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

// GoldenTemplateManager manages WAF golden templates
type GoldenTemplateManager struct {
	templates map[string]*GoldenTemplate
	logger    *zap.Logger
}

// GoldenTemplate represents a WAF golden template
type GoldenTemplate struct {
	ID          string            `yaml:"id" json:"id"`
	Name        string            `yaml:"name" json:"name"`
	Description string            `yaml:"description" json:"description"`
	Provider    string            `yaml:"provider" json:"provider"` // aws, azure, cloudflare, etc.
	Environment string            `yaml:"environment" json:"environment"` // production, staging, development
	Exposure    string            `yaml:"exposure" json:"exposure"` // external, internal, dmz
	RuleSet     RuleSet           `yaml:"rule_set" json:"rule_set"`
	Metadata    TemplateMetadata  `yaml:"metadata" json:"metadata"`
}

// RuleSet contains WAF rules
type RuleSet struct {
	ManagedRules    []ManagedRule    `yaml:"managed_rules" json:"managed_rules"`
	CustomRules     []CustomRule     `yaml:"custom_rules" json:"custom_rules"`
	RateLimiting    RateLimitConfig  `yaml:"rate_limiting" json:"rate_limiting"`
	IPBlocking      IPBlockConfig    `yaml:"ip_blocking" json:"ip_blocking"`
	GeoBlocking     GeoBlockConfig   `yaml:"geo_blocking" json:"geo_blocking"`
	BotProtection   BotProtection    `yaml:"bot_protection" json:"bot_protection"`
}

// ManagedRule represents a managed rule set
type ManagedRule struct {
	Name       string   `yaml:"name" json:"name"`
	Vendor     string   `yaml:"vendor" json:"vendor"`       // owasp, aws, cloudflare
	Version    string   `yaml:"version" json:"version"`
	Action     string   `yaml:"action" json:"action"`       // block, log, count
	Exclusions []string `yaml:"exclusions" json:"exclusions"`
}

// CustomRule represents a custom WAF rule
type CustomRule struct {
	ID          string           `yaml:"id" json:"id"`
	Name        string           `yaml:"name" json:"name"`
	Description string           `yaml:"description" json:"description"`
	Priority    int              `yaml:"priority" json:"priority"`
	Conditions  []RuleCondition  `yaml:"conditions" json:"conditions"`
	Action      string           `yaml:"action" json:"action"` // block, allow, log, redirect
}

// RuleCondition represents a condition in a rule
type RuleCondition struct {
	Field       string   `yaml:"field" json:"field"`           // uri, query, header, body, ip
	Operator    string   `yaml:"operator" json:"operator"`     // contains, equals, regex, starts_with
	Values      []string `yaml:"values" json:"values"`
	Transform   string   `yaml:"transform" json:"transform"`   // lowercase, url_decode, none
	Negate      bool     `yaml:"negate" json:"negate"`
}

// RateLimitConfig configures rate limiting
type RateLimitConfig struct {
	Enabled        bool              `yaml:"enabled" json:"enabled"`
	DefaultLimit   int               `yaml:"default_limit" json:"default_limit"`     // requests per window
	WindowSeconds  int               `yaml:"window_seconds" json:"window_seconds"`
	GroupBy        string            `yaml:"group_by" json:"group_by"`               // ip, session, user
	PathOverrides  []PathRateLimit   `yaml:"path_overrides" json:"path_overrides"`
}

// PathRateLimit allows different limits per path
type PathRateLimit struct {
	PathPattern string `yaml:"path_pattern" json:"path_pattern"`
	Limit       int    `yaml:"limit" json:"limit"`
	Window      int    `yaml:"window" json:"window"`
}

// IPBlockConfig configures IP blocking
type IPBlockConfig struct {
	Enabled      bool     `yaml:"enabled" json:"enabled"`
	AllowList    []string `yaml:"allow_list" json:"allow_list"`
	BlockList    []string `yaml:"block_list" json:"block_list"`
	ThreatFeeds  []string `yaml:"threat_feeds" json:"threat_feeds"`
}

// GeoBlockConfig configures geo-blocking
type GeoBlockConfig struct {
	Enabled          bool     `yaml:"enabled" json:"enabled"`
	Mode             string   `yaml:"mode" json:"mode"` // allow_list, block_list
	AllowedCountries []string `yaml:"allowed_countries" json:"allowed_countries"`
	BlockedCountries []string `yaml:"blocked_countries" json:"blocked_countries"`
}

// BotProtection configures bot protection
type BotProtection struct {
	Enabled           bool     `yaml:"enabled" json:"enabled"`
	Mode              string   `yaml:"mode" json:"mode"` // block, challenge, log
	AllowedBots       []string `yaml:"allowed_bots" json:"allowed_bots"`
	JsChallenge       bool     `yaml:"js_challenge" json:"js_challenge"`
	CaptchaThreshold  float64  `yaml:"captcha_threshold" json:"captcha_threshold"`
}

// TemplateMetadata contains template metadata
type TemplateMetadata struct {
	Author     string   `yaml:"author" json:"author"`
	Version    string   `yaml:"version" json:"version"`
	Compliance []string `yaml:"compliance" json:"compliance"` // PCI-DSS, SOC2, etc.
	Tags       []string `yaml:"tags" json:"tags"`
}

// NewGoldenTemplateManager creates a new template manager
func NewGoldenTemplateManager(logger *zap.Logger) *GoldenTemplateManager {
	gtm := &GoldenTemplateManager{
		templates: make(map[string]*GoldenTemplate),
		logger:    logger,
	}

	// Load default templates
	gtm.loadDefaultTemplates()

	return gtm
}

// GetTemplate returns a template by ID
func (gtm *GoldenTemplateManager) GetTemplate(id string) (*GoldenTemplate, bool) {
	t, ok := gtm.templates[id]
	return t, ok
}

// SelectTemplate returns the best template based on environment and exposure
func (gtm *GoldenTemplateManager) SelectTemplate(ctx context.Context, provider, environment, exposure string) (*GoldenTemplate, error) {
	// Template selection matrix
	for _, t := range gtm.templates {
		if t.Provider == provider && t.Environment == environment && t.Exposure == exposure {
			return t, nil
		}
	}

	// Fall back to default for provider
	for _, t := range gtm.templates {
		if t.Provider == provider && t.Environment == "production" && t.Exposure == "external" {
			gtm.logger.Info("Using fallback template",
				zap.String("requested_env", environment),
				zap.String("requested_exposure", exposure),
				zap.String("template_id", t.ID),
			)
			return t, nil
		}
	}

	return nil, fmt.Errorf("no suitable template found for provider=%s, env=%s, exposure=%s", provider, environment, exposure)
}

// ExportToProvider exports template to provider-specific format
func (gtm *GoldenTemplateManager) ExportToProvider(template *GoldenTemplate) ([]byte, error) {
	switch strings.ToLower(template.Provider) {
	case "aws":
		return gtm.exportToAWS(template)
	case "azure":
		return gtm.exportToAzure(template)
	case "cloudflare":
		return gtm.exportToCloudflare(template)
	default:
		return yaml.Marshal(template)
	}
}

func (gtm *GoldenTemplateManager) exportToAWS(template *GoldenTemplate) ([]byte, error) {
	// Export to AWS WAF v2 format
	awsConfig := map[string]interface{}{
		"Name":        template.Name,
		"Description": template.Description,
		"Scope":       "REGIONAL", // or CLOUDFRONT
		"Rules":       gtm.convertToAWSRules(template.RuleSet),
		"DefaultAction": map[string]interface{}{
			"Allow": map[string]interface{}{},
		},
		"VisibilityConfig": map[string]interface{}{
			"SampledRequestsEnabled":   true,
			"CloudWatchMetricsEnabled": true,
			"MetricName":              template.ID,
		},
	}
	return yaml.Marshal(awsConfig)
}

func (gtm *GoldenTemplateManager) exportToAzure(template *GoldenTemplate) ([]byte, error) {
	// Export to Azure Application Gateway WAF format
	azureConfig := map[string]interface{}{
		"properties": map[string]interface{}{
			"policySettings": map[string]interface{}{
				"state":                "Enabled",
				"mode":                 "Prevention",
				"requestBodyCheck":     true,
				"maxRequestBodySizeInKb": 128,
			},
			"managedRules": gtm.convertToAzureManagedRules(template.RuleSet),
			"customRules":  gtm.convertToAzureCustomRules(template.RuleSet),
		},
	}
	return yaml.Marshal(azureConfig)
}

func (gtm *GoldenTemplateManager) exportToCloudflare(template *GoldenTemplate) ([]byte, error) {
	// Export to Cloudflare WAF format
	cfConfig := map[string]interface{}{
		"description": template.Description,
		"rules":       gtm.convertToCloudflareRules(template.RuleSet),
		"phase":       "http_request_firewall_managed",
	}
	return yaml.Marshal(cfConfig)
}

func (gtm *GoldenTemplateManager) convertToAWSRules(ruleSet RuleSet) []interface{} {
	rules := make([]interface{}, 0)
	// TODO: Implement AWS WAF rule conversion
	return rules
}

func (gtm *GoldenTemplateManager) convertToAzureManagedRules(ruleSet RuleSet) map[string]interface{} {
	// TODO: Implement Azure WAF rule conversion
	return map[string]interface{}{}
}

func (gtm *GoldenTemplateManager) convertToAzureCustomRules(ruleSet RuleSet) []interface{} {
	// TODO: Implement Azure WAF custom rule conversion
	return []interface{}{}
}

func (gtm *GoldenTemplateManager) convertToCloudflareRules(ruleSet RuleSet) []interface{} {
	// TODO: Implement Cloudflare WAF rule conversion
	return []interface{}{}
}

func (gtm *GoldenTemplateManager) loadDefaultTemplates() {
	// Production External - Maximum Protection
	gtm.templates["waf-prod-external"] = &GoldenTemplate{
		ID:          "waf-prod-external",
		Name:        "Production External WAF",
		Description: "Maximum protection for production external-facing applications",
		Provider:    "aws",
		Environment: "production",
		Exposure:    "external",
		RuleSet: RuleSet{
			ManagedRules: []ManagedRule{
				{Name: "AWSManagedRulesCommonRuleSet", Vendor: "aws", Version: "1.0", Action: "block"},
				{Name: "AWSManagedRulesKnownBadInputsRuleSet", Vendor: "aws", Version: "1.0", Action: "block"},
				{Name: "AWSManagedRulesSQLiRuleSet", Vendor: "aws", Version: "1.0", Action: "block"},
				{Name: "AWSManagedRulesLinuxRuleSet", Vendor: "aws", Version: "1.0", Action: "block"},
				{Name: "AWSManagedRulesAmazonIpReputationList", Vendor: "aws", Version: "1.0", Action: "block"},
			},
			CustomRules: []CustomRule{
				{
					ID:          "block-scanner-agents",
					Name:        "Block Known Scanners",
					Description: "Block requests from known vulnerability scanners",
					Priority:    1,
					Conditions: []RuleCondition{
						{
							Field:    "header:user-agent",
							Operator: "contains",
							Values:   []string{"nikto", "sqlmap", "nmap", "burp"},
							Transform: "lowercase",
						},
					},
					Action: "block",
				},
			},
			RateLimiting: RateLimitConfig{
				Enabled:       true,
				DefaultLimit:  1000,
				WindowSeconds: 300,
				GroupBy:       "ip",
				PathOverrides: []PathRateLimit{
					{PathPattern: "/api/login", Limit: 10, Window: 60},
					{PathPattern: "/api/register", Limit: 5, Window: 60},
				},
			},
			IPBlocking: IPBlockConfig{
				Enabled:     true,
				ThreatFeeds: []string{"aws_reputation", "spamhaus"},
			},
			GeoBlocking: GeoBlockConfig{
				Enabled:          true,
				Mode:             "block_list",
				BlockedCountries: []string{"KP", "IR", "CU", "SY"}, // Sanctioned countries
			},
			BotProtection: BotProtection{
				Enabled:     true,
				Mode:        "challenge",
				AllowedBots: []string{"googlebot", "bingbot", "slackbot"},
				JsChallenge: true,
			},
		},
		Metadata: TemplateMetadata{
			Author:     "Security Team",
			Version:    "1.0",
			Compliance: []string{"PCI-DSS", "SOC2", "OWASP-Top10"},
			Tags:       []string{"production", "external", "high-security"},
		},
	}

	// Production Internal - Moderate Protection
	gtm.templates["waf-prod-internal"] = &GoldenTemplate{
		ID:          "waf-prod-internal",
		Name:        "Production Internal WAF",
		Description: "Moderate protection for production internal applications",
		Provider:    "aws",
		Environment: "production",
		Exposure:    "internal",
		RuleSet: RuleSet{
			ManagedRules: []ManagedRule{
				{Name: "AWSManagedRulesCommonRuleSet", Vendor: "aws", Version: "1.0", Action: "block"},
				{Name: "AWSManagedRulesSQLiRuleSet", Vendor: "aws", Version: "1.0", Action: "block"},
			},
			RateLimiting: RateLimitConfig{
				Enabled:       true,
				DefaultLimit:  5000,
				WindowSeconds: 300,
				GroupBy:       "ip",
			},
			IPBlocking: IPBlockConfig{
				Enabled: true,
				AllowList: []string{
					"10.0.0.0/8",
					"172.16.0.0/12",
					"192.168.0.0/16",
				},
			},
			GeoBlocking: GeoBlockConfig{
				Enabled: false, // Internal, no geo-blocking needed
			},
			BotProtection: BotProtection{
				Enabled: false, // Internal, no bot protection needed
			},
		},
		Metadata: TemplateMetadata{
			Author:     "Security Team",
			Version:    "1.0",
			Compliance: []string{"SOC2"},
			Tags:       []string{"production", "internal"},
		},
	}

	// Staging - Logging Mode
	gtm.templates["waf-staging-external"] = &GoldenTemplate{
		ID:          "waf-staging-external",
		Name:        "Staging External WAF",
		Description: "Logging-mode WAF for staging environments",
		Provider:    "aws",
		Environment: "staging",
		Exposure:    "external",
		RuleSet: RuleSet{
			ManagedRules: []ManagedRule{
				{Name: "AWSManagedRulesCommonRuleSet", Vendor: "aws", Version: "1.0", Action: "count"}, // Log only
				{Name: "AWSManagedRulesSQLiRuleSet", Vendor: "aws", Version: "1.0", Action: "count"},
			},
			RateLimiting: RateLimitConfig{
				Enabled:       true,
				DefaultLimit:  10000, // Higher for testing
				WindowSeconds: 300,
				GroupBy:       "ip",
			},
		},
		Metadata: TemplateMetadata{
			Author:  "Security Team",
			Version: "1.0",
			Tags:    []string{"staging", "external", "logging"},
		},
	}

	// Development - Minimal Protection
	gtm.templates["waf-dev-external"] = &GoldenTemplate{
		ID:          "waf-dev-external",
		Name:        "Development WAF",
		Description: "Minimal WAF for development environments",
		Provider:    "aws",
		Environment: "development",
		Exposure:    "external",
		RuleSet: RuleSet{
			ManagedRules: []ManagedRule{
				{Name: "AWSManagedRulesCommonRuleSet", Vendor: "aws", Version: "1.0", Action: "count"},
			},
			RateLimiting: RateLimitConfig{
				Enabled:       false,
			},
		},
		Metadata: TemplateMetadata{
			Author:  "Security Team",
			Version: "1.0",
			Tags:    []string{"development", "minimal"},
		},
	}

	gtm.logger.Info("Golden templates loaded",
		zap.Int("count", len(gtm.templates)),
	)
}

// ListTemplates returns all templates
func (gtm *GoldenTemplateManager) ListTemplates() []*GoldenTemplate {
	result := make([]*GoldenTemplate, 0, len(gtm.templates))
	for _, t := range gtm.templates {
		result = append(result, t)
	}
	return result
}

