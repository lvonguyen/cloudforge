// Package api provides API security scanning and policy enforcement
package api

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"go.uber.org/zap"
)

// SecurityScanner scans API specifications for security issues
type SecurityScanner struct {
	logger *zap.Logger
	config ScannerConfig
}

// ScannerConfig configures the API security scanner
type ScannerConfig struct {
	RequireAuthentication bool     `yaml:"require_authentication"`
	RequireHTTPS          bool     `yaml:"require_https"`
	AllowedAuthMethods    []string `yaml:"allowed_auth_methods"` // oauth2, api_key, jwt, mtls
	MaxRateLimit          int      `yaml:"max_rate_limit"`
	RequireCORS           bool     `yaml:"require_cors"`
	SensitiveHeaders      []string `yaml:"sensitive_headers"`
}

// APIScanResult represents the result of an API security scan
type APIScanResult struct {
	APIID           string           `json:"api_id"`
	Title           string           `json:"title"`
	Version         string           `json:"version"`
	BaseURL         string           `json:"base_url"`
	ScannedAt       time.Time        `json:"scanned_at"`
	Status          string           `json:"status"`           // passed, failed, warning
	SecurityScore   float64          `json:"security_score"`   // 0-100
	Findings        []APIFinding     `json:"findings"`
	Endpoints       []EndpointResult `json:"endpoints"`
	Recommendations []string         `json:"recommendations"`
}

// APIFinding represents a security finding in an API
type APIFinding struct {
	ID          string `json:"id"`
	Severity    string `json:"severity"`
	Category    string `json:"category"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Location    string `json:"location"` // Path or component
	Remediation string `json:"remediation"`
	CWE         string `json:"cwe,omitempty"`
	OWASP       string `json:"owasp,omitempty"`
}

// EndpointResult represents security analysis of a single endpoint
type EndpointResult struct {
	Path            string   `json:"path"`
	Method          string   `json:"method"`
	Authenticated   bool     `json:"authenticated"`
	AuthMethods     []string `json:"auth_methods"`
	RateLimited     bool     `json:"rate_limited"`
	HasInputValidation bool  `json:"has_input_validation"`
	SensitiveData   bool     `json:"sensitive_data"`
	Findings        []APIFinding `json:"findings"`
}

// APISpec represents an API specification (OpenAPI/Swagger)
type APISpec struct {
	Title       string                 `json:"title"`
	Version     string                 `json:"version"`
	Description string                 `json:"description"`
	Servers     []Server               `json:"servers"`
	Paths       map[string]PathItem    `json:"paths"`
	Security    []SecurityRequirement  `json:"security"`
	Components  Components             `json:"components"`
}

// Server represents an API server
type Server struct {
	URL         string `json:"url"`
	Description string `json:"description"`
}

// PathItem represents an API path
type PathItem struct {
	Get     *Operation `json:"get,omitempty"`
	Post    *Operation `json:"post,omitempty"`
	Put     *Operation `json:"put,omitempty"`
	Delete  *Operation `json:"delete,omitempty"`
	Patch   *Operation `json:"patch,omitempty"`
}

// Operation represents an API operation
type Operation struct {
	Summary     string                `json:"summary"`
	Description string                `json:"description"`
	Security    []SecurityRequirement `json:"security,omitempty"`
	Parameters  []Parameter           `json:"parameters,omitempty"`
	RequestBody *RequestBody          `json:"requestBody,omitempty"`
	Responses   map[string]Response   `json:"responses"`
}

// SecurityRequirement represents a security requirement
type SecurityRequirement map[string][]string

// Parameter represents an API parameter
type Parameter struct {
	Name     string `json:"name"`
	In       string `json:"in"` // query, header, path, cookie
	Required bool   `json:"required"`
	Schema   Schema `json:"schema"`
}

// RequestBody represents a request body
type RequestBody struct {
	Required bool              `json:"required"`
	Content  map[string]Schema `json:"content"`
}

// Response represents an API response
type Response struct {
	Description string            `json:"description"`
	Content     map[string]Schema `json:"content,omitempty"`
}

// Schema represents a data schema
type Schema struct {
	Type       string            `json:"type"`
	Format     string            `json:"format,omitempty"`
	Pattern    string            `json:"pattern,omitempty"`
	MinLength  int               `json:"minLength,omitempty"`
	MaxLength  int               `json:"maxLength,omitempty"`
	Properties map[string]Schema `json:"properties,omitempty"`
}

// Components represents API components
type Components struct {
	SecuritySchemes map[string]SecurityScheme `json:"securitySchemes"`
}

// SecurityScheme represents a security scheme
type SecurityScheme struct {
	Type         string `json:"type"`
	Scheme       string `json:"scheme,omitempty"`
	BearerFormat string `json:"bearerFormat,omitempty"`
	In           string `json:"in,omitempty"`
	Name         string `json:"name,omitempty"`
	Flows        *OAuthFlows `json:"flows,omitempty"`
}

// OAuthFlows represents OAuth2 flows
type OAuthFlows struct {
	AuthorizationCode *OAuthFlow `json:"authorizationCode,omitempty"`
	ClientCredentials *OAuthFlow `json:"clientCredentials,omitempty"`
}

// OAuthFlow represents an OAuth2 flow
type OAuthFlow struct {
	AuthorizationURL string            `json:"authorizationUrl,omitempty"`
	TokenURL         string            `json:"tokenUrl,omitempty"`
	Scopes           map[string]string `json:"scopes"`
}

// NewSecurityScanner creates a new API security scanner
func NewSecurityScanner(cfg ScannerConfig, logger *zap.Logger) *SecurityScanner {
	return &SecurityScanner{
		config: cfg,
		logger: logger,
	}
}

// ScanSpec scans an API specification for security issues
func (s *SecurityScanner) ScanSpec(ctx context.Context, spec *APISpec) (*APIScanResult, error) {
	result := &APIScanResult{
		Title:     spec.Title,
		Version:   spec.Version,
		ScannedAt: time.Now(),
		Findings:  make([]APIFinding, 0),
		Endpoints: make([]EndpointResult, 0),
	}

	if len(spec.Servers) > 0 {
		result.BaseURL = spec.Servers[0].URL
	}

	// Check global security
	s.checkGlobalSecurity(spec, result)

	// Check each endpoint
	for path, pathItem := range spec.Paths {
		s.checkPath(path, &pathItem, spec, result)
	}

	// Check security schemes
	s.checkSecuritySchemes(spec, result)

	// Check for sensitive data exposure
	s.checkSensitiveData(spec, result)

	// Calculate score
	result.SecurityScore = s.calculateScore(result.Findings)

	// Determine status
	if result.SecurityScore >= 90 {
		result.Status = "passed"
	} else if result.SecurityScore >= 70 {
		result.Status = "warning"
	} else {
		result.Status = "failed"
	}

	// Generate recommendations
	result.Recommendations = s.generateRecommendations(result.Findings)

	s.logger.Info("API security scan completed",
		zap.String("api", spec.Title),
		zap.Float64("score", result.SecurityScore),
		zap.String("status", result.Status),
		zap.Int("findings", len(result.Findings)),
	)

	return result, nil
}

func (s *SecurityScanner) checkGlobalSecurity(spec *APISpec, result *APIScanResult) {
	// Check if global security is defined
	if len(spec.Security) == 0 && s.config.RequireAuthentication {
		result.Findings = append(result.Findings, APIFinding{
			ID:          "NO_GLOBAL_SECURITY",
			Severity:    "high",
			Category:    "authentication",
			Title:       "No global security defined",
			Description: "API does not define global security requirements",
			Location:    "global",
			Remediation: "Add global security requirement using security schemes",
			CWE:         "CWE-306",
			OWASP:       "API2:2019 Broken Authentication",
		})
	}

	// Check servers for HTTPS
	if s.config.RequireHTTPS {
		for _, server := range spec.Servers {
			if !strings.HasPrefix(server.URL, "https://") && !strings.Contains(server.URL, "localhost") {
				result.Findings = append(result.Findings, APIFinding{
					ID:          "NO_HTTPS",
					Severity:    "high",
					Category:    "transport",
					Title:       "Server not using HTTPS",
					Description: fmt.Sprintf("Server %s is not using HTTPS", server.URL),
					Location:    server.URL,
					Remediation: "Use HTTPS for all API endpoints",
					CWE:         "CWE-319",
					OWASP:       "API7:2019 Security Misconfiguration",
				})
			}
		}
	}
}

func (s *SecurityScanner) checkPath(path string, pathItem *PathItem, spec *APISpec, result *APIScanResult) {
	operations := map[string]*Operation{
		"GET":    pathItem.Get,
		"POST":   pathItem.Post,
		"PUT":    pathItem.Put,
		"DELETE": pathItem.Delete,
		"PATCH":  pathItem.Patch,
	}

	for method, op := range operations {
		if op == nil {
			continue
		}

		endpointResult := EndpointResult{
			Path:   path,
			Method: method,
		}

		// Check authentication
		if len(op.Security) > 0 || len(spec.Security) > 0 {
			endpointResult.Authenticated = true
			endpointResult.AuthMethods = s.extractAuthMethods(op.Security, spec.Security)
		} else if s.config.RequireAuthentication {
			endpointResult.Findings = append(endpointResult.Findings, APIFinding{
				ID:          "UNAUTHENTICATED_ENDPOINT",
				Severity:    "high",
				Category:    "authentication",
				Title:       "Endpoint has no authentication",
				Description: fmt.Sprintf("%s %s has no authentication requirement", method, path),
				Location:    fmt.Sprintf("%s %s", method, path),
				Remediation: "Add authentication requirement to endpoint",
				CWE:         "CWE-306",
				OWASP:       "API2:2019 Broken Authentication",
			})
		}

		// Check for input validation
		endpointResult.HasInputValidation = s.checkInputValidation(op)
		if !endpointResult.HasInputValidation && (method == "POST" || method == "PUT" || method == "PATCH") {
			endpointResult.Findings = append(endpointResult.Findings, APIFinding{
				ID:          "NO_INPUT_VALIDATION",
				Severity:    "medium",
				Category:    "validation",
				Title:       "No input validation defined",
				Description: fmt.Sprintf("%s %s has no input validation schemas", method, path),
				Location:    fmt.Sprintf("%s %s", method, path),
				Remediation: "Add request body schema with validation constraints",
				CWE:         "CWE-20",
				OWASP:       "API8:2019 Injection",
			})
		}

		// Check for sensitive endpoints
		if s.isSensitivePath(path) {
			endpointResult.SensitiveData = true

			// Sensitive endpoints should have extra protections
			if !endpointResult.Authenticated {
				endpointResult.Findings = append(endpointResult.Findings, APIFinding{
					ID:          "SENSITIVE_NO_AUTH",
					Severity:    "critical",
					Category:    "authorization",
					Title:       "Sensitive endpoint without authentication",
					Description: fmt.Sprintf("Sensitive endpoint %s %s has no authentication", method, path),
					Location:    fmt.Sprintf("%s %s", method, path),
					Remediation: "Add strong authentication and authorization",
					CWE:         "CWE-862",
					OWASP:       "API5:2019 Broken Function Level Authorization",
				})
			}
		}

		// Check for BOLA/IDOR vulnerabilities
		if s.hasPotentialBOLA(path, method) {
			endpointResult.Findings = append(endpointResult.Findings, APIFinding{
				ID:          "POTENTIAL_BOLA",
				Severity:    "medium",
				Category:    "authorization",
				Title:       "Potential BOLA vulnerability",
				Description: fmt.Sprintf("%s %s uses object IDs in path without documented authorization", method, path),
				Location:    fmt.Sprintf("%s %s", method, path),
				Remediation: "Implement proper object-level authorization checks",
				CWE:         "CWE-639",
				OWASP:       "API1:2019 Broken Object Level Authorization",
			})
		}

		result.Endpoints = append(result.Endpoints, endpointResult)
		result.Findings = append(result.Findings, endpointResult.Findings...)
	}
}

func (s *SecurityScanner) checkSecuritySchemes(spec *APISpec, result *APIScanResult) {
	if spec.Components.SecuritySchemes == nil {
		if s.config.RequireAuthentication {
			result.Findings = append(result.Findings, APIFinding{
				ID:          "NO_SECURITY_SCHEMES",
				Severity:    "high",
				Category:    "authentication",
				Title:       "No security schemes defined",
				Description: "API has no security schemes defined in components",
				Location:    "components.securitySchemes",
				Remediation: "Define security schemes (OAuth2, API key, JWT, etc.)",
				CWE:         "CWE-306",
			})
		}
		return
	}

	for name, scheme := range spec.Components.SecuritySchemes {
		// Check for weak schemes
		if scheme.Type == "apiKey" && scheme.In == "query" {
			result.Findings = append(result.Findings, APIFinding{
				ID:          "API_KEY_IN_QUERY",
				Severity:    "medium",
				Category:    "authentication",
				Title:       "API key in query string",
				Description: fmt.Sprintf("Security scheme '%s' uses API key in query string", name),
				Location:    fmt.Sprintf("components.securitySchemes.%s", name),
				Remediation: "Use API key in header instead of query string",
				CWE:         "CWE-598",
			})
		}

		// Check for basic auth
		if scheme.Type == "http" && scheme.Scheme == "basic" {
			result.Findings = append(result.Findings, APIFinding{
				ID:          "BASIC_AUTH",
				Severity:    "low",
				Category:    "authentication",
				Title:       "Basic authentication used",
				Description: fmt.Sprintf("Security scheme '%s' uses basic authentication", name),
				Location:    fmt.Sprintf("components.securitySchemes.%s", name),
				Remediation: "Consider using OAuth2 or JWT for better security",
				CWE:         "CWE-287",
			})
		}
	}
}

func (s *SecurityScanner) checkSensitiveData(spec *APISpec, result *APIScanResult) {
	sensitivePatterns := []struct {
		pattern *regexp.Regexp
		name    string
	}{
		{regexp.MustCompile(`(?i)(password|passwd|pwd)`), "password"},
		{regexp.MustCompile(`(?i)(ssn|social.?security)`), "SSN"},
		{regexp.MustCompile(`(?i)(credit.?card|card.?number|cvv|ccn)`), "credit card"},
		{regexp.MustCompile(`(?i)(secret|private.?key)`), "secret"},
		{regexp.MustCompile(`(?i)(token|api.?key)`), "token"},
	}

	for path, pathItem := range spec.Paths {
		operations := []*Operation{pathItem.Get, pathItem.Post, pathItem.Put, pathItem.Patch}
		for _, op := range operations {
			if op == nil {
				continue
			}

			// Check responses for sensitive data
			for code, response := range op.Responses {
				for contentType, schema := range response.Content {
					for propName := range schema.Properties {
						for _, pattern := range sensitivePatterns {
							if pattern.pattern.MatchString(propName) {
								result.Findings = append(result.Findings, APIFinding{
									ID:          "SENSITIVE_DATA_EXPOSURE",
									Severity:    "medium",
									Category:    "data_exposure",
									Title:       fmt.Sprintf("Potential %s exposure in response", pattern.name),
									Description: fmt.Sprintf("Field '%s' in response %s %s (%s) may expose sensitive data", propName, path, code, contentType),
									Location:    fmt.Sprintf("%s responses.%s.content.%s.%s", path, code, contentType, propName),
									Remediation: "Review if this field should be exposed and implement proper redaction",
									CWE:         "CWE-200",
									OWASP:       "API3:2019 Excessive Data Exposure",
								})
							}
						}
					}
				}
			}
		}
	}
}

func (s *SecurityScanner) extractAuthMethods(opSecurity, globalSecurity []SecurityRequirement) []string {
	methods := make([]string, 0)
	allSecurity := append(opSecurity, globalSecurity...)

	for _, req := range allSecurity {
		for method := range req {
			methods = append(methods, method)
		}
	}

	return methods
}

func (s *SecurityScanner) checkInputValidation(op *Operation) bool {
	// Check parameters for validation
	for _, param := range op.Parameters {
		if param.Schema.Pattern != "" || param.Schema.MinLength > 0 || param.Schema.MaxLength > 0 {
			return true
		}
	}

	// Check request body for validation
	if op.RequestBody != nil {
		return true // Has request body schema
	}

	return false
}

func (s *SecurityScanner) isSensitivePath(path string) bool {
	sensitivePatterns := []string{
		"/admin", "/users", "/accounts", "/payments",
		"/credentials", "/secrets", "/keys", "/tokens",
		"/config", "/settings", "/internal",
	}

	lowerPath := strings.ToLower(path)
	for _, pattern := range sensitivePatterns {
		if strings.Contains(lowerPath, pattern) {
			return true
		}
	}
	return false
}

func (s *SecurityScanner) hasPotentialBOLA(path, method string) bool {
	// Check for object IDs in path
	idPattern := regexp.MustCompile(`\{[^}]+[Ii]d\}`)
	hasID := idPattern.MatchString(path)

	// Methods that typically need BOLA protection
	dangerousMethods := map[string]bool{"GET": true, "PUT": true, "DELETE": true, "PATCH": true}

	return hasID && dangerousMethods[method]
}

func (s *SecurityScanner) calculateScore(findings []APIFinding) float64 {
	if len(findings) == 0 {
		return 100.0
	}

	weights := map[string]float64{
		"critical": 25.0,
		"high":     15.0,
		"medium":   10.0,
		"low":      5.0,
	}

	totalDeduction := 0.0
	for _, f := range findings {
		if weight, ok := weights[f.Severity]; ok {
			totalDeduction += weight
		}
	}

	score := 100.0 - totalDeduction
	if score < 0 {
		score = 0
	}

	return score
}

func (s *SecurityScanner) generateRecommendations(findings []APIFinding) []string {
	recommendations := make([]string, 0)
	seen := make(map[string]bool)

	for _, f := range findings {
		if !seen[f.ID] {
			recommendations = append(recommendations, f.Remediation)
			seen[f.ID] = true
		}
	}

	return recommendations
}

// ValidateRequest validates an HTTP request against API security policies
func (s *SecurityScanner) ValidateRequest(r *http.Request) []APIFinding {
	findings := make([]APIFinding, 0)

	// Check for sensitive headers being exposed
	for _, header := range s.config.SensitiveHeaders {
		if r.Header.Get(header) != "" {
			findings = append(findings, APIFinding{
				ID:          "SENSITIVE_HEADER",
				Severity:    "medium",
				Category:    "headers",
				Title:       "Sensitive header present",
				Description: fmt.Sprintf("Request contains sensitive header: %s", header),
				Location:    "request.headers",
				Remediation: "Remove or redact sensitive headers",
			})
		}
	}

	// Check for API keys in query string
	if r.URL.RawQuery != "" {
		keyPatterns := []string{"api_key", "apikey", "key", "token", "secret"}
		for _, pattern := range keyPatterns {
			if strings.Contains(strings.ToLower(r.URL.RawQuery), pattern) {
				findings = append(findings, APIFinding{
					ID:          "CREDENTIAL_IN_QUERY",
					Severity:    "high",
					Category:    "authentication",
					Title:       "Credential in query string",
					Description: "Potential credential found in query string",
					Location:    "request.query",
					Remediation: "Use Authorization header instead of query parameters",
				})
				break
			}
		}
	}

	return findings
}

