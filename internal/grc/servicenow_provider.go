package grc

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sync"
	"time"
)

// snowSafeInput matches only alphanumeric characters, hyphens, underscores, dots, and @.
// Any input that doesn't match is rejected to prevent sysparm_query injection.
var snowSafeInput = regexp.MustCompile(`^[a-zA-Z0-9._@\-]+$`)

// validateSNOWInput rejects input containing characters that could alter sysparm_query semantics.
func validateSNOWInput(field, value string) error {
	if value == "" {
		return fmt.Errorf("%s must not be empty", field)
	}
	if !snowSafeInput.MatchString(value) {
		return fmt.Errorf("%s contains invalid characters", field)
	}
	return nil
}

// ServiceNowConfig contains configuration for ServiceNow GRC integration.
// Credentials are loaded from environment variables for security.
type ServiceNowConfig struct {
	InstanceURL string // e.g., "https://yourcompany.service-now.com"
	Username    string

	// PasswordEnv is the name of the environment variable containing the password.
	// The actual password is never stored in the struct.
	PasswordEnv string

	ClientID string // for OAuth

	// ClientSecretEnv is the name of the environment variable containing the client secret.
	// The actual secret is never stored in the struct.
	ClientSecretEnv string

	// Table/record configuration - these may vary by ServiceNow implementation
	ExceptionTable  string // e.g., "sn_grc_policy_exception"
	ApprovalTable   string // e.g., "sysapproval_approver"
	RiskAssessTable string // e.g., "sn_risk_risk"
}

// ServiceNowGRCProvider implements GRCProvider for ServiceNow GRC module.
type ServiceNowGRCProvider struct {
	config       ServiceNowConfig
	httpClient   *http.Client
	authMu       sync.RWMutex // guards authToken and tokenExp
	authToken    string
	tokenExp     time.Time
	password     string // loaded from env at initialization
	clientSecret string // loaded from env at initialization
}

// NewServiceNowGRCProvider creates a new ServiceNow GRC provider.
// Returns an error if required credentials are missing from environment variables.
func NewServiceNowGRCProvider(config ServiceNowConfig) (*ServiceNowGRCProvider, error) {
	// Validate required fields
	if config.InstanceURL == "" {
		return nil, fmt.Errorf("creating ServiceNow provider: InstanceURL is required")
	}
	if config.Username == "" {
		return nil, fmt.Errorf("creating ServiceNow provider: Username is required")
	}

	// Load password from environment
	if config.PasswordEnv == "" {
		return nil, fmt.Errorf("creating ServiceNow provider: PasswordEnv must be specified")
	}
	password := os.Getenv(config.PasswordEnv)
	if password == "" {
		return nil, fmt.Errorf("creating ServiceNow provider: password environment variable %s is not set", config.PasswordEnv)
	}

	// Load client secret from environment (required for OAuth)
	var clientSecret string
	if config.ClientID != "" {
		if config.ClientSecretEnv == "" {
			return nil, fmt.Errorf("creating ServiceNow provider: ClientSecretEnv must be specified when ClientID is set")
		}
		clientSecret = os.Getenv(config.ClientSecretEnv)
		if clientSecret == "" {
			return nil, fmt.Errorf("creating ServiceNow provider: client secret environment variable %s is not set", config.ClientSecretEnv)
		}
	}

	// Set defaults for GRC module tables
	if config.ExceptionTable == "" {
		config.ExceptionTable = "sn_grc_policy_exception"
	}
	if config.ApprovalTable == "" {
		config.ApprovalTable = "sysapproval_approver"
	}

	return &ServiceNowGRCProvider{
		config:       config,
		httpClient:   &http.Client{Timeout: 30 * time.Second},
		password:     password,
		clientSecret: clientSecret,
	}, nil
}

// ServiceNow API response wrapper
type snowResponse struct {
	Result json.RawMessage `json:"result"`
}

type snowExceptionRecord struct {
	SysID            string `json:"sys_id"`
	Number           string `json:"number"`
	ShortDescription string `json:"short_description"`
	State            string `json:"state"`
	ApprovalStatus   string `json:"approval"`
	RequestedFor     string `json:"requested_for"`
	ExpirationDate   string `json:"u_expiration_date"`
	PolicyReference  string `json:"u_policy_reference"`
	BusinessCase     string `json:"u_business_justification"`
	RiskLevel        string `json:"u_risk_level"`
}

func (s *ServiceNowGRCProvider) authenticate(ctx context.Context) error {
	s.authMu.Lock()
	defer s.authMu.Unlock()

	// Double-check after acquiring lock (another goroutine may have refreshed)
	if s.authToken != "" && time.Now().Before(s.tokenExp) {
		return nil
	}

	// OAuth2 token request
	tokenURL := fmt.Sprintf("%s/oauth_token.do", s.config.InstanceURL)

	form := url.Values{
		"grant_type":    {"password"},
		"client_id":     {s.config.ClientID},
		"client_secret": {s.clientSecret},
		"username":      {s.config.Username},
		"password":      {s.password},
	}

	req, err := http.NewRequestWithContext(ctx, "POST", tokenURL, bytes.NewBufferString(form.Encode()))
	if err != nil {
		return fmt.Errorf("failed to create auth request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("auth request failed: %w", err)
	}
	defer resp.Body.Close()

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("ServiceNow auth failed with HTTP %d", resp.StatusCode)
	}

	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&tokenResp); err != nil {
		return fmt.Errorf("failed to decode token response: %w", err)
	}

	s.authToken = tokenResp.AccessToken
	expiresIn := tokenResp.ExpiresIn
	if expiresIn <= 0 {
		expiresIn = 3600 // Default to 1 hour when server returns 0 or negative
	}
	s.tokenExp = time.Now().Add(time.Duration(expiresIn-60) * time.Second)

	return nil
}

// getAuthToken returns the current auth token with read-lock protection.
func (s *ServiceNowGRCProvider) getAuthToken() string {
	s.authMu.RLock()
	defer s.authMu.RUnlock()
	return s.authToken
}

// CreateException creates a new exception request in ServiceNow.
func (s *ServiceNowGRCProvider) CreateException(
	ctx context.Context,
	req *ExceptionRequest,
) (*ExceptionRequest, error) {
	if err := s.authenticate(ctx); err != nil {
		return nil, err
	}

	// Map to ServiceNow fields
	snowRecord := map[string]interface{}{
		"short_description":        fmt.Sprintf("Exception: %s - %s", req.PolicyViolated, req.RequestType),
		"u_application_id":         req.ApplicationID,
		"requested_for":            req.RequestorEmail,
		"u_policy_reference":       req.PolicyViolated,
		"u_business_justification": req.BusinessCase,
		"u_requested_resource":     req.ResourceRequested,
		"u_exception_type":         string(req.RequestType),
		"state":                    "1", // New
		"approval":                 "requested",
	}

	if req.ExpirationDate != nil {
		snowRecord["u_expiration_date"] = req.ExpirationDate.Format("2006-01-02")
	}

	body, err := json.Marshal(snowRecord)
	if err != nil {
		return nil, fmt.Errorf("marshaling exception request: %w", err)
	}

	reqURL := fmt.Sprintf("%s/api/now/table/%s", s.config.InstanceURL, s.config.ExceptionTable)
	httpReq, err := http.NewRequestWithContext(ctx, "POST", reqURL, bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}

	httpReq.Header.Set("Authorization", "Bearer "+s.getAuthToken())
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")

	resp, err := s.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to create SNOW record: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("SNOW returned status %d", resp.StatusCode)
	}

	var snowResp snowResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&snowResp); err != nil {
		return nil, err
	}

	var created snowExceptionRecord
	if err := json.Unmarshal(snowResp.Result, &created); err != nil {
		return nil, err
	}

	req.ID = created.SysID
	req.Status = StatusPending

	return req, nil
}

// ValidateException checks if a valid exception exists in ServiceNow.
func (s *ServiceNowGRCProvider) ValidateException(
	ctx context.Context,
	applicationID, policyCode string,
) (*ExceptionValidation, error) {
	if err := validateSNOWInput("applicationID", applicationID); err != nil {
		return nil, fmt.Errorf("validating exception: %w", err)
	}
	if err := validateSNOWInput("policyCode", policyCode); err != nil {
		return nil, fmt.Errorf("validating exception: %w", err)
	}

	if err := s.authenticate(ctx); err != nil {
		return nil, err
	}

	// Query for approved, non-expired exceptions
	// URL-encode user input to prevent query injection attacks
	query := fmt.Sprintf(
		"u_application_id=%s^u_policy_reference=%s^approval=approved^u_expiration_dateONOrAfter%s",
		url.QueryEscape(applicationID),
		url.QueryEscape(policyCode),
		time.Now().Format("2006-01-02"),
	)

	reqURL := fmt.Sprintf(
		"%s/api/now/table/%s?sysparm_query=%s&sysparm_limit=1",
		s.config.InstanceURL,
		s.config.ExceptionTable,
		query,
	)

	httpReq, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return nil, err
	}

	httpReq.Header.Set("Authorization", "Bearer "+s.getAuthToken())
	httpReq.Header.Set("Accept", "application/json")

	resp, err := s.httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var snowResp struct {
		Result []snowExceptionRecord `json:"result"`
	}

	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&snowResp); err != nil {
		return nil, err
	}

	if len(snowResp.Result) == 0 {
		return &ExceptionValidation{
			Valid:  false,
			Reason: fmt.Sprintf("No approved exception for policy %s", policyCode),
		}, nil
	}

	record := snowResp.Result[0]
	validation := &ExceptionValidation{
		Valid:       true,
		ExceptionID: record.SysID,
	}

	if record.ExpirationDate != "" {
		if exp, err := time.Parse("2006-01-02", record.ExpirationDate); err == nil {
			validation.ExpiresAt = &exp
		}
	}

	return validation, nil
}

// GetException retrieves an exception from ServiceNow by sys_id.
func (s *ServiceNowGRCProvider) GetException(ctx context.Context, id string) (*ExceptionRequest, error) {
	if err := s.authenticate(ctx); err != nil {
		return nil, err
	}

	url := fmt.Sprintf("%s/api/now/table/%s/%s", s.config.InstanceURL, s.config.ExceptionTable, id)

	httpReq, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	httpReq.Header.Set("Authorization", "Bearer "+s.getAuthToken())
	httpReq.Header.Set("Accept", "application/json")

	resp, err := s.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to get SNOW record: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("exception %s not found", id)
	}

	var snowResp snowResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&snowResp); err != nil {
		return nil, err
	}

	var record snowExceptionRecord
	if err := json.Unmarshal(snowResp.Result, &record); err != nil {
		return nil, err
	}

	// Map ServiceNow record to our model
	req := &ExceptionRequest{
		ID:                record.SysID,
		PolicyViolated:    record.PolicyReference,
		BusinessCase:      record.BusinessCase,
		RequestorEmail:    record.RequestedFor,
		ResourceRequested: record.ShortDescription,
	}

	// Map status
	switch record.ApprovalStatus {
	case "approved":
		req.Status = StatusApproved
	case "rejected":
		req.Status = StatusRejected
	default:
		req.Status = StatusPending
	}

	return req, nil
}

// UpdateException updates an exception in ServiceNow.
func (s *ServiceNowGRCProvider) UpdateException(ctx context.Context, req *ExceptionRequest) error {
	if err := s.authenticate(ctx); err != nil {
		return err
	}

	snowRecord := map[string]interface{}{
		"u_business_justification": req.BusinessCase,
	}

	if req.ExpirationDate != nil {
		snowRecord["u_expiration_date"] = req.ExpirationDate.Format("2006-01-02")
	}

	body, err := json.Marshal(snowRecord)
	if err != nil {
		return fmt.Errorf("marshaling exception update: %w", err)
	}

	reqURL := fmt.Sprintf("%s/api/now/table/%s/%s", s.config.InstanceURL, s.config.ExceptionTable, req.ID)
	httpReq, err := http.NewRequestWithContext(ctx, "PATCH", reqURL, bytes.NewBuffer(body))
	if err != nil {
		return err
	}

	httpReq.Header.Set("Authorization", "Bearer "+s.getAuthToken())
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := s.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("failed to update SNOW record: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("SNOW returned status %d", resp.StatusCode)
	}

	return nil
}

// SubmitApproval updates an approval record in ServiceNow.
func (s *ServiceNowGRCProvider) SubmitApproval(ctx context.Context, exceptionID string, approver Approver) error {
	if err := s.authenticate(ctx); err != nil {
		return err
	}

	// Map approval decision to ServiceNow state
	state := "rejected"
	if approver.Decision == StatusApproved {
		state = "approved"
	}

	// Update the exception record with approval status
	updateData := map[string]interface{}{
		"approval":   state,
		"u_comments": approver.Comments,
	}

	body, err := json.Marshal(updateData)
	if err != nil {
		return fmt.Errorf("marshaling approval update: %w", err)
	}
	reqURL := fmt.Sprintf("%s/api/now/table/%s/%s", s.config.InstanceURL, s.config.ExceptionTable, exceptionID)

	httpReq, err := http.NewRequestWithContext(ctx, "PATCH", reqURL, bytes.NewBuffer(body))
	if err != nil {
		return fmt.Errorf("creating approval request: %w", err)
	}

	httpReq.Header.Set("Authorization", "Bearer "+s.getAuthToken())
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := s.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("submitting approval: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("ServiceNow returned status %d for approval", resp.StatusCode)
	}

	return nil
}

// GetPendingApprovals returns exceptions pending approval from the given user.
func (s *ServiceNowGRCProvider) GetPendingApprovals(ctx context.Context, approverEmail string) ([]ExceptionRequest, error) {
	if err := validateSNOWInput("approverEmail", approverEmail); err != nil {
		return nil, fmt.Errorf("querying pending approvals: %w", err)
	}

	if err := s.authenticate(ctx); err != nil {
		return nil, err
	}

	// Query for exceptions pending approval where user is in approver chain.
	// URL-encode the full query value so ^ operators survive in the query string.
	query := fmt.Sprintf("approval=requested^requested_for=%s", url.QueryEscape(approverEmail))
	reqURL := fmt.Sprintf(
		"%s/api/now/table/%s?sysparm_query=%s&sysparm_limit=100",
		s.config.InstanceURL,
		s.config.ExceptionTable,
		query,
	)

	httpReq, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return nil, err
	}

	httpReq.Header.Set("Authorization", "Bearer "+s.getAuthToken())
	httpReq.Header.Set("Accept", "application/json")

	resp, err := s.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("querying pending approvals: %w", err)
	}
	defer resp.Body.Close()

	var snowResp struct {
		Result []snowExceptionRecord `json:"result"`
	}

	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&snowResp); err != nil {
		return nil, err
	}

	var results []ExceptionRequest
	for _, record := range snowResp.Result {
		results = append(results, ExceptionRequest{
			ID:             record.SysID,
			PolicyViolated: record.PolicyReference,
			BusinessCase:   record.BusinessCase,
			RequestorEmail: record.RequestedFor,
			Status:         StatusPending,
		})
	}

	return results, nil
}

// GetExceptionsByApplication returns all exceptions for an application.
func (s *ServiceNowGRCProvider) GetExceptionsByApplication(ctx context.Context, appID string) ([]ExceptionRequest, error) {
	if err := validateSNOWInput("appID", appID); err != nil {
		return nil, fmt.Errorf("querying exceptions by application: %w", err)
	}

	if err := s.authenticate(ctx); err != nil {
		return nil, err
	}

	// URL-encode user input to prevent query injection attacks
	query := fmt.Sprintf("u_application_id=%s", url.QueryEscape(appID))
	reqURL := fmt.Sprintf(
		"%s/api/now/table/%s?sysparm_query=%s&sysparm_limit=200",
		s.config.InstanceURL,
		s.config.ExceptionTable,
		query,
	)

	httpReq, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return nil, err
	}

	httpReq.Header.Set("Authorization", "Bearer "+s.getAuthToken())
	httpReq.Header.Set("Accept", "application/json")

	resp, err := s.httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var snowResp struct {
		Result []snowExceptionRecord `json:"result"`
	}

	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&snowResp); err != nil {
		return nil, err
	}

	var results []ExceptionRequest
	for _, record := range snowResp.Result {
		results = append(results, ExceptionRequest{
			ID:             record.SysID,
			PolicyViolated: record.PolicyReference,
			BusinessCase:   record.BusinessCase,
		})
	}

	return results, nil
}

// GetExpiringExceptions returns exceptions expiring within the given days.
func (s *ServiceNowGRCProvider) GetExpiringExceptions(ctx context.Context, withinDays int) ([]ExceptionRequest, error) {
	if err := s.authenticate(ctx); err != nil {
		return nil, err
	}

	// Calculate date range
	now := time.Now()
	expiryDate := now.AddDate(0, 0, withinDays)

	// Query for approved exceptions expiring within range
	query := fmt.Sprintf(
		"approval=approved^u_expiration_dateBETWEEN%s@%s",
		now.Format("2006-01-02"),
		expiryDate.Format("2006-01-02"),
	)
	reqURL := fmt.Sprintf(
		"%s/api/now/table/%s?sysparm_query=%s&sysparm_limit=100",
		s.config.InstanceURL,
		s.config.ExceptionTable,
		query,
	)

	httpReq, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return nil, err
	}

	httpReq.Header.Set("Authorization", "Bearer "+s.getAuthToken())
	httpReq.Header.Set("Accept", "application/json")

	resp, err := s.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("querying expiring exceptions: %w", err)
	}
	defer resp.Body.Close()

	var snowResp struct {
		Result []snowExceptionRecord `json:"result"`
	}

	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&snowResp); err != nil {
		return nil, err
	}

	var results []ExceptionRequest
	for _, record := range snowResp.Result {
		req := ExceptionRequest{
			ID:             record.SysID,
			PolicyViolated: record.PolicyReference,
			BusinessCase:   record.BusinessCase,
			RequestorEmail: record.RequestedFor,
			Status:         StatusApproved,
		}
		if record.ExpirationDate != "" {
			if exp, err := time.Parse("2006-01-02", record.ExpirationDate); err == nil {
				req.ExpirationDate = &exp
			}
		}
		results = append(results, req)
	}

	return results, nil
}
