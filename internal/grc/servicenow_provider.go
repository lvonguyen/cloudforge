package grc

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// ServiceNowConfig contains configuration for ServiceNow GRC integration.
type ServiceNowConfig struct {
	InstanceURL  string // e.g., "https://yourcompany.service-now.com"
	Username     string
	Password     string
	ClientID     string // for OAuth
	ClientSecret string

	// Table/record configuration - these may vary by ServiceNow implementation
	ExceptionTable  string // e.g., "sn_grc_policy_exception"
	ApprovalTable   string // e.g., "sysapproval_approver"
	RiskAssessTable string // e.g., "sn_risk_risk"
}

// ServiceNowGRCProvider implements GRCProvider for ServiceNow GRC module.
type ServiceNowGRCProvider struct {
	config     ServiceNowConfig
	httpClient *http.Client
	authToken  string
	tokenExp   time.Time
}

// NewServiceNowGRCProvider creates a new ServiceNow GRC provider.
func NewServiceNowGRCProvider(config ServiceNowConfig) *ServiceNowGRCProvider {
	// Set defaults for GRC module tables
	if config.ExceptionTable == "" {
		config.ExceptionTable = "sn_grc_policy_exception"
	}
	if config.ApprovalTable == "" {
		config.ApprovalTable = "sysapproval_approver"
	}

	return &ServiceNowGRCProvider{
		config:     config,
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
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
	// Check if token still valid
	if s.authToken != "" && time.Now().Before(s.tokenExp) {
		return nil
	}

	// OAuth2 token request
	tokenURL := fmt.Sprintf("%s/oauth_token.do", s.config.InstanceURL)

	data := fmt.Sprintf(
		"grant_type=password&client_id=%s&client_secret=%s&username=%s&password=%s",
		s.config.ClientID,
		s.config.ClientSecret,
		s.config.Username,
		s.config.Password,
	)

	req, err := http.NewRequestWithContext(ctx, "POST", tokenURL, bytes.NewBufferString(data))
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

	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return fmt.Errorf("failed to decode token response: %w", err)
	}

	s.authToken = tokenResp.AccessToken
	s.tokenExp = time.Now().Add(time.Duration(tokenResp.ExpiresIn-60) * time.Second)

	return nil
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

	body, _ := json.Marshal(snowRecord)

	url := fmt.Sprintf("%s/api/now/table/%s", s.config.InstanceURL, s.config.ExceptionTable)
	httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}

	httpReq.Header.Set("Authorization", "Bearer "+s.authToken)
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
	if err := json.NewDecoder(resp.Body).Decode(&snowResp); err != nil {
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
	if err := s.authenticate(ctx); err != nil {
		return nil, err
	}

	// Query for approved, non-expired exceptions
	query := fmt.Sprintf(
		"u_application_id=%s^u_policy_reference=%s^approval=approved^u_expiration_dateONOrAfter%s",
		applicationID,
		policyCode,
		time.Now().Format("2006-01-02"),
	)

	url := fmt.Sprintf(
		"%s/api/now/table/%s?sysparm_query=%s&sysparm_limit=1",
		s.config.InstanceURL,
		s.config.ExceptionTable,
		query,
	)

	httpReq, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	httpReq.Header.Set("Authorization", "Bearer "+s.authToken)
	httpReq.Header.Set("Accept", "application/json")

	resp, err := s.httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var snowResp struct {
		Result []snowExceptionRecord `json:"result"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&snowResp); err != nil {
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

	httpReq.Header.Set("Authorization", "Bearer "+s.authToken)
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
	if err := json.NewDecoder(resp.Body).Decode(&snowResp); err != nil {
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

	body, _ := json.Marshal(snowRecord)

	url := fmt.Sprintf("%s/api/now/table/%s/%s", s.config.InstanceURL, s.config.ExceptionTable, req.ID)
	httpReq, err := http.NewRequestWithContext(ctx, "PATCH", url, bytes.NewBuffer(body))
	if err != nil {
		return err
	}

	httpReq.Header.Set("Authorization", "Bearer "+s.authToken)
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
	// Implementation: Update sysapproval_approver record
	// This requires looking up the approval record by exception and approver
	return fmt.Errorf("ServiceNow approval submission not fully implemented")
}

// GetPendingApprovals returns exceptions pending approval from the given user.
func (s *ServiceNowGRCProvider) GetPendingApprovals(ctx context.Context, approverEmail string) ([]ExceptionRequest, error) {
	// Implementation: Query approval table by approver email
	return nil, fmt.Errorf("ServiceNow pending approvals not fully implemented")
}

// GetExceptionsByApplication returns all exceptions for an application.
func (s *ServiceNowGRCProvider) GetExceptionsByApplication(ctx context.Context, appID string) ([]ExceptionRequest, error) {
	if err := s.authenticate(ctx); err != nil {
		return nil, err
	}

	query := fmt.Sprintf("u_application_id=%s", appID)
	url := fmt.Sprintf(
		"%s/api/now/table/%s?sysparm_query=%s",
		s.config.InstanceURL,
		s.config.ExceptionTable,
		query,
	)

	httpReq, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	httpReq.Header.Set("Authorization", "Bearer "+s.authToken)
	httpReq.Header.Set("Accept", "application/json")

	resp, err := s.httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var snowResp struct {
		Result []snowExceptionRecord `json:"result"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&snowResp); err != nil {
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
	// Implementation: Query exceptions with expiration date within range
	return nil, fmt.Errorf("ServiceNow expiring exceptions not fully implemented")
}
