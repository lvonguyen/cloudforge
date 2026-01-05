// Package identity provides identity and access management capabilities
package identity

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"go.uber.org/zap"
)

// EntraIDProvider implements the Provider interface for Microsoft Entra ID (Azure AD)
type EntraIDProvider struct {
	tenantID     string
	clientID     string
	clientSecret string
	httpClient   *http.Client
	accessToken  string
	tokenExpiry  time.Time
	logger       *zap.Logger
}

// EntraIDConfig configures the Entra ID provider
type EntraIDConfig struct {
	TenantIDEnv     string `yaml:"tenant_id_env"`
	ClientIDEnv     string `yaml:"client_id_env"`
	ClientSecretEnv string `yaml:"client_secret_env"`
}

// NewEntraIDProvider creates a new Entra ID provider
func NewEntraIDProvider(cfg EntraIDConfig, logger *zap.Logger) (*EntraIDProvider, error) {
	tenantID := os.Getenv(cfg.TenantIDEnv)
	clientID := os.Getenv(cfg.ClientIDEnv)
	clientSecret := os.Getenv(cfg.ClientSecretEnv)

	if tenantID == "" || clientID == "" || clientSecret == "" {
		return nil, fmt.Errorf("missing required Entra ID configuration")
	}

	return &EntraIDProvider{
		tenantID:     tenantID,
		clientID:     clientID,
		clientSecret: clientSecret,
		httpClient:   &http.Client{Timeout: 30 * time.Second},
		logger:       logger,
	}, nil
}

func (p *EntraIDProvider) Name() string { return "entra_id" }

// GetUser retrieves a user by ID
func (p *EntraIDProvider) GetUser(ctx context.Context, userID string) (*User, error) {
	if err := p.ensureToken(ctx); err != nil {
		return nil, fmt.Errorf("authenticating: %w", err)
	}

	url := fmt.Sprintf("https://graph.microsoft.com/v1.0/users/%s", userID)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+p.accessToken)

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("making request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API returned status %d", resp.StatusCode)
	}

	var graphUser struct {
		ID                string `json:"id"`
		Mail              string `json:"mail"`
		DisplayName       string `json:"displayName"`
		Department        string `json:"department"`
		JobTitle          string `json:"jobTitle"`
		AccountEnabled    bool   `json:"accountEnabled"`
		SignInActivity    *struct {
			LastSignInDateTime string `json:"lastSignInDateTime"`
		} `json:"signInActivity"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&graphUser); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	user := &User{
		ID:          graphUser.ID,
		Email:       graphUser.Mail,
		DisplayName: graphUser.DisplayName,
		Department:  graphUser.Department,
		JobTitle:    graphUser.JobTitle,
		Status:      "active",
	}

	if !graphUser.AccountEnabled {
		user.Status = "disabled"
	}

	return user, nil
}

// ListUsers lists users with optional filter
func (p *EntraIDProvider) ListUsers(ctx context.Context, filter UserFilter) ([]*User, error) {
	if err := p.ensureToken(ctx); err != nil {
		return nil, fmt.Errorf("authenticating: %w", err)
	}

	url := "https://graph.microsoft.com/v1.0/users?$select=id,mail,displayName,department,jobTitle,accountEnabled"
	
	if filter.Limit > 0 {
		url += fmt.Sprintf("&$top=%d", filter.Limit)
	}

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+p.accessToken)

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("making request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API returned status %d", resp.StatusCode)
	}

	var result struct {
		Value []struct {
			ID             string `json:"id"`
			Mail           string `json:"mail"`
			DisplayName    string `json:"displayName"`
			Department     string `json:"department"`
			JobTitle       string `json:"jobTitle"`
			AccountEnabled bool   `json:"accountEnabled"`
		} `json:"value"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	users := make([]*User, 0, len(result.Value))
	for _, u := range result.Value {
		status := "active"
		if !u.AccountEnabled {
			status = "disabled"
		}
		users = append(users, &User{
			ID:          u.ID,
			Email:       u.Mail,
			DisplayName: u.DisplayName,
			Department:  u.Department,
			JobTitle:    u.JobTitle,
			Status:      status,
		})
	}

	return users, nil
}

// CreateUser creates a new user
func (p *EntraIDProvider) CreateUser(ctx context.Context, user *User) error {
	// TODO: Implement user creation via Graph API
	return fmt.Errorf("not implemented")
}

// UpdateUser updates a user
func (p *EntraIDProvider) UpdateUser(ctx context.Context, user *User) error {
	// TODO: Implement user update via Graph API
	return fmt.Errorf("not implemented")
}

// DisableUser disables a user
func (p *EntraIDProvider) DisableUser(ctx context.Context, userID string) error {
	if err := p.ensureToken(ctx); err != nil {
		return fmt.Errorf("authenticating: %w", err)
	}

	url := fmt.Sprintf("https://graph.microsoft.com/v1.0/users/%s", userID)
	body := []byte(`{"accountEnabled": false}`)

	req, err := http.NewRequestWithContext(ctx, "PATCH", url, bytes.NewBuffer(body))
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+p.accessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("making request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("API returned status %d", resp.StatusCode)
	}

	p.logger.Info("User disabled",
		zap.String("user_id", userID),
	)

	return nil
}

// GetGroup retrieves a group by ID
func (p *EntraIDProvider) GetGroup(ctx context.Context, groupID string) (*Group, error) {
	if err := p.ensureToken(ctx); err != nil {
		return nil, fmt.Errorf("authenticating: %w", err)
	}

	url := fmt.Sprintf("https://graph.microsoft.com/v1.0/groups/%s", groupID)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+p.accessToken)

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("making request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API returned status %d", resp.StatusCode)
	}

	var graphGroup struct {
		ID          string `json:"id"`
		DisplayName string `json:"displayName"`
		Description string `json:"description"`
		GroupTypes  []string `json:"groupTypes"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&graphGroup); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	groupType := "security"
	for _, gt := range graphGroup.GroupTypes {
		if gt == "DynamicMembership" {
			groupType = "dynamic"
			break
		}
	}

	return &Group{
		ID:          graphGroup.ID,
		Name:        graphGroup.DisplayName,
		Description: graphGroup.Description,
		Type:        groupType,
	}, nil
}

// ListGroups lists groups with optional filter
func (p *EntraIDProvider) ListGroups(ctx context.Context, filter GroupFilter) ([]*Group, error) {
	if err := p.ensureToken(ctx); err != nil {
		return nil, fmt.Errorf("authenticating: %w", err)
	}

	url := "https://graph.microsoft.com/v1.0/groups?$select=id,displayName,description,groupTypes"

	if filter.Limit > 0 {
		url += fmt.Sprintf("&$top=%d", filter.Limit)
	}

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+p.accessToken)

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("making request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API returned status %d", resp.StatusCode)
	}

	var result struct {
		Value []struct {
			ID          string   `json:"id"`
			DisplayName string   `json:"displayName"`
			Description string   `json:"description"`
			GroupTypes  []string `json:"groupTypes"`
		} `json:"value"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	groups := make([]*Group, 0, len(result.Value))
	for _, g := range result.Value {
		groupType := "security"
		for _, gt := range g.GroupTypes {
			if gt == "DynamicMembership" {
				groupType = "dynamic"
				break
			}
		}
		groups = append(groups, &Group{
			ID:          g.ID,
			Name:        g.DisplayName,
			Description: g.Description,
			Type:        groupType,
		})
	}

	return groups, nil
}

// GetGroupMembers retrieves members of a group
func (p *EntraIDProvider) GetGroupMembers(ctx context.Context, groupID string) ([]*User, error) {
	if err := p.ensureToken(ctx); err != nil {
		return nil, fmt.Errorf("authenticating: %w", err)
	}

	url := fmt.Sprintf("https://graph.microsoft.com/v1.0/groups/%s/members", groupID)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+p.accessToken)

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("making request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API returned status %d", resp.StatusCode)
	}

	var result struct {
		Value []struct {
			ODataType   string `json:"@odata.type"`
			ID          string `json:"id"`
			DisplayName string `json:"displayName"`
			Mail        string `json:"mail"`
		} `json:"value"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	users := make([]*User, 0)
	for _, m := range result.Value {
		if m.ODataType == "#microsoft.graph.user" {
			users = append(users, &User{
				ID:          m.ID,
				DisplayName: m.DisplayName,
				Email:       m.Mail,
			})
		}
	}

	return users, nil
}

// AddUserToGroup adds a user to a group
func (p *EntraIDProvider) AddUserToGroup(ctx context.Context, userID, groupID string) error {
	if err := p.ensureToken(ctx); err != nil {
		return fmt.Errorf("authenticating: %w", err)
	}

	url := fmt.Sprintf("https://graph.microsoft.com/v1.0/groups/%s/members/$ref", groupID)
	body := fmt.Sprintf(`{"@odata.id": "https://graph.microsoft.com/v1.0/directoryObjects/%s"}`, userID)

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBufferString(body))
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+p.accessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("making request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("API returned status %d", resp.StatusCode)
	}

	p.logger.Info("User added to group",
		zap.String("user_id", userID),
		zap.String("group_id", groupID),
	)

	return nil
}

// RemoveUserFromGroup removes a user from a group
func (p *EntraIDProvider) RemoveUserFromGroup(ctx context.Context, userID, groupID string) error {
	if err := p.ensureToken(ctx); err != nil {
		return fmt.Errorf("authenticating: %w", err)
	}

	url := fmt.Sprintf("https://graph.microsoft.com/v1.0/groups/%s/members/%s/$ref", groupID, userID)

	req, err := http.NewRequestWithContext(ctx, "DELETE", url, nil)
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+p.accessToken)

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("making request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("API returned status %d", resp.StatusCode)
	}

	p.logger.Info("User removed from group",
		zap.String("user_id", userID),
		zap.String("group_id", groupID),
	)

	return nil
}

// GetUserRoles gets roles assigned to a user
func (p *EntraIDProvider) GetUserRoles(ctx context.Context, userID string) ([]*Role, error) {
	// TODO: Implement via Azure RBAC API
	return []*Role{}, nil
}

// AssignRole assigns a role to a user
func (p *EntraIDProvider) AssignRole(ctx context.Context, userID, roleID string, scope string) error {
	// TODO: Implement via Azure RBAC API
	return fmt.Errorf("not implemented")
}

// RevokeRole revokes a role from a user
func (p *EntraIDProvider) RevokeRole(ctx context.Context, userID, roleID string, scope string) error {
	// TODO: Implement via Azure RBAC API
	return fmt.Errorf("not implemented")
}

// RequestJITAccess creates a JIT access request
func (p *EntraIDProvider) RequestJITAccess(ctx context.Context, request *JITAccessRequest) (*JITAccessGrant, error) {
	// TODO: Implement via PIM API
	return nil, fmt.Errorf("not implemented")
}

// ApproveJITAccess approves a JIT access request
func (p *EntraIDProvider) ApproveJITAccess(ctx context.Context, requestID string, approverID string) error {
	// TODO: Implement via PIM API
	return fmt.Errorf("not implemented")
}

// RevokeJITAccess revokes a JIT access grant
func (p *EntraIDProvider) RevokeJITAccess(ctx context.Context, grantID string) error {
	// TODO: Implement via PIM API
	return fmt.Errorf("not implemented")
}

// ListActiveJITGrants lists active JIT grants for a user
func (p *EntraIDProvider) ListActiveJITGrants(ctx context.Context, userID string) ([]*JITAccessGrant, error) {
	// TODO: Implement via PIM API
	return []*JITAccessGrant{}, nil
}

// GetUserRiskScore gets the risk assessment for a user
func (p *EntraIDProvider) GetUserRiskScore(ctx context.Context, userID string) (*RiskAssessment, error) {
	if err := p.ensureToken(ctx); err != nil {
		return nil, fmt.Errorf("authenticating: %w", err)
	}

	// Query Identity Protection riskyUsers API
	url := fmt.Sprintf("https://graph.microsoft.com/v1.0/identityProtection/riskyUsers/%s", userID)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+p.accessToken)

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("making request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		// User not in risky users list = low risk
		return &RiskAssessment{
			UserID:         userID,
			RiskScore:      0,
			RiskLevel:      "low",
			Factors:        []string{},
			LastAssessedAt: time.Now(),
		}, nil
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API returned status %d", resp.StatusCode)
	}

	var riskyUser struct {
		RiskLevel       string `json:"riskLevel"`
		RiskState       string `json:"riskState"`
		RiskDetail      string `json:"riskDetail"`
		RiskLastUpdated string `json:"riskLastUpdatedDateTime"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&riskyUser); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	// Map risk level to score
	scoreMap := map[string]float64{
		"none":   0,
		"low":    25,
		"medium": 50,
		"high":   75,
		"hidden": 100,
	}

	score := scoreMap[riskyUser.RiskLevel]

	return &RiskAssessment{
		UserID:         userID,
		RiskScore:      score,
		RiskLevel:      riskyUser.RiskLevel,
		Factors:        []string{riskyUser.RiskDetail},
		LastAssessedAt: time.Now(),
	}, nil
}

// ensureToken ensures we have a valid access token
func (p *EntraIDProvider) ensureToken(ctx context.Context) error {
	if p.accessToken != "" && time.Now().Before(p.tokenExpiry) {
		return nil
	}

	url := fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", p.tenantID)
	body := fmt.Sprintf(
		"client_id=%s&client_secret=%s&scope=https://graph.microsoft.com/.default&grant_type=client_credentials",
		p.clientID, p.clientSecret,
	)

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBufferString(body))
	if err != nil {
		return fmt.Errorf("creating token request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("making token request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("token request failed with status %d", resp.StatusCode)
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return fmt.Errorf("decoding token response: %w", err)
	}

	p.accessToken = tokenResp.AccessToken
	p.tokenExpiry = time.Now().Add(time.Duration(tokenResp.ExpiresIn-60) * time.Second)

	return nil
}

