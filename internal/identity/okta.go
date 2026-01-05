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

// OktaProvider implements the Provider interface for Okta
type OktaProvider struct {
	domain     string
	apiToken   string
	httpClient *http.Client
	logger     *zap.Logger
}

// OktaConfig configures the Okta provider
type OktaConfig struct {
	Domain      string `yaml:"domain"`
	APITokenEnv string `yaml:"api_token_env"`
}

// NewOktaProvider creates a new Okta provider
func NewOktaProvider(cfg OktaConfig, logger *zap.Logger) (*OktaProvider, error) {
	apiToken := os.Getenv(cfg.APITokenEnv)

	if cfg.Domain == "" || apiToken == "" {
		return nil, fmt.Errorf("missing required Okta configuration")
	}

	return &OktaProvider{
		domain:     cfg.Domain,
		apiToken:   apiToken,
		httpClient: &http.Client{Timeout: 30 * time.Second},
		logger:     logger,
	}, nil
}

func (p *OktaProvider) Name() string { return "okta" }

// GetUser retrieves a user by ID
func (p *OktaProvider) GetUser(ctx context.Context, userID string) (*User, error) {
	url := fmt.Sprintf("https://%s/api/v1/users/%s", p.domain, userID)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Authorization", "SSWS "+p.apiToken)
	req.Header.Set("Accept", "application/json")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("making request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API returned status %d", resp.StatusCode)
	}

	var oktaUser struct {
		ID      string `json:"id"`
		Status  string `json:"status"`
		Profile struct {
			Email       string `json:"email"`
			FirstName   string `json:"firstName"`
			LastName    string `json:"lastName"`
			DisplayName string `json:"displayName"`
			Department  string `json:"department"`
			Title       string `json:"title"`
			Manager     string `json:"manager"`
		} `json:"profile"`
		LastLogin time.Time `json:"lastLogin"`
		Created   time.Time `json:"created"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&oktaUser); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	displayName := oktaUser.Profile.DisplayName
	if displayName == "" {
		displayName = fmt.Sprintf("%s %s", oktaUser.Profile.FirstName, oktaUser.Profile.LastName)
	}

	status := "active"
	if oktaUser.Status != "ACTIVE" {
		status = "disabled"
	}

	return &User{
		ID:          oktaUser.ID,
		Email:       oktaUser.Profile.Email,
		DisplayName: displayName,
		Department:  oktaUser.Profile.Department,
		JobTitle:    oktaUser.Profile.Title,
		Manager:     oktaUser.Profile.Manager,
		Status:      status,
		LastLogin:   &oktaUser.LastLogin,
		CreatedAt:   oktaUser.Created,
	}, nil
}

// ListUsers lists users with optional filter
func (p *OktaProvider) ListUsers(ctx context.Context, filter UserFilter) ([]*User, error) {
	url := fmt.Sprintf("https://%s/api/v1/users", p.domain)

	if filter.Limit > 0 {
		url += fmt.Sprintf("?limit=%d", filter.Limit)
	}

	if filter.Status != "" {
		if filter.Limit > 0 {
			url += "&"
		} else {
			url += "?"
		}
		url += fmt.Sprintf("filter=status eq \"%s\"", filter.Status)
	}

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Authorization", "SSWS "+p.apiToken)
	req.Header.Set("Accept", "application/json")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("making request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API returned status %d", resp.StatusCode)
	}

	var oktaUsers []struct {
		ID      string `json:"id"`
		Status  string `json:"status"`
		Profile struct {
			Email       string `json:"email"`
			FirstName   string `json:"firstName"`
			LastName    string `json:"lastName"`
			DisplayName string `json:"displayName"`
			Department  string `json:"department"`
			Title       string `json:"title"`
		} `json:"profile"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&oktaUsers); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	users := make([]*User, 0, len(oktaUsers))
	for _, u := range oktaUsers {
		displayName := u.Profile.DisplayName
		if displayName == "" {
			displayName = fmt.Sprintf("%s %s", u.Profile.FirstName, u.Profile.LastName)
		}

		status := "active"
		if u.Status != "ACTIVE" {
			status = "disabled"
		}

		users = append(users, &User{
			ID:          u.ID,
			Email:       u.Profile.Email,
			DisplayName: displayName,
			Department:  u.Profile.Department,
			JobTitle:    u.Profile.Title,
			Status:      status,
		})
	}

	return users, nil
}

// CreateUser creates a new user
func (p *OktaProvider) CreateUser(ctx context.Context, user *User) error {
	url := fmt.Sprintf("https://%s/api/v1/users?activate=true", p.domain)

	oktaUser := map[string]interface{}{
		"profile": map[string]string{
			"firstName":   user.DisplayName, // Would need to split
			"lastName":    user.DisplayName,
			"email":       user.Email,
			"login":       user.Email,
			"department":  user.Department,
			"title":       user.JobTitle,
		},
	}

	body, err := json.Marshal(oktaUser)
	if err != nil {
		return fmt.Errorf("marshaling user: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(body))
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Authorization", "SSWS "+p.apiToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("making request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("API returned status %d", resp.StatusCode)
	}

	p.logger.Info("User created",
		zap.String("email", user.Email),
	)

	return nil
}

// UpdateUser updates a user
func (p *OktaProvider) UpdateUser(ctx context.Context, user *User) error {
	url := fmt.Sprintf("https://%s/api/v1/users/%s", p.domain, user.ID)

	profile := map[string]interface{}{
		"profile": map[string]string{
			"department": user.Department,
			"title":      user.JobTitle,
		},
	}

	body, err := json.Marshal(profile)
	if err != nil {
		return fmt.Errorf("marshaling profile: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(body))
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Authorization", "SSWS "+p.apiToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("making request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("API returned status %d", resp.StatusCode)
	}

	return nil
}

// DisableUser disables a user
func (p *OktaProvider) DisableUser(ctx context.Context, userID string) error {
	url := fmt.Sprintf("https://%s/api/v1/users/%s/lifecycle/suspend", p.domain, userID)

	req, err := http.NewRequestWithContext(ctx, "POST", url, nil)
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Authorization", "SSWS "+p.apiToken)

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("making request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("API returned status %d", resp.StatusCode)
	}

	p.logger.Info("User suspended",
		zap.String("user_id", userID),
	)

	return nil
}

// GetGroup retrieves a group by ID
func (p *OktaProvider) GetGroup(ctx context.Context, groupID string) (*Group, error) {
	url := fmt.Sprintf("https://%s/api/v1/groups/%s", p.domain, groupID)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Authorization", "SSWS "+p.apiToken)
	req.Header.Set("Accept", "application/json")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("making request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API returned status %d", resp.StatusCode)
	}

	var oktaGroup struct {
		ID      string `json:"id"`
		Type    string `json:"type"`
		Profile struct {
			Name        string `json:"name"`
			Description string `json:"description"`
		} `json:"profile"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&oktaGroup); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	return &Group{
		ID:          oktaGroup.ID,
		Name:        oktaGroup.Profile.Name,
		Description: oktaGroup.Profile.Description,
		Type:        oktaGroup.Type,
	}, nil
}

// ListGroups lists groups with optional filter
func (p *OktaProvider) ListGroups(ctx context.Context, filter GroupFilter) ([]*Group, error) {
	url := fmt.Sprintf("https://%s/api/v1/groups", p.domain)

	if filter.Limit > 0 {
		url += fmt.Sprintf("?limit=%d", filter.Limit)
	}

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Authorization", "SSWS "+p.apiToken)
	req.Header.Set("Accept", "application/json")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("making request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API returned status %d", resp.StatusCode)
	}

	var oktaGroups []struct {
		ID      string `json:"id"`
		Type    string `json:"type"`
		Profile struct {
			Name        string `json:"name"`
			Description string `json:"description"`
		} `json:"profile"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&oktaGroups); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	groups := make([]*Group, 0, len(oktaGroups))
	for _, g := range oktaGroups {
		groups = append(groups, &Group{
			ID:          g.ID,
			Name:        g.Profile.Name,
			Description: g.Profile.Description,
			Type:        g.Type,
		})
	}

	return groups, nil
}

// GetGroupMembers retrieves members of a group
func (p *OktaProvider) GetGroupMembers(ctx context.Context, groupID string) ([]*User, error) {
	url := fmt.Sprintf("https://%s/api/v1/groups/%s/users", p.domain, groupID)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Authorization", "SSWS "+p.apiToken)
	req.Header.Set("Accept", "application/json")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("making request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API returned status %d", resp.StatusCode)
	}

	var oktaUsers []struct {
		ID      string `json:"id"`
		Profile struct {
			Email     string `json:"email"`
			FirstName string `json:"firstName"`
			LastName  string `json:"lastName"`
		} `json:"profile"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&oktaUsers); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	users := make([]*User, 0, len(oktaUsers))
	for _, u := range oktaUsers {
		users = append(users, &User{
			ID:          u.ID,
			Email:       u.Profile.Email,
			DisplayName: fmt.Sprintf("%s %s", u.Profile.FirstName, u.Profile.LastName),
		})
	}

	return users, nil
}

// AddUserToGroup adds a user to a group
func (p *OktaProvider) AddUserToGroup(ctx context.Context, userID, groupID string) error {
	url := fmt.Sprintf("https://%s/api/v1/groups/%s/users/%s", p.domain, groupID, userID)

	req, err := http.NewRequestWithContext(ctx, "PUT", url, nil)
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Authorization", "SSWS "+p.apiToken)

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
func (p *OktaProvider) RemoveUserFromGroup(ctx context.Context, userID, groupID string) error {
	url := fmt.Sprintf("https://%s/api/v1/groups/%s/users/%s", p.domain, groupID, userID)

	req, err := http.NewRequestWithContext(ctx, "DELETE", url, nil)
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Authorization", "SSWS "+p.apiToken)

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

// GetUserRoles gets roles assigned to a user (via group memberships)
func (p *OktaProvider) GetUserRoles(ctx context.Context, userID string) ([]*Role, error) {
	url := fmt.Sprintf("https://%s/api/v1/users/%s/roles", p.domain, userID)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Authorization", "SSWS "+p.apiToken)
	req.Header.Set("Accept", "application/json")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("making request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API returned status %d", resp.StatusCode)
	}

	var oktaRoles []struct {
		ID    string `json:"id"`
		Type  string `json:"type"`
		Label string `json:"label"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&oktaRoles); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	roles := make([]*Role, 0, len(oktaRoles))
	for _, r := range oktaRoles {
		roles = append(roles, &Role{
			ID:      r.ID,
			Name:    r.Label,
			BuiltIn: true,
		})
	}

	return roles, nil
}

// AssignRole assigns a role to a user
func (p *OktaProvider) AssignRole(ctx context.Context, userID, roleID string, scope string) error {
	url := fmt.Sprintf("https://%s/api/v1/users/%s/roles", p.domain, userID)

	body := map[string]string{"type": roleID}
	jsonBody, _ := json.Marshal(body)

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(jsonBody))
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Authorization", "SSWS "+p.apiToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("making request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("API returned status %d", resp.StatusCode)
	}

	return nil
}

// RevokeRole revokes a role from a user
func (p *OktaProvider) RevokeRole(ctx context.Context, userID, roleID string, scope string) error {
	url := fmt.Sprintf("https://%s/api/v1/users/%s/roles/%s", p.domain, userID, roleID)

	req, err := http.NewRequestWithContext(ctx, "DELETE", url, nil)
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Authorization", "SSWS "+p.apiToken)

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("making request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("API returned status %d", resp.StatusCode)
	}

	return nil
}

// JIT Access stubs - Okta doesn't have native JIT, but could use workflow API
func (p *OktaProvider) RequestJITAccess(ctx context.Context, request *JITAccessRequest) (*JITAccessGrant, error) {
	return nil, fmt.Errorf("JIT access not supported in Okta - use Access Request workflows")
}

func (p *OktaProvider) ApproveJITAccess(ctx context.Context, requestID string, approverID string) error {
	return fmt.Errorf("JIT access not supported in Okta")
}

func (p *OktaProvider) RevokeJITAccess(ctx context.Context, grantID string) error {
	return fmt.Errorf("JIT access not supported in Okta")
}

func (p *OktaProvider) ListActiveJITGrants(ctx context.Context, userID string) ([]*JITAccessGrant, error) {
	return []*JITAccessGrant{}, nil
}

// GetUserRiskScore - Okta doesn't have native risk scoring like Entra ID
func (p *OktaProvider) GetUserRiskScore(ctx context.Context, userID string) (*RiskAssessment, error) {
	// Could integrate with Okta ThreatInsight if available
	return &RiskAssessment{
		UserID:         userID,
		RiskScore:      0,
		RiskLevel:      "unknown",
		Factors:        []string{},
		LastAssessedAt: time.Now(),
		RecommendedActions: []string{"Enable Okta ThreatInsight for risk scoring"},
	}, nil
}

