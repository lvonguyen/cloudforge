package main

import (
	"context"
	"fmt"

	"cloudforge/internal/identity"
)

// IdentityService encapsulates identity provider operations,
// extracted from Server to reduce God Object field count.
type IdentityService struct {
	providers map[string]identity.Provider
}

// NewIdentityService creates an IdentityService with the given provider map.
func NewIdentityService(providers map[string]identity.Provider) *IdentityService {
	return &IdentityService{providers: providers}
}

// GetProvider returns the named provider or an error if unsupported.
func (svc *IdentityService) GetProvider(name string) (identity.Provider, error) {
	p, ok := svc.providers[name]
	if !ok {
		return nil, fmt.Errorf("unsupported provider: use okta or entra_id")
	}
	return p, nil
}

// ListUsers lists users from the named identity provider.
func (svc *IdentityService) ListUsers(ctx context.Context, providerName string, filter identity.UserFilter) ([]*identity.User, string, error) {
	p, err := svc.GetProvider(providerName)
	if err != nil {
		return nil, "", err
	}
	users, err := p.ListUsers(ctx, filter)
	if err != nil {
		return nil, "", err
	}
	return users, p.Name(), nil
}

// GetUserRiskScore returns the risk score for a user from the named provider.
func (svc *IdentityService) GetUserRiskScore(ctx context.Context, providerName, userID string) (*identity.RiskAssessment, error) {
	p, err := svc.GetProvider(providerName)
	if err != nil {
		return nil, err
	}
	return p.GetUserRiskScore(ctx, userID)
}
