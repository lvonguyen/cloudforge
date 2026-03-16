package identity

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// ErrNotFound is returned when a user or group is not found.
var ErrNotFound = errors.New("not found")

// GroupMembership describes a user's role within a group.
type GroupMembership struct {
	GroupID   string
	GroupName string
	Role      string // admin, member, viewer
}

// SessionProvider extends Provider with session token validation.
// OktaProvider and EntraIDProvider satisfy Provider; mock satisfies SessionProvider.
type SessionProvider interface {
	Provider
	ValidateSession(ctx context.Context, token string) (*User, error)
	ListGroupMemberships(ctx context.Context, userID string) ([]GroupMembership, error)
}

// MockOktaProvider is an in-memory SessionProvider that returns Okta-style mock data.
// NOT for production use.
type MockOktaProvider struct {
	users  map[string]*User
	groups map[string]*Group
}

// NewMockOktaProvider returns a MockOktaProvider seeded with realistic Okta-style data.
func NewMockOktaProvider() *MockOktaProvider {
	now := time.Now()
	lastLogin := now.Add(-2 * time.Hour)

	return &MockOktaProvider{
		users: map[string]*User{
			"00u1a2b3c4d5e6f7g8h9": {
				ID:          "00u1a2b3c4d5e6f7g8h9",
				Email:       "alice@example.com",
				DisplayName: "Alice Chen",
				Department:  "Platform Engineering",
				JobTitle:    "Senior Platform Engineer",
				Status:      statusActive,
				MFAEnabled:  true,
				LastLogin:   &lastLogin,
				CreatedAt:   now.Add(-365 * 24 * time.Hour),
				UpdatedAt:   now,
				Groups:      []string{"cloudforge-admin", "platform-engineers"},
				Roles:       []string{"ADMIN"},
				Attributes:  map[string]string{"provider": "okta", "org": "integrator-3493576"},
			},
			"00u9h8g7f6e5d4c3b2a1": {
				ID:          "00u9h8g7f6e5d4c3b2a1",
				Email:       "bob@example.com",
				DisplayName: "Bob Martinez",
				Department:  "Security",
				JobTitle:    "Security Analyst",
				Status:      statusActive,
				MFAEnabled:  true,
				LastLogin:   &lastLogin,
				CreatedAt:   now.Add(-180 * 24 * time.Hour),
				UpdatedAt:   now,
				Groups:      []string{"cloudforge-operator", "security-team"},
				Roles:       []string{"OPERATOR"},
				Attributes:  map[string]string{"provider": "okta", "org": "integrator-3493576"},
			},
		},
		groups: map[string]*Group{
			"cloudforge-admin": {
				ID:          "00g1cloudforgeadmin",
				Name:        "cloudforge-admin",
				Description: "CloudForge administrators",
				Type:        "security",
				MemberCount: 1,
				CreatedAt:   now.Add(-365 * 24 * time.Hour),
			},
			"cloudforge-operator": {
				ID:          "00g2cloudforgeoperator",
				Name:        "cloudforge-operator",
				Description: "CloudForge operators (read + limited write)",
				Type:        "security",
				MemberCount: 1,
				CreatedAt:   now.Add(-365 * 24 * time.Hour),
			},
		},
	}
}

func (p *MockOktaProvider) Name() string { return "okta" }

func (p *MockOktaProvider) GetUser(_ context.Context, userID string) (*User, error) {
	u, ok := p.users[userID]
	if !ok {
		return nil, fmt.Errorf("getting user %q from okta: %w", userID, ErrNotFound)
	}
	cp := *u
	return &cp, nil
}

func (p *MockOktaProvider) ListUsers(_ context.Context, filter UserFilter) ([]*User, error) {
	out := make([]*User, 0, len(p.users))
	for _, u := range p.users {
		if filter.Status != "" && u.Status != filter.Status {
			continue
		}
		cp := *u
		out = append(out, &cp)
	}
	return out, nil
}

func (p *MockOktaProvider) CreateUser(_ context.Context, user *User) error {
	p.users[user.ID] = user
	return nil
}

func (p *MockOktaProvider) UpdateUser(_ context.Context, user *User) error {
	if _, ok := p.users[user.ID]; !ok {
		return fmt.Errorf("updating user %q in okta: %w", user.ID, ErrNotFound)
	}
	cp := *user
	p.users[user.ID] = &cp
	return nil
}

func (p *MockOktaProvider) DisableUser(_ context.Context, userID string) error {
	u, ok := p.users[userID]
	if !ok {
		return fmt.Errorf("disabling user %q in okta: %w", userID, ErrNotFound)
	}
	u.Status = statusDisabled
	return nil
}

func (p *MockOktaProvider) GetGroup(_ context.Context, groupID string) (*Group, error) {
	g, ok := p.groups[groupID]
	if !ok {
		return nil, fmt.Errorf("getting group %q from okta: %w", groupID, ErrNotFound)
	}
	cp := *g
	return &cp, nil
}

func (p *MockOktaProvider) ListGroups(_ context.Context, _ GroupFilter) ([]*Group, error) {
	out := make([]*Group, 0, len(p.groups))
	for _, g := range p.groups {
		cp := *g
		out = append(out, &cp)
	}
	return out, nil
}

func (p *MockOktaProvider) GetGroupMembers(_ context.Context, groupID string) ([]*User, error) {
	var members []*User
	for _, u := range p.users {
		for _, gID := range u.Groups {
			if gID == groupID {
				cp := *u
				members = append(members, &cp)
				break
			}
		}
	}
	return members, nil
}

func (p *MockOktaProvider) AddUserToGroup(_ context.Context, userID, groupID string) error {
	u, ok := p.users[userID]
	if !ok {
		return fmt.Errorf("adding user to group in okta: user %q: %w", userID, ErrNotFound)
	}
	for _, g := range u.Groups {
		if g == groupID {
			return nil // already a member
		}
	}
	u.Groups = append(u.Groups, groupID)
	return nil
}

func (p *MockOktaProvider) RemoveUserFromGroup(_ context.Context, userID, groupID string) error {
	u, ok := p.users[userID]
	if !ok {
		return fmt.Errorf("removing user from group in okta: user %q: %w", userID, ErrNotFound)
	}
	filtered := u.Groups[:0]
	for _, g := range u.Groups {
		if g != groupID {
			filtered = append(filtered, g)
		}
	}
	u.Groups = filtered
	return nil
}

func (p *MockOktaProvider) GetUserRoles(_ context.Context, userID string) ([]*Role, error) {
	u, ok := p.users[userID]
	if !ok {
		return nil, fmt.Errorf("getting roles for user %q from okta: %w", userID, ErrNotFound)
	}
	roles := make([]*Role, 0, len(u.Roles))
	for _, r := range u.Roles {
		roles = append(roles, &Role{
			ID:   r,
			Name: r,
		})
	}
	return roles, nil
}

func (p *MockOktaProvider) AssignRole(_ context.Context, userID, roleID, _ string) error {
	u, ok := p.users[userID]
	if !ok {
		return fmt.Errorf("assigning role to user %q in okta: %w", userID, ErrNotFound)
	}
	u.Roles = append(u.Roles, roleID)
	return nil
}

func (p *MockOktaProvider) RevokeRole(_ context.Context, userID, roleID, _ string) error {
	u, ok := p.users[userID]
	if !ok {
		return fmt.Errorf("revoking role from user %q in okta: %w", userID, ErrNotFound)
	}
	filtered := u.Roles[:0]
	for _, r := range u.Roles {
		if r != roleID {
			filtered = append(filtered, r)
		}
	}
	u.Roles = filtered
	return nil
}

func (p *MockOktaProvider) RequestJITAccess(_ context.Context, _ *JITAccessRequest) (*JITAccessGrant, error) {
	return nil, fmt.Errorf("JIT access not supported in Okta mock — use Access Request workflows")
}

func (p *MockOktaProvider) ApproveJITAccess(_ context.Context, _, _ string) error {
	return fmt.Errorf("JIT access not supported in Okta mock")
}

func (p *MockOktaProvider) RevokeJITAccess(_ context.Context, _ string) error {
	return fmt.Errorf("JIT access not supported in Okta mock")
}

func (p *MockOktaProvider) ListActiveJITGrants(_ context.Context, _ string) ([]*JITAccessGrant, error) {
	return []*JITAccessGrant{}, nil
}

func (p *MockOktaProvider) GetUserRiskScore(_ context.Context, userID string) (*RiskAssessment, error) {
	return &RiskAssessment{
		UserID:             userID,
		RiskScore:          0,
		RiskLevel:          "low",
		Factors:            []string{},
		LastAssessedAt:     time.Now(),
		RecommendedActions: []string{"Enable Okta ThreatInsight for risk scoring"},
	}, nil
}

// ValidateSession resolves a bearer token to a User.
// The mock treats the token as a user ID for simplicity.
func (p *MockOktaProvider) ValidateSession(_ context.Context, token string) (*User, error) {
	if token == "" {
		return nil, fmt.Errorf("validating session in okta: token must not be empty")
	}
	u, ok := p.users[token]
	if !ok {
		return nil, fmt.Errorf("validating session in okta: token %q: %w", token, ErrNotFound)
	}
	cp := *u
	return &cp, nil
}

// ListGroupMemberships returns the group memberships for a user.
func (p *MockOktaProvider) ListGroupMemberships(_ context.Context, userID string) ([]GroupMembership, error) {
	u, ok := p.users[userID]
	if !ok {
		return nil, fmt.Errorf("listing group memberships for user %q in okta: %w", userID, ErrNotFound)
	}

	memberships := make([]GroupMembership, 0, len(u.Groups))
	for _, gName := range u.Groups {
		g, gOk := p.groups[gName]
		role := "member"
		if gOk && gName == "cloudforge-admin" {
			role = "admin"
		}
		gID := gName
		if gOk {
			gID = g.ID
		}
		memberships = append(memberships, GroupMembership{
			GroupID:   gID,
			GroupName: gName,
			Role:      role,
		})
	}
	return memberships, nil
}

// =============================================================================
// MockEntraIDProvider
// =============================================================================

// MockEntraIDProvider is an in-memory SessionProvider that returns Entra ID-style mock data.
// NOT for production use.
type MockEntraIDProvider struct {
	users  map[string]*User
	groups map[string]*Group
}

// NewMockEntraIDProvider returns a MockEntraIDProvider seeded with Entra ID-style data.
func NewMockEntraIDProvider() *MockEntraIDProvider {
	now := time.Now()
	lastLogin := now.Add(-4 * time.Hour)

	return &MockEntraIDProvider{
		users: map[string]*User{
			"a1b2c3d4-e5f6-7890-abcd-ef1234567890": {
				ID:          "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
				Email:       "carol@example.com",
				DisplayName: "Carol Zhang",
				Department:  "Cloud Infrastructure",
				JobTitle:    "Cloud Security Architect",
				Status:      statusActive,
				MFAEnabled:  true,
				LastLogin:   &lastLogin,
				CreatedAt:   now.Add(-400 * 24 * time.Hour),
				UpdatedAt:   now,
				Groups:      []string{"sg-cloudforge-admin", "sg-cloud-infra"},
				Roles:       []string{"ADMIN"},
				Attributes:  map[string]string{"provider": "entra_id", "tenant": "example.onmicrosoft.com"},
			},
			"f0e9d8c7-b6a5-4321-dcba-fe9876543210": {
				ID:          "f0e9d8c7-b6a5-4321-dcba-fe9876543210",
				Email:       "dave@example.com",
				DisplayName: "Dave Patel",
				Department:  "DevOps",
				JobTitle:    "DevOps Engineer",
				Status:      statusActive,
				MFAEnabled:  false,
				LastLogin:   &lastLogin,
				CreatedAt:   now.Add(-200 * 24 * time.Hour),
				UpdatedAt:   now,
				Groups:      []string{"sg-cloudforge-operator", "sg-devops"},
				Roles:       []string{"OPERATOR"},
				Attributes:  map[string]string{"provider": "entra_id", "tenant": "example.onmicrosoft.com"},
			},
		},
		groups: map[string]*Group{
			"sg-cloudforge-admin": {
				ID:          "11111111-2222-3333-4444-555555555555",
				Name:        "sg-cloudforge-admin",
				Description: "CloudForge Administrators (Entra ID)",
				Type:        "security",
				MemberCount: 1,
				CreatedAt:   now.Add(-400 * 24 * time.Hour),
			},
			"sg-cloudforge-operator": {
				ID:          "66666666-7777-8888-9999-aaaaaaaaaaaa",
				Name:        "sg-cloudforge-operator",
				Description: "CloudForge Operators (Entra ID)",
				Type:        "security",
				MemberCount: 1,
				CreatedAt:   now.Add(-400 * 24 * time.Hour),
			},
		},
	}
}

func (p *MockEntraIDProvider) Name() string { return "entra_id" }

func (p *MockEntraIDProvider) GetUser(_ context.Context, userID string) (*User, error) {
	u, ok := p.users[userID]
	if !ok {
		return nil, fmt.Errorf("getting user %q from entra_id: %w", userID, ErrNotFound)
	}
	cp := *u
	return &cp, nil
}

func (p *MockEntraIDProvider) ListUsers(_ context.Context, filter UserFilter) ([]*User, error) {
	out := make([]*User, 0, len(p.users))
	for _, u := range p.users {
		if filter.Status != "" && u.Status != filter.Status {
			continue
		}
		cp := *u
		out = append(out, &cp)
	}
	return out, nil
}

func (p *MockEntraIDProvider) CreateUser(_ context.Context, user *User) error {
	p.users[user.ID] = user
	return nil
}

func (p *MockEntraIDProvider) UpdateUser(_ context.Context, user *User) error {
	if _, ok := p.users[user.ID]; !ok {
		return fmt.Errorf("updating user %q in entra_id: %w", user.ID, ErrNotFound)
	}
	cp := *user
	p.users[user.ID] = &cp
	return nil
}

func (p *MockEntraIDProvider) DisableUser(_ context.Context, userID string) error {
	u, ok := p.users[userID]
	if !ok {
		return fmt.Errorf("disabling user %q in entra_id: %w", userID, ErrNotFound)
	}
	u.Status = statusDisabled
	return nil
}

func (p *MockEntraIDProvider) GetGroup(_ context.Context, groupID string) (*Group, error) {
	for _, g := range p.groups {
		if g.ID == groupID || g.Name == groupID {
			cp := *g
			return &cp, nil
		}
	}
	return nil, fmt.Errorf("getting group %q from entra_id: %w", groupID, ErrNotFound)
}

func (p *MockEntraIDProvider) ListGroups(_ context.Context, _ GroupFilter) ([]*Group, error) {
	out := make([]*Group, 0, len(p.groups))
	for _, g := range p.groups {
		cp := *g
		out = append(out, &cp)
	}
	return out, nil
}

func (p *MockEntraIDProvider) GetGroupMembers(_ context.Context, groupID string) ([]*User, error) {
	var members []*User
	for _, u := range p.users {
		for _, gID := range u.Groups {
			if gID == groupID {
				cp := *u
				members = append(members, &cp)
				break
			}
		}
	}
	return members, nil
}

func (p *MockEntraIDProvider) AddUserToGroup(_ context.Context, userID, groupID string) error {
	u, ok := p.users[userID]
	if !ok {
		return fmt.Errorf("adding user to group in entra_id: user %q: %w", userID, ErrNotFound)
	}
	for _, g := range u.Groups {
		if g == groupID {
			return nil
		}
	}
	u.Groups = append(u.Groups, groupID)
	return nil
}

func (p *MockEntraIDProvider) RemoveUserFromGroup(_ context.Context, userID, groupID string) error {
	u, ok := p.users[userID]
	if !ok {
		return fmt.Errorf("removing user from group in entra_id: user %q: %w", userID, ErrNotFound)
	}
	filtered := u.Groups[:0]
	for _, g := range u.Groups {
		if g != groupID {
			filtered = append(filtered, g)
		}
	}
	u.Groups = filtered
	return nil
}

func (p *MockEntraIDProvider) GetUserRoles(_ context.Context, userID string) ([]*Role, error) {
	u, ok := p.users[userID]
	if !ok {
		return nil, fmt.Errorf("getting roles for user %q from entra_id: %w", userID, ErrNotFound)
	}
	roles := make([]*Role, 0, len(u.Roles))
	for _, r := range u.Roles {
		roles = append(roles, &Role{ID: r, Name: r})
	}
	return roles, nil
}

func (p *MockEntraIDProvider) AssignRole(_ context.Context, userID, roleID, _ string) error {
	u, ok := p.users[userID]
	if !ok {
		return fmt.Errorf("assigning role to user %q in entra_id: %w", userID, ErrNotFound)
	}
	u.Roles = append(u.Roles, roleID)
	return nil
}

func (p *MockEntraIDProvider) RevokeRole(_ context.Context, userID, roleID, _ string) error {
	u, ok := p.users[userID]
	if !ok {
		return fmt.Errorf("revoking role from user %q in entra_id: %w", userID, ErrNotFound)
	}
	filtered := u.Roles[:0]
	for _, r := range u.Roles {
		if r != roleID {
			filtered = append(filtered, r)
		}
	}
	u.Roles = filtered
	return nil
}

func (p *MockEntraIDProvider) RequestJITAccess(_ context.Context, _ *JITAccessRequest) (*JITAccessGrant, error) {
	return nil, fmt.Errorf("PIM JIT access not implemented in Entra ID mock")
}

func (p *MockEntraIDProvider) ApproveJITAccess(_ context.Context, _, _ string) error {
	return fmt.Errorf("PIM JIT access not implemented in Entra ID mock")
}

func (p *MockEntraIDProvider) RevokeJITAccess(_ context.Context, _ string) error {
	return fmt.Errorf("PIM JIT access not implemented in Entra ID mock")
}

func (p *MockEntraIDProvider) ListActiveJITGrants(_ context.Context, _ string) ([]*JITAccessGrant, error) {
	return []*JITAccessGrant{}, nil
}

func (p *MockEntraIDProvider) GetUserRiskScore(_ context.Context, userID string) (*RiskAssessment, error) {
	return &RiskAssessment{
		UserID:         userID,
		RiskScore:      0,
		RiskLevel:      "low",
		Factors:        []string{},
		LastAssessedAt: time.Now(),
	}, nil
}

// ValidateSession resolves a bearer token to a User.
// The mock treats the token as a user ID for simplicity.
func (p *MockEntraIDProvider) ValidateSession(_ context.Context, token string) (*User, error) {
	if token == "" {
		return nil, fmt.Errorf("validating session in entra_id: token must not be empty")
	}
	u, ok := p.users[token]
	if !ok {
		return nil, fmt.Errorf("validating session in entra_id: token %q: %w", token, ErrNotFound)
	}
	cp := *u
	return &cp, nil
}

// ListGroupMemberships returns the group memberships for a user.
func (p *MockEntraIDProvider) ListGroupMemberships(_ context.Context, userID string) ([]GroupMembership, error) {
	u, ok := p.users[userID]
	if !ok {
		return nil, fmt.Errorf("listing group memberships for user %q in entra_id: %w", userID, ErrNotFound)
	}

	memberships := make([]GroupMembership, 0, len(u.Groups))
	for _, gName := range u.Groups {
		g, gOk := p.groups[gName]
		role := "member"
		if gOk && gName == "sg-cloudforge-admin" {
			role = "admin"
		}
		gID := gName
		if gOk {
			gID = g.ID
		}
		memberships = append(memberships, GroupMembership{
			GroupID:   gID,
			GroupName: gName,
			Role:      role,
		})
	}
	return memberships, nil
}
