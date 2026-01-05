// Package identity provides identity and access management capabilities
package identity

import (
	"context"
	"time"

	"go.uber.org/zap"
)

// Provider defines the interface for identity providers
type Provider interface {
	// Name returns the provider name
	Name() string

	// Users
	GetUser(ctx context.Context, userID string) (*User, error)
	ListUsers(ctx context.Context, filter UserFilter) ([]*User, error)
	CreateUser(ctx context.Context, user *User) error
	UpdateUser(ctx context.Context, user *User) error
	DisableUser(ctx context.Context, userID string) error

	// Groups
	GetGroup(ctx context.Context, groupID string) (*Group, error)
	ListGroups(ctx context.Context, filter GroupFilter) ([]*Group, error)
	GetGroupMembers(ctx context.Context, groupID string) ([]*User, error)
	AddUserToGroup(ctx context.Context, userID, groupID string) error
	RemoveUserFromGroup(ctx context.Context, userID, groupID string) error

	// Roles
	GetUserRoles(ctx context.Context, userID string) ([]*Role, error)
	AssignRole(ctx context.Context, userID, roleID string, scope string) error
	RevokeRole(ctx context.Context, userID, roleID string, scope string) error

	// JIT Access
	RequestJITAccess(ctx context.Context, request *JITAccessRequest) (*JITAccessGrant, error)
	ApproveJITAccess(ctx context.Context, requestID string, approverID string) error
	RevokeJITAccess(ctx context.Context, grantID string) error
	ListActiveJITGrants(ctx context.Context, userID string) ([]*JITAccessGrant, error)

	// Risk
	GetUserRiskScore(ctx context.Context, userID string) (*RiskAssessment, error)
}

// User represents an identity user
type User struct {
	ID                string            `json:"id"`
	Email             string            `json:"email"`
	DisplayName       string            `json:"display_name"`
	Department        string            `json:"department"`
	JobTitle          string            `json:"job_title"`
	Manager           string            `json:"manager_id"`
	Status            string            `json:"status"` // active, disabled, suspended
	MFAEnabled        bool              `json:"mfa_enabled"`
	LastLogin         *time.Time        `json:"last_login,omitempty"`
	CreatedAt         time.Time         `json:"created_at"`
	UpdatedAt         time.Time         `json:"updated_at"`
	Attributes        map[string]string `json:"attributes,omitempty"`
	Groups            []string          `json:"groups,omitempty"`
	Roles             []string          `json:"roles,omitempty"`
	RiskLevel         string            `json:"risk_level,omitempty"`
}

// Group represents an identity group
type Group struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Type        string    `json:"type"` // security, distribution, dynamic
	MemberCount int       `json:"member_count"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// Role represents an RBAC role
type Role struct {
	ID          string       `json:"id"`
	Name        string       `json:"name"`
	Description string       `json:"description"`
	Permissions []Permission `json:"permissions"`
	Scope       string       `json:"scope"` // organization, subscription, resource_group, resource
	BuiltIn     bool         `json:"built_in"`
}

// Permission represents a permission
type Permission struct {
	Resource string   `json:"resource"`
	Actions  []string `json:"actions"` // read, write, delete, admin
}

// JITAccessRequest represents a just-in-time access request
type JITAccessRequest struct {
	ID            string        `json:"id"`
	UserID        string        `json:"user_id"`
	RoleID        string        `json:"role_id"`
	Scope         string        `json:"scope"`
	Justification string        `json:"justification"`
	Duration      time.Duration `json:"duration"`
	RequestedAt   time.Time     `json:"requested_at"`
	Status        string        `json:"status"` // pending, approved, denied, expired
	ApproverID    string        `json:"approver_id,omitempty"`
	ApprovedAt    *time.Time    `json:"approved_at,omitempty"`
}

// JITAccessGrant represents an active JIT access grant
type JITAccessGrant struct {
	ID        string    `json:"id"`
	RequestID string    `json:"request_id"`
	UserID    string    `json:"user_id"`
	RoleID    string    `json:"role_id"`
	Scope     string    `json:"scope"`
	GrantedAt time.Time `json:"granted_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Active    bool      `json:"active"`
}

// RiskAssessment represents a user risk assessment
type RiskAssessment struct {
	UserID           string    `json:"user_id"`
	RiskScore        float64   `json:"risk_score"` // 0-100
	RiskLevel        string    `json:"risk_level"` // low, medium, high, critical
	Factors          []string  `json:"factors"`
	LastAssessedAt   time.Time `json:"last_assessed_at"`
	RecommendedActions []string `json:"recommended_actions"`
}

// UserFilter for listing users
type UserFilter struct {
	Status     string `json:"status,omitempty"`
	Department string `json:"department,omitempty"`
	GroupID    string `json:"group_id,omitempty"`
	RiskLevel  string `json:"risk_level,omitempty"`
	Limit      int    `json:"limit,omitempty"`
	Offset     int    `json:"offset,omitempty"`
}

// GroupFilter for listing groups
type GroupFilter struct {
	Type   string `json:"type,omitempty"`
	Limit  int    `json:"limit,omitempty"`
	Offset int    `json:"offset,omitempty"`
}

// Manager manages identity providers
type Manager struct {
	providers map[string]Provider
	logger    *zap.Logger
}

// NewManager creates a new identity manager
func NewManager(logger *zap.Logger) *Manager {
	return &Manager{
		providers: make(map[string]Provider),
		logger:    logger,
	}
}

// RegisterProvider registers an identity provider
func (m *Manager) RegisterProvider(provider Provider) {
	m.providers[provider.Name()] = provider
	m.logger.Info("Registered identity provider",
		zap.String("provider", provider.Name()),
	)
}

// GetProvider returns a provider by name
func (m *Manager) GetProvider(name string) (Provider, bool) {
	p, ok := m.providers[name]
	return p, ok
}

// ListProviders returns all registered providers
func (m *Manager) ListProviders() []string {
	names := make([]string, 0, len(m.providers))
	for name := range m.providers {
		names = append(names, name)
	}
	return names
}

