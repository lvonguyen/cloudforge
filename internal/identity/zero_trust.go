// Package identity provides identity and access management capabilities
package identity

import (
	"context"
	"fmt"
	"time"

	"go.uber.org/zap"
)

// ZeroTrustPolicy defines a zero trust access policy
type ZeroTrustPolicy struct {
	ID          string              `json:"id" yaml:"id"`
	Name        string              `json:"name" yaml:"name"`
	Description string              `json:"description" yaml:"description"`
	Enabled     bool                `json:"enabled" yaml:"enabled"`
	Priority    int                 `json:"priority" yaml:"priority"`
	Conditions  []PolicyCondition   `json:"conditions" yaml:"conditions"`
	Actions     []PolicyAction      `json:"actions" yaml:"actions"`
	Exceptions  []PolicyException   `json:"exceptions" yaml:"exceptions"`
}

// PolicyCondition defines a condition for policy evaluation
type PolicyCondition struct {
	Type     string   `json:"type" yaml:"type"`         // user, group, device, location, risk, time
	Operator string   `json:"operator" yaml:"operator"` // equals, not_equals, contains, in
	Values   []string `json:"values" yaml:"values"`
}

// PolicyAction defines an action to take when policy matches
type PolicyAction struct {
	Type       string            `json:"type" yaml:"type"` // allow, deny, mfa, step_up, session_control
	Parameters map[string]string `json:"parameters" yaml:"parameters"`
}

// PolicyException defines an exception to the policy
type PolicyException struct {
	Type   string   `json:"type" yaml:"type"`
	Values []string `json:"values" yaml:"values"`
	Reason string   `json:"reason" yaml:"reason"`
}

// AccessRequest represents a request to access a resource
type AccessRequest struct {
	UserID       string            `json:"user_id"`
	Resource     string            `json:"resource"`
	Action       string            `json:"action"`
	Context      AccessContext     `json:"context"`
	Timestamp    time.Time         `json:"timestamp"`
}

// AccessContext provides context for access decisions
type AccessContext struct {
	DeviceID         string            `json:"device_id,omitempty"`
	DeviceCompliant  bool              `json:"device_compliant"`
	DeviceTrusted    bool              `json:"device_trusted"`
	IPAddress        string            `json:"ip_address"`
	Location         string            `json:"location,omitempty"`
	UserAgent        string            `json:"user_agent,omitempty"`
	MFACompleted     bool              `json:"mfa_completed"`
	RiskLevel        string            `json:"risk_level"`
	SessionAge       time.Duration     `json:"session_age"`
	Attributes       map[string]string `json:"attributes,omitempty"`
}

// AccessDecision represents the result of a policy evaluation
type AccessDecision struct {
	Allowed       bool              `json:"allowed"`
	PolicyID      string            `json:"policy_id"`
	PolicyName    string            `json:"policy_name"`
	Reason        string            `json:"reason"`
	RequiredActions []string        `json:"required_actions,omitempty"`
	SessionControls map[string]string `json:"session_controls,omitempty"`
	EvaluatedAt   time.Time         `json:"evaluated_at"`
}

// ZeroTrustEngine evaluates access requests against policies
type ZeroTrustEngine struct {
	policies   []*ZeroTrustPolicy
	providers  map[string]Provider
	logger     *zap.Logger
}

// NewZeroTrustEngine creates a new zero trust policy engine
func NewZeroTrustEngine(logger *zap.Logger) *ZeroTrustEngine {
	engine := &ZeroTrustEngine{
		policies:  make([]*ZeroTrustPolicy, 0),
		providers: make(map[string]Provider),
		logger:    logger,
	}

	// Load default policies
	engine.loadDefaultPolicies()

	return engine
}

// RegisterProvider registers an identity provider for enrichment
func (e *ZeroTrustEngine) RegisterProvider(provider Provider) {
	e.providers[provider.Name()] = provider
}

// AddPolicy adds a policy to the engine
func (e *ZeroTrustEngine) AddPolicy(policy *ZeroTrustPolicy) {
	e.policies = append(e.policies, policy)
	e.sortPoliciesByPriority()
}

// Evaluate evaluates an access request against all policies
func (e *ZeroTrustEngine) Evaluate(ctx context.Context, request *AccessRequest) (*AccessDecision, error) {
	e.logger.Debug("Evaluating access request",
		zap.String("user_id", request.UserID),
		zap.String("resource", request.Resource),
		zap.String("action", request.Action),
	)

	// Enrich context with identity provider data
	enrichedContext, err := e.enrichContext(ctx, request)
	if err != nil {
		e.logger.Warn("Failed to enrich context", zap.Error(err))
		// Continue with available context
	}
	request.Context = enrichedContext

	// Evaluate policies in priority order
	for _, policy := range e.policies {
		if !policy.Enabled {
			continue
		}

		if e.matchesPolicy(request, policy) {
			decision := e.applyPolicy(request, policy)
			
			e.logger.Info("Access decision made",
				zap.String("user_id", request.UserID),
				zap.String("resource", request.Resource),
				zap.String("policy", policy.Name),
				zap.Bool("allowed", decision.Allowed),
			)

			return decision, nil
		}
	}

	// Default deny if no policy matches
	return &AccessDecision{
		Allowed:     false,
		Reason:      "No matching policy - default deny",
		EvaluatedAt: time.Now(),
	}, nil
}

func (e *ZeroTrustEngine) enrichContext(ctx context.Context, request *AccessRequest) (AccessContext, error) {
	context := request.Context

	// Try to get user risk level from identity providers
	for _, provider := range e.providers {
		risk, err := provider.GetUserRiskScore(ctx, request.UserID)
		if err == nil && risk != nil {
			context.RiskLevel = risk.RiskLevel
			break
		}
	}

	return context, nil
}

func (e *ZeroTrustEngine) matchesPolicy(request *AccessRequest, policy *ZeroTrustPolicy) bool {
	// Check if any exception applies
	for _, exception := range policy.Exceptions {
		if e.matchesException(request, &exception) {
			return false
		}
	}

	// Check all conditions (AND logic)
	for _, condition := range policy.Conditions {
		if !e.matchesCondition(request, &condition) {
			return false
		}
	}

	return true
}

func (e *ZeroTrustEngine) matchesCondition(request *AccessRequest, condition *PolicyCondition) bool {
	var value string

	switch condition.Type {
	case "user":
		value = request.UserID
	case "resource":
		value = request.Resource
	case "action":
		value = request.Action
	case "risk":
		value = request.Context.RiskLevel
	case "device_compliant":
		if request.Context.DeviceCompliant {
			value = "true"
		} else {
			value = "false"
		}
	case "mfa_completed":
		if request.Context.MFACompleted {
			value = "true"
		} else {
			value = "false"
		}
	case "location":
		value = request.Context.Location
	case "ip":
		value = request.Context.IPAddress
	default:
		return false
	}

	switch condition.Operator {
	case "equals":
		return len(condition.Values) > 0 && value == condition.Values[0]
	case "not_equals":
		return len(condition.Values) > 0 && value != condition.Values[0]
	case "in":
		for _, v := range condition.Values {
			if value == v {
				return true
			}
		}
		return false
	case "not_in":
		for _, v := range condition.Values {
			if value == v {
				return false
			}
		}
		return true
	default:
		return false
	}
}

func (e *ZeroTrustEngine) matchesException(request *AccessRequest, exception *PolicyException) bool {
	// Simplified exception matching
	switch exception.Type {
	case "user":
		for _, v := range exception.Values {
			if request.UserID == v {
				return true
			}
		}
	case "resource":
		for _, v := range exception.Values {
			if request.Resource == v {
				return true
			}
		}
	}
	return false
}

func (e *ZeroTrustEngine) applyPolicy(request *AccessRequest, policy *ZeroTrustPolicy) *AccessDecision {
	decision := &AccessDecision{
		PolicyID:    policy.ID,
		PolicyName:  policy.Name,
		EvaluatedAt: time.Now(),
	}

	requiredActions := make([]string, 0)
	sessionControls := make(map[string]string)

	for _, action := range policy.Actions {
		switch action.Type {
		case "allow":
			decision.Allowed = true
			decision.Reason = "Access granted by policy"
		case "deny":
			decision.Allowed = false
			decision.Reason = fmt.Sprintf("Access denied by policy: %s", policy.Name)
		case "mfa":
			if !request.Context.MFACompleted {
				decision.Allowed = false
				decision.Reason = "MFA required"
				requiredActions = append(requiredActions, "complete_mfa")
			}
		case "step_up":
			requiredActions = append(requiredActions, "step_up_auth")
		case "session_control":
			for k, v := range action.Parameters {
				sessionControls[k] = v
			}
		}
	}

	decision.RequiredActions = requiredActions
	decision.SessionControls = sessionControls

	return decision
}

func (e *ZeroTrustEngine) sortPoliciesByPriority() {
	// Simple bubble sort - could use sort.Slice for larger sets
	for i := 0; i < len(e.policies)-1; i++ {
		for j := 0; j < len(e.policies)-i-1; j++ {
			if e.policies[j].Priority > e.policies[j+1].Priority {
				e.policies[j], e.policies[j+1] = e.policies[j+1], e.policies[j]
			}
		}
	}
}

func (e *ZeroTrustEngine) loadDefaultPolicies() {
	// Block high-risk users
	e.policies = append(e.policies, &ZeroTrustPolicy{
		ID:          "zt-block-high-risk",
		Name:        "Block High Risk Users",
		Description: "Deny access for users with high or critical risk level",
		Enabled:     true,
		Priority:    1,
		Conditions: []PolicyCondition{
			{Type: "risk", Operator: "in", Values: []string{"high", "critical"}},
		},
		Actions: []PolicyAction{
			{Type: "deny"},
		},
	})

	// Require MFA for sensitive resources
	e.policies = append(e.policies, &ZeroTrustPolicy{
		ID:          "zt-mfa-sensitive",
		Name:        "MFA for Sensitive Resources",
		Description: "Require MFA for access to sensitive resources",
		Enabled:     true,
		Priority:    10,
		Conditions: []PolicyCondition{
			{Type: "resource", Operator: "in", Values: []string{"/admin", "/secrets", "/pii"}},
		},
		Actions: []PolicyAction{
			{Type: "mfa"},
			{Type: "allow"},
		},
	})

	// Require compliant device for corporate resources
	e.policies = append(e.policies, &ZeroTrustPolicy{
		ID:          "zt-device-compliance",
		Name:        "Device Compliance Required",
		Description: "Require compliant device for corporate resources",
		Enabled:     true,
		Priority:    20,
		Conditions: []PolicyCondition{
			{Type: "resource", Operator: "in", Values: []string{"/corporate", "/internal"}},
			{Type: "device_compliant", Operator: "equals", Values: []string{"false"}},
		},
		Actions: []PolicyAction{
			{Type: "deny"},
		},
	})

	// Default allow for authenticated users
	e.policies = append(e.policies, &ZeroTrustPolicy{
		ID:          "zt-default-allow",
		Name:        "Default Allow Authenticated",
		Description: "Allow access for authenticated users to non-sensitive resources",
		Enabled:     true,
		Priority:    100,
		Conditions:  []PolicyCondition{}, // Matches all
		Actions: []PolicyAction{
			{Type: "allow"},
			{Type: "session_control", Parameters: map[string]string{
				"max_session_duration": "8h",
				"require_reauthentication": "4h",
			}},
		},
	})

	e.sortPoliciesByPriority()
	e.logger.Info("Loaded default zero trust policies",
		zap.Int("count", len(e.policies)),
	)
}

// ListPolicies returns all policies
func (e *ZeroTrustEngine) ListPolicies() []*ZeroTrustPolicy {
	return e.policies
}

// GetPolicy returns a policy by ID
func (e *ZeroTrustEngine) GetPolicy(id string) (*ZeroTrustPolicy, bool) {
	for _, p := range e.policies {
		if p.ID == id {
			return p, true
		}
	}
	return nil, false
}

// UpdatePolicy updates an existing policy
func (e *ZeroTrustEngine) UpdatePolicy(policy *ZeroTrustPolicy) error {
	for i, p := range e.policies {
		if p.ID == policy.ID {
			e.policies[i] = policy
			e.sortPoliciesByPriority()
			return nil
		}
	}
	return fmt.Errorf("policy not found: %s", policy.ID)
}

// DeletePolicy removes a policy
func (e *ZeroTrustEngine) DeletePolicy(id string) error {
	for i, p := range e.policies {
		if p.ID == id {
			e.policies = append(e.policies[:i], e.policies[i+1:]...)
			return nil
		}
	}
	return fmt.Errorf("policy not found: %s", id)
}

