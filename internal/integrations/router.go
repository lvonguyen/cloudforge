package integrations

import (
	"context"
	"time"
)

// RoutingEngine determines priority, team, and SLA for a finding.
type RoutingEngine interface {
	Route(ctx context.Context, input RoutingInput) (*RoutingDecision, error)
}

// RoutingInput carries the signals used for routing decisions.
type RoutingInput struct {
	Severity       string `json:"severity"`        // CRITICAL, HIGH, MEDIUM, LOW
	IsChokePoint   bool   `json:"is_choke_point"`  // Part of multiple attack paths
	ComplianceHits int    `json:"compliance_hits"` // # of compliance controls violated
}

// RoutingRule maps a condition to a routing decision.
type RoutingRule struct {
	Name     string
	Match    func(RoutingInput) bool
	Decision RoutingDecision
}

// ruleBasedRouter evaluates rules top-down; first match wins.
type ruleBasedRouter struct {
	rules []RoutingRule
}

// NewRoutingEngine creates a rule-based router with the given rules.
func NewRoutingEngine(rules []RoutingRule) RoutingEngine {
	return &ruleBasedRouter{rules: rules}
}

func (r *ruleBasedRouter) Route(_ context.Context, input RoutingInput) (*RoutingDecision, error) {
	for _, rule := range r.rules {
		if rule.Match(input) {
			d := rule.Decision
			d.Reason = rule.Name
			return &d, nil
		}
	}
	// Fallback: low priority, 30-day SLA
	return &RoutingDecision{
		Priority: PriorityLow,
		Team:     "backlog",
		SLAHours: 30 * 24,
		Reason:   "default-fallback",
	}, nil
}

// DefaultRules returns the standard risk-aware routing ruleset.
// Order matters — first match wins.
func DefaultRules() []RoutingRule {
	return []RoutingRule{
		{
			Name: "critical-choke-point",
			Match: func(in RoutingInput) bool {
				return in.Severity == "CRITICAL" && in.IsChokePoint
			},
			Decision: RoutingDecision{Priority: PriorityUrgent, Team: "incident-response", SLAHours: 4},
		},
		{
			Name: "critical",
			Match: func(in RoutingInput) bool {
				return in.Severity == "CRITICAL"
			},
			Decision: RoutingDecision{Priority: PriorityUrgent, Team: "security-ops", SLAHours: 24},
		},
		{
			Name: "high",
			Match: func(in RoutingInput) bool {
				return in.Severity == "HIGH"
			},
			Decision: RoutingDecision{Priority: PriorityHigh, Team: "security-ops", SLAHours: 72},
		},
		{
			Name: "medium",
			Match: func(in RoutingInput) bool {
				return in.Severity == "MEDIUM"
			},
			Decision: RoutingDecision{Priority: PriorityNormal, Team: "platform-eng", SLAHours: 7 * 24},
		},
		{
			Name: "low",
			Match: func(in RoutingInput) bool {
				return in.Severity == "LOW"
			},
			Decision: RoutingDecision{Priority: PriorityLow, Team: "backlog", SLAHours: 30 * 24},
		},
	}
}

// SLADeadline computes the absolute deadline from a routing decision.
func (d *RoutingDecision) SLADeadline(from time.Time) time.Time {
	return from.Add(time.Duration(d.SLAHours) * time.Hour)
}
