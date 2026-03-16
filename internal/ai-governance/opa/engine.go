// Package opa provides an in-process OPA policy engine for AI agent governance.
//
// This engine evaluates tool access and data flow policies for AI agents using
// embedded Rego policies. It complements CloudForge's existing HTTP-based policy
// evaluator (internal/policy/) which handles cloud provisioning governance.
//
// Migrated from AgentGuard — selective merge of the in-process OPA evaluation
// engine for AI agent security controls (tool access, data flow, rate limiting).
package opa

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/storage"
	"github.com/open-policy-agent/opa/storage/inmem"
)

// Engine is the in-process policy evaluation engine powered by OPA.
type Engine struct {
	mu      sync.RWMutex
	queries map[string]*rego.PreparedEvalQuery
	store   storage.Store
}

// Decision represents the result of a policy evaluation.
type Decision struct {
	Allow      bool           `json:"allow"`
	Reasons    []string       `json:"reasons,omitempty"`
	Violations []Violation    `json:"violations,omitempty"`
	Metadata   map[string]any `json:"metadata,omitempty"`
	EvalTimeUs int64          `json:"eval_time_us"`
}

// Violation represents a policy violation.
type Violation struct {
	Policy      string `json:"policy"`
	Rule        string `json:"rule"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
}

// EvaluationInput is the input to policy evaluation.
type EvaluationInput struct {
	Agent       AgentContext      `json:"agent"`
	Tool        *ToolContext      `json:"tool,omitempty"`
	Data        *DataContext      `json:"data,omitempty"`
	Request     *RequestContext   `json:"request,omitempty"`
	Environment map[string]string `json:"environment,omitempty"`
}

// AgentContext provides agent information for policy evaluation.
type AgentContext struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Team         string   `json:"team"`
	Environment  string   `json:"environment"`
	Capabilities []string `json:"capabilities"`
}

// ToolContext provides tool invocation information.
type ToolContext struct {
	Name       string         `json:"name"`
	Category   string         `json:"category"`
	Parameters map[string]any `json:"parameters"`
	External   bool           `json:"external"`
}

// DataContext provides data flow information.
type DataContext struct {
	Classification string   `json:"classification"`
	Source         string   `json:"source"`
	Destination    string   `json:"destination"`
	PIIFields      []string `json:"pii_fields,omitempty"`
}

// RequestContext provides request metadata.
type RequestContext struct {
	UserID    string    `json:"user_id"`
	SessionID string    `json:"session_id"`
	Timestamp time.Time `json:"timestamp"`
	IP        string    `json:"ip,omitempty"`
}

// NewEngine creates a new in-process policy engine.
func NewEngine() (*Engine, error) {
	store := inmem.New()

	return &Engine{
		queries: make(map[string]*rego.PreparedEvalQuery),
		store:   store,
	}, nil
}

// LoadPolicies loads Rego policies from the specified paths.
// Each call is keyed by paths[0] so that multiple disjoint policy groups can
// be loaded without overwriting one another. Previously every call stored
// under the hard-coded key "default", causing a key collision when LoadPolicies
// was invoked more than once with different path sets.
func (e *Engine) LoadPolicies(ctx context.Context, paths []string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if len(paths) == 0 {
		return fmt.Errorf("no policy paths provided")
	}

	// Build rego.Module options from each path so no write transaction is
	// needed on the store (rego.Load requires a write transaction; rego.Module
	// does not, allowing multiple policy groups to coexist in one engine).
	opts := []func(*rego.Rego){
		rego.Query("data.cloudforge.ai"),
		rego.Store(e.store),
	}
	for _, p := range paths {
		src, err := os.ReadFile(p)
		if err != nil {
			return fmt.Errorf("reading policy %s: %w", p, err)
		}
		opts = append(opts, rego.Module(p, string(src)))
	}

	r := rego.New(opts...)

	pq, err := r.PrepareForEval(ctx)
	if err != nil {
		return fmt.Errorf("preparing policy: %w", err)
	}

	// Key by the first path so each policy group is independently addressable.
	e.queries[paths[0]] = &pq
	e.queries["default"] = &pq
	return nil
}

// LoadPolicyBundle loads a policy bundle from a tar.gz file.
func (e *Engine) LoadPolicyBundle(ctx context.Context, bundlePath string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	r := rego.New(
		rego.Query("data.cloudforge.ai.allow"),
		rego.Store(e.store),
		rego.LoadBundle(bundlePath),
	)

	pq, err := r.PrepareForEval(ctx)
	if err != nil {
		return fmt.Errorf("loading bundle: %w", err)
	}

	e.queries["default"] = &pq
	return nil
}

// Evaluate evaluates a policy decision.
func (e *Engine) Evaluate(ctx context.Context, policyPath string, input *EvaluationInput) (*Decision, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	start := time.Now()

	pq, ok := e.queries[policyPath]
	if !ok {
		pq = e.queries["default"]
	}
	if pq == nil {
		return nil, fmt.Errorf("no policy loaded for path: %s", policyPath)
	}

	results, err := pq.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		return nil, fmt.Errorf("policy evaluation failed: %w", err)
	}

	evalTime := time.Since(start).Microseconds()

	decision := &Decision{
		Allow:      false,
		EvalTimeUs: evalTime,
	}

	if len(results) > 0 && len(results[0].Expressions) > 0 {
		result := results[0].Expressions[0].Value
		if resultMap, ok := result.(map[string]any); ok {
			if allow, ok := resultMap["allow"].(bool); ok {
				decision.Allow = allow
			}
			if reasons, ok := resultMap["reasons"].([]any); ok {
				for _, r := range reasons {
					if s, ok := r.(string); ok {
						decision.Reasons = append(decision.Reasons, s)
					}
				}
			}
			if violations, ok := resultMap["violations"].([]any); ok {
				for _, v := range violations {
					if vm, ok := v.(map[string]any); ok {
						decision.Violations = append(decision.Violations, Violation{
							Policy:      getString(vm, "policy"),
							Rule:        getString(vm, "rule"),
							Description: getString(vm, "description"),
							Severity:    getString(vm, "severity"),
						})
					}
				}
			}
		} else if allow, ok := result.(bool); ok {
			decision.Allow = allow
		}
	}

	return decision, nil
}

// EvaluateToolAccess evaluates tool access policy for an AI agent.
func (e *Engine) EvaluateToolAccess(ctx context.Context, agent *AgentContext, tool *ToolContext) (*Decision, error) {
	input := &EvaluationInput{
		Agent: *agent,
		Tool:  tool,
	}
	return e.Evaluate(ctx, "cloudforge.ai.tool_access.allow", input)
}

// EvaluateDataFlow evaluates data flow policy for an AI agent.
func (e *Engine) EvaluateDataFlow(ctx context.Context, agent *AgentContext, data *DataContext) (*Decision, error) {
	input := &EvaluationInput{
		Agent: *agent,
		Data:  data,
	}
	return e.Evaluate(ctx, "cloudforge.ai.data_flow.allow", input)
}

func getString(m map[string]any, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

// BaseToolAccessPolicy is the default Rego policy for AI agent tool access control.
const BaseToolAccessPolicy = `
package cloudforge.ai.tool_access

import future.keywords.in

default allow = false

# Allow if tool is in agent's allowed list and parameters pass validation
allow {
    tool_allowed
    parameters_valid
    not rate_limit_exceeded
}

# Tool is allowed if explicitly listed for this agent
tool_allowed {
    input.tool.name in data.policies.allowed_tools[input.agent.id]
}

# Tool is allowed if its category is permitted
tool_allowed {
    input.tool.category in data.policies.allowed_categories[input.agent.id]
}

# Deny if tool is explicitly blocked
tool_blocked {
    input.tool.name in data.policies.blocked_tools[input.agent.id]
}

# Parameters are valid if no forbidden patterns found
parameters_valid {
    not contains_forbidden_pattern
}

contains_forbidden_pattern {
    pattern := data.policies.forbidden_patterns[_]
    regex.match(pattern, json.marshal(input.tool.parameters))
}

# Rate limiting check
rate_limit_exceeded {
    count := data.rate_limits[input.agent.id][input.tool.name]
    count > data.policies.rate_limits[input.tool.name].max_per_minute
}

# Collect denial reasons for audit
denial_reasons[reason] {
    not tool_allowed
    reason := sprintf("Tool '%s' not allowed for agent '%s'", [input.tool.name, input.agent.id])
}

denial_reasons[reason] {
    tool_blocked
    reason := sprintf("Tool '%s' is explicitly blocked for agent '%s'", [input.tool.name, input.agent.id])
}

denial_reasons[reason] {
    not parameters_valid
    reason := sprintf("Invalid parameters for tool '%s'", [input.tool.name])
}

denial_reasons[reason] {
    rate_limit_exceeded
    reason := sprintf("Rate limit exceeded for tool '%s'", [input.tool.name])
}
`

// BaseDataFlowPolicy is the default Rego policy for AI agent data flow control.
const BaseDataFlowPolicy = `
package cloudforge.ai.data_flow

import future.keywords.in

default allow_flow = false

# Allow data flow if classification permits destination
allow_flow {
    destination_allowed
    not source_restricted
}

# Destination is allowed for this classification
destination_allowed {
    input.data.destination in data.policies.allowed_destinations[input.data.classification]
}

# Source has restrictions that apply
source_restricted {
    input.data.source in data.policies.restricted_sources[_]
    not input.data.destination in data.policies.trusted_destinations
}

# Check if redaction is required
requires_redaction {
    input.data.classification == "PII"
    input.data.destination in data.policies.redact_destinations
}

# Fields to redact
redaction_fields[field] {
    requires_redaction
    field := input.data.pii_fields[_]
}

# Denial reasons for audit
denial_reasons[reason] {
    not destination_allowed
    reason := sprintf(
        "Data with classification '%s' cannot flow to '%s'",
        [input.data.classification, input.data.destination]
    )
}
`
