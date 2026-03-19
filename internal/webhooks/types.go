// Package webhooks provides an outbound webhook delivery engine for CloudForge events.
package webhooks

import "time"

// EventType identifies the kind of event being delivered.
type EventType string

const (
	EventFindingCreated     EventType = "finding.created"
	EventFindingResolved    EventType = "finding.resolved"
	EventFindingEscalated   EventType = "finding.escalated"
	EventRemediationStarted EventType = "remediation.started"
	EventRemediationDone    EventType = "remediation.completed"
	EventComplianceDrift    EventType = "compliance.drift"
	EventAttackPathNew      EventType = "attack_path.new"
	EventExceptionApproved  EventType = "exception.approved"
	EventExceptionExpiring  EventType = "exception.expiring"
	EventDeployPreview      EventType = "deploy.preview"
)

// Event is the envelope delivered to webhook endpoints.
type Event struct {
	ID        string    `json:"id"`
	Type      EventType `json:"type"`
	Timestamp time.Time `json:"timestamp"`
	Payload   any       `json:"payload"`
}

// Endpoint is a registered webhook receiver.
type Endpoint struct {
	ID        string    `json:"id"`
	URL       string    `json:"url"`
	Secret    string    `json:"-"` // HMAC signing secret — never serialised
	Events    []string  `json:"events"`
	Active    bool      `json:"active"`
	CreatedAt time.Time `json:"created_at"`
}

// RegisterEndpointRequest is the input for registering a new webhook endpoint.
type RegisterEndpointRequest struct {
	URL    string   `json:"url"`
	Secret string   `json:"secret"`
	Events []string `json:"events"` // Empty = all events
}

// DeliveryStatus represents the outcome of a webhook delivery attempt.
type DeliveryStatus string

const (
	DeliveryPending DeliveryStatus = "pending"
	DeliverySuccess DeliveryStatus = "success"
	DeliveryFailed  DeliveryStatus = "failed"
)

// Delivery records one attempt to deliver an event to an endpoint.
type Delivery struct {
	ID          string         `json:"id"`
	EndpointID  string         `json:"endpoint_id"`
	EventID     string         `json:"event_id"`
	EventType   EventType      `json:"event_type"`
	Status      DeliveryStatus `json:"status"`
	StatusCode  int            `json:"status_code,omitempty"`
	Error       string         `json:"error,omitempty"`
	AttemptedAt time.Time      `json:"attempted_at"`
	DurationMs  int64          `json:"duration_ms"`
}
