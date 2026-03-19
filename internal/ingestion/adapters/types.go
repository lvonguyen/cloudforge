// Package adapters provides scanner-specific parsers that normalise third-party
// scan output (Prowler, Trivy, AWS Config) into Cloud Aegis's finding format.
package adapters

import (
	"context"
	"time"
)

// ScannerAdapter parses raw scanner output into normalised findings.
type ScannerAdapter interface {
	Name() string
	Parse(ctx context.Context, data []byte) ([]NormalizedFinding, error)
}

// NormalizedFinding is the scanner-agnostic finding representation produced by
// each adapter. It maps 1:1 to Cloud Aegis's internal Finding schema.
type NormalizedFinding struct {
	Title         string            `json:"title"`
	Description   string            `json:"description"`
	Severity      string            `json:"severity"` // CRITICAL, HIGH, MEDIUM, LOW
	ResourceID    string            `json:"resource_id"`
	ResourceType  string            `json:"resource_type"`
	CloudProvider string            `json:"cloud_provider"` // aws, gcp, azure
	Region        string            `json:"region"`
	AccountID     string            `json:"account_id"`
	Scanner       string            `json:"scanner"` // prowler, trivy, aws-config
	SourceCheckID string            `json:"source_check_id"`
	FoundAt       time.Time         `json:"found_at"`
	RawData       map[string]string `json:"raw_data,omitempty"`
}

// ParseError wraps parsing failures with the adapter name and position context.
type ParseError struct {
	Adapter string `json:"adapter"`
	Index   int    `json:"index"`
	Message string `json:"message"`
}

func (e *ParseError) Error() string {
	return e.Adapter + ": " + e.Message
}
