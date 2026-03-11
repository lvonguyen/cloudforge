// Package container provides container security scanning and policy enforcement.
package container

import (
	"context"
	"errors"
)

// ErrNotFound is returned when a resource is not found.
var ErrNotFound = errors.New("not found")

// AdmissionDecision represents a Kubernetes admission webhook response.
type AdmissionDecision struct {
	Allowed  bool
	Reason   string
	Warnings []string
}

// Scanner scans container images for vulnerabilities and enforces admission policy.
type Scanner interface {
	ScanImage(ctx context.Context, image, tag string) (*ImageScanResult, error)
	CheckAdmission(ctx context.Context, image, tag, namespace string) (*AdmissionDecision, error)
}

// NewScanner returns a Scanner for the given provider name.
// Supports "memory" (in-process mock). Extend the switch for real providers.
func NewScanner(provider string) Scanner {
	switch provider {
	case "memory", "":
		return newMockScanner()
	default:
		return newMockScanner()
	}
}
