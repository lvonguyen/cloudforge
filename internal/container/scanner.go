// Package container provides container security scanning and policy enforcement.
package container

import (
	"context"
	"errors"
	"fmt"
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

// ProviderType represents the type of container scanner.
type ProviderType string

const (
	ProviderTypeMemory ProviderType = "memory"
	ProviderTypeTrivy  ProviderType = "trivy"
)

// ScannerConfig contains configuration for creating a container scanner.
type ScannerConfig struct {
	Type              ProviderType
	SeverityThreshold string // Trivy severity threshold (e.g., "HIGH,CRITICAL")
}

// NewScanner returns a Scanner for the given provider name.
// Supports "memory" (in-process mock) and "trivy" (Trivy CLI).
func NewScanner(provider string) (Scanner, error) {
	t, err := ProviderFromString(provider)
	if err != nil {
		return nil, err
	}
	return NewScannerFromConfig(ScannerConfig{Type: t})
}

// NewScannerFromConfig returns a Scanner based on the given configuration.
func NewScannerFromConfig(cfg ScannerConfig) (Scanner, error) {
	switch cfg.Type {
	case ProviderTypeMemory, "":
		return newMockScanner(), nil
	case ProviderTypeTrivy:
		return newTrivyScanner(), nil
	default:
		return nil, fmt.Errorf("unsupported container scanner provider: %q", cfg.Type)
	}
}

// ProviderFromString converts a string to ProviderType.
func ProviderFromString(s string) (ProviderType, error) {
	switch s {
	case "memory", "":
		return ProviderTypeMemory, nil
	case "trivy":
		return ProviderTypeTrivy, nil
	default:
		return "", fmt.Errorf("unknown container scanner provider: %s", s)
	}
}
