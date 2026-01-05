// Package container provides container security scanning and policy enforcement
package container

import (
	"context"
	"fmt"
	"time"

	"go.uber.org/zap"
)

// SecurityScanner scans container images and configurations for security issues
type SecurityScanner struct {
	logger *zap.Logger
	config SecurityScannerConfig
}

// SecurityScannerConfig configures the container security scanner
type SecurityScannerConfig struct {
	VulnerabilityThreshold   string        `yaml:"vulnerability_threshold"`   // critical, high, medium, low
	IgnoredCVEs              []string      `yaml:"ignored_cves"`
	RequireSignedImages      bool          `yaml:"require_signed_images"`
	AllowedRegistries        []string      `yaml:"allowed_registries"`
	ScanTimeout              time.Duration `yaml:"scan_timeout"`
	EnableMalwareScan        bool          `yaml:"enable_malware_scan"`
	EnableSecretScan         bool          `yaml:"enable_secret_scan"`
	EnforcePolicies          bool          `yaml:"enforce_policies"`
}

// ImageScanResult represents the result of an image security scan
type ImageScanResult struct {
	ImageRef         string              `json:"image_ref"`
	Digest           string              `json:"digest"`
	Registry         string              `json:"registry"`
	Repository       string              `json:"repository"`
	Tag              string              `json:"tag"`
	ScannedAt        time.Time           `json:"scanned_at"`
	Status           string              `json:"status"` // passed, failed, warning
	Vulnerabilities  []Vulnerability     `json:"vulnerabilities"`
	Secrets          []SecretFinding     `json:"secrets,omitempty"`
	Misconfigurations []Misconfiguration `json:"misconfigurations,omitempty"`
	Compliance       ComplianceResult    `json:"compliance"`
	Metadata         ImageMetadata       `json:"metadata"`
}

// Vulnerability represents a container vulnerability
type Vulnerability struct {
	ID               string   `json:"id"`           // CVE ID
	PackageName      string   `json:"package_name"`
	InstalledVersion string   `json:"installed_version"`
	FixedVersion     string   `json:"fixed_version"`
	Severity         string   `json:"severity"`
	Title            string   `json:"title"`
	Description      string   `json:"description"`
	CVSS             float64  `json:"cvss"`
	References       []string `json:"references"`
}

// SecretFinding represents a secret found in an image
type SecretFinding struct {
	Type        string `json:"type"`         // api_key, password, private_key
	File        string `json:"file"`
	Line        int    `json:"line"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
}

// Misconfiguration represents a security misconfiguration
type Misconfiguration struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	Remediation string `json:"remediation"`
}

// ComplianceResult represents compliance check results
type ComplianceResult struct {
	Passed  []string `json:"passed"`
	Failed  []string `json:"failed"`
	Score   float64  `json:"score"`
}

// ImageMetadata contains image metadata
type ImageMetadata struct {
	OS              string    `json:"os"`
	Architecture    string    `json:"architecture"`
	Size            int64     `json:"size"`
	Created         time.Time `json:"created"`
	Author          string    `json:"author"`
	Signed          bool      `json:"signed"`
	SignatureValid  bool      `json:"signature_valid"`
	BaseImage       string    `json:"base_image"`
	Labels          map[string]string `json:"labels"`
}

// NewSecurityScanner creates a new container security scanner
func NewSecurityScanner(cfg SecurityScannerConfig, logger *zap.Logger) *SecurityScanner {
	return &SecurityScanner{
		config: cfg,
		logger: logger,
	}
}

// ScanImage scans a container image for security issues
func (s *SecurityScanner) ScanImage(ctx context.Context, imageRef string) (*ImageScanResult, error) {
	s.logger.Info("Scanning container image",
		zap.String("image", imageRef),
	)

	result := &ImageScanResult{
		ImageRef:  imageRef,
		ScannedAt: time.Now(),
		Vulnerabilities: make([]Vulnerability, 0),
		Secrets:         make([]SecretFinding, 0),
		Misconfigurations: make([]Misconfiguration, 0),
	}

	// Parse image reference
	if err := s.parseImageRef(imageRef, result); err != nil {
		return nil, fmt.Errorf("parsing image ref: %w", err)
	}

	// Check registry allowlist
	if err := s.checkRegistryAllowed(result.Registry); err != nil {
		result.Status = "failed"
		result.Misconfigurations = append(result.Misconfigurations, Misconfiguration{
			ID:          "REGISTRY_NOT_ALLOWED",
			Title:       "Image from non-approved registry",
			Description: err.Error(),
			Severity:    "high",
			Remediation: "Use images from approved registries only",
		})
		return result, nil
	}

	// Scan for vulnerabilities (stub - integrate with Trivy, Clair, etc.)
	vulns, err := s.scanVulnerabilities(ctx, imageRef)
	if err != nil {
		s.logger.Warn("Vulnerability scan failed", zap.Error(err))
	} else {
		result.Vulnerabilities = vulns
	}

	// Scan for secrets
	if s.config.EnableSecretScan {
		secrets, err := s.scanSecrets(ctx, imageRef)
		if err != nil {
			s.logger.Warn("Secret scan failed", zap.Error(err))
		} else {
			result.Secrets = secrets
		}
	}

	// Check configurations
	misconfigs := s.checkConfigurations(ctx, imageRef)
	result.Misconfigurations = append(result.Misconfigurations, misconfigs...)

	// Check image signature
	if s.config.RequireSignedImages {
		if err := s.checkImageSignature(ctx, imageRef, result); err != nil {
			result.Misconfigurations = append(result.Misconfigurations, Misconfiguration{
				ID:          "IMAGE_NOT_SIGNED",
				Title:       "Image is not signed",
				Description: err.Error(),
				Severity:    "high",
				Remediation: "Sign images using cosign or Docker Content Trust",
			})
		}
	}

	// Calculate compliance
	result.Compliance = s.calculateCompliance(result)

	// Determine overall status
	result.Status = s.determineStatus(result)

	s.logger.Info("Image scan completed",
		zap.String("image", imageRef),
		zap.String("status", result.Status),
		zap.Int("vulnerabilities", len(result.Vulnerabilities)),
		zap.Int("misconfigurations", len(result.Misconfigurations)),
	)

	return result, nil
}

func (s *SecurityScanner) parseImageRef(imageRef string, result *ImageScanResult) error {
	// TODO: Implement proper image reference parsing
	// For now, use stub values
	result.Registry = "docker.io"
	result.Repository = imageRef
	result.Tag = "latest"
	return nil
}

func (s *SecurityScanner) checkRegistryAllowed(registry string) error {
	if len(s.config.AllowedRegistries) == 0 {
		return nil // No allowlist configured
	}

	for _, allowed := range s.config.AllowedRegistries {
		if registry == allowed {
			return nil
		}
	}

	return fmt.Errorf("registry %s is not in allowlist", registry)
}

func (s *SecurityScanner) scanVulnerabilities(ctx context.Context, imageRef string) ([]Vulnerability, error) {
	// TODO: Integrate with Trivy, Clair, or other scanner
	// This is a stub implementation
	vulns := []Vulnerability{
		{
			ID:               "CVE-2023-12345",
			PackageName:      "openssl",
			InstalledVersion: "1.1.1k",
			FixedVersion:     "1.1.1l",
			Severity:         "high",
			Title:            "OpenSSL vulnerability",
			CVSS:             7.5,
		},
	}
	return vulns, nil
}

func (s *SecurityScanner) scanSecrets(ctx context.Context, imageRef string) ([]SecretFinding, error) {
	// TODO: Integrate with secret scanner
	return []SecretFinding{}, nil
}

func (s *SecurityScanner) checkConfigurations(ctx context.Context, imageRef string) []Misconfiguration {
	misconfigs := make([]Misconfiguration, 0)

	// Check for common misconfigurations
	// TODO: Integrate with container config scanner

	// Example checks:
	// - Running as root
	// - No USER instruction
	// - Using latest tag
	// - No health check

	return misconfigs
}

func (s *SecurityScanner) checkImageSignature(ctx context.Context, imageRef string, result *ImageScanResult) error {
	// TODO: Implement signature verification using cosign or DCT
	result.Metadata.Signed = false
	result.Metadata.SignatureValid = false
	return fmt.Errorf("image signature not found")
}

func (s *SecurityScanner) calculateCompliance(result *ImageScanResult) ComplianceResult {
	compliance := ComplianceResult{
		Passed: make([]string, 0),
		Failed: make([]string, 0),
	}

	// Check various compliance requirements
	checks := map[string]func(*ImageScanResult) bool{
		"NO_CRITICAL_VULNS":    func(r *ImageScanResult) bool { return !s.hasCriticalVulns(r) },
		"NO_HIGH_VULNS":        func(r *ImageScanResult) bool { return !s.hasHighVulns(r) },
		"NO_SECRETS":           func(r *ImageScanResult) bool { return len(r.Secrets) == 0 },
		"SIGNED_IMAGE":         func(r *ImageScanResult) bool { return r.Metadata.Signed && r.Metadata.SignatureValid },
		"APPROVED_REGISTRY":    func(r *ImageScanResult) bool { return s.checkRegistryAllowed(r.Registry) == nil },
		"NO_ROOT_USER":         func(r *ImageScanResult) bool { return !s.hasMisconfig(r, "RUN_AS_ROOT") },
	}

	passed := 0
	for check, fn := range checks {
		if fn(result) {
			compliance.Passed = append(compliance.Passed, check)
			passed++
		} else {
			compliance.Failed = append(compliance.Failed, check)
		}
	}

	compliance.Score = float64(passed) / float64(len(checks)) * 100

	return compliance
}

func (s *SecurityScanner) hasCriticalVulns(result *ImageScanResult) bool {
	for _, v := range result.Vulnerabilities {
		if v.Severity == "critical" && !s.isIgnored(v.ID) {
			return true
		}
	}
	return false
}

func (s *SecurityScanner) hasHighVulns(result *ImageScanResult) bool {
	for _, v := range result.Vulnerabilities {
		if v.Severity == "high" && !s.isIgnored(v.ID) {
			return true
		}
	}
	return false
}

func (s *SecurityScanner) hasMisconfig(result *ImageScanResult, id string) bool {
	for _, m := range result.Misconfigurations {
		if m.ID == id {
			return true
		}
	}
	return false
}

func (s *SecurityScanner) isIgnored(cveID string) bool {
	for _, ignored := range s.config.IgnoredCVEs {
		if ignored == cveID {
			return true
		}
	}
	return false
}

func (s *SecurityScanner) determineStatus(result *ImageScanResult) string {
	// Check for failures based on threshold
	threshold := s.config.VulnerabilityThreshold
	if threshold == "" {
		threshold = "critical"
	}

	switch threshold {
	case "critical":
		if s.hasCriticalVulns(result) {
			return "failed"
		}
	case "high":
		if s.hasCriticalVulns(result) || s.hasHighVulns(result) {
			return "failed"
		}
	}

	// Check for secrets
	if len(result.Secrets) > 0 {
		return "failed"
	}

	// Check for high/critical misconfigurations
	for _, m := range result.Misconfigurations {
		if m.Severity == "critical" || m.Severity == "high" {
			return "failed"
		}
	}

	// Check compliance score
	if result.Compliance.Score < 70 {
		return "warning"
	}

	return "passed"
}

// AdmissionPolicy enforces container security policies at admission time
type AdmissionPolicy struct {
	Name                  string   `yaml:"name"`
	Enabled               bool     `yaml:"enabled"`
	BlockOnFailure        bool     `yaml:"block_on_failure"`
	VulnerabilityThreshold string  `yaml:"vulnerability_threshold"`
	RequireSignedImages   bool     `yaml:"require_signed_images"`
	AllowedRegistries     []string `yaml:"allowed_registries"`
	BlockedImages         []string `yaml:"blocked_images"`
	RequiredLabels        []string `yaml:"required_labels"`
}

// ValidateAdmission validates a container against admission policies
func (s *SecurityScanner) ValidateAdmission(ctx context.Context, imageRef string, policies []AdmissionPolicy) (bool, []string) {
	reasons := make([]string, 0)

	scanResult, err := s.ScanImage(ctx, imageRef)
	if err != nil {
		reasons = append(reasons, fmt.Sprintf("scan failed: %v", err))
		return false, reasons
	}

	for _, policy := range policies {
		if !policy.Enabled {
			continue
		}

		// Check image signature
		if policy.RequireSignedImages && !scanResult.Metadata.SignatureValid {
			reasons = append(reasons, "image is not signed with valid signature")
		}

		// Check registry
		if len(policy.AllowedRegistries) > 0 {
			allowed := false
			for _, reg := range policy.AllowedRegistries {
				if scanResult.Registry == reg {
					allowed = true
					break
				}
			}
			if !allowed {
				reasons = append(reasons, fmt.Sprintf("registry %s not in allowlist", scanResult.Registry))
			}
		}

		// Check blocked images
		for _, blocked := range policy.BlockedImages {
			if scanResult.ImageRef == blocked || scanResult.Repository == blocked {
				reasons = append(reasons, fmt.Sprintf("image %s is blocked", blocked))
			}
		}

		// Check scan result
		if scanResult.Status == "failed" && policy.BlockOnFailure {
			reasons = append(reasons, "image failed security scan")
		}
	}

	return len(reasons) == 0, reasons
}

