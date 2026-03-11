package container

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// mockScanner is an in-memory Scanner implementation for testing and demos.
// NOT for production use.
type mockScanner struct{}

func newMockScanner() *mockScanner { return &mockScanner{} }

// ScanImage returns a realistic mock scan result for the given image and tag.
// Images with known CVEs in the mock database return realistic vulnerability data.
func (m *mockScanner) ScanImage(_ context.Context, image, tag string) (*ImageScanResult, error) {
	if image == "" {
		return nil, fmt.Errorf("scanning image: image reference must not be empty")
	}

	now := time.Now()
	result := &ImageScanResult{
		ImageRef:          fmt.Sprintf("%s:%s", image, tag),
		Repository:        image,
		Tag:               tag,
		ScannedAt:         now,
		Vulnerabilities:   mockVulns(image, tag),
		Secrets:           []SecretFinding{},
		Misconfigurations: []Misconfiguration{},
		Metadata: ImageMetadata{
			OS:           "linux",
			Architecture: "amd64",
			Size:         148_000_000,
			Created:      now.Add(-72 * time.Hour),
			BaseImage:    "debian:bullseye-slim",
		},
	}

	// Flag :latest tag as a misconfiguration.
	if tag == "latest" {
		result.Misconfigurations = append(result.Misconfigurations, Misconfiguration{
			ID:          "LATEST_TAG",
			Title:       "Image uses mutable :latest tag",
			Description: "Using :latest prevents reproducible deployments and disables admission digest pinning",
			Severity:    "medium",
			Remediation: "Pin image to an immutable digest or semantic version tag",
		})
	}

	result.Compliance = m.calcCompliance(result)
	result.Status = m.determineStatus(result)

	return result, nil
}

// CheckAdmission evaluates whether an image should be admitted to a namespace.
// Denies :latest tag and images with any critical vulnerabilities.
func (m *mockScanner) CheckAdmission(ctx context.Context, image, tag, namespace string) (*AdmissionDecision, error) {
	if image == "" {
		return nil, fmt.Errorf("checking admission for image in %s: image reference must not be empty", namespace)
	}

	decision := &AdmissionDecision{
		Allowed:  true,
		Warnings: []string{},
	}

	if tag == "latest" {
		decision.Allowed = false
		decision.Reason = fmt.Sprintf("image %s uses mutable :latest tag; pin to an immutable digest", image)
		return decision, nil
	}

	scanResult, err := m.ScanImage(ctx, image, tag)
	if err != nil {
		return nil, fmt.Errorf("checking admission for %s:%s: %w", image, tag, err)
	}

	for _, v := range scanResult.Vulnerabilities {
		if strings.EqualFold(v.Severity, "critical") && !m.isIgnored(v.ID) {
			decision.Allowed = false
			decision.Reason = fmt.Sprintf(
				"image %s:%s contains critical vulnerability %s (%s); remediate before deploying to %s",
				image, tag, v.ID, v.PackageName, namespace,
			)
			return decision, nil
		}
	}

	if len(scanResult.Misconfigurations) > 0 {
		for _, mc := range scanResult.Misconfigurations {
			decision.Warnings = append(decision.Warnings,
				fmt.Sprintf("misconfiguration %s: %s", mc.ID, mc.Title),
			)
		}
	}

	return decision, nil
}

// mockVulns returns realistic sample CVEs for well-known vulnerable images.
// For all others it returns a baseline medium-severity finding.
func mockVulns(image, tag string) []Vulnerability {
	// Simulate a known-vulnerable base image.
	if strings.Contains(image, "nginx") && tag != "1.25.3" {
		return []Vulnerability{
			{
				ID:               "CVE-2023-44487",
				PackageName:      "nginx",
				InstalledVersion: "1.24.0",
				FixedVersion:     "1.25.3",
				Severity:         "high",
				Title:            "HTTP/2 Rapid Reset Attack (CONTINUATION flood)",
				CVSS:             7.5,
				References:       []string{"https://nvd.nist.gov/vuln/detail/CVE-2023-44487"},
			},
			{
				ID:               "CVE-2023-38545",
				PackageName:      "libcurl",
				InstalledVersion: "7.88.1",
				FixedVersion:     "8.4.0",
				Severity:         "critical",
				Title:            "curl SOCKS5 heap buffer overflow",
				CVSS:             9.8,
				References:       []string{"https://nvd.nist.gov/vuln/detail/CVE-2023-38545"},
			},
		}
	}

	if strings.Contains(image, "debian") || strings.Contains(image, "ubuntu") {
		return []Vulnerability{
			{
				ID:               "CVE-2023-29383",
				PackageName:      "shadow",
				InstalledVersion: "4.13",
				FixedVersion:     "",
				Severity:         "medium",
				Title:            "shadow: Improper input validation in /etc/shadow",
				CVSS:             5.5,
				References:       []string{"https://nvd.nist.gov/vuln/detail/CVE-2023-29383"},
			},
		}
	}

	// Known-good image — no findings.
	if strings.Contains(image, "distroless") {
		return []Vulnerability{}
	}

	// Default: single low-severity finding for any other image.
	return []Vulnerability{
		{
			ID:               "CVE-2022-37434",
			PackageName:      "zlib",
			InstalledVersion: "1.2.11",
			FixedVersion:     "1.2.12",
			Severity:         "low",
			Title:            "zlib: heap-based buffer over-read and overflow in inflate()",
			CVSS:             3.1,
			References:       []string{"https://nvd.nist.gov/vuln/detail/CVE-2022-37434"},
		},
	}
}

func (m *mockScanner) calcCompliance(result *ImageScanResult) ComplianceResult {
	passed := []string{}
	failed := []string{}

	hasCritical := false
	for _, v := range result.Vulnerabilities {
		if strings.EqualFold(v.Severity, "critical") {
			hasCritical = true
			break
		}
	}

	if hasCritical {
		failed = append(failed, "NO_CRITICAL_VULNS")
	} else {
		passed = append(passed, "NO_CRITICAL_VULNS")
	}

	if len(result.Secrets) == 0 {
		passed = append(passed, "NO_SECRETS")
	} else {
		failed = append(failed, "NO_SECRETS")
	}

	score := float64(len(passed)) / float64(len(passed)+len(failed)) * 100
	return ComplianceResult{Passed: passed, Failed: failed, Score: score}
}

func (m *mockScanner) determineStatus(result *ImageScanResult) string {
	for _, v := range result.Vulnerabilities {
		if strings.EqualFold(v.Severity, "critical") {
			return "failed"
		}
	}
	if len(result.Secrets) > 0 {
		return "failed"
	}
	for _, mc := range result.Misconfigurations {
		if strings.EqualFold(mc.Severity, "high") || strings.EqualFold(mc.Severity, "critical") {
			return "failed"
		}
	}
	if result.Compliance.Score < 70 {
		return "warning"
	}
	return "passed"
}

func (*mockScanner) isIgnored(cveID string) bool {
	// No CVEs are ignored in the mock scanner.
	return false
}
