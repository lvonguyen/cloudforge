package container

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

const statusFailed = "failed"

// trivyResult mirrors the top-level JSON structure emitted by `trivy image --format json`.
type trivyResult struct {
	Results []trivyTarget `json:"Results"`
}

type trivyTarget struct {
	Target          string           `json:"Target"`
	Vulnerabilities []trivyVuln      `json:"Vulnerabilities"`
	Secrets         []trivySecret    `json:"Secrets"`
	Misconfigs      []trivyMisconfig `json:"Misconfigurations"`
}

type trivyVuln struct {
	VulnerabilityID  string    `json:"VulnerabilityID"`
	PkgName          string    `json:"PkgName"`
	InstalledVersion string    `json:"InstalledVersion"`
	FixedVersion     string    `json:"FixedVersion"`
	Severity         string    `json:"Severity"`
	Title            string    `json:"Title"`
	Description      string    `json:"Description"`
	CVSS             trivyCVSS `json:"CVSS"`
	References       []string  `json:"References"`
}

// trivyCVSS holds per-source CVSS data. We prefer nvd, fall back to any present.
type trivyCVSS map[string]struct {
	V3Score float64 `json:"V3Score"`
	V2Score float64 `json:"V2Score"`
}

func (c trivyCVSS) score() float64 {
	if v, ok := c["nvd"]; ok && v.V3Score > 0 {
		return v.V3Score
	}
	for _, v := range c {
		if v.V3Score > 0 {
			return v.V3Score
		}
		if v.V2Score > 0 {
			return v.V2Score
		}
	}
	return 0
}

type trivySecret struct {
	RuleID   string `json:"RuleID"`
	Category string `json:"Category"`
	Title    string `json:"Title"`
	Severity string `json:"Severity"`
	Match    string `json:"Match"`
}

type trivyMisconfig struct {
	ID          string `json:"ID"`
	Title       string `json:"Title"`
	Description string `json:"Description"`
	Severity    string `json:"Severity"`
	Resolution  string `json:"Resolution"`
	Status      string `json:"Status"`
}

// cmdFunc is the function signature used to create exec.Cmd instances.
// Replacing this field in tests allows injecting fake Trivy output.
type cmdFunc func(ctx context.Context, name string, args ...string) *exec.Cmd

// trivyScanner shells out to the Trivy CLI to perform real scans.
type trivyScanner struct {
	execCommand cmdFunc
}

// newTrivyScanner returns a trivyScanner using the real exec.CommandContext.
func newTrivyScanner() *trivyScanner {
	return &trivyScanner{execCommand: exec.CommandContext}
}

// ScanImage runs `trivy image --format json --quiet <image>:<tag>` and maps
// the output into an ImageScanResult.
func (t *trivyScanner) ScanImage(ctx context.Context, image, tag string) (*ImageScanResult, error) {
	if image == "" {
		return nil, fmt.Errorf("scanning image: image reference must not be empty")
	}

	ref := fmt.Sprintf("%s:%s", image, tag)
	out, err := t.runTrivy(ctx, "image", "--format", "json", "--quiet", ref)
	if err != nil {
		return nil, err
	}

	var trivy trivyResult
	if jsonErr := json.Unmarshal(out, &trivy); jsonErr != nil {
		return nil, fmt.Errorf("parsing trivy output for %s: %w", ref, jsonErr)
	}

	result := &ImageScanResult{
		ImageRef:          ref,
		Repository:        image,
		Tag:               tag,
		ScannedAt:         time.Now(),
		Vulnerabilities:   []Vulnerability{},
		Secrets:           []SecretFinding{},
		Misconfigurations: []Misconfiguration{},
		Metadata: ImageMetadata{
			OS:           "linux",
			Architecture: "amd64",
		},
	}

	for _, target := range trivy.Results {
		for _, v := range target.Vulnerabilities {
			result.Vulnerabilities = append(result.Vulnerabilities, Vulnerability{
				ID:               v.VulnerabilityID,
				PackageName:      v.PkgName,
				InstalledVersion: v.InstalledVersion,
				FixedVersion:     v.FixedVersion,
				Severity:         strings.ToLower(v.Severity),
				Title:            v.Title,
				Description:      v.Description,
				CVSS:             v.CVSS.score(),
				References:       v.References,
			})
		}
		for _, s := range target.Secrets {
			result.Secrets = append(result.Secrets, SecretFinding{
				Type:        s.Category,
				File:        target.Target,
				Description: s.Title,
				Severity:    strings.ToLower(s.Severity),
			})
		}
		for _, m := range target.Misconfigs {
			if strings.EqualFold(m.Status, "PASS") {
				continue
			}
			result.Misconfigurations = append(result.Misconfigurations, Misconfiguration{
				ID:          m.ID,
				Title:       m.Title,
				Description: m.Description,
				Severity:    strings.ToLower(m.Severity),
				Remediation: m.Resolution,
			})
		}
	}

	// Flag :latest tag as a misconfiguration, same as mockScanner.
	if tag == "latest" {
		result.Misconfigurations = append(result.Misconfigurations, Misconfiguration{
			ID:          "LATEST_TAG",
			Title:       "Image uses mutable :latest tag",
			Description: "Using :latest prevents reproducible deployments and disables admission digest pinning",
			Severity:    "medium",
			Remediation: "Pin image to an immutable digest or semantic version tag",
		})
	}

	result.Compliance = t.calcCompliance(result)
	result.Status = t.determineStatus(result)

	return result, nil
}

// CheckAdmission scans the image and denies admission on critical vulns or :latest tag.
func (t *trivyScanner) CheckAdmission(ctx context.Context, image, tag, namespace string) (*AdmissionDecision, error) {
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

	scanResult, err := t.ScanImage(ctx, image, tag)
	if err != nil {
		return nil, fmt.Errorf("checking admission for %s:%s: %w", image, tag, err)
	}

	for _, v := range scanResult.Vulnerabilities {
		if strings.EqualFold(v.Severity, "critical") {
			decision.Allowed = false
			decision.Reason = fmt.Sprintf(
				"image %s:%s contains critical vulnerability %s (%s); remediate before deploying to %s",
				image, tag, v.ID, v.PackageName, namespace,
			)
			return decision, nil
		}
	}

	for _, mc := range scanResult.Misconfigurations {
		decision.Warnings = append(decision.Warnings,
			fmt.Sprintf("misconfiguration %s: %s", mc.ID, mc.Title),
		)
	}

	return decision, nil
}

// runTrivy executes the trivy binary with the given arguments and returns stdout.
// Returns a descriptive error when Trivy is not found in PATH.
func (t *trivyScanner) runTrivy(ctx context.Context, args ...string) ([]byte, error) {
	cmd := t.execCommand(ctx, "trivy", args...)
	out, err := cmd.Output()
	if err != nil {
		var execErr *exec.Error
		if errors.As(err, &execErr) && errors.Is(execErr.Err, exec.ErrNotFound) {
			return nil, fmt.Errorf("trivy binary not found in PATH: install Trivy (https://aquasecurity.github.io/trivy/latest/getting-started/installation/)")
		}
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return nil, fmt.Errorf("running trivy %s: exit %d: %s", strings.Join(args, " "), exitErr.ExitCode(), string(exitErr.Stderr))
		}
		return nil, fmt.Errorf("running trivy %s: %w", strings.Join(args, " "), err)
	}
	return out, nil
}

func (t *trivyScanner) calcCompliance(result *ImageScanResult) ComplianceResult {
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

func (t *trivyScanner) determineStatus(result *ImageScanResult) string {
	for _, v := range result.Vulnerabilities {
		if strings.EqualFold(v.Severity, "critical") {
			return statusFailed
		}
	}
	if len(result.Secrets) > 0 {
		return statusFailed
	}
	for _, mc := range result.Misconfigurations {
		if strings.EqualFold(mc.Severity, "high") || strings.EqualFold(mc.Severity, "critical") {
			return statusFailed
		}
	}
	if result.Compliance.Score < 70 {
		return "warning"
	}
	return "passed"
}
