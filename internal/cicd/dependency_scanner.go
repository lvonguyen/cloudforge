// Package cicd provides CI/CD pipeline security scanning
package cicd

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"go.uber.org/zap"
)

// DependencyScanner scans dependency files for vulnerabilities
type DependencyScanner struct {
	logger *zap.Logger
}

// DependencyScanResult represents the result of a dependency scan
type DependencyScanResult struct {
	FilePath      string              `json:"file_path"`
	FileType      string              `json:"file_type"`
	ScannedAt     time.Time           `json:"scanned_at"`
	Dependencies  []Dependency        `json:"dependencies"`
	Vulnerabilities []VulnerableDep   `json:"vulnerabilities"`
	Outdated      []OutdatedDep       `json:"outdated"`
	Summary       DepScanSummary      `json:"summary"`
}

// Dependency represents a project dependency
type Dependency struct {
	Name           string `json:"name"`
	Version        string `json:"version"`
	VersionPinned  bool   `json:"version_pinned"`
	Source         string `json:"source,omitempty"`
}

// VulnerableDep represents a vulnerable dependency
type VulnerableDep struct {
	Dependency
	CVEID       string `json:"cve_id"`
	Severity    string `json:"severity"`
	Title       string `json:"title"`
	FixedIn     string `json:"fixed_in,omitempty"`
	Reference   string `json:"reference,omitempty"`
}

// OutdatedDep represents an outdated dependency
type OutdatedDep struct {
	Dependency
	LatestVersion string `json:"latest_version"`
	UpdateType    string `json:"update_type"` // major, minor, patch
}

// DepScanSummary summarizes dependency scan results
type DepScanSummary struct {
	TotalDependencies  int `json:"total_dependencies"`
	VulnerableCount    int `json:"vulnerable_count"`
	OutdatedCount      int `json:"outdated_count"`
	UnpinnedCount      int `json:"unpinned_count"`
	CriticalVulns      int `json:"critical_vulns"`
	HighVulns          int `json:"high_vulns"`
	MediumVulns        int `json:"medium_vulns"`
	LowVulns           int `json:"low_vulns"`
}

// NewDependencyScanner creates a new dependency scanner
func NewDependencyScanner(logger *zap.Logger) *DependencyScanner {
	return &DependencyScanner{
		logger: logger,
	}
}

// Scan scans a dependency file
func (s *DependencyScanner) Scan(ctx context.Context, filePath string, content string) (*DependencyScanResult, error) {
	fileType := s.detectFileType(filePath)

	result := &DependencyScanResult{
		FilePath:       filePath,
		FileType:       fileType,
		ScannedAt:      time.Now(),
		Dependencies:   make([]Dependency, 0),
		Vulnerabilities: make([]VulnerableDep, 0),
		Outdated:       make([]OutdatedDep, 0),
	}

	switch fileType {
	case "go.mod":
		result.Dependencies = s.parseGoMod(content)
	case "package.json":
		result.Dependencies = s.parsePackageJSON(content)
	case "requirements.txt":
		result.Dependencies = s.parseRequirementsTxt(content)
	case "Gemfile":
		result.Dependencies = s.parseGemfile(content)
	case "pom.xml":
		result.Dependencies = s.parsePomXML(content)
	default:
		return nil, fmt.Errorf("unsupported dependency file type: %s", fileType)
	}

	// Check for unpinned versions
	unpinnedCount := 0
	for _, dep := range result.Dependencies {
		if !dep.VersionPinned {
			unpinnedCount++
		}
	}

	// Calculate summary
	result.Summary = DepScanSummary{
		TotalDependencies: len(result.Dependencies),
		VulnerableCount:   len(result.Vulnerabilities),
		OutdatedCount:     len(result.Outdated),
		UnpinnedCount:     unpinnedCount,
	}

	for _, v := range result.Vulnerabilities {
		switch v.Severity {
		case "critical":
			result.Summary.CriticalVulns++
		case "high":
			result.Summary.HighVulns++
		case "medium":
			result.Summary.MediumVulns++
		case "low":
			result.Summary.LowVulns++
		}
	}

	s.logger.Info("Dependency scan completed",
		zap.String("file", filePath),
		zap.Int("dependencies", len(result.Dependencies)),
		zap.Int("vulnerabilities", len(result.Vulnerabilities)),
	)

	return result, nil
}

func (s *DependencyScanner) detectFileType(filePath string) string {
	lowerPath := strings.ToLower(filePath)

	switch {
	case strings.HasSuffix(lowerPath, "go.mod"):
		return "go.mod"
	case strings.HasSuffix(lowerPath, "package.json"):
		return "package.json"
	case strings.HasSuffix(lowerPath, "requirements.txt"):
		return "requirements.txt"
	case strings.HasSuffix(lowerPath, "gemfile"):
		return "Gemfile"
	case strings.HasSuffix(lowerPath, "pom.xml"):
		return "pom.xml"
	case strings.HasSuffix(lowerPath, "cargo.toml"):
		return "Cargo.toml"
	case strings.HasSuffix(lowerPath, "build.gradle"):
		return "build.gradle"
	default:
		return "unknown"
	}
}

func (s *DependencyScanner) parseGoMod(content string) []Dependency {
	deps := make([]Dependency, 0)
	scanner := bufio.NewScanner(strings.NewReader(content))

	inRequire := false
	requirePattern := regexp.MustCompile(`^\s*require\s*\(`)
	depPattern := regexp.MustCompile(`^\s*([^\s]+)\s+v?([^\s]+)`)

	for scanner.Scan() {
		line := scanner.Text()

		if requirePattern.MatchString(line) {
			inRequire = true
			continue
		}

		if inRequire {
			if strings.TrimSpace(line) == ")" {
				inRequire = false
				continue
			}

			matches := depPattern.FindStringSubmatch(line)
			if len(matches) >= 3 {
				version := matches[2]
				deps = append(deps, Dependency{
					Name:          matches[1],
					Version:       version,
					VersionPinned: !strings.Contains(version, "latest") && !strings.HasPrefix(version, "v0.0.0"),
				})
			}
		}

		// Single line require
		if strings.HasPrefix(strings.TrimSpace(line), "require ") && !strings.Contains(line, "(") {
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				deps = append(deps, Dependency{
					Name:          parts[1],
					Version:       parts[2],
					VersionPinned: true,
				})
			}
		}
	}

	return deps
}

func (s *DependencyScanner) parsePackageJSON(content string) []Dependency {
	deps := make([]Dependency, 0)

	var pkg struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}

	if err := json.Unmarshal([]byte(content), &pkg); err != nil {
		s.logger.Warn("Failed to parse package.json", zap.Error(err))
		return deps
	}

	for name, version := range pkg.Dependencies {
		deps = append(deps, Dependency{
			Name:          name,
			Version:       version,
			VersionPinned: s.isNPMVersionPinned(version),
		})
	}

	for name, version := range pkg.DevDependencies {
		deps = append(deps, Dependency{
			Name:          name,
			Version:       version,
			VersionPinned: s.isNPMVersionPinned(version),
		})
	}

	return deps
}

func (s *DependencyScanner) isNPMVersionPinned(version string) bool {
	// Pinned versions don't have ^, ~, *, >, <, or ranges
	unpinnedPatterns := []string{"^", "~", "*", ">", "<", "||", " - "}
	for _, p := range unpinnedPatterns {
		if strings.Contains(version, p) {
			return false
		}
	}
	return true
}

func (s *DependencyScanner) parseRequirementsTxt(content string) []Dependency {
	deps := make([]Dependency, 0)
	scanner := bufio.NewScanner(strings.NewReader(content))

	depPattern := regexp.MustCompile(`^([a-zA-Z0-9_-]+)([=<>!]+)?(.+)?$`)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip comments and empty lines
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}

		matches := depPattern.FindStringSubmatch(line)
		if len(matches) >= 2 {
			version := ""
			pinned := false

			if len(matches) >= 4 {
				operator := matches[2]
				version = matches[3]
				pinned = operator == "==" // Only == is truly pinned
			}

			deps = append(deps, Dependency{
				Name:          matches[1],
				Version:       version,
				VersionPinned: pinned,
			})
		}
	}

	return deps
}

func (s *DependencyScanner) parseGemfile(content string) []Dependency {
	deps := make([]Dependency, 0)
	scanner := bufio.NewScanner(strings.NewReader(content))

	gemPattern := regexp.MustCompile(`^\s*gem\s+['"]([^'"]+)['"](?:\s*,\s*['"]([^'"]+)['"])?`)

	for scanner.Scan() {
		line := scanner.Text()

		matches := gemPattern.FindStringSubmatch(line)
		if len(matches) >= 2 {
			version := ""
			pinned := false

			if len(matches) >= 3 && matches[2] != "" {
				version = matches[2]
				// Pinned if exact version (no ~>, >=, etc.)
				pinned = !strings.Contains(version, "~>") && !strings.Contains(version, ">=") && !strings.Contains(version, ">")
			}

			deps = append(deps, Dependency{
				Name:          matches[1],
				Version:       version,
				VersionPinned: pinned,
			})
		}
	}

	return deps
}

func (s *DependencyScanner) parsePomXML(content string) []Dependency {
	deps := make([]Dependency, 0)

	// Simple regex-based parsing (a proper XML parser would be better)
	depPattern := regexp.MustCompile(`(?s)<dependency>.*?<groupId>([^<]+)</groupId>.*?<artifactId>([^<]+)</artifactId>.*?(?:<version>([^<]+)</version>)?.*?</dependency>`)

	matches := depPattern.FindAllStringSubmatch(content, -1)
	for _, match := range matches {
		if len(match) >= 3 {
			name := fmt.Sprintf("%s:%s", match[1], match[2])
			version := ""
			pinned := false

			if len(match) >= 4 && match[3] != "" {
				version = match[3]
				// Check if version is a property reference
				pinned = !strings.HasPrefix(version, "${")
			}

			deps = append(deps, Dependency{
				Name:          name,
				Version:       version,
				VersionPinned: pinned,
			})
		}
	}

	return deps
}

// CheckVulnerabilities checks dependencies against vulnerability databases
// In a real implementation, this would call OSV, NVD, or similar APIs
func (s *DependencyScanner) CheckVulnerabilities(ctx context.Context, deps []Dependency) ([]VulnerableDep, error) {
	// TODO: Implement actual vulnerability checking
	// This would integrate with:
	// - OSV (https://osv.dev)
	// - GitHub Advisory Database
	// - NVD
	// - Snyk
	
	s.logger.Info("Vulnerability check would query external databases",
		zap.Int("dependencies", len(deps)),
	)

	return []VulnerableDep{}, nil
}

