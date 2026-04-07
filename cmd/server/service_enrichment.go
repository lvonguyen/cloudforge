package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"aegis/internal/ai"
	"aegis/internal/cspm/threatintel"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.uber.org/zap"
	"golang.org/x/sync/singleflight"
)

// FindingEnrichment holds cached AI analysis and threat intel for a single finding.
type FindingEnrichment struct {
	FindingID       string                             `json:"finding_id"`
	RootCause       string                             `json:"root_cause"`
	Impact          string                             `json:"impact"`
	Remediation     string                             `json:"remediation"`
	RelatedControls []string                           `json:"related_controls"`
	ThreatIntel     *threatintel.ThreatIntelEnrichment `json:"threat_intel,omitempty"`
	CodeToCloud     *FindingCodeToCloud                `json:"code_to_cloud,omitempty"`
	EnrichedAt      string                             `json:"enriched_at"`
	CreatedAt       time.Time                          `json:"-"` // cache eviction timestamp
}

type FindingCodeToCloud struct {
	RepositoryURL      string `json:"repository_url,omitempty"`
	RepositoryName     string `json:"repository_name,omitempty"`
	RepositoryProvider string `json:"repository_provider,omitempty"`
	Branch             string `json:"branch,omitempty"`
	CommitSHA          string `json:"commit_sha,omitempty"`
	BuildSystem        string `json:"build_system,omitempty"`
	PipelineName       string `json:"pipeline_name,omitempty"`
	PipelineRunID      string `json:"pipeline_run_id,omitempty"`
	PipelineRunURL     string `json:"pipeline_run_url,omitempty"`
	Artifact           string `json:"artifact,omitempty"`
}

const findingEnrichSystemPrompt = `You are a cloud security analyst. Given a security finding, provide:
1. Root cause analysis
2. Business impact assessment
3. Step-by-step remediation
4. Related CIS/NIST controls

Respond ONLY with valid JSON matching this schema:
{"root_cause":"...","impact":"...","remediation":"...","related_controls":["CIS x.y","NIST SC-z"]}`

func readFindingTag(tags map[string]string, keys ...string) string {
	if len(tags) == 0 {
		return ""
	}

	normalizedKeys := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		normalizedKeys[strings.ToLower(strings.TrimSpace(key))] = struct{}{}
	}

	for key, value := range tags {
		if _, ok := normalizedKeys[strings.ToLower(strings.TrimSpace(key))]; !ok {
			continue
		}
		value = strings.TrimSpace(value)
		if value != "" {
			return value
		}
	}

	return ""
}

func inferRepositoryName(repoURL string) string {
	if repoURL == "" {
		return ""
	}

	trimmed := strings.TrimSpace(repoURL)
	trimmed = strings.TrimSuffix(trimmed, ".git")
	trimmed = strings.TrimRight(trimmed, "/")
	if strings.HasPrefix(trimmed, "git@") {
		trimmed = strings.TrimPrefix(trimmed, "git@")
		if idx := strings.Index(trimmed, ":"); idx != -1 {
			trimmed = trimmed[idx+1:]
		}
	}
	if idx := strings.Index(trimmed, "://"); idx != -1 {
		trimmed = trimmed[idx+3:]
	}
	if idx := strings.Index(trimmed, "/"); idx != -1 {
		trimmed = trimmed[idx+1:]
	}

	return strings.Trim(trimmed, "/")
}

func inferRepositoryProvider(repoURL string) string {
	switch {
	case strings.Contains(strings.ToLower(repoURL), "github"):
		return "github"
	case strings.Contains(strings.ToLower(repoURL), "gitlab"):
		return "gitlab"
	case strings.Contains(strings.ToLower(repoURL), "bitbucket"):
		return "bitbucket"
	default:
		return ""
	}
}

func hasCodeToCloudContext(ctx *FindingCodeToCloud) bool {
	if ctx == nil {
		return false
	}
	return ctx.RepositoryURL != "" ||
		ctx.RepositoryName != "" ||
		ctx.RepositoryProvider != "" ||
		ctx.Branch != "" ||
		ctx.CommitSHA != "" ||
		ctx.BuildSystem != "" ||
		ctx.PipelineName != "" ||
		ctx.PipelineRunID != "" ||
		ctx.PipelineRunURL != "" ||
		ctx.Artifact != ""
}

func extractFindingCodeToCloud(finding *Finding) *FindingCodeToCloud {
	if finding == nil {
		return nil
	}

	ctx := &FindingCodeToCloud{
		RepositoryURL: readFindingTag(
			finding.Tags,
			"repository_url", "repo_url", "repository", "repo", "scm_url", "git_repository",
			"git_url", "github_repository", "gitlab_repository",
		),
		RepositoryName: readFindingTag(
			finding.Tags,
			"repository_name", "repo_name", "service_repo", "service_repository",
		),
		RepositoryProvider: readFindingTag(
			finding.Tags,
			"repository_provider", "repo_provider", "scm_provider", "git_provider",
		),
		Branch: readFindingTag(
			finding.Tags,
			"branch", "git_branch", "repository_branch", "repo_branch", "workflow_branch",
		),
		CommitSHA: readFindingTag(
			finding.Tags,
			"commit_sha", "git_commit", "commit", "sha", "revision", "git_revision",
		),
		BuildSystem: readFindingTag(
			finding.Tags,
			"build_system", "ci_system", "cicd", "pipeline_system", "workflow_system",
		),
		PipelineName: readFindingTag(
			finding.Tags,
			"pipeline_name", "pipeline", "workflow", "workflow_name", "build_pipeline",
		),
		PipelineRunID: readFindingTag(
			finding.Tags,
			"pipeline_run_id", "run_id", "workflow_run_id", "build_id", "pipeline_execution_id",
		),
		PipelineRunURL: readFindingTag(
			finding.Tags,
			"pipeline_run_url", "pipeline_url", "run_url", "workflow_url", "build_url",
		),
		Artifact: readFindingTag(
			finding.Tags,
			"artifact", "artifact_name", "image", "image_uri", "container_image", "build_artifact",
		),
	}

	if ctx.RepositoryName == "" {
		ctx.RepositoryName = inferRepositoryName(ctx.RepositoryURL)
	}
	if ctx.RepositoryProvider == "" {
		ctx.RepositoryProvider = inferRepositoryProvider(ctx.RepositoryURL)
	}
	if !hasCodeToCloudContext(ctx) {
		return nil
	}
	return ctx
}

func parseFindingEnrichment(findingID, response string) (*FindingEnrichment, error) {
	type aiResponse struct {
		RootCause       string   `json:"root_cause"`
		Impact          string   `json:"impact"`
		Remediation     string   `json:"remediation"`
		RelatedControls []string `json:"related_controls"`
	}

	var parsed aiResponse

	// Try direct parse
	if err := json.Unmarshal([]byte(response), &parsed); err != nil {
		// Extract JSON from surrounding text
		start := strings.Index(response, "{")
		end := strings.LastIndex(response, "}")
		if start == -1 || end == -1 || end <= start {
			return nil, fmt.Errorf("no JSON in response")
		}
		if err := json.Unmarshal([]byte(response[start:end+1]), &parsed); err != nil {
			return nil, fmt.Errorf("parsing extracted JSON: %w", err)
		}
	}

	if parsed.RootCause == "" {
		return nil, fmt.Errorf("missing root_cause in response")
	}
	if parsed.Impact == "" {
		return nil, fmt.Errorf("missing impact in response")
	}
	if parsed.Remediation == "" {
		return nil, fmt.Errorf("missing remediation in response")
	}

	// Cap string field lengths to prevent unbounded LLM output in cache.
	const maxFieldLen = 2000
	parsed.RootCause = truncateField(parsed.RootCause, maxFieldLen)
	parsed.Impact = truncateField(parsed.Impact, maxFieldLen)
	parsed.Remediation = truncateField(parsed.Remediation, maxFieldLen)

	// Validate related_controls match known framework patterns.
	parsed.RelatedControls = filterValidControls(parsed.RelatedControls)

	now := time.Now().UTC()
	return &FindingEnrichment{
		FindingID:       findingID,
		RootCause:       parsed.RootCause,
		Impact:          parsed.Impact,
		Remediation:     parsed.Remediation,
		RelatedControls: parsed.RelatedControls,
		EnrichedAt:      now.Format(time.RFC3339),
		CreatedAt:       now,
	}, nil
}

const (
	// enrichmentCacheTTL is how long enrichment results are cached.
	enrichmentCacheTTL = 30 * time.Minute
	// enrichmentCacheMaxSize caps the number of cached enrichments to bound memory.
	enrichmentCacheMaxSize = 5000
)

// EnrichmentService encapsulates AI-powered finding enrichment with a
// thread-safe cache. Extracted from Server to isolate the AI provider,
// cache map, and mutex into a cohesive unit.
type EnrichmentService struct {
	AI          ai.Provider
	ThreatIntel *threatintel.Enricher // nil = threat intel disabled
	Cache       map[string]*FindingEnrichment
	Mu          sync.RWMutex
	Logger      *zap.Logger
	group       singleflight.Group
}

// Enabled returns true when AI or threat intel enrichment is available.
func (svc *EnrichmentService) Enabled() bool {
	return svc.AI != nil || svc.ThreatIntel != nil
}

// GetCached returns a cached enrichment if available and not expired.
func (svc *EnrichmentService) GetCached(id string) (*FindingEnrichment, bool) {
	svc.Mu.RLock()
	defer svc.Mu.RUnlock()
	cached, ok := svc.Cache[id]
	if ok && time.Since(cached.CreatedAt) >= enrichmentCacheTTL {
		return nil, false
	}
	return cached, ok
}

// Enrich calls AI and/or threat intel providers to analyze a finding, caching the result.
// Returns the cached result if already enriched. Concurrent calls for the
// same finding ID are deduplicated via singleflight.
func (svc *EnrichmentService) Enrich(ctx context.Context, finding *Finding) (*FindingEnrichment, error) {
	// Check cache first
	_, cacheSpan := otel.Tracer("aegis.enrichment").Start(ctx, "enrichment.cache_check")
	cached, cacheHit := svc.GetCached(finding.ID)
	cacheSpan.SetAttributes(attribute.Bool("cache.hit", cacheHit))
	cacheSpan.End()
	if cacheHit {
		return cached, nil
	}

	if svc.AI == nil && svc.ThreatIntel == nil {
		return nil, fmt.Errorf("enrichment is not enabled (no AI provider or threat intel)")
	}

	// Deduplicate concurrent requests for the same finding
	result, err, _ := svc.group.Do(finding.ID, func() (interface{}, error) {
		// Re-check cache inside singleflight (another caller may have populated it)
		if cached, ok := svc.GetCached(finding.ID); ok {
			return cached, nil
		}

		now := time.Now().UTC()
		enrichment := &FindingEnrichment{
			FindingID:   finding.ID,
			CodeToCloud: extractFindingCodeToCloud(finding),
			EnrichedAt:  now.Format(time.RFC3339),
			CreatedAt:   now,
		}

		// AI enrichment (optional — skipped when AI provider is nil)
		if svc.AI != nil {
			aiCtx, aiSpan := otel.Tracer("aegis.enrichment").Start(ctx, "enrichment.ai_call")
			defer aiSpan.End()
			callCtx, cancel := context.WithTimeout(aiCtx, 30*time.Second)
			defer cancel()

			prompt := fmt.Sprintf(`Finding: %s
Severity: %s | Category: %s | Provider: %s
Resource: %s (%s) in %s
Status: %s
Description: %s`,
				finding.Title,
				finding.Severity, finding.Category, finding.CloudProvider,
				finding.ResourceName, finding.ResourceType, finding.Region,
				finding.Status,
				finding.Remediation,
			)

			aiSpan.SetAttributes(attribute.Int("ai.input_length", len(prompt)))

			response, err := svc.AI.CompleteWithSystem(callCtx, findingEnrichSystemPrompt, prompt)
			if err != nil {
				aiSpan.RecordError(err)
				svc.Logger.Warn("AI enrichment failed, continuing with threat intel only",
					zap.String("finding_id", finding.ID), zap.Error(err))
			} else {
				aiSpan.SetAttributes(attribute.Int("ai.response_length", len(response)))

				_, parseSpan := otel.Tracer("aegis.enrichment").Start(aiCtx, "enrichment.parse")
				parsed, err := parseFindingEnrichment(finding.ID, response)
				if err != nil {
					parseSpan.RecordError(err)
					svc.Logger.Warn("parsing AI response failed",
						zap.String("finding_id", finding.ID), zap.Error(err))
				} else {
					enrichment.RootCause = parsed.RootCause
					enrichment.Impact = parsed.Impact
					enrichment.Remediation = parsed.Remediation
					enrichment.RelatedControls = parsed.RelatedControls
				}
				parseSpan.End()
			}
		}

		// Threat intel enrichment (optional — skipped when enricher is nil)
		if svc.ThreatIntel != nil {
			cves := make([]string, 0, len(finding.CVEs))
			for _, cve := range finding.CVEs {
				cves = append(cves, cve.ID)
			}

			// Extract IPs and emails from finding fields.
			ips := finding.IPs
			if len(ips) == 0 {
				ips = extractIPsFromText(finding.Description + " " + finding.ResourceID)
			}
			emails := finding.Emails

			enrichment.ThreatIntel = svc.ThreatIntel.Enrich(ctx, cves, ips, emails)
		}

		// Cache the result
		_, storeSpan := otel.Tracer("aegis.enrichment").Start(ctx, "enrichment.cache_store")
		svc.Mu.Lock()
		svc.Cache[finding.ID] = enrichment
		svc.Mu.Unlock()
		storeSpan.SetAttributes(attribute.String("finding.id", finding.ID))
		storeSpan.End()

		return enrichment, nil
	})

	if err != nil {
		return nil, err
	}
	return result.(*FindingEnrichment), nil
}

// StartEviction launches a background goroutine that periodically removes
// stale enrichment cache entries (older than enrichmentCacheTTL) and evicts
// oldest entries when the cache exceeds enrichmentCacheMaxSize.
func (svc *EnrichmentService) StartEviction(ctx context.Context, interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				svc.evictExpired()
			}
		}
	}()
}

// controlPattern matches known compliance framework references:
// CIS x.y, NIST XX-n, SOC n, ISO 27001, PCI DSS n.n, HIPAA §nnn, GDPR Art n.
var controlPattern = regexp.MustCompile(
	`^(?:CIS \d+\.\d+|NIST [A-Z]{2}-\d+|SOC \d|ISO 27\d{3}|PCI DSS \d+\.\d+|HIPAA §\d+|GDPR Art(?:icle)? \d+)`,
)

func truncateField(s string, max int) string {
	runes := []rune(s)
	if len(runes) <= max {
		return s
	}
	return string(runes[:max])
}

func filterValidControls(controls []string) []string {
	valid := make([]string, 0, len(controls))
	for _, c := range controls {
		if controlPattern.MatchString(c) {
			valid = append(valid, c)
		}
	}
	return valid
}

func (svc *EnrichmentService) evictExpired() {
	svc.Mu.Lock()
	defer svc.Mu.Unlock()

	now := time.Now()

	// Pass 1: remove entries older than TTL
	for key, entry := range svc.Cache {
		if now.Sub(entry.CreatedAt) >= enrichmentCacheTTL {
			delete(svc.Cache, key)
		}
	}

	// Pass 2: if still over max size, evict oldest until at cap
	if len(svc.Cache) > enrichmentCacheMaxSize {
		type kv struct {
			key string
			ts  time.Time
		}
		items := make([]kv, 0, len(svc.Cache))
		for k, v := range svc.Cache {
			items = append(items, kv{k, v.CreatedAt})
		}
		sort.Slice(items, func(i, j int) bool { return items[i].ts.Before(items[j].ts) })
		excess := len(svc.Cache) - enrichmentCacheMaxSize
		for i := 0; i < excess; i++ {
			delete(svc.Cache, items[i].key)
		}
	}
}

// ipv4Pattern matches IPv4 addresses in text. Avoids matching version numbers
// by requiring word boundary context.
var ipv4Pattern = regexp.MustCompile(`\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b`)

// extractIPsFromText extracts unique IPv4 addresses from text fields.
// Filters out common non-IP patterns (loopback, link-local, broadcast).
func extractIPsFromText(text string) []string {
	matches := ipv4Pattern.FindAllString(text, 50) // cap at 50 to bound allocation
	seen := make(map[string]bool, len(matches))
	var ips []string
	for _, m := range matches {
		if seen[m] {
			continue
		}
		// Validate octets are 0-255 (regex only checks digit count).
		if net.ParseIP(m) == nil {
			continue
		}
		if strings.HasPrefix(m, "127.") || strings.HasPrefix(m, "169.254.") ||
			m == "0.0.0.0" || m == "255.255.255.255" {
			continue
		}
		seen[m] = true
		ips = append(ips, m)
	}
	return ips
}
