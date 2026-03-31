package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
	"unicode"

	"aegis/internal/ai"

	"go.uber.org/zap"
	"golang.org/x/text/unicode/norm"
)

// enrichmentResponse is the expected JSON structure from the AI model.
type enrichmentResponse struct {
	Description   string   `json:"description"`
	Remediation   string   `json:"remediation"`
	Likelihood    string   `json:"likelihood"`
	MITRETactics  []string `json:"mitre_tactics,omitempty"`
	Confidence    float64  `json:"confidence"`
	Validated     bool     `json:"validated"`
	RiskNarrative string   `json:"risk_narrative,omitempty"`
}

const enrichSystemPrompt = `You are a senior cloud security analyst. Given an attack path through cloud infrastructure, provide:
1. A concise human-readable narrative of how the attack would progress
2. Prioritized remediation recommendations
3. Estimated real-world exploit likelihood (low, medium, or high)
4. A confidence score (0.0-1.0) for how plausible this attack path is in practice
5. Whether this path is validated as realistic (true/false)
6. A brief business-impact risk narrative (1-2 sentences)

Respond ONLY with valid JSON matching this schema:
{"description":"...","remediation":"...","likelihood":"low|medium|high","mitre_tactics":["..."],"confidence":0.85,"validated":true,"risk_narrative":"..."}`

// enrichAttackPaths enriches attack paths with AI-generated descriptions.
// Top-10 critical paths use TierPremium (Opus 4.6), remainder use TierFast (Sonnet 4.6).
// Paths are processed in batches of 5 with a 300ms delay between batches.
// Failures (including ErrBudgetExhausted) are logged and skipped — static heuristic data preserved.
func enrichAttackPaths(ctx context.Context, provider ai.Provider, paths []AttackPath, mu *sync.RWMutex, logger *zap.Logger) {
	if len(paths) == 0 {
		return
	}

	const batchSize = 5
	const batchDelay = 300 * time.Millisecond
	enriched := 0

	// Determine if provider supports tiered routing
	router, hasRouter := provider.(*ai.RoutingProvider)

	for i := 0; i < len(paths); i += batchSize {
		end := i + batchSize
		if end > len(paths) {
			end = len(paths)
		}

		for j := i; j < end; j++ {
			if ctx.Err() != nil {
				logger.Warn("Attack path enrichment cancelled", zap.Int("enriched", enriched), zap.Int("total", len(paths)))
				return
			}

			// Top-10 critical paths use Opus; rest use Sonnet
			var result *enrichmentResponse
			var err error
			if hasRouter && j < 10 && paths[j].Severity == "CRITICAL" {
				result, err = fetchEnrichmentWithTier(ctx, router, ai.TierPremium, &paths[j])
			} else {
				result, err = fetchEnrichment(ctx, provider, &paths[j])
			}

			if err != nil {
				if errors.Is(err, ai.ErrBudgetExhausted) {
					logger.Warn("AI budget exhausted, stopping enrichment",
						zap.Int("enriched", enriched),
						zap.Int("remaining", len(paths)-j),
					)
					return
				}
				logger.Warn("Failed to enrich attack path",
					zap.String("path_id", paths[j].ID),
					zap.Error(err),
				)
				continue
			}

			mu.Lock()
			applyEnrichment(&paths[j], result)
			mu.Unlock()
			enriched++
		}

		// Delay between batches to respect rate limits
		if end < len(paths) {
			select {
			case <-ctx.Done():
				return
			case <-time.After(batchDelay):
			}
		}
	}

	logger.Info("Attack path enrichment complete", zap.Int("enriched", enriched), zap.Int("total", len(paths)))
}

// fetchEnrichmentWithTier calls a specific tier on the routing provider.
func fetchEnrichmentWithTier(ctx context.Context, router *ai.RoutingProvider, tier ai.ModelTier, path *AttackPath) (*enrichmentResponse, error) {
	callCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	prompt := buildEnrichmentPrompt(path)

	response, err := router.CompleteWithTier(callCtx, tier, enrichSystemPrompt, prompt)
	if err != nil {
		return nil, fmt.Errorf("AI tier %d call failed: %w", tier, err)
	}

	return parseEnrichmentResponse(response)
}

// fetchEnrichment calls the AI provider and returns the parsed result without
// mutating the path. The caller is responsible for applying under lock.
func fetchEnrichment(ctx context.Context, provider ai.Provider, path *AttackPath) (*enrichmentResponse, error) {
	callCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	prompt := buildEnrichmentPrompt(path)

	response, err := provider.CompleteWithSystem(callCtx, enrichSystemPrompt, prompt)
	if err != nil {
		return nil, fmt.Errorf("AI call failed: %w", err)
	}

	return parseEnrichmentResponse(response)
}

// applyEnrichment writes AI results to the path. Must be called under write lock.
func applyEnrichment(path *AttackPath, result *enrichmentResponse) {
	path.AIDescription = result.Description
	path.AIRemediation = result.Remediation
	path.AILikelihood = result.Likelihood
	path.AIConfidence = result.Confidence
	path.AIValidated = result.Validated
	path.AIRiskNarrative = result.RiskNarrative
	path.AIEnriched = true

	// Flag low-confidence paths for frontend filtering
	if result.Confidence < 0.3 {
		path.LowConfidence = true
	}

	if len(result.MITRETactics) > 0 {
		existing := make(map[string]bool, len(path.MITRETactics))
		for _, t := range path.MITRETactics {
			existing[t] = true
		}
		for _, t := range result.MITRETactics {
			if !existing[t] {
				path.MITRETactics = append(path.MITRETactics, t)
			}
		}
	}
}

// sanitizeForPrompt strips control characters and truncates to maxLen.
// Prevents prompt injection via user-controlled resource names/types.
func sanitizeForPrompt(s string, maxLen int) string {
	s = norm.NFKC.String(s)
	var b strings.Builder
	for _, r := range s {
		if r < 32 || r == 127 {
			continue
		}
		if unicode.Is(unicode.Cf, r) {
			continue
		}
		if r != ' ' && unicode.Is(unicode.Zs, r) {
			b.WriteRune(' ')
			continue
		}
		b.WriteRune(r)
	}
	result := b.String()
	runes := []rune(result)
	if len(runes) > maxLen {
		runes = runes[:maxLen]
	}
	return string(runes)
}

func buildEnrichmentPrompt(path *AttackPath) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("Attack Path: %s\nSeverity: %s, Score: %.0f, Hops: %d\n\n",
		sanitizeForPrompt(path.Title, 128), sanitizeForPrompt(path.Severity, 16), path.Score, path.HopCount))

	sb.WriteString("Entry Point:\n")
	writeNodeSummary(&sb, &path.EntryPoint)

	sb.WriteString("\nTarget:\n")
	writeNodeSummary(&sb, &path.Target)

	if len(path.Nodes) > 2 {
		sb.WriteString("\nIntermediate Nodes:\n")
		for i := 1; i < len(path.Nodes)-1; i++ {
			writeNodeSummary(&sb, &path.Nodes[i])
		}
	}

	sb.WriteString("\nEdge Types: ")
	for i, e := range path.Edges {
		if i > 0 {
			sb.WriteString(" → ")
		}
		label := sanitizeForPrompt(e.Label, 64)
		if label == "" {
			label = "unknown"
		}
		sb.WriteString(label)
	}
	sb.WriteString("\n")

	if len(path.MITRETactics) > 0 {
		tactics := sanitizePromptFields(path.MITRETactics, 64)
		if len(tactics) > 0 {
			sb.WriteString("\nCurrent MITRE Tactics: " + strings.Join(tactics, ", ") + "\n")
		}
	}

	return sb.String()
}

func sanitizePromptFields(values []string, maxLen int) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		cleaned := sanitizeForPrompt(value, maxLen)
		if cleaned == "" {
			continue
		}
		result = append(result, cleaned)
	}
	return result
}

func writeNodeSummary(sb *strings.Builder, node *AttackPathNode) {
	sb.WriteString(fmt.Sprintf("  - %s (%s, %s) | %s/%s | %s | %s\n",
		sanitizeForPrompt(node.ResourceName, 128),
		sanitizeForPrompt(node.ResourceType, 64),
		sanitizeForPrompt(node.Category, 64),
		sanitizeForPrompt(node.Provider, 64),
		sanitizeForPrompt(node.Region, 64),
		sanitizeForPrompt(node.Severity, 16),
		sanitizeForPrompt(node.AccountID, 32)))
}

func parseEnrichmentResponse(response string) (*enrichmentResponse, error) {
	// Try direct parse first
	var result enrichmentResponse
	if err := json.Unmarshal([]byte(response), &result); err == nil {
		return validateEnrichment(&result)
	}

	// Extract JSON from markdown code blocks or surrounding text
	jsonStart := strings.Index(response, "{")
	jsonEnd := strings.LastIndex(response, "}")
	if jsonStart == -1 || jsonEnd == -1 || jsonEnd <= jsonStart {
		return nil, fmt.Errorf("no JSON found in AI response")
	}

	if err := json.Unmarshal([]byte(response[jsonStart:jsonEnd+1]), &result); err != nil {
		return nil, fmt.Errorf("parsing extracted JSON: %w", err)
	}

	return validateEnrichment(&result)
}

func validateEnrichment(r *enrichmentResponse) (*enrichmentResponse, error) {
	if r.Description == "" {
		return nil, fmt.Errorf("missing description in enrichment response")
	}

	// Normalize likelihood to expected values
	switch strings.ToLower(r.Likelihood) {
	case "low", "medium", "high":
		r.Likelihood = strings.ToLower(r.Likelihood)
	default:
		r.Likelihood = "medium"
	}

	// Clamp confidence to 0-1
	if r.Confidence < 0 {
		r.Confidence = 0
	}
	if r.Confidence > 1 {
		r.Confidence = 1
	}

	return r, nil
}
