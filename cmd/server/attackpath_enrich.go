package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"cloudforge/internal/ai"

	"go.uber.org/zap"
)

// enrichmentResponse is the expected JSON structure from the AI model.
type enrichmentResponse struct {
	Description  string   `json:"description"`
	Remediation  string   `json:"remediation"`
	Likelihood   string   `json:"likelihood"`
	MITRETactics []string `json:"mitre_tactics,omitempty"`
}

const enrichSystemPrompt = `You are a senior cloud security analyst. Given an attack path through cloud infrastructure, provide:
1. A concise human-readable narrative of how the attack would progress
2. Prioritized remediation recommendations
3. Estimated real-world exploit likelihood (low, medium, or high)

Respond ONLY with valid JSON matching this schema:
{"description":"...","remediation":"...","likelihood":"low|medium|high","mitre_tactics":["..."]}`

// enrichAttackPaths enriches attack paths with AI-generated descriptions.
// Paths are processed in batches of 5 with a 300ms delay between batches.
// Failures are logged and skipped — the static heuristic data is preserved.
func enrichAttackPaths(ctx context.Context, provider ai.Provider, paths []AttackPath, logger *zap.Logger) {
	if len(paths) == 0 {
		return
	}

	const batchSize = 5
	const batchDelay = 300 * time.Millisecond
	enriched := 0

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

			if err := enrichSinglePath(ctx, provider, &paths[j]); err != nil {
				logger.Warn("Failed to enrich attack path",
					zap.String("path_id", paths[j].ID),
					zap.Error(err),
				)
				continue
			}
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

func enrichSinglePath(ctx context.Context, provider ai.Provider, path *AttackPath) error {
	callCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	prompt := buildEnrichmentPrompt(path)

	response, err := provider.CompleteWithSystem(callCtx, enrichSystemPrompt, prompt)
	if err != nil {
		return fmt.Errorf("AI call failed: %w", err)
	}

	result, err := parseEnrichmentResponse(response)
	if err != nil {
		return fmt.Errorf("parsing AI response: %w", err)
	}

	path.AIDescription = result.Description
	path.AIRemediation = result.Remediation
	path.AILikelihood = result.Likelihood
	path.AIEnriched = true

	// Merge any additional MITRE tactics from AI
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

	return nil
}

func buildEnrichmentPrompt(path *AttackPath) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("Attack Path: %s\nSeverity: %s, Score: %.0f, Hops: %d\n\n",
		path.Title, path.Severity, path.Score, path.HopCount))

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
		sb.WriteString(e.Label)
	}
	sb.WriteString("\n")

	if len(path.MITRETactics) > 0 {
		sb.WriteString("\nCurrent MITRE Tactics: " + strings.Join(path.MITRETactics, ", ") + "\n")
	}

	return sb.String()
}

func writeNodeSummary(sb *strings.Builder, node *AttackPathNode) {
	sb.WriteString(fmt.Sprintf("  - %s (%s, %s) | %s/%s | %s | %s\n",
		node.ResourceName, node.ResourceType, node.Category,
		node.Provider, node.Region, node.Severity, node.AccountID))
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

	return r, nil
}
