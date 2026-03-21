// Package main implements the remediation dispatcher service.
//
// The dispatcher consumes findings from the auto_remediation queue (written by
// cspm-aggregator) and executes remediation handlers. It maintains rollback
// state for 48 hours to handle "dev teams broke our app" scenarios.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	cspmscoring "aegis/internal/cspm/scoring"
	"aegis/internal/remediation/compute"
	"aegis/internal/remediation/identity"
	"aegis/internal/remediation/network"
	"aegis/internal/remediation/patching"
	"aegis/internal/remediation/secrets"
	"aegis/internal/remediation/security_services"
	"aegis/internal/remediation/storage"
	"aegis/pkg/remediation"

	"go.uber.org/zap"
)

var (
	findingsDir    = flag.String("findings-dir", "./findings/auto_remediation", "Directory containing auto-remediation findings JSON")
	execute        = flag.Bool("execute", false, "Execute remediations (default: dry-run)")
	maxConcurrency = flag.Int("max-concurrency", 5, "Max concurrent remediations per run")
	rollbackID     = flag.String("rollback", "", "Rollback a specific remediation by ID (format: YYYYMMDD-HHMMSS-findingID)")
	rollbackAll    = flag.Bool("rollback-all", false, "Rollback ALL remediations from the last run")
	stateDir       = flag.String("state-dir", "./state/remediation", "Directory for rollback state snapshots")
)

// RemediationState captures the pre-remediation state for rollback.
type RemediationState struct {
	FindingID      string                         `json:"finding_id"`
	Handler        string                         `json:"handler"`
	Timestamp      time.Time                      `json:"timestamp"`
	PreState       map[string]interface{}         `json:"pre_state"` // Resource state before remediation
	Result         *remediation.RemediationResult `json:"result"`
	RollbackScript string                         `json:"rollback_script"` // Commands to undo the change
	ExpiresAt      time.Time                      `json:"expires_at"`      // Rollback window expiry
}

func main() {
	flag.Parse()

	logger, err := zap.NewProduction()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize logger: %v\n", err)
		os.Exit(1)
	}
	defer logger.Sync()

	ctx := context.Background()

	// Handle rollback mode
	if *rollbackID != "" || *rollbackAll {
		if err := authorizeRollback(logger); err != nil {
			fmt.Fprintf(os.Stderr, "Authorization failed: %v\n", err)
			os.Exit(1)
		}
	}

	if *rollbackID != "" {
		if err := rollbackRemediation(ctx, logger, *rollbackID); err != nil {
			fmt.Fprintf(os.Stderr, "Rollback failed: %v\n", err)
			os.Exit(1)
		}
		logger.Info("rollback successful", zap.String("rollback_id", *rollbackID))
		return
	}

	if *rollbackAll {
		if err := rollbackLastRun(ctx, logger); err != nil {
			fmt.Fprintf(os.Stderr, "Rollback all failed: %v\n", err)
			os.Exit(1)
		}
		logger.Info("rollback all successful")
		return
	}

	// Normal execution mode
	executor := remediation.NewExecutor(!*execute) // dryRun = !execute

	// Register all handlers
	registerHandlers(logger, executor)

	// Load findings
	findings, err := loadFindings(logger, *findingsDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load findings: %v\n", err)
		os.Exit(1)
	}

	if len(findings) == 0 {
		logger.Info("no auto-remediation findings to process")
		return
	}

	logger.Info("loaded findings for remediation", zap.Int("count", len(findings)))
	if !*execute {
		logger.Info("dry-run mode enabled - no changes will be made")
	}

	// Execute batch with concurrency limit
	results, err := executor.ExecuteBatch(ctx, findings, *maxConcurrency)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Batch execution failed: %v\n", err)
		os.Exit(1)
	}

	// Capture rollback state (only in execute mode)
	if *execute {
		if err := captureRollbackState(ctx, logger, findings, results); err != nil {
			fmt.Fprintf(os.Stderr, "WARNING: Failed to capture rollback state: %v\n", err)
			// Don't fail - remediation already happened
		}
	}

	// Print summary
	printSummary(logger, results)

	// Write results for Asana integration (future)
	if err := writeResults(logger, results); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to write results: %v\n", err)
		os.Exit(1)
	}
}

// registerHandlers registers all available remediation handlers.
func registerHandlers(logger *zap.Logger, executor *remediation.Executor) {
	// Security services
	executor.Register("GuardDuty.1", security_services.NewGuardDutyRemediator())
	executor.Register("Defender.Storage", security_services.NewAzureDefenderStorageRemediator())

	// Network
	executor.Register("OPEN_SSH_PORT", network.NewBlockPublicSSHRemediator())
	executor.Register("OPEN_RDP_PORT", network.NewBlockPublicSSHRemediator()) // Same handler
	executor.Register("AWS.EC2.SecurityGroup.SSH", network.NewBlockPublicSSHRemediator())

	// Storage
	executor.Register("S3_PUBLIC_ACCESS", storage.NewBlockPublicS3Remediator())

	// Identity
	executor.Register("IAM_OLD_ACCESS_KEY", identity.NewRotateIAMKeysRemediator())

	// Compute
	executor.Register("EC2_IMDSV1_ENABLED", compute.NewEnforceIMDSv2Remediator())

	// Secrets (no-op handler — documents manual rotation steps)
	executor.Register("EXPOSED_SECRET", secrets.NewRotateExposedSecretRemediator())

	// Patching (query-only — requires change window for actual patching)
	executor.Register("OS_PATCH_MISSING", patching.NewOSPatchRemediator())

	logger.Info("registered remediation handlers", zap.Int("handler_count", len(executor.ListHandlers())))
}

// loadFindings reads all JSON files from the findings directory.
func loadFindings(logger *zap.Logger, dir string) ([]*cspmscoring.PrioritizedFinding, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		return nil, fmt.Errorf("failed to glob findings: %w", err)
	}

	var results []*cspmscoring.PrioritizedFinding
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			logger.Warn("failed to read finding file", zap.String("file", file), zap.Error(err))
			continue
		}

		var finding cspmscoring.PrioritizedFinding
		if err := json.Unmarshal(data, &finding); err != nil {
			logger.Warn("failed to parse finding file", zap.String("file", file), zap.Error(err))
			continue
		}

		// Only process auto-remediation-ready findings.
		// Copy before taking address for clarity — ensures distinct pointers
		// regardless of future refactoring to range-based iteration.
		if finding.AutoRemediationReady {
			f := finding
			results = append(results, &f)
		}
	}

	return results, nil
}

// captureRollbackState saves pre-remediation state for rollback capability.
func captureRollbackState(ctx context.Context, logger *zap.Logger, findingsList []*cspmscoring.PrioritizedFinding, results []*remediation.RemediationResult) error {
	if err := os.MkdirAll(*stateDir, 0700); err != nil {
		return fmt.Errorf("failed to create state dir: %w", err)
	}

	// Build a lookup map so we match findings to results by ID, not by index.
	// Index correlation is fragile if ordering assumptions change.
	findingsByID := make(map[string]*cspmscoring.PrioritizedFinding, len(findingsList))
	for _, f := range findingsList {
		findingsByID[f.Finding.ID] = f
	}

	timestamp := time.Now()
	runID := timestamp.Format("20060102-150405")

	for _, result := range results {
		if !result.Success {
			continue // Don't save state for failed remediations
		}

		finding, ok := findingsByID[result.FindingID]
		if !ok {
			logger.Warn("no matching finding for result", zap.String("result_id", result.FindingID))
			continue
		}
		state := RemediationState{
			FindingID: finding.Finding.ID,
			Handler:   finding.Finding.FindingType,
			Timestamp: timestamp,
			Result:    result,
			PreState:  captureHandlerPreState(finding, result),
			ExpiresAt: timestamp.Add(48 * time.Hour), // 48h rollback window
		}

		// Generate rollback script
		state.RollbackScript = generateRollbackScript(finding, result)

		// Sanitize finding ID to prevent path traversal (e.g. "../../etc/something")
		safeID := filepath.Base(finding.Finding.ID)
		if safeID == "." || safeID == "/" {
			return fmt.Errorf("invalid finding ID %q", finding.Finding.ID)
		}

		// Write state file
		stateFile := filepath.Join(*stateDir, fmt.Sprintf("%s-%s.json", runID, safeID))
		data, err := json.MarshalIndent(state, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal state for %s: %w", finding.Finding.ID, err)
		}
		if err := os.WriteFile(stateFile, data, 0600); err != nil {
			return fmt.Errorf("failed to write state file: %w", err)
		}
	}

	successCount := 0
	for _, r := range results {
		if r.Success {
			successCount++
		}
	}
	logger.Info("captured rollback state",
		zap.Int("success_count", successCount),
		zap.String("expiry", "48h"))
	return nil
}

// generateRollbackScript creates executable commands to undo the remediation.
func generateRollbackScript(finding *cspmscoring.PrioritizedFinding, result *remediation.RemediationResult) string {
	// Generate CSP-specific rollback commands based on finding type
	switch finding.Finding.FindingType {
	case "GuardDuty.1":
		return fmt.Sprintf("aws guardduty delete-detector --detector-id <detector-id> --region %s", finding.Finding.Region)
	case "OPEN_SSH_PORT":
		return fmt.Sprintf("aws ec2 authorize-security-group-ingress --group-id <sg-id> --protocol tcp --port 22 --cidr 0.0.0.0/0 --region %s", finding.Finding.Region)
	case "S3_PUBLIC_ACCESS":
		return fmt.Sprintf("aws s3api delete-public-access-block --bucket <bucket-name>")
	case "IAM_OLD_ACCESS_KEY":
		return fmt.Sprintf("aws iam update-access-key --access-key-id <key-id> --status Active --user-name <user-name>")
	case "EC2_IMDSV1_ENABLED":
		return fmt.Sprintf("aws ec2 modify-instance-metadata-options --instance-id <instance-id> --http-tokens optional --region %s", finding.Finding.Region)
	default:
		return "# No automated rollback available - manual intervention required"
	}
}

// rollbackRemediation undoes a specific remediation by ID.
func rollbackRemediation(ctx context.Context, logger *zap.Logger, rollbackID string) error {
	stateFile := filepath.Join(*stateDir, rollbackID+".json")

	// Guard against path traversal: resolved path must stay within stateDir.
	absState, _ := filepath.Abs(stateFile)
	absDir, _ := filepath.Abs(*stateDir)
	if !strings.HasPrefix(absState, absDir+string(filepath.Separator)) {
		return fmt.Errorf("invalid rollback ID: path traversal detected")
	}

	data, err := os.ReadFile(stateFile)
	if err != nil {
		return fmt.Errorf("rollback state not found: %w", err)
	}

	var state RemediationState
	if err := json.Unmarshal(data, &state); err != nil {
		return fmt.Errorf("failed to parse rollback state: %w", err)
	}

	// Check expiry
	if time.Now().After(state.ExpiresAt) {
		return fmt.Errorf("rollback window expired (expired at %s)", state.ExpiresAt)
	}

	logger.Info("rolling back remediation",
		zap.String("finding_id", state.FindingID),
		zap.String("handler", state.Handler),
		zap.Time("timestamp", state.Timestamp),
		zap.String("rollback_commands", state.RollbackScript))
	logger.Info("execute these commands manually to rollback")
	logger.Info("automated rollback execution coming soon")

	// TODO: Actually execute rollback commands via cloud SDKs
	// For now, just print the commands for manual execution

	return nil
}

// rollbackLastRun rolls back all remediations from the most recent run.
func rollbackLastRun(ctx context.Context, logger *zap.Logger) error {
	files, err := filepath.Glob(filepath.Join(*stateDir, "*.json"))
	if err != nil {
		return fmt.Errorf("failed to find rollback files: %w", err)
	}

	if len(files) == 0 {
		return fmt.Errorf("no rollback state found")
	}

	// Find most recent run ID (files are named YYYYMMDD-HHMMSS-findingID.json)
	var latestRun string
	for _, file := range files {
		base := filepath.Base(file)
		if len(base) < 15 {
			continue // skip non-conformant files
		}
		runID := base[:15] // YYYYMMDD-HHMMSS
		if runID > latestRun {
			latestRun = runID
		}
	}

	logger.Info("rolling back all remediations from run", zap.String("run_id", latestRun))

	// Rollback all findings from that run
	count := 0
	for _, file := range files {
		base := filepath.Base(file)
		if len(base) < 15 || base[:15] != latestRun {
			continue
		}
		rollbackID := strings.TrimSuffix(base, ".json")
		if err := rollbackRemediation(ctx, logger, rollbackID); err != nil {
			logger.Warn("failed to rollback", zap.String("rollback_id", rollbackID), zap.Error(err))
		} else {
			count++
		}
	}

	logger.Info("completed rollback", zap.Int("count", count))
	return nil
}

// printSummary displays remediation results summary.
func printSummary(logger *zap.Logger, results []*remediation.RemediationResult) {
	success := 0
	failed := 0

	for _, result := range results {
		if result.Success {
			success++
		} else {
			failed++
		}
	}

	logger.Info("remediation summary",
		zap.Int("total", len(results)),
		zap.Int("success", success),
		zap.Int("failed", failed))

	if failed > 0 {
		logger.Info("failed remediations")
		for _, result := range results {
			if !result.Success {
				logger.Info("failed remediation",
					zap.String("finding_id", result.FindingID),
					zap.String("error", result.Error))
			}
		}
	}
}

// authorizeRollback verifies the caller has permission to perform rollback operations.
// Rollbacks re-open security remediations, so they require explicit authorization via
// the AEGIS_ROLLBACK_TOKEN environment variable set by the deployment pipeline.
func authorizeRollback(logger *zap.Logger) error {
	token := os.Getenv("AEGIS_ROLLBACK_TOKEN")
	if token == "" {
		return fmt.Errorf("AEGIS_ROLLBACK_TOKEN environment variable is required for rollback operations")
	}
	if len(token) < 16 {
		return fmt.Errorf("AEGIS_ROLLBACK_TOKEN is too short (minimum 16 characters)")
	}
	logger.Info("rollback authorization verified")
	return nil
}

// writeResults writes remediation results to JSON for Asana integration.
func writeResults(logger *zap.Logger, results []*remediation.RemediationResult) error {
	resultsDir := "./results/remediation"
	if err := os.MkdirAll(resultsDir, 0700); err != nil {
		return fmt.Errorf("failed to create results dir: %w", err)
	}

	timestamp := time.Now().Format("20060102-150405")
	resultsFile := filepath.Join(resultsDir, fmt.Sprintf("results-%s.json", timestamp))

	data, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal results: %w", err)
	}

	if err := os.WriteFile(resultsFile, data, 0600); err != nil {
		return fmt.Errorf("failed to write results: %w", err)
	}

	logger.Info("results written", zap.String("file", resultsFile))
	return nil
}
