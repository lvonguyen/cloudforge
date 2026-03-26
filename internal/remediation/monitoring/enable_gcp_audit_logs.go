package monitoring

import (
	"context"
	"fmt"
	"strings"
	"time"

	cspmscoring "aegis/internal/cspm/scoring"
	"aegis/pkg/remediation"
)

// gcpAuditAPI defines the GCP operations used by this remediator.
type gcpAuditAPI interface {
	GetAuditLogConfig(ctx context.Context, projectID string) (*GCPAuditConfig, error)
	SetAuditLogConfig(ctx context.Context, projectID string, config *GCPAuditConfig) error
}

// GCPAuditConfig represents the audit logging configuration for a GCP project.
type GCPAuditConfig struct {
	ProjectID       string   `json:"project_id"`
	DataAccessLogs  bool     `json:"data_access_logs"`
	AdminReadLogs   bool     `json:"admin_read_logs"`
	DataReadLogs    bool     `json:"data_read_logs"`
	DataWriteLogs   bool     `json:"data_write_logs"`
	ExemptedMembers []string `json:"exempted_members"`
}

// EnableGCPAuditLogsRemediator enables comprehensive audit logging on GCP projects.
//
// Finding Types: GCP_AUDIT_LOGS_DISABLED, GCP.AUDIT_LOGGING
// Tier: 1 (Auto-safe — enabling audit logs has no destructive side effects)
// Impact: Enables Data Access audit logs (ADMIN_READ, DATA_READ, DATA_WRITE)
// CSPs: GCP
type EnableGCPAuditLogsRemediator struct {
	tier   int
	client gcpAuditAPI
}

// WithGCPAuditClient injects a custom GCP audit client (used in tests).
func WithGCPAuditClient(c gcpAuditAPI) func(*EnableGCPAuditLogsRemediator) {
	return func(r *EnableGCPAuditLogsRemediator) {
		r.client = c
	}
}

// NewEnableGCPAuditLogsRemediator creates a new handler for enabling GCP audit logs.
func NewEnableGCPAuditLogsRemediator(opts ...func(*EnableGCPAuditLogsRemediator)) *EnableGCPAuditLogsRemediator {
	r := &EnableGCPAuditLogsRemediator{tier: 1}
	for _, o := range opts {
		o(r)
	}
	return r
}

// Tier returns the complexity tier (1 = auto-safe).
func (g *EnableGCPAuditLogsRemediator) Tier() int {
	return g.tier
}

// Remediate enables all audit log types on the GCP project.
func (g *EnableGCPAuditLogsRemediator) Remediate(ctx context.Context, finding *cspmscoring.PrioritizedFinding) (*remediation.RemediationResult, error) {
	startTime := time.Now()
	result := &remediation.RemediationResult{
		FindingID:  finding.Finding.ID,
		ResourceID: finding.Finding.ResourceID,
		StartedAt:  startTime,
		Actions:    []string{},
	}

	if g.client == nil {
		return nil, fmt.Errorf("GCP audit client not configured")
	}

	projectID := extractGCPProjectID(finding.Finding.ResourceID)
	newConfig := &GCPAuditConfig{
		ProjectID:      projectID,
		DataAccessLogs: true,
		AdminReadLogs:  true,
		DataReadLogs:   true,
		DataWriteLogs:  true,
	}

	err := g.client.SetAuditLogConfig(ctx, projectID, newConfig)
	if err != nil {
		result.CompletedAt = time.Now()
		result.Duration = time.Since(startTime).String()
		result.Error = err.Error()
		return result, fmt.Errorf("enabling audit logs on project %s: %w", projectID, err)
	}

	result.Actions = append(result.Actions,
		fmt.Sprintf("Enabled ADMIN_READ audit logs on project: %s", projectID),
		"Enabled DATA_READ audit logs",
		"Enabled DATA_WRITE audit logs",
	)
	result.CompletedAt = time.Now()
	result.Duration = time.Since(startTime).String()
	result.Success = true
	result.Message = fmt.Sprintf("GCP audit logging enabled on project: %s", projectID)
	return result, nil
}

// Validate verifies that audit logging is fully enabled.
func (g *EnableGCPAuditLogsRemediator) Validate(ctx context.Context, finding *cspmscoring.PrioritizedFinding) (*remediation.ValidationResult, error) {
	validation := &remediation.ValidationResult{
		FindingID:   finding.Finding.ID,
		ValidatedAt: time.Now(),
		Evidence:    []string{},
	}

	if g.client == nil {
		return nil, fmt.Errorf("GCP audit client not configured")
	}

	projectID := extractGCPProjectID(finding.Finding.ResourceID)
	config, err := g.client.GetAuditLogConfig(ctx, projectID)
	if err != nil {
		return nil, fmt.Errorf("getting audit config for project %s: %w", projectID, err)
	}

	if !config.AdminReadLogs || !config.DataReadLogs || !config.DataWriteLogs {
		validation.IsCompliant = false
		validation.Message = fmt.Sprintf("Audit logs not fully enabled on project: %s", projectID)
		validation.Evidence = append(validation.Evidence,
			fmt.Sprintf("ADMIN_READ=%t, DATA_READ=%t, DATA_WRITE=%t",
				config.AdminReadLogs, config.DataReadLogs, config.DataWriteLogs),
		)
		return validation, nil
	}

	validation.IsCompliant = true
	validation.Message = fmt.Sprintf("All audit log types enabled on project: %s", projectID)
	validation.Evidence = append(validation.Evidence, "ADMIN_READ, DATA_READ, DATA_WRITE all enabled")
	return validation, nil
}

// DryRun simulates enabling audit logs without making changes.
func (g *EnableGCPAuditLogsRemediator) DryRun(ctx context.Context, finding *cspmscoring.PrioritizedFinding) (*remediation.DryRunResult, error) {
	projectID := extractGCPProjectID(finding.Finding.ResourceID)
	return &remediation.DryRunResult{
		FindingID:        finding.Finding.ID,
		WouldSucceed:     true,
		PrerequisitesMet: g.client != nil,
		PlannedActions: []string{
			fmt.Sprintf("Would enable ADMIN_READ, DATA_READ, DATA_WRITE audit logs on project: %s", projectID),
		},
		EstimatedImpact: "No downtime. Increases Cloud Logging volume and associated storage costs. Estimate: $0.50/GB ingested.",
	}, nil
}

func extractGCPProjectID(resourceID string) string {
	// Handle "projects/my-project" format
	if strings.HasPrefix(resourceID, "projects/") {
		parts := strings.SplitN(resourceID, "/", 3)
		if len(parts) >= 2 {
			return parts[1]
		}
	}
	return resourceID
}
