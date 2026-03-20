package identity

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/iam"

	cspmscoring "aegis/internal/cspm/scoring"
	"aegis/pkg/remediation"
)

// excessivePermsAPI defines the IAM operations used by this remediator.
type excessivePermsAPI interface {
	ListAttachedRolePolicies(ctx context.Context, params *iam.ListAttachedRolePoliciesInput, optFns ...func(*iam.Options)) (*iam.ListAttachedRolePoliciesOutput, error)
	DetachRolePolicy(ctx context.Context, params *iam.DetachRolePolicyInput, optFns ...func(*iam.Options)) (*iam.DetachRolePolicyOutput, error)
}

// overprivilegedPolicies is the set of AWS-managed policies that are considered
// excessive when attached to service roles.
var overprivilegedPolicies = map[string]bool{
	"arn:aws:iam::aws:policy/AdministratorAccess": true,
	"arn:aws:iam::aws:policy/PowerUserAccess":     true,
	"arn:aws:iam::aws:policy/IAMFullAccess":       true,
}

// RestrictExcessivePermsRemediator detaches overly permissive IAM policies
// from service roles.
//
// Finding Types: IAM_ROLE_HAS_EXCESSIVE_PERMISSIONS, SERVICE_AGENT_GRANTED_BASIC_ROLE
// Tier: 2 (Requires verification — detaching policies may break services)
// Impact: Detaches AdministratorAccess, PowerUserAccess, IAMFullAccess from roles
// CSPs: AWS (IAM), GCP (IAM), Azure (RBAC)
type RestrictExcessivePermsRemediator struct {
	tier          int
	clientFactory func(ctx context.Context, region string) (excessivePermsAPI, error)
}

// RestrictExcessivePermsOption configures the remediator.
type RestrictExcessivePermsOption func(*RestrictExcessivePermsRemediator)

// WithExcessivePermsClient injects a custom IAM client factory (used in tests).
func WithExcessivePermsClient(factory func(ctx context.Context, region string) (excessivePermsAPI, error)) RestrictExcessivePermsOption {
	return func(r *RestrictExcessivePermsRemediator) {
		r.clientFactory = factory
	}
}

// NewRestrictExcessivePermsRemediator creates a new handler for restricting
// excessive IAM permissions on service roles.
func NewRestrictExcessivePermsRemediator(opts ...RestrictExcessivePermsOption) *RestrictExcessivePermsRemediator {
	r := &RestrictExcessivePermsRemediator{
		tier: 2,
		clientFactory: func(ctx context.Context, region string) (excessivePermsAPI, error) {
			cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
			if err != nil {
				return nil, err
			}
			return iam.NewFromConfig(cfg), nil
		},
	}
	for _, o := range opts {
		o(r)
	}
	return r
}

// Tier returns the complexity tier (2 = requires verification).
func (r *RestrictExcessivePermsRemediator) Tier() int {
	return r.tier
}

// Remediate detaches overly permissive policies from the IAM role.
func (r *RestrictExcessivePermsRemediator) Remediate(ctx context.Context, finding *cspmscoring.PrioritizedFinding) (*remediation.RemediationResult, error) {
	startTime := time.Now()

	result := &remediation.RemediationResult{
		FindingID:  finding.Finding.ID,
		ResourceID: finding.Finding.ResourceID,
		StartedAt:  startTime,
		Actions:    []string{},
	}

	switch {
	case strings.Contains(finding.Finding.Source, "aws"):
		return r.remediateAWS(ctx, finding, result)
	case strings.Contains(finding.Finding.Source, "gcp"):
		return r.remediateGCP(ctx, finding, result)
	case strings.Contains(finding.Finding.Source, "azure"):
		return r.remediateAzure(ctx, finding, result)
	default:
		result.Error = fmt.Sprintf("Unsupported CSP: %s", finding.Finding.Source)
		return result, fmt.Errorf("unsupported CSP: %s", finding.Finding.Source)
	}
}

func (r *RestrictExcessivePermsRemediator) remediateAWS(ctx context.Context, finding *cspmscoring.PrioritizedFinding, result *remediation.RemediationResult) (*remediation.RemediationResult, error) {
	client, err := r.clientFactory(ctx, finding.Finding.Region)
	if err != nil {
		return nil, fmt.Errorf("failed to create IAM client: %w", err)
	}

	roleName := extractRoleName(finding.Finding.ResourceID)

	// List attached policies
	listOutput, err := client.ListAttachedRolePolicies(ctx, &iam.ListAttachedRolePoliciesInput{
		RoleName: aws.String(roleName),
	})
	if err != nil {
		result.CompletedAt = time.Now()
		result.Duration = time.Since(result.StartedAt).String()
		result.Error = err.Error()
		return result, fmt.Errorf("failed to list policies for role %s: %w", roleName, err)
	}

	detached := 0
	for _, policy := range listOutput.AttachedPolicies {
		if policy.PolicyArn == nil {
			continue
		}
		if !overprivilegedPolicies[*policy.PolicyArn] {
			continue
		}

		_, err := client.DetachRolePolicy(ctx, &iam.DetachRolePolicyInput{
			RoleName:  aws.String(roleName),
			PolicyArn: policy.PolicyArn,
		})
		if err != nil {
			result.CompletedAt = time.Now()
			result.Duration = time.Since(result.StartedAt).String()
			result.Error = fmt.Sprintf("failed to detach policy %s: %v", *policy.PolicyArn, err)
			return result, fmt.Errorf("failed to detach policy %s from role %s: %w", *policy.PolicyArn, roleName, err)
		}

		policyName := ""
		if policy.PolicyName != nil {
			policyName = *policy.PolicyName
		}
		result.Actions = append(result.Actions,
			fmt.Sprintf("Detached %s (%s) from role: %s", policyName, *policy.PolicyArn, roleName))
		detached++
	}

	result.CompletedAt = time.Now()
	result.Duration = time.Since(result.StartedAt).String()

	if detached == 0 {
		result.Success = true
		result.Message = fmt.Sprintf("No overprivileged policies found on role: %s", roleName)
	} else {
		result.Success = true
		result.Message = fmt.Sprintf("Detached %d overprivileged policy(ies) from role: %s", detached, roleName)
	}

	return result, nil
}

func (r *RestrictExcessivePermsRemediator) remediateGCP(_ context.Context, _ *cspmscoring.PrioritizedFinding, result *remediation.RemediationResult) (*remediation.RemediationResult, error) {
	result.Message = "GCP excessive permissions remediation not yet implemented"
	result.Success = false
	return result, fmt.Errorf("GCP remediation not implemented")
}

func (r *RestrictExcessivePermsRemediator) remediateAzure(_ context.Context, _ *cspmscoring.PrioritizedFinding, result *remediation.RemediationResult) (*remediation.RemediationResult, error) {
	result.Message = "Azure excessive permissions remediation not yet implemented"
	result.Success = false
	return result, fmt.Errorf("Azure remediation not implemented")
}

// Validate verifies no overprivileged policies remain attached.
func (r *RestrictExcessivePermsRemediator) Validate(ctx context.Context, finding *cspmscoring.PrioritizedFinding) (*remediation.ValidationResult, error) {
	validation := &remediation.ValidationResult{
		FindingID:   finding.Finding.ID,
		ValidatedAt: time.Now(),
		Evidence:    []string{},
	}

	client, err := r.clientFactory(ctx, finding.Finding.Region)
	if err != nil {
		return nil, fmt.Errorf("failed to create IAM client: %w", err)
	}

	roleName := extractRoleName(finding.Finding.ResourceID)

	listOutput, err := client.ListAttachedRolePolicies(ctx, &iam.ListAttachedRolePoliciesInput{
		RoleName: aws.String(roleName),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list policies for role %s: %w", roleName, err)
	}

	overprivileged := 0
	for _, policy := range listOutput.AttachedPolicies {
		if policy.PolicyArn != nil && overprivilegedPolicies[*policy.PolicyArn] {
			overprivileged++
			validation.Evidence = append(validation.Evidence,
				fmt.Sprintf("Overprivileged policy still attached: %s", *policy.PolicyArn))
		}
	}

	if overprivileged > 0 {
		validation.IsCompliant = false
		validation.Message = fmt.Sprintf("Role %s still has %d overprivileged policy(ies)", roleName, overprivileged)
	} else {
		validation.IsCompliant = true
		validation.Message = fmt.Sprintf("Role %s has no overprivileged policies", roleName)
		validation.Evidence = append(validation.Evidence, fmt.Sprintf("Role: %s", roleName))
	}

	return validation, nil
}

// DryRun simulates detaching overprivileged policies without making changes.
func (r *RestrictExcessivePermsRemediator) DryRun(_ context.Context, finding *cspmscoring.PrioritizedFinding) (*remediation.DryRunResult, error) {
	roleName := extractRoleName(finding.Finding.ResourceID)

	dryRun := &remediation.DryRunResult{
		FindingID:        finding.Finding.ID,
		WouldSucceed:     true,
		PrerequisitesMet: true,
		PlannedActions: []string{
			fmt.Sprintf("Would list attached policies for role: %s", roleName),
			"Would detach AdministratorAccess, PowerUserAccess, IAMFullAccess if found",
		},
		EstimatedImpact: "Services using this role may lose access to resources. Ensure least-privilege policies are attached first.",
		Warnings: []string{
			"WARNING: Detaching policies may break applications relying on elevated permissions",
			"Verify replacement policies exist before executing",
		},
	}

	return dryRun, nil
}

// extractRoleName extracts the IAM role name from a resource ARN or name.
func extractRoleName(resourceID string) string {
	// Handle ARN: arn:aws:iam::123456789012:role/my-role
	if strings.Contains(resourceID, ":role/") {
		parts := strings.Split(resourceID, ":role/")
		if len(parts) > 1 {
			return parts[1]
		}
	}
	return resourceID
}
