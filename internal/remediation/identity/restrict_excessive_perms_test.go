package identity

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"

	cspmscoring "aegis/internal/cspm/scoring"
)

func makeExcessivePermsFinding(id, source, resourceID string) *cspmscoring.PrioritizedFinding {
	return &cspmscoring.PrioritizedFinding{
		Finding: &cspmscoring.Finding{
			ID:          id,
			Source:      source,
			Severity:    "CRITICAL",
			FindingType: "IAM_ROLE_HAS_EXCESSIVE_PERMISSIONS",
			ResourceID:  resourceID,
			Region:      "us-east-1",
			AccountID:   "123456789012",
		},
	}
}

// mockExcessivePermsClient implements excessivePermsAPI for testing.
type mockExcessivePermsClient struct {
	listFunc   func(ctx context.Context, params *iam.ListAttachedRolePoliciesInput, optFns ...func(*iam.Options)) (*iam.ListAttachedRolePoliciesOutput, error)
	detachFunc func(ctx context.Context, params *iam.DetachRolePolicyInput, optFns ...func(*iam.Options)) (*iam.DetachRolePolicyOutput, error)
}

func (m *mockExcessivePermsClient) ListAttachedRolePolicies(ctx context.Context, params *iam.ListAttachedRolePoliciesInput, optFns ...func(*iam.Options)) (*iam.ListAttachedRolePoliciesOutput, error) {
	if m.listFunc != nil {
		return m.listFunc(ctx, params, optFns...)
	}
	return &iam.ListAttachedRolePoliciesOutput{}, nil
}

func (m *mockExcessivePermsClient) DetachRolePolicy(ctx context.Context, params *iam.DetachRolePolicyInput, optFns ...func(*iam.Options)) (*iam.DetachRolePolicyOutput, error) {
	if m.detachFunc != nil {
		return m.detachFunc(ctx, params, optFns...)
	}
	return &iam.DetachRolePolicyOutput{}, nil
}

func mockExcessivePermsFactory(client excessivePermsAPI) func(ctx context.Context, region string) (excessivePermsAPI, error) {
	return func(_ context.Context, _ string) (excessivePermsAPI, error) {
		return client, nil
	}
}

func TestRestrictExcessivePerms_Tier(t *testing.T) {
	r := NewRestrictExcessivePermsRemediator()
	if got := r.Tier(); got != 2 {
		t.Fatalf("expected tier 2, got %d", got)
	}
}

func TestRestrictExcessivePerms_DryRun(t *testing.T) {
	tests := []struct {
		name       string
		resourceID string
	}{
		{name: "ARN resource ID", resourceID: "arn:aws:iam::123456789012:role/svc-deploy-role"},
		{name: "plain role name", resourceID: "svc-deploy-role"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := NewRestrictExcessivePermsRemediator()
			finding := makeExcessivePermsFinding("ep-dry-1", "aws-securityhub", tt.resourceID)

			result, err := r.DryRun(context.Background(), finding)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !result.WouldSucceed {
				t.Fatal("expected WouldSucceed=true")
			}
			if len(result.PlannedActions) != 2 {
				t.Fatalf("expected 2 planned actions, got %d", len(result.PlannedActions))
			}
			if len(result.Warnings) < 2 {
				t.Fatalf("expected at least 2 warnings, got %d", len(result.Warnings))
			}
		})
	}
}

func TestRestrictExcessivePerms_Remediate_AWS(t *testing.T) {
	tests := []struct {
		name        string
		resourceID  string
		policies    []iamtypes.AttachedPolicy
		listErr     error
		detachErr   error
		wantSuccess bool
		wantErrMsg  string
		wantDetach  int
	}{
		{
			name:       "detaches AdminAccess",
			resourceID: "svc-deploy-role",
			policies: []iamtypes.AttachedPolicy{
				{PolicyName: aws.String("AdministratorAccess"), PolicyArn: aws.String("arn:aws:iam::aws:policy/AdministratorAccess")},
				{PolicyName: aws.String("AmazonS3ReadOnly"), PolicyArn: aws.String("arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess")},
			},
			wantSuccess: true,
			wantDetach:  1,
		},
		{
			name:       "detaches multiple overprivileged",
			resourceID: "arn:aws:iam::123456789012:role/over-priv-role",
			policies: []iamtypes.AttachedPolicy{
				{PolicyName: aws.String("AdministratorAccess"), PolicyArn: aws.String("arn:aws:iam::aws:policy/AdministratorAccess")},
				{PolicyName: aws.String("PowerUserAccess"), PolicyArn: aws.String("arn:aws:iam::aws:policy/PowerUserAccess")},
			},
			wantSuccess: true,
			wantDetach:  2,
		},
		{
			name:       "no overprivileged policies",
			resourceID: "clean-role",
			policies: []iamtypes.AttachedPolicy{
				{PolicyName: aws.String("AmazonS3ReadOnly"), PolicyArn: aws.String("arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess")},
			},
			wantSuccess: true,
			wantDetach:  0,
		},
		{
			name:       "list fails",
			resourceID: "err-role",
			listErr:    fmt.Errorf("NoSuchEntity"),
			wantErrMsg: "failed to list policies",
		},
		{
			name:       "detach fails",
			resourceID: "detach-err-role",
			policies: []iamtypes.AttachedPolicy{
				{PolicyName: aws.String("AdministratorAccess"), PolicyArn: aws.String("arn:aws:iam::aws:policy/AdministratorAccess")},
			},
			detachErr:  fmt.Errorf("UnmodifiableEntity"),
			wantErrMsg: "failed to detach policy",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			detachCount := 0
			mock := &mockExcessivePermsClient{
				listFunc: func(_ context.Context, params *iam.ListAttachedRolePoliciesInput, _ ...func(*iam.Options)) (*iam.ListAttachedRolePoliciesOutput, error) {
					if tt.listErr != nil {
						return nil, tt.listErr
					}
					wantRole := extractRoleName(tt.resourceID)
					if *params.RoleName != wantRole {
						t.Fatalf("expected RoleName %q, got %q", wantRole, *params.RoleName)
					}
					return &iam.ListAttachedRolePoliciesOutput{
						AttachedPolicies: tt.policies,
					}, nil
				},
				detachFunc: func(_ context.Context, params *iam.DetachRolePolicyInput, _ ...func(*iam.Options)) (*iam.DetachRolePolicyOutput, error) {
					if tt.detachErr != nil {
						return nil, tt.detachErr
					}
					if params.PolicyArn == nil || !overprivilegedPolicies[*params.PolicyArn] {
						t.Fatalf("unexpected detach of non-overprivileged policy: %v", params.PolicyArn)
					}
					detachCount++
					return &iam.DetachRolePolicyOutput{}, nil
				},
			}

			r := NewRestrictExcessivePermsRemediator(
				WithExcessivePermsClient(mockExcessivePermsFactory(mock)),
			)
			finding := makeExcessivePermsFinding("ep-aws-1", "aws-securityhub", tt.resourceID)

			result, err := r.Remediate(context.Background(), finding)

			if tt.wantErrMsg != "" {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if !strings.Contains(err.Error(), tt.wantErrMsg) {
					t.Fatalf("expected error containing %q, got %q", tt.wantErrMsg, err.Error())
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result.Success != tt.wantSuccess {
				t.Fatalf("expected success=%v, got %v", tt.wantSuccess, result.Success)
			}
			if detachCount != tt.wantDetach {
				t.Fatalf("expected %d detach calls, got %d", tt.wantDetach, detachCount)
			}
		})
	}
}

func TestRestrictExcessivePerms_Remediate_CSPRouting(t *testing.T) {
	tests := []struct {
		name       string
		source     string
		wantErrMsg string
	}{
		{name: "GCP returns not implemented", source: "gcp-scc", wantErrMsg: "GCP remediation not implemented"},
		{name: "Azure returns not implemented", source: "azure-defender", wantErrMsg: "Azure remediation not implemented"},
		{name: "unknown CSP returns error", source: "oracle-cloud", wantErrMsg: "unsupported CSP"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := NewRestrictExcessivePermsRemediator()
			finding := makeExcessivePermsFinding("ep-csp-1", tt.source, "some-role")

			_, err := r.Remediate(context.Background(), finding)
			if err == nil {
				t.Fatal("expected error for non-AWS CSP")
			}
			if !strings.Contains(err.Error(), tt.wantErrMsg) {
				t.Fatalf("expected error containing %q, got %q", tt.wantErrMsg, err.Error())
			}
		})
	}
}

func TestExtractRoleName(t *testing.T) {
	tests := []struct {
		name       string
		resourceID string
		want       string
	}{
		{name: "ARN", resourceID: "arn:aws:iam::123456789012:role/my-service-role", want: "my-service-role"},
		{name: "plain name", resourceID: "my-service-role", want: "my-service-role"},
		{name: "ARN with path", resourceID: "arn:aws:iam::123456789012:role/service-role/AWSLambdaRole", want: "service-role/AWSLambdaRole"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractRoleName(tt.resourceID)
			if got != tt.want {
				t.Fatalf("extractRoleName(%q) = %q, want %q", tt.resourceID, got, tt.want)
			}
		})
	}
}
