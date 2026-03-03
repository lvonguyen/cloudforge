package identity

import (
	"context"
	"strings"
	"testing"

	cspmscoring "cloudforge/internal/cspm/scoring"
)

func makeIAMFinding(id, userName string) *cspmscoring.PrioritizedFinding {
	return &cspmscoring.PrioritizedFinding{
		Finding: &cspmscoring.Finding{
			ID:          id,
			Source:      "aws-securityhub",
			Severity:    "HIGH",
			FindingType: "IAM_OLD_ACCESS_KEY",
			ResourceID:  userName,
			Region:      "us-east-1",
			AccountID:   "123456789012",
		},
	}
}

func TestRotateIAMKeys_Tier(t *testing.T) {
	r := NewRotateIAMKeysRemediator()
	if got := r.Tier(); got != 2 {
		t.Fatalf("expected tier 2, got %d", got)
	}
}

func TestRotateIAMKeys_DryRun(t *testing.T) {
	tests := []struct {
		name     string
		userName string
	}{
		{name: "service account", userName: "svc-cicd-deployer"},
		{name: "human user", userName: "john.doe"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := NewRotateIAMKeysRemediator()
			finding := makeIAMFinding("iam-dry-1", tt.userName)

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
			if !strings.Contains(result.PlannedActions[0], tt.userName) {
				t.Fatalf("expected first action to reference user %q, got %q", tt.userName, result.PlannedActions[0])
			}
			if len(result.Warnings) < 2 {
				t.Fatalf("expected at least 2 warnings, got %d", len(result.Warnings))
			}
		})
	}
}

// TODO(human): Implement TestRotateIAMKeys_Remediate below.
//
// The mock needs to simulate IAM access keys with different ages and statuses.
// Use time.Now().Add(-duration) to create keys at specific ages.
//
// Suggested test cases:
//   - "deactivates stale key" - one active key at 120 days old -> should be deactivated
//   - "skips fresh key" - one active key at 30 days old -> no deactivation
//   - "skips inactive key" - one inactive key at 120 days old -> already handled
//   - "mixed keys" - multiple keys with different ages/statuses
//   - "list fails" - ListAccessKeys returns error
//   - "update fails" - UpdateAccessKey returns error
//
// The function signature should be:
//
//	func TestRotateIAMKeys_Remediate(t *testing.T) {
//	    tests := []struct {
//	        name          string
//	        keys          []iamtypes.AccessKeyMetadata
//	        listErr       error
//	        updateErr     error
//	        wantSuccess   bool
//	        wantErrMsg    string
//	        wantDeactivated int
//	    }{ ... }
//	}
//
// Key types to use:
//   - iamtypes.AccessKeyMetadata{AccessKeyId, Status, CreateDate, UserName}  (import iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types")
//   - iamtypes.StatusTypeActive / iamtypes.StatusTypeInactive
//   - aws.String(), aws.Time()  (import "github.com/aws/aws-sdk-go-v2/aws")
//
// When implementing, use mockIAMClient with listFunc/updateFunc fields to inject
// test doubles via WithIAMClient option on NewRotateIAMKeysRemediator.
// Use daysAgo(n) helper to generate *time.Time values for CreateDate fields.
