package encryption

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"

	cspmscoring "aegis/internal/cspm/scoring"
)

type mockKMSClient struct {
	rotationEnabled bool
	enableErr       error
}

func (m *mockKMSClient) EnableKeyRotation(_ context.Context, _ *kms.EnableKeyRotationInput, _ ...func(*kms.Options)) (*kms.EnableKeyRotationOutput, error) {
	if m.enableErr != nil {
		return nil, m.enableErr
	}
	m.rotationEnabled = true
	return &kms.EnableKeyRotationOutput{}, nil
}

func (m *mockKMSClient) GetKeyRotationStatus(_ context.Context, _ *kms.GetKeyRotationStatusInput, _ ...func(*kms.Options)) (*kms.GetKeyRotationStatusOutput, error) {
	return &kms.GetKeyRotationStatusOutput{
		KeyRotationEnabled: m.rotationEnabled,
	}, nil
}

func (m *mockKMSClient) DescribeKey(_ context.Context, _ *kms.DescribeKeyInput, _ ...func(*kms.Options)) (*kms.DescribeKeyOutput, error) {
	return &kms.DescribeKeyOutput{
		KeyMetadata: &kmstypes.KeyMetadata{
			KeyId:      aws.String("test-key-id"),
			KeyState:   kmstypes.KeyStateEnabled,
			KeyManager: kmstypes.KeyManagerTypeCustomer,
		},
	}, nil
}

func kmsTestFinding(id, keyID string) *cspmscoring.PrioritizedFinding {
	return &cspmscoring.PrioritizedFinding{
		Finding: &cspmscoring.Finding{
			ID:          id,
			FindingType: "KMS_KEY_ROTATION_DISABLED",
			ResourceID:  keyID,
			Region:      "us-east-1",
			AccountID:   "123456789012",
		},
		AutoRemediationReady: true,
	}
}

func TestRotateKMSKey_Tier(t *testing.T) {
	r := NewRotateKMSKeyRemediator()
	if r.Tier() != 2 {
		t.Errorf("expected tier 2, got %d", r.Tier())
	}
}

func TestRotateKMSKey_Remediate(t *testing.T) {
	mock := &mockKMSClient{}
	r := NewRotateKMSKeyRemediator(WithKMSClient(mock))
	finding := kmsTestFinding("f-001", "arn:aws:kms:us-east-1:123456789012:key/test-key")

	result, err := r.Remediate(context.Background(), finding)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Success {
		t.Errorf("expected success, got: %s", result.Message)
	}
	if !mock.rotationEnabled {
		t.Error("expected rotation to be enabled after remediation")
	}
}

func TestRotateKMSKey_Validate_Compliant(t *testing.T) {
	mock := &mockKMSClient{rotationEnabled: true}
	r := NewRotateKMSKeyRemediator(WithKMSClient(mock))
	finding := kmsTestFinding("f-001", "arn:aws:kms:us-east-1:123456789012:key/test-key")

	validation, err := r.Validate(context.Background(), finding)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !validation.IsCompliant {
		t.Errorf("expected compliant, got: %s", validation.Message)
	}
}

func TestRotateKMSKey_Validate_NonCompliant(t *testing.T) {
	mock := &mockKMSClient{rotationEnabled: false}
	r := NewRotateKMSKeyRemediator(WithKMSClient(mock))
	finding := kmsTestFinding("f-001", "arn:aws:kms:us-east-1:123456789012:key/test-key")

	validation, err := r.Validate(context.Background(), finding)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if validation.IsCompliant {
		t.Error("expected non-compliant for key without rotation")
	}
}

func TestRotateKMSKey_CaptureRollbackState(t *testing.T) {
	mock := &mockKMSClient{rotationEnabled: false}
	r := NewRotateKMSKeyRemediator(WithKMSClient(mock))
	finding := kmsTestFinding("f-001", "arn:aws:kms:us-east-1:123456789012:key/test-key")

	state, err := r.CaptureRollbackState(context.Background(), finding)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if state.PreState["rotation_enabled"] != false {
		t.Error("expected rotation_enabled=false in pre-state")
	}
}

func TestRotateKMSKey_DryRun(t *testing.T) {
	r := NewRotateKMSKeyRemediator(WithKMSClient(&mockKMSClient{}))
	finding := kmsTestFinding("f-001", "arn:aws:kms:us-east-1:123456789012:key/test-key")

	dryRun, err := r.DryRun(context.Background(), finding)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !dryRun.WouldSucceed {
		t.Error("expected dry run to succeed")
	}
}
