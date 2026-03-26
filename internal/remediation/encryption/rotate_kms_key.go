// Package encryption provides remediation handlers for encryption-related security findings.
package encryption

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"

	cspmscoring "aegis/internal/cspm/scoring"
	"aegis/pkg/remediation"
)

// kmsAPI defines the KMS operations used by this remediator.
type kmsAPI interface {
	EnableKeyRotation(ctx context.Context, params *kms.EnableKeyRotationInput, optFns ...func(*kms.Options)) (*kms.EnableKeyRotationOutput, error)
	GetKeyRotationStatus(ctx context.Context, params *kms.GetKeyRotationStatusInput, optFns ...func(*kms.Options)) (*kms.GetKeyRotationStatusOutput, error)
	DescribeKey(ctx context.Context, params *kms.DescribeKeyInput, optFns ...func(*kms.Options)) (*kms.DescribeKeyOutput, error)
}

// RotateKMSKeyRemediator enables automatic key rotation on AWS KMS customer-managed keys.
//
// Finding Types: KMS_KEY_ROTATION_DISABLED, AWS.KMS.KeyRotation
// Tier: 2 (Requires verification — affects all services using the key)
// Impact: Enables annual automatic rotation; old key versions remain for decrypt
// CSPs: AWS
// Rollback: Captures pre-state (rotation status, key metadata)
type RotateKMSKeyRemediator struct {
	tier   int
	client kmsAPI
}

// WithKMSClient injects a custom KMS client (used in tests).
func WithKMSClient(c kmsAPI) func(*RotateKMSKeyRemediator) {
	return func(r *RotateKMSKeyRemediator) {
		r.client = c
	}
}

// NewRotateKMSKeyRemediator creates a new handler for enabling KMS key rotation.
func NewRotateKMSKeyRemediator(opts ...func(*RotateKMSKeyRemediator)) *RotateKMSKeyRemediator {
	r := &RotateKMSKeyRemediator{tier: 2}
	for _, o := range opts {
		o(r)
	}
	return r
}

func (k *RotateKMSKeyRemediator) getClient(ctx context.Context, region string) (kmsAPI, error) {
	if k.client != nil {
		return k.client, nil
	}
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("loading AWS config: %w", err)
	}
	return kms.NewFromConfig(cfg), nil
}

// Tier returns the complexity tier (2 = requires verification).
func (k *RotateKMSKeyRemediator) Tier() int {
	return k.tier
}

// CaptureRollbackState stores pre-remediation key rotation status.
func (k *RotateKMSKeyRemediator) CaptureRollbackState(ctx context.Context, finding *cspmscoring.PrioritizedFinding) (*remediation.RollbackState, error) {
	client, err := k.getClient(ctx, finding.Finding.Region)
	if err != nil {
		return nil, err
	}

	keyID := finding.Finding.ResourceID
	rotStatus, err := client.GetKeyRotationStatus(ctx, &kms.GetKeyRotationStatusInput{
		KeyId: aws.String(keyID),
	})
	if err != nil {
		return nil, fmt.Errorf("getting key rotation status for %s: %w", keyID, err)
	}

	descOutput, err := client.DescribeKey(ctx, &kms.DescribeKeyInput{
		KeyId: aws.String(keyID),
	})
	if err != nil {
		return nil, fmt.Errorf("describing key %s: %w", keyID, err)
	}

	preState := map[string]any{
		"key_id":           keyID,
		"rotation_enabled": rotStatus.KeyRotationEnabled,
		"key_state":        string(descOutput.KeyMetadata.KeyState),
		"key_manager":      string(descOutput.KeyMetadata.KeyManager),
	}

	return &remediation.RollbackState{
		FindingID:  finding.Finding.ID,
		ResourceID: finding.Finding.ResourceID,
		Region:     finding.Finding.Region,
		AccountID:  finding.Finding.AccountID,
		PreState:   preState,
		CapturedAt: time.Now(),
	}, nil
}

// Remediate enables automatic annual key rotation on the KMS key.
func (k *RotateKMSKeyRemediator) Remediate(ctx context.Context, finding *cspmscoring.PrioritizedFinding) (*remediation.RemediationResult, error) {
	startTime := time.Now()
	result := &remediation.RemediationResult{
		FindingID:  finding.Finding.ID,
		ResourceID: finding.Finding.ResourceID,
		StartedAt:  startTime,
		Actions:    []string{},
	}

	client, err := k.getClient(ctx, finding.Finding.Region)
	if err != nil {
		return nil, err
	}

	keyID := finding.Finding.ResourceID
	_, err = client.EnableKeyRotation(ctx, &kms.EnableKeyRotationInput{
		KeyId: aws.String(keyID),
	})
	if err != nil {
		result.CompletedAt = time.Now()
		result.Duration = time.Since(startTime).String()
		result.Error = err.Error()
		return result, fmt.Errorf("enabling key rotation on %s: %w", keyID, err)
	}

	result.Actions = append(result.Actions,
		fmt.Sprintf("Enabled automatic annual key rotation on KMS key: %s", keyID),
		"Old key versions retained for decryption of existing ciphertext",
	)
	result.CompletedAt = time.Now()
	result.Duration = time.Since(startTime).String()
	result.Success = true
	result.Message = fmt.Sprintf("KMS key rotation enabled: %s", keyID)
	return result, nil
}

// Validate verifies that key rotation is enabled.
func (k *RotateKMSKeyRemediator) Validate(ctx context.Context, finding *cspmscoring.PrioritizedFinding) (*remediation.ValidationResult, error) {
	validation := &remediation.ValidationResult{
		FindingID:   finding.Finding.ID,
		ValidatedAt: time.Now(),
		Evidence:    []string{},
	}

	client, err := k.getClient(ctx, finding.Finding.Region)
	if err != nil {
		return nil, err
	}

	keyID := finding.Finding.ResourceID
	output, err := client.GetKeyRotationStatus(ctx, &kms.GetKeyRotationStatusInput{
		KeyId: aws.String(keyID),
	})
	if err != nil {
		return nil, fmt.Errorf("checking key rotation status: %w", err)
	}

	if !output.KeyRotationEnabled {
		validation.IsCompliant = false
		validation.Message = fmt.Sprintf("Key rotation not enabled on KMS key: %s", keyID)
		return validation, nil
	}

	validation.IsCompliant = true
	validation.Message = fmt.Sprintf("Key rotation enabled on KMS key: %s", keyID)
	validation.Evidence = append(validation.Evidence, "KeyRotationEnabled: true")
	return validation, nil
}

// DryRun simulates enabling key rotation without making changes.
func (k *RotateKMSKeyRemediator) DryRun(ctx context.Context, finding *cspmscoring.PrioritizedFinding) (*remediation.DryRunResult, error) {
	keyID := finding.Finding.ResourceID
	return &remediation.DryRunResult{
		FindingID:        finding.Finding.ID,
		WouldSucceed:     true,
		PrerequisitesMet: true,
		PlannedActions: []string{
			fmt.Sprintf("Would enable automatic annual rotation on KMS key: %s", keyID),
		},
		EstimatedImpact: "No disruption. Existing ciphertext remains decryptable. New encryptions use latest key version.",
	}, nil
}
