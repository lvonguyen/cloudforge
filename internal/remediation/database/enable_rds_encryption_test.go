package database

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"

	cspmscoring "aegis/internal/cspm/scoring"
)

type mockRDSClient struct {
	encrypted   bool
	describeErr error
	snapshotErr error
	modifyErr   error
}

func (m *mockRDSClient) DescribeDBInstances(_ context.Context, _ *rds.DescribeDBInstancesInput, _ ...func(*rds.Options)) (*rds.DescribeDBInstancesOutput, error) {
	if m.describeErr != nil {
		return nil, m.describeErr
	}
	enc := m.encrypted
	return &rds.DescribeDBInstancesOutput{
		DBInstances: []rdstypes.DBInstance{
			{
				DBInstanceIdentifier: aws.String("test-db"),
				StorageEncrypted:     &enc,
				KmsKeyId:             aws.String("arn:aws:kms:us-east-1:123456789012:key/test-key"),
				Engine:               aws.String("postgres"),
				EngineVersion:        aws.String("15.4"),
				DBInstanceClass:      aws.String("db.t3.micro"),
			},
		},
	}, nil
}

func (m *mockRDSClient) CreateDBSnapshot(_ context.Context, _ *rds.CreateDBSnapshotInput, _ ...func(*rds.Options)) (*rds.CreateDBSnapshotOutput, error) {
	if m.snapshotErr != nil {
		return nil, m.snapshotErr
	}
	return &rds.CreateDBSnapshotOutput{}, nil
}

func (m *mockRDSClient) ModifyDBInstance(_ context.Context, _ *rds.ModifyDBInstanceInput, _ ...func(*rds.Options)) (*rds.ModifyDBInstanceOutput, error) {
	if m.modifyErr != nil {
		return nil, m.modifyErr
	}
	m.encrypted = true
	return &rds.ModifyDBInstanceOutput{}, nil
}

func testFinding(id, resourceID string) *cspmscoring.PrioritizedFinding {
	return &cspmscoring.PrioritizedFinding{
		Finding: &cspmscoring.Finding{
			ID:          id,
			FindingType: "RDS_ENCRYPTION_DISABLED",
			ResourceID:  resourceID,
			Region:      "us-east-1",
			AccountID:   "123456789012",
		},
		AutoRemediationReady: true,
	}
}

func TestEnableRDSEncryption_Tier(t *testing.T) {
	r := NewEnableRDSEncryptionRemediator()
	if r.Tier() != 2 {
		t.Errorf("expected tier 2, got %d", r.Tier())
	}
}

func TestEnableRDSEncryption_Remediate(t *testing.T) {
	mock := &mockRDSClient{}
	r := NewEnableRDSEncryptionRemediator(WithRDSClient(mock))
	finding := testFinding("f-001", "arn:aws:rds:us-east-1:123456789012:db:test-db")

	result, err := r.Remediate(context.Background(), finding)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Success {
		t.Errorf("expected success, got: %s", result.Message)
	}
	if len(result.Actions) != 2 {
		t.Errorf("expected 2 actions, got %d", len(result.Actions))
	}
	if !mock.encrypted {
		t.Error("mock should have encryption enabled after remediation")
	}
}

func TestEnableRDSEncryption_Validate_Compliant(t *testing.T) {
	mock := &mockRDSClient{encrypted: true}
	r := NewEnableRDSEncryptionRemediator(WithRDSClient(mock))
	finding := testFinding("f-001", "arn:aws:rds:us-east-1:123456789012:db:test-db")

	validation, err := r.Validate(context.Background(), finding)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !validation.IsCompliant {
		t.Errorf("expected compliant, got: %s", validation.Message)
	}
}

func TestEnableRDSEncryption_Validate_NonCompliant(t *testing.T) {
	mock := &mockRDSClient{encrypted: false}
	r := NewEnableRDSEncryptionRemediator(WithRDSClient(mock))
	finding := testFinding("f-001", "arn:aws:rds:us-east-1:123456789012:db:test-db")

	validation, err := r.Validate(context.Background(), finding)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if validation.IsCompliant {
		t.Error("expected non-compliant for unencrypted instance")
	}
}

func TestEnableRDSEncryption_DryRun(t *testing.T) {
	r := NewEnableRDSEncryptionRemediator(WithRDSClient(&mockRDSClient{}))
	finding := testFinding("f-001", "arn:aws:rds:us-east-1:123456789012:db:test-db")

	dryRun, err := r.DryRun(context.Background(), finding)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !dryRun.WouldSucceed {
		t.Error("expected dry run to succeed")
	}
	if len(dryRun.PlannedActions) != 2 {
		t.Errorf("expected 2 planned actions, got %d", len(dryRun.PlannedActions))
	}
}

func TestEnableRDSEncryption_CaptureRollbackState(t *testing.T) {
	mock := &mockRDSClient{encrypted: false}
	r := NewEnableRDSEncryptionRemediator(WithRDSClient(mock))
	finding := testFinding("f-001", "arn:aws:rds:us-east-1:123456789012:db:test-db")

	state, err := r.CaptureRollbackState(context.Background(), finding)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if state.FindingID != "f-001" {
		t.Errorf("expected finding ID f-001, got %s", state.FindingID)
	}
	if state.PreState["encrypted"] != false {
		t.Error("expected encrypted=false in pre-state")
	}
	if state.PreState["engine"] != "postgres" {
		t.Errorf("expected engine=postgres, got %v", state.PreState["engine"])
	}
}

func TestExtractDBInstanceID(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"arn:aws:rds:us-east-1:123456789012:db:mydb", "mydb"},
		{"mydb", "mydb"},
		{"rds/mydb", "mydb"},
	}
	for _, tt := range tests {
		got := extractDBInstanceID(tt.input)
		if got != tt.want {
			t.Errorf("extractDBInstanceID(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}
