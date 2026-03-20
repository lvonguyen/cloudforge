package network

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"

	cspmscoring "aegis/internal/cspm/scoring"
)

func makeSSLFinding(id, source, resourceID string) *cspmscoring.PrioritizedFinding {
	return &cspmscoring.PrioritizedFinding{
		Finding: &cspmscoring.Finding{
			ID:          id,
			Source:      source,
			Severity:    "HIGH",
			FindingType: "SSL_NOT_ENFORCED",
			ResourceID:  resourceID,
			Region:      "us-east-1",
			AccountID:   "123456789012",
		},
	}
}

// mockRDSClient implements rdsAPI for testing.
type mockRDSClient struct {
	describeFunc func(ctx context.Context, params *rds.DescribeDBInstancesInput, optFns ...func(*rds.Options)) (*rds.DescribeDBInstancesOutput, error)
	modifyFunc   func(ctx context.Context, params *rds.ModifyDBInstanceInput, optFns ...func(*rds.Options)) (*rds.ModifyDBInstanceOutput, error)
}

func (m *mockRDSClient) DescribeDBInstances(ctx context.Context, params *rds.DescribeDBInstancesInput, optFns ...func(*rds.Options)) (*rds.DescribeDBInstancesOutput, error) {
	if m.describeFunc != nil {
		return m.describeFunc(ctx, params, optFns...)
	}
	return &rds.DescribeDBInstancesOutput{}, nil
}

func (m *mockRDSClient) ModifyDBInstance(ctx context.Context, params *rds.ModifyDBInstanceInput, optFns ...func(*rds.Options)) (*rds.ModifyDBInstanceOutput, error) {
	if m.modifyFunc != nil {
		return m.modifyFunc(ctx, params, optFns...)
	}
	return &rds.ModifyDBInstanceOutput{}, nil
}

func mockRDSFactory(client rdsAPI) func(ctx context.Context, region string) (rdsAPI, error) {
	return func(_ context.Context, _ string) (rdsAPI, error) {
		return client, nil
	}
}

func TestEnforceSSL_Tier(t *testing.T) {
	r := NewEnforceSSLRemediator()
	if got := r.Tier(); got != 1 {
		t.Fatalf("expected tier 1, got %d", got)
	}
}

func TestEnforceSSL_DryRun(t *testing.T) {
	tests := []struct {
		name       string
		resourceID string
	}{
		{name: "ARN resource ID", resourceID: "arn:aws:rds:us-east-1:123456789012:db:my-database"},
		{name: "plain DB ID", resourceID: "my-database"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := NewEnforceSSLRemediator()
			finding := makeSSLFinding("ssl-dry-1", "aws-securityhub", tt.resourceID)

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
		})
	}
}

func TestEnforceSSL_Remediate_AWS(t *testing.T) {
	tests := []struct {
		name        string
		resourceID  string
		instances   []rdstypes.DBInstance
		describeErr error
		modifyErr   error
		wantSuccess bool
		wantErrMsg  string
	}{
		{
			name:       "successful SSL enforcement",
			resourceID: "arn:aws:rds:us-east-1:123456789012:db:my-database",
			instances: []rdstypes.DBInstance{
				{
					DBInstanceIdentifier:    aws.String("my-database"),
					CACertificateIdentifier: aws.String("rds-ca-2019"),
				},
			},
			wantSuccess: true,
		},
		{
			name:       "plain DB ID",
			resourceID: "my-other-db",
			instances: []rdstypes.DBInstance{
				{
					DBInstanceIdentifier:    aws.String("my-other-db"),
					CACertificateIdentifier: aws.String("rds-ca-2019"),
				},
			},
			wantSuccess: true,
		},
		{
			name:       "DB not found",
			resourceID: "gone-db",
			instances:  []rdstypes.DBInstance{},
			wantErrMsg: "not found",
		},
		{
			name:        "describe fails",
			resourceID:  "err-db",
			describeErr: fmt.Errorf("DBInstanceNotFound"),
			wantErrMsg:  "failed to describe DB instance",
		},
		{
			name:       "modify fails",
			resourceID: "mod-err-db",
			instances: []rdstypes.DBInstance{
				{DBInstanceIdentifier: aws.String("mod-err-db")},
			},
			modifyErr:  fmt.Errorf("InvalidParameterCombination"),
			wantErrMsg: "failed to enforce SSL",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &mockRDSClient{
				describeFunc: func(_ context.Context, params *rds.DescribeDBInstancesInput, _ ...func(*rds.Options)) (*rds.DescribeDBInstancesOutput, error) {
					if tt.describeErr != nil {
						return nil, tt.describeErr
					}
					wantDB := extractDBInstanceID(tt.resourceID)
					if *params.DBInstanceIdentifier != wantDB {
						t.Fatalf("expected DBInstanceIdentifier %q, got %q", wantDB, *params.DBInstanceIdentifier)
					}
					return &rds.DescribeDBInstancesOutput{
						DBInstances: tt.instances,
					}, nil
				},
				modifyFunc: func(_ context.Context, params *rds.ModifyDBInstanceInput, _ ...func(*rds.Options)) (*rds.ModifyDBInstanceOutput, error) {
					if tt.modifyErr != nil {
						return nil, tt.modifyErr
					}
					if params.CACertificateIdentifier == nil || *params.CACertificateIdentifier != "rds-ca-rsa2048-g1" {
						t.Fatalf("expected CA cert rds-ca-rsa2048-g1, got %v", params.CACertificateIdentifier)
					}
					return &rds.ModifyDBInstanceOutput{}, nil
				},
			}

			r := NewEnforceSSLRemediator(WithRDSClient(mockRDSFactory(mock)))
			finding := makeSSLFinding("ssl-aws-1", "aws-securityhub", tt.resourceID)

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
			if len(result.Actions) == 0 {
				t.Fatal("expected non-empty actions")
			}
		})
	}
}

func TestEnforceSSL_Remediate_CSPRouting(t *testing.T) {
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
			r := NewEnforceSSLRemediator()
			finding := makeSSLFinding("ssl-csp-1", tt.source, "db-123")

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

func TestExtractDBInstanceID(t *testing.T) {
	tests := []struct {
		name       string
		resourceID string
		want       string
	}{
		{name: "db ARN", resourceID: "arn:aws:rds:us-east-1:123456789012:db:my-database", want: "my-database"},
		{name: "cluster ARN", resourceID: "arn:aws:rds:us-east-1:123456789012:cluster:my-cluster", want: "my-cluster"},
		{name: "plain ID", resourceID: "my-database", want: "my-database"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractDBInstanceID(tt.resourceID)
			if got != tt.want {
				t.Fatalf("extractDBInstanceID(%q) = %q, want %q", tt.resourceID, got, tt.want)
			}
		})
	}
}
