package network

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/ec2"

	cspmscoring "aegis/internal/cspm/scoring"
)

func makePortFinding(id, source, resourceID string) *cspmscoring.PrioritizedFinding {
	return &cspmscoring.PrioritizedFinding{
		Finding: &cspmscoring.Finding{
			ID:          id,
			Source:      source,
			Severity:    "HIGH",
			FindingType: "OPEN_RDP_PORT",
			ResourceID:  resourceID,
			Region:      "us-east-1",
			AccountID:   "123456789012",
		},
	}
}

func TestBlockOpenPort_Tier(t *testing.T) {
	r := NewBlockOpenPortRemediator(3389, "RDP")
	if got := r.Tier(); got != 1 {
		t.Fatalf("expected tier 1, got %d", got)
	}
}

func TestBlockOpenPort_DryRun(t *testing.T) {
	tests := []struct {
		name     string
		port     int32
		portName string
	}{
		{name: "RDP", port: 3389, portName: "RDP"},
		{name: "MySQL", port: 3306, portName: "MySQL"},
		{name: "PostgreSQL", port: 5432, portName: "PostgreSQL"},
		{name: "Redis", port: 6379, portName: "Redis"},
		{name: "MongoDB", port: 27017, portName: "MongoDB"},
		{name: "FTP", port: 21, portName: "FTP"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := NewBlockOpenPortRemediator(tt.port, tt.portName)
			finding := makePortFinding("port-dry-1", "aws-securityhub", "sg-0abc123")

			result, err := r.DryRun(context.Background(), finding)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !result.WouldSucceed {
				t.Fatal("expected WouldSucceed=true")
			}
			if len(result.PlannedActions) == 0 {
				t.Fatal("expected non-empty planned actions")
			}
			wantPort := fmt.Sprintf(":%d", tt.port)
			if !strings.Contains(result.PlannedActions[0], wantPort) {
				t.Fatalf("expected planned action to contain %q, got %q", wantPort, result.PlannedActions[0])
			}
			if !strings.Contains(result.PlannedActions[0], tt.portName) {
				t.Fatalf("expected planned action to contain %q, got %q", tt.portName, result.PlannedActions[0])
			}
		})
	}
}

func TestBlockOpenPort_Remediate_AWS(t *testing.T) {
	tests := []struct {
		name        string
		port        int32
		portName    string
		resourceID  string
		revokeErr   error
		wantSuccess bool
		wantErrMsg  string
	}{
		{
			name:        "successful RDP revoke",
			port:        3389,
			portName:    "RDP",
			resourceID:  "arn:aws:ec2:us-east-1:123456789012:security-group/sg-0abc123",
			wantSuccess: true,
		},
		{
			name:        "successful MySQL revoke",
			port:        3306,
			portName:    "MySQL",
			resourceID:  "sg-0xyz789",
			wantSuccess: true,
		},
		{
			name:       "revoke fails",
			port:       5432,
			portName:   "PostgreSQL",
			resourceID: "sg-fail",
			revokeErr:  fmt.Errorf("InvalidGroup.NotFound: sg-fail"),
			wantErrMsg: "failed to revoke PostgreSQL ingress",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &mockEC2Client{
				revokeFunc: func(_ context.Context, params *ec2.RevokeSecurityGroupIngressInput, _ ...func(*ec2.Options)) (*ec2.RevokeSecurityGroupIngressOutput, error) {
					wantSG := extractSGID(tt.resourceID)
					if *params.GroupId != wantSG {
						t.Fatalf("expected GroupId %q, got %q", wantSG, *params.GroupId)
					}
					if len(params.IpPermissions) != 1 {
						t.Fatalf("expected 1 IpPermission, got %d", len(params.IpPermissions))
					}
					perm := params.IpPermissions[0]
					if *perm.FromPort != tt.port || *perm.ToPort != tt.port {
						t.Fatalf("expected port %d, got %d-%d", tt.port, *perm.FromPort, *perm.ToPort)
					}
					if tt.revokeErr != nil {
						return nil, tt.revokeErr
					}
					return &ec2.RevokeSecurityGroupIngressOutput{}, nil
				},
			}

			r := NewBlockOpenPortRemediator(tt.port, tt.portName, WithOpenPortEC2Client(mock))
			finding := makePortFinding("port-aws-1", "aws-securityhub", tt.resourceID)

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

func TestBlockOpenPort_Remediate_CSPRouting(t *testing.T) {
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
			r := NewBlockOpenPortRemediator(3389, "RDP")
			finding := makePortFinding("port-csp-1", tt.source, "sg-123")

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
