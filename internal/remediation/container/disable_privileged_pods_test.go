package container

import (
	"context"
	"testing"

	cspmscoring "aegis/internal/cspm/scoring"
)

type mockK8sClient struct {
	info     *PodSecurityInfo
	getErr   error
	patchErr error
	patched  bool
}

func (m *mockK8sClient) GetPodSecurityPolicy(_ context.Context, _, _ string) (*PodSecurityInfo, error) {
	if m.getErr != nil {
		return nil, m.getErr
	}
	return m.info, nil
}

func (m *mockK8sClient) PatchPodSecurityContext(_ context.Context, _, _ string, _ []byte) error {
	if m.patchErr != nil {
		return m.patchErr
	}
	m.patched = true
	m.info.Privileged = false
	m.info.RunAsRoot = false
	m.info.HostPID = false
	m.info.HostNet = false
	return nil
}

func k8sTestFinding(id, resourceID string) *cspmscoring.PrioritizedFinding {
	return &cspmscoring.PrioritizedFinding{
		Finding: &cspmscoring.Finding{
			ID:          id,
			FindingType: "K8S_PRIVILEGED_CONTAINER",
			ResourceID:  resourceID,
			Region:      "us-east-1",
			AccountID:   "123456789012",
		},
		AutoRemediationReady: true,
	}
}

func TestDisablePrivilegedPods_Tier(t *testing.T) {
	r := NewDisablePrivilegedPodsRemediator()
	if r.Tier() != 2 {
		t.Errorf("expected tier 2, got %d", r.Tier())
	}
}

func TestDisablePrivilegedPods_Remediate(t *testing.T) {
	mock := &mockK8sClient{
		info: &PodSecurityInfo{
			Namespace:  "kube-system",
			Name:       "node-exporter",
			Privileged: true,
			RunAsRoot:  true,
			HostPID:    true,
			HostNet:    true,
		},
	}
	r := NewDisablePrivilegedPodsRemediator(WithK8sClient(mock))
	finding := k8sTestFinding("f-001", "kube-system/node-exporter")

	result, err := r.Remediate(context.Background(), finding)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Success {
		t.Errorf("expected success, got: %s", result.Message)
	}
	if !mock.patched {
		t.Error("expected patch to be applied")
	}
}

func TestDisablePrivilegedPods_Validate_Compliant(t *testing.T) {
	mock := &mockK8sClient{
		info: &PodSecurityInfo{
			Namespace: "default", Name: "app",
			Privileged: false, RunAsRoot: false, HostPID: false, HostNet: false,
		},
	}
	r := NewDisablePrivilegedPodsRemediator(WithK8sClient(mock))
	finding := k8sTestFinding("f-001", "default/app")

	validation, err := r.Validate(context.Background(), finding)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !validation.IsCompliant {
		t.Errorf("expected compliant, got: %s", validation.Message)
	}
}

func TestDisablePrivilegedPods_Validate_NonCompliant(t *testing.T) {
	mock := &mockK8sClient{
		info: &PodSecurityInfo{
			Namespace: "default", Name: "app",
			Privileged: true, RunAsRoot: false, HostPID: false, HostNet: false,
		},
	}
	r := NewDisablePrivilegedPodsRemediator(WithK8sClient(mock))
	finding := k8sTestFinding("f-001", "default/app")

	validation, err := r.Validate(context.Background(), finding)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if validation.IsCompliant {
		t.Error("expected non-compliant for privileged pod")
	}
}

func TestDisablePrivilegedPods_DryRun(t *testing.T) {
	mock := &mockK8sClient{info: &PodSecurityInfo{}}
	r := NewDisablePrivilegedPodsRemediator(WithK8sClient(mock))
	finding := k8sTestFinding("f-001", "default/app")

	dryRun, err := r.DryRun(context.Background(), finding)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !dryRun.WouldSucceed {
		t.Error("expected dry run to succeed")
	}
}

func TestExtractK8sResource(t *testing.T) {
	tests := []struct {
		input    string
		wantNs   string
		wantName string
	}{
		{"kube-system/node-exporter", "kube-system", "node-exporter"},
		{"my-app", "default", "my-app"},
	}
	for _, tt := range tests {
		ns, name := extractK8sResource(tt.input)
		if ns != tt.wantNs || name != tt.wantName {
			t.Errorf("extractK8sResource(%q) = (%q, %q), want (%q, %q)", tt.input, ns, name, tt.wantNs, tt.wantName)
		}
	}
}
