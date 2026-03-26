// Package container provides remediation handlers for container security findings.
package container

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	cspmscoring "aegis/internal/cspm/scoring"
	"aegis/pkg/remediation"
)

// k8sAPI defines the Kubernetes operations used by this remediator.
type k8sAPI interface {
	GetPodSecurityPolicy(ctx context.Context, namespace, name string) (*PodSecurityInfo, error)
	PatchPodSecurityContext(ctx context.Context, namespace, name string, patch []byte) error
}

// PodSecurityInfo contains the security context of a pod/deployment.
type PodSecurityInfo struct {
	Namespace  string `json:"namespace"`
	Name       string `json:"name"`
	Privileged bool   `json:"privileged"`
	RunAsRoot  bool   `json:"run_as_root"`
	HostPID    bool   `json:"host_pid"`
	HostNet    bool   `json:"host_network"`
}

// DisablePrivilegedPodsRemediator removes privileged mode from Kubernetes pods.
//
// Finding Types: K8S_PRIVILEGED_CONTAINER, EKS_PRIVILEGED_POD, GKE_PRIVILEGED_POD, AKS_PRIVILEGED_POD
// Tier: 2 (Requires verification — may break workloads that need host access)
// Impact: Sets securityContext.privileged=false, removes hostPID/hostNetwork
// CSPs: AWS (EKS), GCP (GKE), Azure (AKS)
// Rollback: Captures pre-remediation security context
type DisablePrivilegedPodsRemediator struct {
	tier   int
	client k8sAPI
}

// WithK8sClient injects a custom Kubernetes client (used in tests).
func WithK8sClient(c k8sAPI) func(*DisablePrivilegedPodsRemediator) {
	return func(r *DisablePrivilegedPodsRemediator) {
		r.client = c
	}
}

// NewDisablePrivilegedPodsRemediator creates a new handler for disabling privileged pods.
func NewDisablePrivilegedPodsRemediator(opts ...func(*DisablePrivilegedPodsRemediator)) *DisablePrivilegedPodsRemediator {
	r := &DisablePrivilegedPodsRemediator{tier: 2}
	for _, o := range opts {
		o(r)
	}
	return r
}

// Tier returns the complexity tier (2 = requires verification).
func (d *DisablePrivilegedPodsRemediator) Tier() int {
	return d.tier
}

// CaptureRollbackState stores pre-remediation pod security context.
func (d *DisablePrivilegedPodsRemediator) CaptureRollbackState(ctx context.Context, finding *cspmscoring.PrioritizedFinding) (*remediation.RollbackState, error) {
	if d.client == nil {
		return nil, fmt.Errorf("kubernetes client not configured")
	}

	ns, name := extractK8sResource(finding.Finding.ResourceID)
	info, err := d.client.GetPodSecurityPolicy(ctx, ns, name)
	if err != nil {
		return nil, fmt.Errorf("getting pod security for %s/%s: %w", ns, name, err)
	}

	return &remediation.RollbackState{
		FindingID:  finding.Finding.ID,
		ResourceID: finding.Finding.ResourceID,
		Region:     finding.Finding.Region,
		AccountID:  finding.Finding.AccountID,
		PreState: map[string]interface{}{
			"namespace":    info.Namespace,
			"name":         info.Name,
			"privileged":   info.Privileged,
			"run_as_root":  info.RunAsRoot,
			"host_pid":     info.HostPID,
			"host_network": info.HostNet,
		},
		CapturedAt: time.Now(),
	}, nil
}

// Remediate patches the pod/deployment to disable privileged mode.
func (d *DisablePrivilegedPodsRemediator) Remediate(ctx context.Context, finding *cspmscoring.PrioritizedFinding) (*remediation.RemediationResult, error) {
	startTime := time.Now()
	result := &remediation.RemediationResult{
		FindingID:  finding.Finding.ID,
		ResourceID: finding.Finding.ResourceID,
		StartedAt:  startTime,
		Actions:    []string{},
	}

	if d.client == nil {
		return nil, fmt.Errorf("kubernetes client not configured")
	}

	ns, name := extractK8sResource(finding.Finding.ResourceID)

	patch := map[string]interface{}{
		"spec": map[string]interface{}{
			"template": map[string]interface{}{
				"spec": map[string]interface{}{
					"hostPID":     false,
					"hostNetwork": false,
					"containers": []map[string]interface{}{
						{
							"name": name,
							"securityContext": map[string]interface{}{
								"privileged":               false,
								"allowPrivilegeEscalation": false,
								"runAsNonRoot":             true,
							},
						},
					},
				},
			},
		},
	}

	patchBytes, err := json.Marshal(patch)
	if err != nil {
		return nil, fmt.Errorf("marshaling patch: %w", err)
	}

	err = d.client.PatchPodSecurityContext(ctx, ns, name, patchBytes)
	if err != nil {
		result.CompletedAt = time.Now()
		result.Duration = time.Since(startTime).String()
		result.Error = err.Error()
		return result, fmt.Errorf("patching pod security context for %s/%s: %w", ns, name, err)
	}

	result.Actions = append(result.Actions,
		fmt.Sprintf("Disabled privileged mode on %s/%s", ns, name),
		"Set allowPrivilegeEscalation=false",
		"Set runAsNonRoot=true",
		"Disabled hostPID and hostNetwork",
	)
	result.CompletedAt = time.Now()
	result.Duration = time.Since(startTime).String()
	result.Success = true
	result.Message = fmt.Sprintf("Privileged container hardened: %s/%s", ns, name)
	return result, nil
}

// Validate verifies that privileged mode is disabled.
func (d *DisablePrivilegedPodsRemediator) Validate(ctx context.Context, finding *cspmscoring.PrioritizedFinding) (*remediation.ValidationResult, error) {
	validation := &remediation.ValidationResult{
		FindingID:   finding.Finding.ID,
		ValidatedAt: time.Now(),
		Evidence:    []string{},
	}

	if d.client == nil {
		return nil, fmt.Errorf("kubernetes client not configured")
	}

	ns, name := extractK8sResource(finding.Finding.ResourceID)
	info, err := d.client.GetPodSecurityPolicy(ctx, ns, name)
	if err != nil {
		return nil, fmt.Errorf("validating pod security: %w", err)
	}

	if info.Privileged || info.RunAsRoot || info.HostPID || info.HostNet {
		validation.IsCompliant = false
		validation.Message = fmt.Sprintf("Pod %s/%s still has elevated privileges", ns, name)
		validation.Evidence = append(validation.Evidence,
			fmt.Sprintf("privileged=%t, runAsRoot=%t, hostPID=%t, hostNetwork=%t",
				info.Privileged, info.RunAsRoot, info.HostPID, info.HostNet),
		)
		return validation, nil
	}

	validation.IsCompliant = true
	validation.Message = fmt.Sprintf("Pod %s/%s hardened: no privileged access", ns, name)
	validation.Evidence = append(validation.Evidence, "All privilege escalation vectors disabled")
	return validation, nil
}

// DryRun simulates disabling privileged mode without making changes.
func (d *DisablePrivilegedPodsRemediator) DryRun(ctx context.Context, finding *cspmscoring.PrioritizedFinding) (*remediation.DryRunResult, error) {
	ns, name := extractK8sResource(finding.Finding.ResourceID)
	return &remediation.DryRunResult{
		FindingID:        finding.Finding.ID,
		WouldSucceed:     true,
		PrerequisitesMet: d.client != nil,
		PlannedActions: []string{
			fmt.Sprintf("Would set securityContext.privileged=false on %s/%s", ns, name),
			"Would set allowPrivilegeEscalation=false",
			"Would set runAsNonRoot=true",
			"Would disable hostPID and hostNetwork",
		},
		EstimatedImpact: "Pod will be restarted. Workloads requiring host access (node exporters, CNI plugins) will fail.",
		Warnings:        []string{"Verify workload does not require privileged access before applying"},
	}, nil
}

// extractK8sResource splits a resource ID into namespace and name.
// Expected format: "namespace/resource-name" or just "resource-name" (default namespace).
func extractK8sResource(resourceID string) (namespace, name string) {
	parts := splitLast(resourceID, "/")
	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	return "default", resourceID
}

func splitLast(s, sep string) []string {
	for i := len(s) - 1; i >= 0; i-- {
		if string(s[i]) == sep {
			return []string{s[:i], s[i+1:]}
		}
	}
	return []string{s}
}
