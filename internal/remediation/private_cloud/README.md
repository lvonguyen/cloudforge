# Private Cloud Remediation Domain

This domain handles security remediations for private/on-premises infrastructure.

## Supported Platforms

- **VMware vSphere** - ESXi hosts, vCenter, NSX
- **OpenStack** - Nova, Neutron, Cinder security configurations
- **Proxmox VE** - Hypervisor and container security
- **Hyper-V** - Microsoft virtualization platform
- **On-Prem Kubernetes** - Self-hosted K8s clusters (non-EKS/AKS/GKE)

## Example Finding Types

| Finding Type | Description | Tier |
|--------------|-------------|------|
| `VMWARE_ESXI_SSH_ENABLED` | ESXi SSH service enabled (should be disabled) | 1 |
| `VMWARE_WEAK_PASSWORD_POLICY` | vCenter password policy too weak | 2 |
| `OPENSTACK_DEFAULT_CREDENTIALS` | Default admin credentials detected | 1 |
| `KUBERNETES_PRIVILEGED_POD` | Privileged pod running in non-system namespace | 2 |
| `PROXMOX_UNENCRYPTED_BACKUP` | Backup storage not encrypted | 3 |

## Remediation Patterns

### VMware ESXi SSH Remediation (Tier 1)
```go
type ESXiSSHRemediator struct {
    tier int
}

func (e *ESXiSSHRemediator) Remediate(ctx context.Context, finding *findings.PrioritizedFinding) (*remediation.RemediationResult, error) {
    // Connect to ESXi host via vSphere API
    // Disable SSH service
    // Verify service stopped
}
```

### On-Prem Kubernetes Privileged Pod (Tier 2)
```go
type K8sPrivilegedPodRemediator struct {
    tier int
}

func (k *K8sPrivilegedPodRemediator) Remediate(ctx context.Context, finding *findings.PrioritizedFinding) (*remediation.RemediationResult, error) {
    // Connect to K8s cluster
    // Create PodSecurityPolicy or Pod Security Standard
    // Update pod spec to remove privileged: true
    // Restart pod
}
```

## Integration with Cloud Providers

Some private cloud findings may overlap with public cloud:
- **Hybrid Kubernetes**: EKS/AKS/GKE vs on-prem K8s
- **VMware Cloud**: vSphere on-prem vs VMware Cloud on AWS
- **Azure Stack**: On-prem Azure vs public Azure

Use finding metadata (`EnvType`, `DataCenter`) to route correctly.

## Authentication

Private cloud remediations typically use:
- **VMware**: vSphere API credentials from env vars or secret manager
- **OpenStack**: Keystone auth tokens
- **Kubernetes**: kubeconfig or in-cluster service account
- **Proxmox**: API tokens

Store credentials in:
- AWS Secrets Manager (for cloud-hosted aggregator)
- Azure Key Vault
- HashiCorp Vault (for on-prem aggregator)
