import { useQuery } from '@tanstack/react-query'
import { apiClient, ApiError, fetchWithMockFallback } from '@/lib/api'

export interface PostureFramework {
  id: string
  name: string
  version: string
  description: string
  sector: string
  controls: number
}

export interface ComplianceControl {
  id: string
  title: string
  description: string
  section: string
  category: string
  severity: string
  keywords: string[]
}

const MOCK_POSTURE: PostureFramework[] = [
  { id: 'cis-benchmarks', name: 'CIS Benchmarks', version: '3.0', description: 'Center for Internet Security cloud configuration baselines', sector: 'general', controls: 142 },
  { id: 'nist-csf', name: 'NIST CSF', version: '2.0', description: 'NIST Cybersecurity Framework for critical infrastructure', sector: 'general', controls: 108 },
  { id: 'iso-27001', name: 'ISO 27001', version: '2022', description: 'Information security management system requirements', sector: 'general', controls: 93 },
  { id: 'cmmc-l2', name: 'CMMC Level 2', version: '2.0', description: 'Defense Industrial Base practice set mapped to CUI protection evidence', sector: 'government', controls: 110 },
  { id: 'nist-800-171', name: 'NIST SP 800-171', version: 'Rev. 3', description: 'Security requirements for CUI in nonfederal systems and organizations', sector: 'government', controls: 97 },
  { id: 'fedramp-high', name: 'FedRAMP High', version: 'Rev. 5', description: 'Cloud authorization and continuous monitoring baseline for high-impact systems', sector: 'government', controls: 421 },
  { id: 'dod-srg', name: 'DoD Cloud SRG', version: 'IL4/IL5', description: 'DoD cloud impact-level readiness for mission and controlled-data workloads', sector: 'government', controls: 152 },
  { id: 'itar-ear', name: 'ITAR/EAR Boundary', version: 'Demo', description: 'Export-control-aware labeling, access boundary, and artifact handling checks', sector: 'government', controls: 32 },
]

const MOCK_CONTROLS: Record<string, ComplianceControl[]> = {
  'cis-benchmarks': [
    { id: 'CIS-1.1', title: 'Ensure MFA is enabled for all IAM users', description: 'Multi-factor authentication adds a layer of protection on top of a username and password.', section: '1. Identity and Access Management', category: 'identity', severity: 'HIGH', keywords: ['mfa', 'iam', 'authentication'] },
    { id: 'CIS-1.2', title: 'Ensure credentials unused for 90 days are disabled', description: 'AWS IAM users can access resources using different types of credentials.', section: '1. Identity and Access Management', category: 'identity', severity: 'MEDIUM', keywords: ['credentials', 'rotation'] },
    { id: 'CIS-2.1', title: 'Ensure CloudTrail is enabled in all regions', description: 'AWS CloudTrail is a web service that records AWS API calls in your account.', section: '2. Logging', category: 'logging', severity: 'HIGH', keywords: ['cloudtrail', 'logging', 'audit'] },
    { id: 'CIS-3.1', title: 'Ensure VPC Flow Logs are enabled', description: 'VPC Flow Logs capture information about IP traffic going to and from network interfaces.', section: '3. Networking', category: 'network', severity: 'MEDIUM', keywords: ['vpc', 'flow-logs', 'network'] },
    { id: 'CIS-4.1', title: 'Ensure no security groups allow ingress from 0.0.0.0/0', description: 'Security groups provide stateful filtering of ingress/egress traffic.', section: '4. Monitoring', category: 'network', severity: 'CRITICAL', keywords: ['security-groups', 'ingress', 'firewall'] },
  ],
  'nist-csf': [
    { id: 'ID.AM-1', title: 'Physical devices and systems are inventoried', description: 'Organization inventories physical devices and systems within its environment.', section: 'Identify', category: 'asset-management', severity: 'MEDIUM', keywords: ['inventory', 'assets'] },
    { id: 'PR.AC-1', title: 'Identities and credentials are issued and managed', description: 'Credentials for authorized devices, users, and processes are managed.', section: 'Protect', category: 'access-control', severity: 'HIGH', keywords: ['identity', 'credentials'] },
    { id: 'DE.CM-1', title: 'The network is monitored to detect potential cybersecurity events', description: 'Monitoring of the network for anomalous activity.', section: 'Detect', category: 'monitoring', severity: 'HIGH', keywords: ['network', 'monitoring', 'detection'] },
  ],
  'iso-27001': [
    { id: 'A.5.1', title: 'Policies for information security', description: 'A set of policies for information security shall be defined, approved by management.', section: 'A.5 Information Security Policies', category: 'governance', severity: 'MEDIUM', keywords: ['policies', 'governance'] },
    { id: 'A.8.1', title: 'Inventory of assets', description: 'Assets associated with information and information processing facilities shall be identified.', section: 'A.8 Asset Management', category: 'asset-management', severity: 'MEDIUM', keywords: ['assets', 'inventory'] },
  ],
  'cmmc-l2': [
    { id: 'AC.L2-3.1.1', title: 'Limit system access to authorized users', description: 'Access to systems, accounts, and services is scoped to authorized users and service identities.', section: 'Access Control', category: 'identity', severity: 'HIGH', keywords: ['rbac', 'least-privilege', 'conditional-access'] },
    { id: 'AU.L2-3.3.1', title: 'Create and retain system audit logs', description: 'Security-relevant events are captured, retained, protected, and reviewable.', section: 'Audit and Accountability', category: 'logging', severity: 'HIGH', keywords: ['audit', 'centralized-logging', 'retention'] },
    { id: 'CM.L2-3.4.2', title: 'Establish baseline configurations', description: 'Secure baselines are defined, enforced, and monitored for cloud and endpoint assets.', section: 'Configuration Management', category: 'configuration', severity: 'MEDIUM', keywords: ['baseline', 'stig', 'drift'] },
    { id: 'SC.L2-3.13.16', title: 'Protect CUI at rest', description: 'Data-at-rest controls are enforced for systems that process, store, or transmit CUI.', section: 'System and Communications Protection', category: 'data-protection', severity: 'HIGH', keywords: ['cui', 'encryption', 'kms'] },
  ],
  'nist-800-171': [
    { id: '03.01.02', title: 'Limit information system access', description: 'Access enforcement is tied to users, processes, service accounts, and devices.', section: 'Access Control', category: 'identity', severity: 'HIGH', keywords: ['access', 'service-account', 'device'] },
    { id: '03.05.03', title: 'Use multifactor authentication', description: 'Privileged and non-privileged remote access requires MFA appropriate to risk.', section: 'Identification and Authentication', category: 'identity', severity: 'HIGH', keywords: ['mfa', 'phishing-resistant', 'sso'] },
    { id: '03.12.04', title: 'Develop and update system security plans', description: 'System boundaries, environments, and protection assets are documented and kept current.', section: 'Security Assessment', category: 'governance', severity: 'MEDIUM', keywords: ['ssp', 'boundary', 'evidence'] },
  ],
  'fedramp-high': [
    { id: 'AU-9', title: 'Protection of audit information', description: 'Audit data is protected from unauthorized access, modification, and deletion.', section: 'Audit and Accountability', category: 'logging', severity: 'HIGH', keywords: ['immutable-logs', 'audit', 'retention'] },
    { id: 'CM-6', title: 'Configuration settings', description: 'Hardened settings are established, monitored, and remediated across cloud assets.', section: 'Configuration Management', category: 'configuration', severity: 'HIGH', keywords: ['baseline', 'drift', 'policy-as-code'] },
    { id: 'IR-4', title: 'Incident handling', description: 'Incident handling procedures are integrated with alerting, triage, escalation, and evidence capture.', section: 'Incident Response', category: 'incident-response', severity: 'MEDIUM', keywords: ['ir', 'runbook', 'evidence'] },
  ],
  'dod-srg': [
    { id: 'SRG-IL4-NET-01', title: 'Restrict enclave ingress paths', description: 'Mission enclave ingress is limited to approved VPN, ZTNA, or controlled service endpoints.', section: 'Network Security', category: 'network', severity: 'HIGH', keywords: ['enclave', 'vpn', 'ztna'] },
    { id: 'SRG-IL5-LOG-02', title: 'Centralize audit telemetry', description: 'Cloud control-plane, identity, and workload logs are centralized for operations review.', section: 'Monitoring', category: 'logging', severity: 'HIGH', keywords: ['cloudtrail', 'sentinel', 'siem'] },
  ],
  'itar-ear': [
    { id: 'EXP-01', title: 'Restricted data label required', description: 'Build artifacts and object storage paths carrying restricted labels require an explicit release gate.', section: 'Export-Control Boundary', category: 'data-protection', severity: 'HIGH', keywords: ['itar', 'ear', 'artifact'] },
    { id: 'EXP-02', title: 'Commercial workspace upload guardrail', description: 'Commercial SaaS upload paths block files tagged as synthetic CUI or export-controlled data.', section: 'Collaboration Controls', category: 'data-protection', severity: 'MEDIUM', keywords: ['cui', 'gcc-high', 'classification'] },
  ],
}

export function useCompliancePosture() {
  return useQuery({
    queryKey: ['compliance', 'posture'],
    queryFn: () => fetchWithMockFallback<PostureFramework[]>(
      '/compliance/posture',
      () => Promise.resolve({ default: MOCK_POSTURE }),
      'useCompliancePosture',
    ),
  })
}

export function useComplianceControls(frameworkId: string) {
  return useQuery({
    queryKey: ['compliance', 'controls', frameworkId],
    queryFn: async () => {
      try {
        return await apiClient.get<ComplianceControl[]>(`/compliance/controls/${frameworkId}`)
      } catch (err) {
        if (err instanceof ApiError && err.status < 500) throw err
        console.warn('[useComplianceControls] API unavailable, using mock data')
        return MOCK_CONTROLS[frameworkId] ?? []
      }
    },
    enabled: Boolean(frameworkId),
  })
}
