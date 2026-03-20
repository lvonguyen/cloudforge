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
