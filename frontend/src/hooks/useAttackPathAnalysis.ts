import { useQuery } from '@tanstack/react-query'
import { apiClient, ApiError } from '@/lib/api'

export interface BlastRadius {
  direct: number
  indirect: number
  total: number
}

export interface AttackPathAnalysis {
  analysis: string
  remediation_steps: string[]
  risk_factors: string[]
  blast_radius: BlastRadius
}

const MOCK_ANALYSIS: AttackPathAnalysis = {
  analysis:
    'This CRITICAL-severity attack path spans 4 resources across 3 lateral movement steps. ' +
    'The entry point is a publicly exposed EC2 instance (AWS/us-east-1) with an overly permissive ' +
    'security group allowing inbound traffic on port 22. An attacker could leverage compromised SSH ' +
    'credentials to pivot through an IAM role with cross-account AssumeRole permissions, ultimately ' +
    'reaching an S3 bucket containing sensitive PII data.',
  remediation_steps: [
    'Restrict security group ingress to known CIDR ranges and remove 0.0.0.0/0 on port 22',
    'Apply least-privilege IAM policies — scope AssumeRole to specific resource ARNs',
    'Enable GuardDuty runtime threat detection on the affected AWS account',
    'Rotate credentials for the IAM role used in the lateral movement chain',
  ],
  risk_factors: [
    'Entry point has public-facing exposure with unrestricted SSH access',
    'Cross-account IAM role trust policy allows broad principal access',
    'Target S3 bucket lacks server-side encryption and versioning',
  ],
  blast_radius: {
    direct: 4,
    indirect: 8,
    total: 12,
  },
}

export function useAttackPathAnalysis(pathId: string) {
  return useQuery({
    queryKey: ['attack-paths', pathId, 'analysis'],
    queryFn: async () => {
      try {
        return await apiClient.get<AttackPathAnalysis>(`/attack-paths/${pathId}/analysis`)
      } catch (err) {
        if (err instanceof ApiError && err.status < 500) throw err
        if (import.meta.env.PROD && import.meta.env.VITE_DEMO_MODE !== 'true') throw err
        console.warn('[useAttackPathAnalysis] API unavailable, using mock data')
        return MOCK_ANALYSIS
      }
    },
    enabled: Boolean(pathId),
  })
}
