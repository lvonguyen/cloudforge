import { z } from 'zod'
import type { PolicyResult } from '@/types/policy'

export interface RequestCatalogItem {
  id: string
  name: string
  description: string
  provider: string
  resourceType: string
  estimatedMonthlyCost?: string
  icon_path?: string
}

export const REGIONS: Record<string, string[]> = {
  aws: ['us-east-1', 'us-west-2', 'eu-west-1', 'ap-southeast-1', 'ap-northeast-1'],
  azure: ['eastus', 'westus2', 'westeurope', 'southeastasia'],
  gcp: ['us-central1', 'us-east1', 'europe-west1', 'asia-southeast1'],
}

export const SERVICE_MODELS = ['IaaS', 'PaaS', 'SaaS'] as const

export const step1Schema = z.object({
  resourceId: z.string().min(1, 'Select a resource type'),
  cloudProvider: z.string().min(1, 'Select a cloud provider'),
  region: z.string().min(1, 'Select a region'),
  serviceModel: z.string().min(1, 'Select a service model'),
})

export const step2BaseSchema = z.object({
  applicationId: z.string().min(1, 'Application ID is required'),
  tagTeam: z.string().min(1, 'Team tag is required'),
  tagCostCenter: z.string().min(1, 'Cost center is required'),
  tagEnvironment: z.enum(['dev', 'staging', 'prod']),
})

export type Step1Values = z.infer<typeof step1Schema>

export const GENERIC_SKUS = [
  { id: 'small', name: 'Small', description: 'Dev/test workloads', cost: '$5–$50/mo' },
  { id: 'medium', name: 'Medium', description: 'Staging and light production', cost: '$50–$200/mo' },
  { id: 'large', name: 'Large', description: 'Production workloads', cost: '$200–$1,000/mo' },
  { id: 'xlarge', name: 'X-Large', description: 'High-performance and data-intensive', cost: '$1,000+/mo' },
]

export const MOCK_POLICY_RESULT: PolicyResult = {
  allowed: false,
  denials: [
    {
      code: 'REGION-001',
      message: 'ap-southeast-3 not in approved regions',
      severity: 'high',
      remediation: 'Use us-east-1, eu-west-1, or ap-southeast-1',
    },
  ],
  warnings: [
    {
      code: 'COST-002',
      message: 't3.2xlarge exceeds standard size (t3.large)',
      severity: 'medium',
      remediation: 'Requires business justification + manager approval',
    },
  ],
  suggestions: ['Add required tags: team, cost-center'],
}
