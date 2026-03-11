import { describe, it, expect } from 'vitest'
import { generatePlan } from '../plan-templates'
import type { DeployPreviewConfig } from '@/types/deploy'

function baseConfig(overrides: Partial<DeployPreviewConfig> = {}): DeployPreviewConfig {
  return {
    resourceType: 's3',
    provider: 'aws',
    region: 'us-east-1',
    appId: 'testapp',
    configuration: {},
    ...overrides,
  }
}

describe('generatePlan', () => {
  it('s3: returns a plan with 3 resources (bucket, encryption, versioning)', () => {
    const plan = generatePlan(baseConfig({ resourceType: 's3' }))
    const resources = plan.planned_values.root_module.resources
    expect(resources).toHaveLength(3)
    const types = resources.map((r) => r.type)
    expect(types).toContain('aws_s3_bucket')
    expect(types).toContain('aws_s3_bucket_server_side_encryption_configuration')
    expect(types).toContain('aws_s3_bucket_versioning')
  })

  it('s3: all resources have create action', () => {
    const plan = generatePlan(baseConfig({ resourceType: 's3' }))
    for (const r of plan.planned_values.root_module.resources) {
      expect(r.change.actions).toContain('create')
      expect(r.change.before).toBeNull()
    }
  })

  it('ec2: returns a plan with instance and security group', () => {
    const plan = generatePlan(baseConfig({ resourceType: 'ec2' }))
    const resources = plan.planned_values.root_module.resources
    expect(resources).toHaveLength(2)
    const types = resources.map((r) => r.type)
    expect(types).toContain('aws_instance')
    expect(types).toContain('aws_security_group')
  })

  it('rds: returns a plan with db instance and subnet group', () => {
    const plan = generatePlan(baseConfig({ resourceType: 'rds' }))
    const resources = plan.planned_values.root_module.resources
    expect(resources).toHaveLength(2)
    const types = resources.map((r) => r.type)
    expect(types).toContain('aws_db_instance')
    expect(types).toContain('aws_db_subnet_group')
  })

  it('aks: returns azure kubernetes cluster resource', () => {
    const plan = generatePlan(baseConfig({ resourceType: 'aks', provider: 'azure' }))
    const resources = plan.planned_values.root_module.resources
    expect(resources).toHaveLength(1)
    expect(resources[0].type).toBe('azurerm_kubernetes_cluster')
  })

  it('gke: returns google container cluster resource', () => {
    const plan = generatePlan(baseConfig({ resourceType: 'gke', provider: 'gcp' }))
    const resources = plan.planned_values.root_module.resources
    expect(resources).toHaveLength(1)
    expect(resources[0].type).toBe('google_container_cluster')
  })

  it('unknown resource type falls back to s3 plan', () => {
    const plan = generatePlan(baseConfig({ resourceType: 'lambda' }))
    const resources = plan.planned_values.root_module.resources
    const types = resources.map((r) => r.type)
    expect(types).toContain('aws_s3_bucket')
  })

  it('plan always includes format_version and terraform_version', () => {
    for (const resourceType of ['s3', 'ec2', 'rds', 'aks', 'gke']) {
      const plan = generatePlan(baseConfig({ resourceType, provider: resourceType === 'aks' ? 'azure' : 'aws' }))
      expect(plan.format_version).toBe('1.2')
      expect(plan.terraform_version).toBe('1.9.8')
      expect(Array.isArray(plan.resource_changes)).toBe(true)
    }
  })

  it('s3: uses appId in bucket name', () => {
    const plan = generatePlan(baseConfig({ resourceType: 's3', appId: 'myapp' }))
    const bucket = plan.planned_values.root_module.resources.find((r) => r.type === 'aws_s3_bucket')
    expect(bucket).toBeDefined()
    const bucketName = bucket!.change.after.bucket as string
    expect(bucketName).toMatch(/^cf-demo-myapp-/)
  })
})
