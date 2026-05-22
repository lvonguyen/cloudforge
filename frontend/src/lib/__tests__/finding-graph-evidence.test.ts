import { describe, expect, it } from 'vitest'
import { deriveFindingGraphEvidence } from '@/lib/finding-graph-evidence'
import type { AttackPath } from '@/types/attack-path'
import type { Finding } from '@/types/compliance'

const finding = {
  id: 'f-storage-1',
  resource_id: 'bucket-prod-1',
  resource_name: 'prod-invoices',
  resource_type: 's3_bucket',
  cloud_provider: 'aws',
  account_id: '111111111111',
  category: 'STORAGE',
} as Finding

const attackPath = {
  id: 'path-1',
  title: 'Invoice OCR reaches archive bucket',
  description: 'Storage-adjacent graph evidence exists in the same account.',
  severity: 'HIGH',
  score: 82,
  hop_count: 2,
  entry_point: {
    id: 'node-entry',
    finding_id: 'f-network-1',
    resource_id: 'api-public-1',
    resource_name: 'public-api',
    resource_type: 'ecs_task',
    provider: 'aws',
    account_id: '111111111111',
    region: 'us-east-1',
    severity: 'HIGH',
    category: 'NETWORK',
    label: 'Public API',
  },
  target: {
    id: 'node-target',
    finding_id: 'f-storage-2',
    resource_id: 'bucket-prod-2',
    resource_name: 'prod-invoice-archive',
    resource_type: 's3_bucket',
    provider: 'aws',
    account_id: '111111111111',
    region: 'us-east-1',
    severity: 'HIGH',
    category: 'STORAGE',
    label: 'Invoice archive',
  },
  nodes: [
    {
      id: 'node-entry',
      finding_id: 'f-network-1',
      resource_id: 'api-public-1',
      resource_name: 'public-api',
      resource_type: 'ecs_task',
      provider: 'aws',
      account_id: '111111111111',
      region: 'us-east-1',
      severity: 'HIGH',
      category: 'NETWORK',
      label: 'Public API',
    },
    {
      id: 'node-target',
      finding_id: 'f-storage-2',
      resource_id: 'bucket-prod-2',
      resource_name: 'prod-invoice-archive',
      resource_type: 's3_bucket',
      provider: 'aws',
      account_id: '111111111111',
      region: 'us-east-1',
      severity: 'HIGH',
      category: 'STORAGE',
      label: 'Invoice archive',
    },
  ],
  edges: [{ id: 'edge-1', source: 'node-entry', target: 'node-target', label: 'read-access', edge_type: 'can_access' }],
  mitre_tactics: ['TA0009'],
  finding_ids: ['f-network-1', 'f-storage-2'],
  ai_enriched: true,
} as AttackPath

describe('deriveFindingGraphEvidence', () => {
  it('summarizes nearby same-account graph evidence when no direct path includes the finding', () => {
    const evidence = deriveFindingGraphEvidence(finding, [attackPath])

    expect(evidence.linkedPathCount).toBe(0)
    expect(evidence.nearbyNodeCount).toBe(1)
    expect(evidence.pathCount).toBe(1)
    expect(evidence.label).toBe('Graph evidence nearby')
    expect(evidence.detail).toMatch(/1 neighboring graph signal/i)
    expect(evidence.detail).toMatch(/same account and provider/i)
  })

  it('does not count nodes from other accounts as nearby evidence', () => {
    const otherAccountPath = {
      ...attackPath,
      id: 'path-2',
      target: { ...attackPath.target, account_id: '222222222222' },
      nodes: attackPath.nodes.map(node => ({ ...node, account_id: '222222222222' })),
    } as AttackPath

    const evidence = deriveFindingGraphEvidence(finding, [otherAccountPath])

    expect(evidence.nearbyNodeCount).toBe(0)
    expect(evidence.label).toBe('No graph neighborhood')
  })
})
