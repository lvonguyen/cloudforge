import { describe, expect, it } from 'vitest'
import { inferAttackPathThreatContextSignals, inferFindingThreatContextSignals } from '@/lib/threat-context'
import type { AttackPath } from '@/types/attack-path'
import type { Finding } from '@/types/compliance'

const BASE_FINDING: Finding = {
  id: 'finding-1',
  source: 'prowler',
  source_finding_id: 'prowler-1',
  type: 'misconfiguration',
  title: 'Open security group on database subnet',
  description: 'Database is reachable from 0.0.0.0/0 through a permissive security group.',
  resource_type: 'database',
  resource_id: 'db-1',
  resource_name: 'orders-db',
  platform: 'aws',
  cloud_provider: 'aws',
  region: 'us-east-1',
  account_id: '111111111111',
  environment_type: 'production',
  static_severity: 'HIGH',
  severity: 'HIGH',
  ai_risk_score: 8,
  ai_risk_level: 'high',
  ai_risk_rationale: 'Database has public ingress.',
  ai_contextual_factors: [],
  exploit_available: false,
  remediation: 'Restrict inbound access.',
  auto_remediatable: false,
  category: 'NETWORK',
  status: 'open',
  workflow_status: 'triaged',
  suppressed: false,
  service_name: 'orders',
  line_of_business: 'commerce',
  first_found_at: '2026-04-06T00:00:00Z',
  last_seen_at: '2026-04-06T00:00:00Z',
  deduplication_key: 'dedup-1',
  canonical_rule_id: 'NETWORK-001',
}

const BASE_PATH: AttackPath = {
  id: 'path-1',
  title: 'Public workload reaches orders database',
  description: 'Public ingress pivots to an internal data store.',
  severity: 'CRITICAL',
  score: 95,
  hop_count: 2,
  entry_point: {
    id: 'node-1',
    finding_id: 'finding-1',
    resource_id: 'api-1',
    resource_name: 'public-api',
    resource_type: 'compute',
    provider: 'aws',
    account_id: '111111111111',
    region: 'us-east-1',
    severity: 'CRITICAL',
    category: 'NETWORK',
    label: 'Public API',
  },
  target: {
    id: 'node-2',
    finding_id: 'finding-2',
    resource_id: 'db-1',
    resource_name: 'orders-db',
    resource_type: 'database',
    provider: 'aws',
    account_id: '111111111111',
    region: 'us-east-1',
    severity: 'HIGH',
    category: 'DATABASE',
    label: 'Orders DB',
  },
  nodes: [
    {
      id: 'node-1',
      finding_id: 'finding-1',
      resource_id: 'api-1',
      resource_name: 'public-api',
      resource_type: 'compute',
      provider: 'aws',
      account_id: '111111111111',
      region: 'us-east-1',
      severity: 'CRITICAL',
      category: 'NETWORK',
      label: 'Public API',
    },
    {
      id: 'node-2',
      finding_id: 'finding-2',
      resource_id: 'db-1',
      resource_name: 'orders-db',
      resource_type: 'database',
      provider: 'aws',
      account_id: '111111111111',
      region: 'us-east-1',
      severity: 'HIGH',
      category: 'DATABASE',
      label: 'Orders DB',
    },
  ],
  edges: [
    { id: 'edge-1', source: 'node-1', target: 'node-2', label: 'db-access', edge_type: 'can_access' },
  ],
  mitre_tactics: ['TA0001'],
  finding_ids: ['finding-1'],
  ai_enriched: false,
}

describe('threat-context inference', () => {
  it('infers exposure and network controls from heuristic finding text', () => {
    const signals = inferFindingThreatContextSignals(BASE_FINDING)

    expect(signals.exposureSurface?.label).toBe('Public internet')
    expect(signals.networkBoundary?.label).toBe('Security group / subnet')
  })

  it('prefers explicit network metadata over heuristic labels when present', () => {
    const signals = inferAttackPathThreatContextSignals(
      {
        ...BASE_PATH,
        entry_point: {
          ...BASE_PATH.entry_point,
          internet_facing: true,
          network_boundary: 'NSG: app-ingress-prod',
        },
        entry_point_type: 'internet',
      },
      [{
        ...BASE_FINDING,
        internet_facing: true,
        subnet: 'subnet-private-app-a',
      }],
    )

    expect(signals.exposureSurface?.detail).toMatch(/reported directly/i)
    expect(signals.networkBoundary?.label).toBe('NSG: app-ingress-prod')
  })
})
