import { beforeAll, beforeEach, describe, expect, it } from 'vitest'
import { act, screen, waitFor } from '@testing-library/react'
import { AttackPathMiniGraph } from '@/components/attack-path/AttackPathMiniGraph'
import { renderWithProviders } from '@/test/utils'
import type { AttackPath } from '@/types/attack-path'

const SAMPLE_PATH: AttackPath = {
  id: 'path-1',
  title: 'Public workload pivots to production database',
  description: 'An exposed container and over-permissive identity create a direct route into a production data plane.',
  severity: 'CRITICAL',
  score: 96,
  hop_count: 3,
  entry_point: {
    id: 'node-1',
    finding_id: 'f-001',
    resource_id: 'res-1',
    resource_name: 'public-api',
    resource_type: 'ecs_task',
    provider: 'aws',
    account_id: '111111111111',
    region: 'us-east-1',
    severity: 'CRITICAL',
    category: 'NETWORK',
    label: 'Public API',
  },
  target: {
    id: 'node-3',
    finding_id: 'f-003',
    resource_id: 'res-3',
    resource_name: 'prod-orders-db',
    resource_type: 'rds_instance',
    provider: 'aws',
    account_id: '111111111111',
    region: 'us-east-1',
    severity: 'HIGH',
    category: 'MISCONFIGURATION',
    label: 'Orders DB',
  },
  nodes: [
    {
      id: 'node-1',
      finding_id: 'f-001',
      resource_id: 'res-1',
      resource_name: 'public-api',
      resource_type: 'ecs_task',
      provider: 'aws',
      account_id: '111111111111',
      region: 'us-east-1',
      severity: 'CRITICAL',
      category: 'NETWORK',
      label: 'Public API',
    },
    {
      id: 'node-2',
      finding_id: 'f-002',
      resource_id: 'res-2',
      resource_name: 'orders-role',
      resource_type: 'iam_role',
      provider: 'aws',
      account_id: '111111111111',
      region: 'us-east-1',
      severity: 'HIGH',
      category: 'IDENTITY',
      label: 'Orders Role',
    },
    {
      id: 'node-3',
      finding_id: 'f-003',
      resource_id: 'res-3',
      resource_name: 'prod-orders-db',
      resource_type: 'rds_instance',
      provider: 'aws',
      account_id: '111111111111',
      region: 'us-east-1',
      severity: 'HIGH',
      category: 'MISCONFIGURATION',
      label: 'Orders DB',
    },
  ],
  edges: [
    { id: 'edge-1', source: 'node-1', target: 'node-2', label: 'assume-role', edge_type: 'assume_role' },
    { id: 'edge-2', source: 'node-2', target: 'node-3', label: 'db-access', edge_type: 'can_access' },
  ],
  mitre_tactics: ['TA0001', 'TA0003'],
  finding_ids: ['f-001', 'f-002', 'f-003'],
  ai_description: 'Validated attack path with chained exposure and privilege abuse.',
  ai_remediation: 'Remove internet ingress and tighten the role trust policy.',
  ai_likelihood: 'high',
  ai_confidence: 0.92,
  ai_validated: true,
  ai_risk_narrative: 'An external actor can move from public ingress into the database control plane.',
  ai_enriched: true,
}

beforeAll(() => {
  global.ResizeObserver = class {
    observe() {}
    unobserve() {}
    disconnect() {}
  }
})

beforeEach(() => {
  document.documentElement.classList.remove('dark')
})

describe('AttackPathMiniGraph', () => {
  it('renders the light canvas by default', () => {
    renderWithProviders(<AttackPathMiniGraph paths={[SAMPLE_PATH]} resourceId="res-1" />)

    expect(screen.getByText('Attack Path')).toBeInTheDocument()
    expect(screen.getAllByText('public-api').length).toBeGreaterThan(0)
    expect(screen.getAllByText('prod-orders-db').length).toBeGreaterThan(0)
    expect(screen.getByText(/1 privilege hop/i)).toBeInTheDocument()
    expect(screen.getByText(/1 crown jewel/i)).toBeInTheDocument()
    expect(document.querySelector('[data-canvas-tone="light"]')).toBeTruthy()
  })

  it('reacts to document dark mode changes', async () => {
    renderWithProviders(<AttackPathMiniGraph paths={[SAMPLE_PATH]} resourceId="res-1" />)

    act(() => {
      document.documentElement.classList.add('dark')
    })

    await waitFor(() => {
      expect(document.querySelector('[data-canvas-tone="dark"]')).toBeTruthy()
    })
  })
})
