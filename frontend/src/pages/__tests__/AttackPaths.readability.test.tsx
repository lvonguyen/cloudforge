import { beforeAll, beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, screen, waitFor } from '@testing-library/react'
import AttackPaths from '@/pages/ops/AttackPaths'
import { renderWithProviders } from '@/test/utils'
import { useAttackPaths, useAttackPathStats } from '@/hooks/useAttackPaths'
import type { AttackPath, AttackPathStats, PaginatedResponse } from '@/types/attack-path'

vi.mock('@/hooks/useAttackPaths', () => ({
  useAttackPaths: vi.fn(),
  useAttackPathStats: vi.fn(),
}))

const mockUseAttackPaths = vi.mocked(useAttackPaths)
const mockUseAttackPathStats = vi.mocked(useAttackPathStats)

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

const SAMPLE_RESPONSE: PaginatedResponse<AttackPath> = {
  data: [SAMPLE_PATH],
  page: 1,
  per_page: 20,
  total: 1,
  total_pages: 1,
}

const SAMPLE_STATS: AttackPathStats = {
  total_findings: 3,
  findings_in_paths: 3,
  isolated_findings: 0,
  coverage_percent: 100,
  total_paths: 1,
  critical_paths: 1,
  high_paths: 0,
  medium_paths: 0,
  by_provider: { aws: 1 },
}

beforeAll(() => {
  global.ResizeObserver = class {
    observe() {}
    unobserve() {}
    disconnect() {}
  }
})

beforeEach(() => {
  const storageState = new Map<string, string>()
  Object.defineProperty(window, 'localStorage', {
    configurable: true,
    value: {
      getItem: (key: string) => storageState.get(key) ?? null,
      setItem: (key: string, value: string) => { storageState.set(key, value) },
      removeItem: (key: string) => { storageState.delete(key) },
      clear: () => { storageState.clear() },
    },
  })
  window.localStorage.clear()
  document.documentElement.classList.remove('dark')

  mockUseAttackPaths.mockImplementation(() => ({
    data: SAMPLE_RESPONSE,
    isLoading: false,
    isError: false,
  }) as ReturnType<typeof useAttackPaths>)

  mockUseAttackPathStats.mockReturnValue(({
    data: SAMPLE_STATS,
  }) as ReturnType<typeof useAttackPathStats>)
})

describe('AttackPaths readability controls', () => {
  it('renders the local canvas tone controls on the overview page', () => {
    renderWithProviders(<AttackPaths />)

    expect(screen.getByText('Attack Paths')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /auto canvas/i })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /light canvas/i })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /dark canvas/i })).toBeInTheDocument()
  })

  it('applies and persists a local dark canvas selection in the detail view', async () => {
    renderWithProviders(<AttackPaths />)

    fireEvent.keyDown(document, { key: 'j' })

    const canvas = await screen.findByTestId('attack-path-canvas')
    expect(canvas).toHaveAttribute('data-canvas-tone', 'light')

    fireEvent.click(screen.getByRole('button', { name: /dark canvas/i }))

    await waitFor(() => expect(canvas).toHaveAttribute('data-canvas-tone', 'dark'))
    expect(window.localStorage.getItem('attack-path-canvas-tone')).toBe('dark')
  })

  it('supports keyboard navigation through paths and escape back to the overview', async () => {
    renderWithProviders(<AttackPaths />)

    expect(screen.queryByText('Finding References')).not.toBeInTheDocument()

    fireEvent.keyDown(document, { key: 'j' })

    expect(await screen.findByText('Finding References')).toBeInTheDocument()

    fireEvent.keyDown(document, { key: 'Escape' })

    await waitFor(() => {
      expect(screen.queryByText('Finding References')).not.toBeInTheDocument()
    })
  })
})
