import { beforeAll, beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, screen, waitFor, within } from '@testing-library/react'
import type { ReactNode } from 'react'
import AttackPaths from '@/pages/ops/AttackPaths'
import { renderWithProviders } from '@/test/utils'
import { useAttackPaths, useAttackPathStats } from '@/hooks/useAttackPaths'
import { useFindingsByIds } from '@/hooks/useFindings'
import type { Finding } from '@/types/compliance'
import type { AttackPath, AttackPathStats, PaginatedResponse } from '@/types/attack-path'

vi.mock('@xyflow/react', () => ({
  ReactFlow: ({
    children,
    nodes = [],
    edges = [],
  }: {
    children?: ReactNode
    nodes?: Array<{ id: string; data?: { label?: ReactNode } }>
    edges?: Array<{ id: string; label?: ReactNode }>
  }) => (
    <div data-testid="reactflow-mock">
      {nodes.map(node => (
        <div key={node.id} data-testid={`mock-node-${node.id}`}>
          {node.data?.label}
        </div>
      ))}
      {edges.map(edge => (
        <div key={edge.id} data-testid={`mock-edge-${edge.id}`}>
          {edge.label}
        </div>
      ))}
      {children}
    </div>
  ),
  Background: () => null,
  Controls: () => <div data-testid="reactflow-controls-mock" />,
  Position: { Left: 'left', Right: 'right', Top: 'top', Bottom: 'bottom' },
  MarkerType: { ArrowClosed: 'arrowclosed' },
}))

vi.mock('@/hooks/useAttackPaths', () => ({
  useAttackPaths: vi.fn(),
  useAttackPathStats: vi.fn(),
}))

vi.mock('@/hooks/useFindings', () => ({
  useFindingsByIds: vi.fn(),
}))

const mockUseAttackPaths = vi.mocked(useAttackPaths)
const mockUseAttackPathStats = vi.mocked(useAttackPathStats)
const mockUseFindingsByIds = vi.mocked(useFindingsByIds)

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

const SAMPLE_FINDING: Finding = {
  id: 'f-001',
  source: 'prowler',
  source_finding_id: 'prowler-123',
  type: 'vulnerability',
  title: 'Public workload can reach sensitive orders database',
  description: 'A public-facing workload can pivot into a production database through an over-privileged role.',
  resource_type: 'database',
  resource_id: 'res-db-1',
  resource_name: 'prod-orders-db',
  platform: 'aws',
  cloud_provider: 'aws',
  region: 'us-east-1',
  account_id: '111111111111',
  account_name: 'production',
  environment_type: 'production',
  static_severity: 'HIGH',
  severity: 'HIGH',
  ai_risk_score: 8.7,
  ai_risk_level: 'high',
  ai_risk_rationale: 'Public exposure plus privilege pivot creates a credible lateral path into regulated data.',
  ai_contextual_factors: ['public entry', 'privilege escalation', 'sensitive data'],
  exploit_available: true,
  remediation: 'Remove public reachability and tighten trust policy on the intermediate role.',
  remediation_steps: [
    {
      order: 1,
      title: 'Remove public ingress',
      description: 'Restrict inbound access to approved CIDRs and private paths.',
      automated: false,
    },
    {
      order: 2,
      title: 'Reduce IAM trust',
      description: 'Limit the role trust policy and remove broad sts:AssumeRole permissions.',
      automated: false,
    },
  ],
  auto_remediatable: false,
  category: 'DATABASE',
  status: 'open',
  workflow_status: 'assigned',
  suppressed: false,
  service_name: 'orders',
  line_of_business: 'commerce',
  first_found_at: '2026-03-29T01:00:00Z',
  last_seen_at: '2026-03-30T02:00:00Z',
  due_date: '2026-04-05T00:00:00Z',
  deduplication_key: 'ddb-key',
  canonical_rule_id: 'db-public-access',
  cves: [
    {
      id: 'CVE-2026-0001',
      url: 'https://example.com/cve-2026-0001',
      nvd_url: 'https://nvd.nist.gov/vuln/detail/CVE-2026-0001',
      mitre_url: 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-0001',
      description: 'Remote issue in supporting workload',
      cvss: 9.1,
      cvss_vector: 'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
      cvss_version: '3.1',
      epss: 0.91,
      cisa_known_exploited: true,
      published: '2026-03-01T00:00:00Z',
      modified: '2026-03-05T00:00:00Z',
    },
  ],
  toxic_combo_details: {
    combo_type: 'public_db_chain',
    description: 'Internet exposure plus privilege pivot reaches sensitive data.',
    related_findings: ['f-001', 'f-002'],
    attack_vector: 'network',
    attack_path: ['public-api', 'orders-role', 'prod-orders-db'],
    exploit_potential: 'high',
    blast_radius: 'high',
    mitre_techniques: ['T1190'],
  },
} as Finding

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

  mockUseFindingsByIds.mockReturnValue(({
    queries: [],
    data: [SAMPLE_FINDING],
    isLoading: false,
    isError: false,
  }) as ReturnType<typeof useFindingsByIds>)
})

describe('AttackPaths readability controls', () => {
  it('renders the local canvas tone controls on the overview page', () => {
    renderWithProviders(<AttackPaths />)

    expect(screen.getByText('Attack Paths')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /auto canvas/i })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /light canvas/i })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /dark canvas/i })).toBeInTheDocument()
  }, 10_000)

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
    expect(screen.getAllByText(/privilege escalation/i).length).toBeGreaterThan(0)
    expect(screen.getAllByText(/crown jewel/i).length).toBeGreaterThan(0)

    fireEvent.keyDown(document, { key: 'Escape' })

    await waitFor(() => {
      expect(screen.queryByText('Finding References')).not.toBeInTheDocument()
    })
  })

  it('surfaces analyst detail cues for remediation and finding context', async () => {
    renderWithProviders(<AttackPaths />)

    fireEvent.keyDown(document, { key: 'j' })

    expect(await screen.findByLabelText(/score 96 out of 100/i)).toBeInTheDocument()
    expect(screen.getByText(/ai remediation/i)).toBeInTheDocument()
    expect(screen.getAllByText(/remove internet ingress and tighten the role trust policy/i).length).toBeGreaterThan(0)
    expect(screen.getByText(/1 privesc hop/i)).toBeInTheDocument()
    expect(screen.getAllByText(/crown jewel/i).length).toBeGreaterThan(0)
    expect(within(screen.getByTestId('mock-edge-edge-1')).getByText(/hop 1: privilege escalation/i)).toBeInTheDocument()
    expect(within(screen.getByTestId('mock-edge-edge-2')).getByText(/hop 2: data access/i)).toBeInTheDocument()
    expect(within(screen.getByTestId('mock-node-node-1')).getByText(/in progress/i)).toBeInTheDocument()
    expect(within(screen.getByTestId('mock-node-node-1')).getByText(/cve-2026-0001/i)).toBeInTheDocument()

    expect(screen.getByText('Finding Context')).toBeInTheDocument()
    expect(screen.getByText(/public workload can reach sensitive orders database/i)).toBeInTheDocument()
    expect(
      screen
        .getAllByRole('link', { name: /cve-2026-0001/i })
        .some(link => link.getAttribute('href') === 'https://nvd.nist.gov/vuln/detail/CVE-2026-0001'),
    ).toBe(true)
    expect(screen.getByText(/internet exposure plus privilege pivot reaches sensitive data/i)).toBeInTheDocument()
    expect(screen.getByText(/1\. remove public ingress/i)).toBeInTheDocument()
  })
})
