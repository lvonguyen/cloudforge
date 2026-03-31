import { beforeAll, beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, screen } from '@testing-library/react'
import { Route, Routes } from 'react-router-dom'
import { renderWithAuth } from '@/test/utils'
import { useFinding, useFindingEnrichment } from '@/hooks/useFindings'
import { useAttackPaths } from '@/hooks/useAttackPaths'
import { useComments, useAddComment } from '@/hooks/useComments'
import { useFindingTicket, useRemediateFinding } from '@/hooks/useIntegrations'
import { useCreateException } from '@/hooks/useExceptions'
import { useActionCooldown } from '@/hooks/useActionCooldown'
import type { Finding } from '@/types/compliance'
import type { AttackPath } from '@/types/attack-path'

vi.mock('@/hooks/useFindings', () => ({
  useFinding: vi.fn(),
  useFindingEnrichment: vi.fn(),
}))

vi.mock('@/hooks/useAttackPaths', () => ({
  useAttackPaths: vi.fn(),
}))

vi.mock('@/hooks/useComments', () => ({
  useComments: vi.fn(),
  useAddComment: vi.fn(),
}))

vi.mock('@/hooks/useIntegrations', () => ({
  useFindingTicket: vi.fn(),
  useRemediateFinding: vi.fn(),
}))

vi.mock('@/hooks/useExceptions', () => ({
  useCreateException: vi.fn(),
}))

vi.mock('@/hooks/useActionCooldown', () => ({
  useActionCooldown: vi.fn(),
}))

const mockUseFinding = vi.mocked(useFinding)
const mockUseFindingEnrichment = vi.mocked(useFindingEnrichment)
const mockUseAttackPaths = vi.mocked(useAttackPaths)
const mockUseComments = vi.mocked(useComments)
const mockUseAddComment = vi.mocked(useAddComment)
const mockUseFindingTicket = vi.mocked(useFindingTicket)
const mockUseRemediateFinding = vi.mocked(useRemediateFinding)
const mockUseCreateException = vi.mocked(useCreateException)
const mockUseActionCooldown = vi.mocked(useActionCooldown)

const SAMPLE_FINDING: Finding = {
  id: 'f-001',
  source: 'wiz',
  source_finding_id: 'wiz-123',
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
    resource_id: 'res-api-1',
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
    finding_id: 'f-001',
    resource_id: 'res-db-1',
    resource_name: 'prod-orders-db',
    resource_type: 'rds_instance',
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
      finding_id: 'f-100',
      resource_id: 'res-api-1',
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
      finding_id: 'f-200',
      resource_id: 'res-role-1',
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
      finding_id: 'f-001',
      resource_id: 'res-db-1',
      resource_name: 'prod-orders-db',
      resource_type: 'rds_instance',
      provider: 'aws',
      account_id: '111111111111',
      region: 'us-east-1',
      severity: 'HIGH',
      category: 'DATABASE',
      label: 'Orders DB',
    },
  ],
  edges: [
    { id: 'edge-1', source: 'node-1', target: 'node-2', label: 'assume-role', edge_type: 'assume_role' },
    { id: 'edge-2', source: 'node-2', target: 'node-3', label: 'db-access', edge_type: 'can_access' },
  ],
  mitre_tactics: ['TA0001', 'TA0003'],
  finding_ids: ['f-001'],
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
  mockUseFinding.mockReturnValue({
    data: SAMPLE_FINDING,
    isLoading: false,
  } as ReturnType<typeof useFinding>)

  mockUseFindingEnrichment.mockReturnValue({
    data: null,
  } as ReturnType<typeof useFindingEnrichment>)

  mockUseAttackPaths.mockReturnValue({
    data: { data: [SAMPLE_PATH], page: 1, per_page: 50, total: 1, total_pages: 1 },
  } as ReturnType<typeof useAttackPaths>)

  mockUseComments.mockReturnValue({ data: [] } as ReturnType<typeof useComments>)
  mockUseAddComment.mockReturnValue({ isPending: false, mutate: vi.fn() } as ReturnType<typeof useAddComment>)
  mockUseFindingTicket.mockReturnValue({ data: null } as ReturnType<typeof useFindingTicket>)
  mockUseRemediateFinding.mockReturnValue({ isPending: false, mutate: vi.fn() } as ReturnType<typeof useRemediateFinding>)
  mockUseCreateException.mockReturnValue({ isPending: false, mutate: vi.fn() } as ReturnType<typeof useCreateException>)
  mockUseActionCooldown.mockReturnValue({ canFire: true, fire: vi.fn() } as ReturnType<typeof useActionCooldown>)
})

describe('FindingDetail graph tabs', () => {
  it('shows Attack Path and Security Graph tabs on the finding detail page', async () => {
    const { default: FindingDetail } = await import('@/pages/ops/FindingDetail')

    renderWithAuth(
      <Routes>
        <Route path="/ops/findings/:id" element={<FindingDetail />} />
      </Routes>,
      { route: '/ops/findings/f-001' },
    )

    const attackPathControl = (await screen.findAllByText(/attack path/i))
      .map((element) => element.closest('button'))
      .find((element): element is HTMLButtonElement => Boolean(element))
    expect(attackPathControl).toBeTruthy()
    fireEvent.click(attackPathControl!)
    expect(await screen.findByText(/attack path analyst view/i)).toBeInTheDocument()

    const securityGraphControl = (await screen.findAllByText(/security graph/i))
      .map((element) => element.closest('button'))
      .find((element): element is HTMLButtonElement => Boolean(element))
    expect(securityGraphControl).toBeTruthy()
    fireEvent.click(securityGraphControl!)
    expect(await screen.findByText(/^security graph$/i)).toBeInTheDocument()
    expect(screen.getByText(/open trace timeline/i)).toBeInTheDocument()
  })
})
