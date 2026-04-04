import { describe, it, expect, vi, beforeEach } from 'vitest'
import { screen, waitFor } from '@testing-library/react'
import { renderWithProviders } from '@/test/utils'
import Investigations from '@/pages/ops/Investigations'
import { useFindings } from '@/hooks/useFindings'
import type { Finding } from '@/types/compliance'

vi.mock('@/hooks/useFindings', () => ({
  useFindings: vi.fn(),
}))

vi.mock('@/components/ops/BaseGraphView', () => ({
  BaseGraphView: () => <div data-testid="investigation-graph-mock" />,
}))

const mockUseFindings = vi.mocked(useFindings)

const SAMPLE_FINDING: Finding = {
  id: 'f-invest-001',
  source: 'prowler',
  source_finding_id: 'prowler-001',
  type: 'misconfiguration',
  title: 'Public workload can reach the order database role chain',
  description: 'Internet ingress plus a broad trust policy creates a reachable path into a production role.',
  resource_type: 'compute',
  resource_id: 'res-api-1',
  resource_name: 'public-orders-api',
  resource_arn: 'arn:aws:ecs:us-east-1:111111111111:task/public-orders-api',
  platform: 'cloud',
  cloud_provider: 'aws',
  region: 'us-east-1',
  account_id: '111111111111',
  account_name: 'prod-apps',
  environment_type: 'production',
  impacted_resources: [
    {
      resource_id: 'res-db-1',
      resource_name: 'orders-db',
      resource_type: 'database',
      relationship: 'reachable from role chain',
      impact_level: 'high',
    },
  ],
  static_severity: 'HIGH',
  severity: 'HIGH',
  ai_risk_score: 8.4,
  ai_risk_level: 'high',
  ai_risk_rationale: 'A public entry point plus downstream data access makes the path operationally urgent.',
  ai_contextual_factors: ['public ingress', 'privilege chain'],
  exploit_available: true,
  compliance_mappings: [
    {
      framework_id: 'cis',
      framework_name: 'CIS AWS Foundations',
      control_id: '4.1',
      control_title: 'Restrict public access',
      section: '4',
      severity: 'high',
      url: 'https://example.com/control',
    },
  ],
  remediation: 'Remove public access and tighten IAM trust policy.',
  auto_remediatable: false,
  category: 'NETWORK',
  status: 'open',
  workflow_status: 'assigned',
  assignee: {
    user_id: 'u-1',
    user_email: 'owner@example.com',
    user_name: 'Taylor Chen',
    team: 'Cloud Security',
    assigned_at: '2026-03-30T12:00:00Z',
    assigned_by: 'system',
    escalated: false,
  },
  suppressed: false,
  technical_contact: {
    name: 'Jordan Rivera',
    email: 'jordan@example.com',
    team: 'Platform',
  },
  service_name: 'orders',
  line_of_business: 'commerce',
  first_found_at: '2026-03-29T01:00:00Z',
  last_seen_at: '2026-03-30T02:00:00Z',
  due_date: '2026-04-05T00:00:00Z',
  deduplication_key: 'invest-001',
  canonical_rule_id: 'NET-001',
}

describe('OpsInvestigations', () => {
  beforeEach(() => {
    mockUseFindings.mockReset()
  })

  it('shows a loading state while findings are unresolved', () => {
    mockUseFindings.mockReturnValue({
      data: undefined,
      isLoading: true,
    } as ReturnType<typeof useFindings>)

    renderWithProviders(<Investigations />)
    expect(screen.getByText(/loading investigations/i)).toBeInTheDocument()
  })

  it('renders the analyst workflow and graph reading guidance for a selected finding', async () => {
    mockUseFindings.mockReturnValue({
      data: [SAMPLE_FINDING],
      isLoading: false,
    } as ReturnType<typeof useFindings>)

    renderWithProviders(<Investigations />, { route: '/ops/investigations?findingId=f-invest-001' })

    expect(screen.getByText('Analyst workflow')).toBeInTheDocument()
    expect(await screen.findByText('How to read this graph', {}, { timeout: 10_000 })).toBeInTheDocument()
    expect(screen.getByText('Analyst briefing')).toBeInTheDocument()
    expect(screen.getAllByText(/Taylor Chen/).length).toBeGreaterThan(0)
  }, 10_000)
})
