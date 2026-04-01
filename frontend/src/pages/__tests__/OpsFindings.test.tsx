import { describe, it, expect, beforeEach, vi } from 'vitest'
import { screen } from '@testing-library/react'
import { renderWithProviders } from '@/test/utils'
import Findings from '@/pages/ops/Findings'
import { useFindings, useFindingsStats } from '@/hooks/useFindings'

vi.mock('@/hooks/useFindings', () => ({
  useFindings: vi.fn(),
  useFindingsStats: vi.fn(),
}))

const mockUseFindings = vi.mocked(useFindings)
const mockUseFindingsStats = vi.mocked(useFindingsStats)

const sampleFinding = {
  id: 'finding-1',
  title: 'Public S3 bucket',
  severity: 'LOW',
  category: 'NETWORK',
  cloud_provider: 'aws',
  resource_type: 's3_bucket',
  resource_name: 'cf-demo-bucket',
  resource_id: 'arn:aws:s3:::cf-demo-bucket',
  region: 'us-east-1',
  ai_risk_score: 28,
  status: 'open',
  workflow_status: 'new',
  first_found_at: '2026-03-01T00:00:00Z',
  due_date: '2026-04-15T00:00:00Z',
  sla_breach_date: '',
  auto_remediatable: false,
  account_name: 'cloudforge-demo',
  description: 'Test finding for findings page rendering',
} as const

beforeEach(() => {
  mockUseFindings.mockReturnValue({
    data: [sampleFinding],
    isLoading: false,
    total: 1,
    totalPages: 1,
    page: 1,
    perPage: 100,
    isUsingMockData: false,
  } as ReturnType<typeof useFindings>)

  mockUseFindingsStats.mockReturnValue({
    data: {
      total: 300123,
      by_severity: {
        CRITICAL: 4321,
        HIGH: 7654,
        MEDIUM: 12345,
        LOW: 275803,
      },
      by_status: {
        open: 200111,
        in_progress: 50123,
        resolved: 49989,
      },
      by_provider: {
        aws: 100123,
        azure: 100000,
        gcp: 100000,
      },
      by_category: {
        NETWORK: 300123,
      },
      sla_breached: 1234,
      auto_remedial: 5678,
    },
    isLoading: false,
  } as ReturnType<typeof useFindingsStats>)
})

describe('OpsFindings', () => {
  it('renders without crashing', () => {
    renderWithProviders(<Findings />)
    expect(screen.getByRole('heading', { level: 1 })).toBeInTheDocument()
  })

  it('shows the Findings heading', () => {
    renderWithProviders(<Findings />)
    expect(screen.getByText('Findings')).toBeInTheDocument()
  })

  it('renders the search input', () => {
    renderWithProviders(<Findings />)
    expect(screen.getByRole('textbox')).toBeInTheDocument()
  })

  it('uses findings stats for severity cards when the page is unfiltered', () => {
    renderWithProviders(<Findings />)

    const criticalCard = screen
      .getAllByRole('button')
      .find((button) => button.textContent?.includes('CRITICAL') && button.textContent?.includes('4,321'))

    expect(criticalCard).toBeDefined()
    expect(criticalCard).toHaveTextContent('4,321')
  })
})
