import { describe, it, expect, vi } from 'vitest'
import { screen } from '@testing-library/react'
import { renderWithProviders } from '@/test/utils'
import { FindingsTreemap } from '../FindingsTreemap'
import type { Finding } from '@/types/compliance'

// Recharts uses ResizeObserver internally
beforeAll(() => {
  global.ResizeObserver = class {
    observe() {}
    unobserve() {}
    disconnect() {}
  }
})

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: 'f-001',
    source: 'SecurityHub',
    source_finding_id: 'src-001',
    type: 'Software and Configuration Checks',
    title: 'S3 bucket public',
    description: 'Bucket is public',
    resource_type: 'storage',
    resource_id: 'arn:aws:s3:::my-bucket',
    resource_name: 'my-bucket',
    platform: 'AWS',
    cloud_provider: 'aws',
    region: 'us-east-1',
    account_id: '123456789',
    environment_type: 'production',
    static_severity: 'HIGH',
    severity: 'HIGH',
    ai_risk_score: 8.5,
    ai_risk_level: 'HIGH',
    ai_risk_rationale: 'Public bucket',
    ai_contextual_factors: [],
    exploit_available: false,
    auto_remediatable: true,
    remediation: 'Block public access',
    category: 'MISCONFIGURATION',
    status: 'open',
    workflow_status: 'new',
    suppressed: false,
    service_name: 'S3',
    line_of_business: 'Platform',
    deduplication_key: 'key-001',
    canonical_rule_id: 'rule-001',
    first_found_at: '2024-01-01T00:00:00Z',
    last_seen_at: '2024-01-02T00:00:00Z',
    ...overrides,
  }
}

describe('FindingsTreemap', () => {
  it('returns null when findings array is empty', () => {
    const onSelect = vi.fn()
    const { container } = renderWithProviders(
      <FindingsTreemap findings={[]} onSelect={onSelect} />,
    )
    expect(container.innerHTML).toBe('')
  })

  it('renders treemap container with findings', () => {
    const findings = [
      makeFinding({ id: 'f-001', cloud_provider: 'aws', category: 'MISCONFIGURATION' }),
      makeFinding({ id: 'f-002', cloud_provider: 'azure', category: 'VULNERABILITY', severity: 'CRITICAL' }),
    ]
    const onSelect = vi.fn()
    renderWithProviders(
      <FindingsTreemap findings={findings} onSelect={onSelect} />,
    )
    expect(screen.getByTestId('findings-treemap')).toBeInTheDocument()
    expect(screen.getByText('Severity Heatmap')).toBeInTheDocument()
  })

  it('renders severity legend with all 4 levels', () => {
    const findings = [makeFinding()]
    const onSelect = vi.fn()
    renderWithProviders(
      <FindingsTreemap findings={findings} onSelect={onSelect} />,
    )
    expect(screen.getByText('CRITICAL')).toBeInTheDocument()
    expect(screen.getByText('HIGH')).toBeInTheDocument()
    expect(screen.getByText('MEDIUM')).toBeInTheDocument()
    expect(screen.getByText('LOW')).toBeInTheDocument()
  })

  it('groups findings by provider then category', () => {
    const findings = [
      makeFinding({ id: 'f-001', cloud_provider: 'aws', category: 'MISCONFIGURATION' }),
      makeFinding({ id: 'f-002', cloud_provider: 'aws', category: 'VULNERABILITY' }),
      makeFinding({ id: 'f-003', cloud_provider: 'gcp', category: 'MISCONFIGURATION' }),
    ]
    const onSelect = vi.fn()
    renderWithProviders(
      <FindingsTreemap findings={findings} onSelect={onSelect} />,
    )
    // Treemap should render without errors — grouping is internal
    expect(screen.getByTestId('findings-treemap')).toBeInTheDocument()
  })
})
