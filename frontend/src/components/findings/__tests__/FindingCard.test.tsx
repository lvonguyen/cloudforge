import { describe, it, expect, vi } from 'vitest'
import { screen } from '@testing-library/react'
import { renderWithProviders } from '@/test/utils'
import { FindingCard } from '../FindingCard'
import type { Finding } from '@/types/compliance'

describe('FindingCard', () => {
  it('renders finding title', () => {
    const finding: Finding = {
      id: 'f-001',
      title: 'S3 bucket publicly accessible',
      severity: 'HIGH',
      status: 'open',
      cloud_provider: 'aws',
      category: 'MISCONFIGURATION',
      service_name: 'S3',
      line_of_business: 'Platform',
      deduplication_key: 'key-001',
      canonical_rule_id: 'rule-001',
      source: 'SecurityHub',
      source_finding_id: 'src-001',
      type: 'Software and Configuration Checks',
      description: 'Bucket is public',
      resource_type: 'storage',
      resource_id: 'arn:aws:s3:::my-bucket',
      resource_name: 'my-bucket',
      platform: 'AWS',
      region: 'us-east-1',
      account_id: '123456789',
      environment_type: 'production',
      static_severity: 'HIGH',
      ai_risk_score: 8.5,
      ai_risk_level: 'HIGH',
      ai_risk_rationale: 'Public bucket',
      ai_contextual_factors: [],
      exploit_available: false,
      auto_remediatable: false,
      remediation: 'Block public access',
      suppressed: false,
      workflow_status: 'new',
      first_found_at: '2024-01-01T00:00:00Z',
      last_seen_at: '2024-01-02T00:00:00Z',
    }

    renderWithProviders(<FindingCard finding={finding} />)
    expect(screen.getByText('S3 bucket publicly accessible')).toBeInTheDocument()
  })

  it('renders SeverityBadge with correct severity', () => {
    const finding: Finding = {
      id: 'f-002',
      title: 'Critical vulnerability',
      severity: 'CRITICAL',
      status: 'open',
      cloud_provider: 'aws',
      category: 'VULNERABILITY',
      resource_name: 'test-resource',
      region: 'us-west-2',
      auto_remediatable: false,
    } as Finding

    renderWithProviders(<FindingCard finding={finding} />)
    expect(screen.getByText('CRITICAL')).toBeInTheDocument()
  })

  it('displays AUTO badge when auto_remediatable is true', () => {
    const finding: Finding = {
      id: 'f-003',
      title: 'Security group open',
      severity: 'HIGH',
      status: 'open',
      cloud_provider: 'aws',
      category: 'MISCONFIGURATION',
      resource_name: 'sg-123',
      region: 'us-east-1',
      auto_remediatable: true,
    } as Finding

    renderWithProviders(<FindingCard finding={finding} />)
    expect(screen.getByText('AUTO')).toBeInTheDocument()
  })

  it('does not display AUTO badge when auto_remediatable is false', () => {
    const finding: Finding = {
      id: 'f-004',
      title: 'Manual fix required',
      severity: 'MEDIUM',
      status: 'open',
      cloud_provider: 'azure',
      category: 'MISCONFIGURATION',
      resource_name: 'test',
      region: 'eastus',
      auto_remediatable: false,
    } as Finding

    renderWithProviders(<FindingCard finding={finding} />)
    expect(screen.queryByText('AUTO')).not.toBeInTheDocument()
  })

  it('displays resource_name', () => {
    const finding: Finding = {
      id: 'f-005',
      title: 'Resource issue',
      severity: 'LOW',
      status: 'open',
      cloud_provider: 'gcp',
      category: 'MISCONFIGURATION',
      resource_name: 'prod-vm-instance-42',
      region: 'us-central1',
      auto_remediatable: false,
    } as Finding

    renderWithProviders(<FindingCard finding={finding} />)
    expect(screen.getByText(/prod-vm-instance-42/)).toBeInTheDocument()
  })

  it('displays region', () => {
    const finding: Finding = {
      id: 'f-006',
      title: 'Regional issue',
      severity: 'MEDIUM',
      status: 'open',
      cloud_provider: 'aws',
      category: 'MISCONFIGURATION',
      resource_name: 'resource',
      region: 'eu-west-1',
      auto_remediatable: false,
    } as Finding

    renderWithProviders(<FindingCard finding={finding} />)
    expect(screen.getByText(/eu-west-1/)).toBeInTheDocument()
  })

  it('displays CVE when cves array is present', () => {
    const finding: Finding = {
      id: 'f-007',
      title: 'Vulnerable package',
      severity: 'HIGH',
      status: 'open',
      cloud_provider: 'aws',
      category: 'VULNERABILITY',
      resource_name: 'app-server',
      region: 'us-east-1',
      auto_remediatable: false,
      cves: [{ id: 'CVE-2024-1234', score: 8.5 }],
      cvss: 8.5,
    } as Finding

    renderWithProviders(<FindingCard finding={finding} />)
    expect(screen.getByText(/CVE-2024-1234/)).toBeInTheDocument()
  })

  it('displays CVSS score with one decimal', () => {
    const finding: Finding = {
      id: 'f-008',
      title: 'Vulnerable package',
      severity: 'CRITICAL',
      status: 'open',
      cloud_provider: 'aws',
      category: 'VULNERABILITY',
      resource_name: 'app-server',
      region: 'us-east-1',
      auto_remediatable: false,
      cves: [{ id: 'CVE-2024-5678', score: 9.2 }],
      cvss: 9.2,
    } as Finding

    renderWithProviders(<FindingCard finding={finding} />)
    expect(screen.getByText(/CVSS 9.2/)).toBeInTheDocument()
  })

  it('does not display CVE section when cves array is empty', () => {
    const finding: Finding = {
      id: 'f-009',
      title: 'Misconfiguration',
      severity: 'MEDIUM',
      status: 'open',
      cloud_provider: 'aws',
      category: 'MISCONFIGURATION',
      resource_name: 'resource',
      region: 'us-east-1',
      auto_remediatable: false,
      cves: [],
    } as Finding

    renderWithProviders(<FindingCard finding={finding} />)
    expect(screen.queryByText(/CVE-/)).not.toBeInTheDocument()
  })

  it('calls onClick handler when clicked', () => {
    const onClick = vi.fn()
    const finding: Finding = {
      id: 'f-010',
      title: 'Clickable finding',
      severity: 'LOW',
      status: 'open',
      cloud_provider: 'aws',
      category: 'MISCONFIGURATION',
      resource_name: 'resource',
      region: 'us-east-1',
      auto_remediatable: false,
    } as Finding

    const { container } = renderWithProviders(<FindingCard finding={finding} onClick={onClick} />)
    const card = container.firstChild as HTMLElement
    card.click()
    expect(onClick).toHaveBeenCalledTimes(1)
  })

  it('applies hover effect classes', () => {
    const finding: Finding = {
      id: 'f-011',
      title: 'Hoverable finding',
      severity: 'MEDIUM',
      status: 'open',
      cloud_provider: 'aws',
      category: 'MISCONFIGURATION',
      resource_name: 'resource',
      region: 'us-east-1',
      auto_remediatable: false,
    } as Finding

    const { container } = renderWithProviders(<FindingCard finding={finding} />)
    const card = container.querySelector('.cursor-pointer')
    expect(card).toBeInTheDocument()
    expect(card?.className).toMatch(/hover:shadow-md/)
  })
})
