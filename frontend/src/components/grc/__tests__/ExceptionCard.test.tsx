import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { screen } from '@testing-library/react'
import { renderWithProviders } from '@/test/utils'
import { ExceptionCard } from '../ExceptionCard'
import type { ExceptionRequest } from '@/types/grc'

describe('ExceptionCard', () => {
  beforeEach(() => {
    vi.useFakeTimers()
  })

  afterEach(() => {
    vi.useRealTimers()
  })

  it('renders exception id', () => {
    const exception: ExceptionRequest = {
      id: 'ex-001',
      application_id: 'app-001',
      policy_violated: 'IAM-001',
      resource_requested: 'arn:aws:iam::123456789:role/admin',
      requestor_email: 'user@contoso.dev',
      status: 'pending',
      created_at: '2024-01-01T00:00:00Z',
    }

    renderWithProviders(<ExceptionCard exception={exception} />)
    expect(screen.getByText('ex-001')).toBeInTheDocument()
  })

  it('renders application_id', () => {
    const exception: ExceptionRequest = {
      id: 'ex-002',
      application_id: 'app-payroll',
      policy_violated: 'DATA-001',
      resource_requested: 'database',
      requestor_email: 'admin@contoso.dev',
      status: 'pending',
      created_at: '2024-01-01T00:00:00Z',
    }

    renderWithProviders(<ExceptionCard exception={exception} />)
    expect(screen.getByText('app-payroll')).toBeInTheDocument()
  })

  it('renders policy_violated', () => {
    const exception: ExceptionRequest = {
      id: 'ex-003',
      application_id: 'app-003',
      policy_violated: 'NETWORK-ISOLATION',
      resource_requested: 'vpc-peering',
      requestor_email: 'eng@contoso.dev',
      status: 'pending',
      created_at: '2024-01-01T00:00:00Z',
    }

    renderWithProviders(<ExceptionCard exception={exception} />)
    expect(screen.getByText(/NETWORK-ISOLATION/)).toBeInTheDocument()
  })

  it('renders resource_requested', () => {
    const exception: ExceptionRequest = {
      id: 'ex-004',
      application_id: 'app-004',
      policy_violated: 'IAM-002',
      resource_requested: 'arn:aws:s3:::sensitive-bucket/*',
      requestor_email: 'dev@contoso.dev',
      status: 'pending',
      created_at: '2024-01-01T00:00:00Z',
    }

    renderWithProviders(<ExceptionCard exception={exception} />)
    expect(screen.getByText('arn:aws:s3:::sensitive-bucket/*')).toBeInTheDocument()
  })

  it('renders requestor_email', () => {
    const exception: ExceptionRequest = {
      id: 'ex-005',
      application_id: 'app-005',
      policy_violated: 'IAM-003',
      resource_requested: 'role',
      requestor_email: 'manager@contoso.dev',
      status: 'pending',
      created_at: '2024-01-01T00:00:00Z',
    }

    renderWithProviders(<ExceptionCard exception={exception} />)
    expect(screen.getByText(/manager@contoso.dev/)).toBeInTheDocument()
  })

  it('calculates age in days correctly', () => {
    const threeDaysAgo = new Date()
    threeDaysAgo.setDate(threeDaysAgo.getDate() - 3)

    const exception: ExceptionRequest = {
      id: 'ex-006',
      application_id: 'app-006',
      policy_violated: 'IAM-004',
      resource_requested: 'resource',
      requestor_email: 'user@contoso.dev',
      status: 'pending',
      created_at: threeDaysAgo.toISOString(),
    }

    renderWithProviders(<ExceptionCard exception={exception} />)
    expect(screen.getByText(/3d ago/)).toBeInTheDocument()
  })

  it('displays 0d ago for very recent exception', () => {
    const now = new Date().toISOString()

    const exception: ExceptionRequest = {
      id: 'ex-007',
      application_id: 'app-007',
      policy_violated: 'IAM-005',
      resource_requested: 'resource',
      requestor_email: 'user@contoso.dev',
      status: 'pending',
      created_at: now,
    }

    renderWithProviders(<ExceptionCard exception={exception} />)
    expect(screen.getByText(/0d ago/)).toBeInTheDocument()
  })

  it('renders StatusBadge with correct status', () => {
    const exception: ExceptionRequest = {
      id: 'ex-008',
      application_id: 'app-008',
      policy_violated: 'IAM-006',
      resource_requested: 'resource',
      requestor_email: 'user@contoso.dev',
      status: 'APPROVED',
      created_at: '2024-01-01T00:00:00Z',
    }

    renderWithProviders(<ExceptionCard exception={exception} />)
    expect(screen.getByText('Approved')).toBeInTheDocument()
  })

  it('applies hover effect classes', () => {
    const exception: ExceptionRequest = {
      id: 'ex-009',
      application_id: 'app-009',
      policy_violated: 'IAM-007',
      resource_requested: 'resource',
      requestor_email: 'user@contoso.dev',
      status: 'pending',
      created_at: '2024-01-01T00:00:00Z',
    }

    const { container } = renderWithProviders(<ExceptionCard exception={exception} />)
    const card = container.querySelector('.cursor-pointer')
    expect(card).toBeInTheDocument()
    expect(card?.className).toMatch(/hover:shadow-md/)
  })
})
