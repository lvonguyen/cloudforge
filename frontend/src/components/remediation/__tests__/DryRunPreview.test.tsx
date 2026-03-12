import { describe, it, expect } from 'vitest'
import { screen } from '@testing-library/react'
import { renderWithProviders } from '@/test/utils'
import { DryRunPreview } from '../DryRunPreview'
import type { DryRunResult } from '@/types/remediation'

describe('DryRunPreview', () => {
  it('renders success state when would_succeed is true', () => {
    const result: DryRunResult = {
      would_succeed: true,
      planned_actions: ['Action 1', 'Action 2'],
      warnings: [],
      estimated_impact: 'Low',
    }

    renderWithProviders(<DryRunPreview result={result} />)
    expect(screen.getByText('Dry run would succeed')).toBeInTheDocument()
  })

  it('renders failure state when would_succeed is false', () => {
    const result: DryRunResult = {
      would_succeed: false,
      planned_actions: [],
      warnings: ['Error: Permission denied'],
      estimated_impact: 'High',
    }

    renderWithProviders(<DryRunPreview result={result} />)
    expect(screen.getByText('Dry run would fail')).toBeInTheDocument()
  })

  it('displays planned actions when present', () => {
    const result: DryRunResult = {
      would_succeed: true,
      planned_actions: ['Update S3 bucket policy', 'Enable encryption'],
      warnings: [],
      estimated_impact: 'Medium',
    }

    renderWithProviders(<DryRunPreview result={result} />)
    expect(screen.getByText('Planned actions:')).toBeInTheDocument()
    expect(screen.getByText('Update S3 bucket policy')).toBeInTheDocument()
    expect(screen.getByText('Enable encryption')).toBeInTheDocument()
  })

  it('does not display planned actions section when empty', () => {
    const result: DryRunResult = {
      would_succeed: true,
      planned_actions: [],
      warnings: [],
      estimated_impact: 'Low',
    }

    renderWithProviders(<DryRunPreview result={result} />)
    expect(screen.queryByText('Planned actions:')).not.toBeInTheDocument()
  })

  it('displays warnings when present', () => {
    const result: DryRunResult = {
      would_succeed: true,
      planned_actions: ['Action 1'],
      warnings: ['Warning: This action may take longer than expected', 'Warning: Backup recommended'],
      estimated_impact: 'High',
    }

    renderWithProviders(<DryRunPreview result={result} />)
    expect(screen.getByText('Warning: This action may take longer than expected')).toBeInTheDocument()
    expect(screen.getByText('Warning: Backup recommended')).toBeInTheDocument()
  })

  it('does not display warnings section when empty', () => {
    const result: DryRunResult = {
      would_succeed: true,
      planned_actions: ['Action 1'],
      warnings: [],
      estimated_impact: 'Low',
    }

    renderWithProviders(<DryRunPreview result={result} />)

    const warnings = screen.queryAllByText(/Warning:/)
    expect(warnings).toHaveLength(0)
  })

  it('displays estimated impact', () => {
    const result: DryRunResult = {
      would_succeed: true,
      planned_actions: [],
      warnings: [],
      estimated_impact: 'Critical - Production database',
    }

    renderWithProviders(<DryRunPreview result={result} />)
    expect(screen.getByText('Impact: Critical - Production database')).toBeInTheDocument()
  })

  it('renders CheckCircle icon for success', () => {
    const result: DryRunResult = {
      would_succeed: true,
      planned_actions: [],
      warnings: [],
      estimated_impact: 'Low',
    }

    const { container } = renderWithProviders(<DryRunPreview result={result} />)
    const icon = container.querySelector('.text-green-600')
    expect(icon).toBeInTheDocument()
  })

  it('renders XCircle icon for failure', () => {
    const result: DryRunResult = {
      would_succeed: false,
      planned_actions: [],
      warnings: [],
      estimated_impact: 'Low',
    }

    const { container } = renderWithProviders(<DryRunPreview result={result} />)
    const icon = container.querySelector('.text-red-600')
    expect(icon).toBeInTheDocument()
  })
})
