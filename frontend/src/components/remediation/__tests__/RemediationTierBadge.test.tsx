import { describe, it, expect } from 'vitest'
import { screen } from '@testing-library/react'
import { renderWithProviders } from '@/test/utils'
import { RemediationTierBadge } from '../RemediationTierBadge'

describe('RemediationTierBadge', () => {
  it('renders Tier 1 label', () => {
    renderWithProviders(<RemediationTierBadge tier={1} />)
    expect(screen.getByText('Tier 1')).toBeInTheDocument()
  })

  it('renders Tier 2 label', () => {
    renderWithProviders(<RemediationTierBadge tier={2} />)
    expect(screen.getByText('Tier 2')).toBeInTheDocument()
  })

  it('renders Tier 3 label', () => {
    renderWithProviders(<RemediationTierBadge tier={3} />)
    expect(screen.getByText('Tier 3')).toBeInTheDocument()
  })

  it('applies green class for tier 1', () => {
    renderWithProviders(<RemediationTierBadge tier={1} />)
    const el = screen.getByText('Tier 1')
    expect(el.className).toMatch(/green/)
  })

  it('applies yellow class for tier 2', () => {
    renderWithProviders(<RemediationTierBadge tier={2} />)
    const el = screen.getByText('Tier 2')
    expect(el.className).toMatch(/yellow/)
  })

  it('applies red class for tier 3', () => {
    renderWithProviders(<RemediationTierBadge tier={3} />)
    const el = screen.getByText('Tier 3')
    expect(el.className).toMatch(/red/)
  })

  it('falls back to Tier 3 config for unknown tier', () => {
    renderWithProviders(<RemediationTierBadge tier={99} />)
    // TIER_CONFIG[99] ?? TIER_CONFIG[3] => "Tier 3" label
    expect(screen.getByText('Tier 3')).toBeInTheDocument()
  })
})
