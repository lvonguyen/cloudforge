import { describe, it, expect } from 'vitest'
import { screen } from '@testing-library/react'
import { renderWithProviders } from '@/test/utils'
import { ProviderBadge, PROVIDER_COLORS } from '../ProviderBadge'

describe('ProviderBadge', () => {
  it('renders AWS badge with title tooltip', () => {
    renderWithProviders(<ProviderBadge provider="aws" />)
    expect(screen.getByTitle('AWS')).toBeInTheDocument()
  })

  it('renders Azure badge with title tooltip', () => {
    renderWithProviders(<ProviderBadge provider="azure" />)
    expect(screen.getByTitle('AZURE')).toBeInTheDocument()
  })

  it('renders GCP badge with title tooltip', () => {
    renderWithProviders(<ProviderBadge provider="gcp" />)
    expect(screen.getByTitle('GCP')).toBeInTheDocument()
  })

  it('renders icon for unknown provider', () => {
    renderWithProviders(<ProviderBadge provider="unknown" />)
    expect(screen.getByTitle('UNKNOWN')).toBeInTheDocument()
  })

  it('uses neutral stone palette for whitelabel', () => {
    expect(PROVIDER_COLORS.aws).toContain('bg-stone-200/60')
    expect(PROVIDER_COLORS.azure).toContain('bg-stone-200/60')
    expect(PROVIDER_COLORS.gcp).toContain('bg-stone-200/60')
  })

  it('applies custom className', () => {
    const { container } = renderWithProviders(
      <ProviderBadge provider="aws" className="custom-class" />,
    )
    const badge = container.querySelector('.custom-class')
    expect(badge).toBeInTheDocument()
  })
})
