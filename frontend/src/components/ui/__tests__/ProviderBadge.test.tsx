import { describe, it, expect } from 'vitest'
import { screen } from '@testing-library/react'
import { renderWithProviders } from '@/test/utils'
import { ProviderBadge, PROVIDER_COLORS } from '../ProviderBadge'

describe('ProviderBadge', () => {
  it('renders AWS badge with provider text', () => {
    renderWithProviders(<ProviderBadge provider="aws" />)
    expect(screen.getByText('AWS')).toBeInTheDocument()
  })

  it('renders Azure badge with provider text', () => {
    renderWithProviders(<ProviderBadge provider="azure" />)
    expect(screen.getByText('AZURE')).toBeInTheDocument()
  })

  it('renders GCP badge with provider text', () => {
    renderWithProviders(<ProviderBadge provider="gcp" />)
    expect(screen.getByText('GCP')).toBeInTheDocument()
  })

  it('renders text for unknown provider', () => {
    renderWithProviders(<ProviderBadge provider="unknown" />)
    expect(screen.getByText('UNKNOWN')).toBeInTheDocument()
  })

  it('AWS badge has font-semibold for contrast', () => {
    expect(PROVIDER_COLORS.aws).toContain('font-semibold')
  })

  it('AWS badge uses tinted background and light text', () => {
    expect(PROVIDER_COLORS.aws).toContain('bg-orange-500/20')
    expect(PROVIDER_COLORS.aws).toContain('text-orange-300')
  })

  it('applies custom className', () => {
    const { container } = renderWithProviders(
      <ProviderBadge provider="aws" className="custom-class" />,
    )
    const badge = container.querySelector('.custom-class')
    expect(badge).toBeInTheDocument()
  })
})
