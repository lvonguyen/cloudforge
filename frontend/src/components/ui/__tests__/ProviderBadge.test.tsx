import { describe, it, expect } from 'vitest'
import { screen } from '@testing-library/react'
import { renderWithProviders } from '@/test/utils'
import { ProviderBadge } from '../ProviderBadge'

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

  it('renders correct SVG viewBox per provider', () => {
    const { unmount } = renderWithProviders(<ProviderBadge provider="aws" />)
    expect(screen.getByLabelText('AWS').getAttribute('viewBox')).toBe('0 0 120.4 72')
    unmount()
    renderWithProviders(<ProviderBadge provider="azure" />)
    expect(screen.getByLabelText('Azure').getAttribute('viewBox')).toBe('0 0 16 16')
    unmount()
    renderWithProviders(<ProviderBadge provider="gcp" />)
    expect(screen.getByLabelText('GCP').getAttribute('viewBox')).toBe('0 10 128 108')
  })

  it('renders icon for unknown provider', () => {
    renderWithProviders(<ProviderBadge provider="unknown" />)
    expect(screen.getByTitle('UNKNOWN')).toBeInTheDocument()
  })

  it('applies custom className', () => {
    const { container } = renderWithProviders(
      <ProviderBadge provider="aws" className="custom-class" />,
    )
    const badge = container.querySelector('.custom-class')
    expect(badge).toBeInTheDocument()
  })
})
