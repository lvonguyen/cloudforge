import { describe, it, expect } from 'vitest'
import { screen } from '@testing-library/react'
import { renderWithProviders } from '@/test/utils'
import Landing from '@/pages/Landing'

describe('Landing', () => {
  it('renders without crashing', () => {
    renderWithProviders(<Landing />)
    expect(screen.getByRole('heading', { level: 1 })).toBeInTheDocument()
  })

  it('shows the Cloud Aegis Platform heading', () => {
    renderWithProviders(<Landing />)
    expect(screen.getByText(/Cloud Aegis Platform/i)).toBeInTheDocument()
  })

  it('shows the Tier 1 — Flagship section heading', () => {
    renderWithProviders(<Landing />)
    expect(screen.getByText(/Tier 1.*Flagship/i)).toBeInTheDocument()
  })

  it('shows the Tier 2 — Supporting section heading', () => {
    renderWithProviders(<Landing />)
    expect(screen.getByText(/Tier 2.*Supporting/i)).toBeInTheDocument()
  })

  it('renders architecture KPI card labels', () => {
    renderWithProviders(<Landing />)
    // Use getAllByText since "Multi-Cloud" appears in both KPI label and tag badges
    expect(screen.getAllByText(/Multi-Cloud/i).length).toBeGreaterThan(0)
    expect(screen.getAllByText(/Policy Engine/i).length).toBeGreaterThan(0)
    expect(screen.getAllByText(/AI Providers/i).length).toBeGreaterThan(0)
    // "Language" is unique to the KPI card
    expect(screen.getByText(/^Language$/i)).toBeInTheDocument()
  })

  it('renders the 2 core project tiles', () => {
    renderWithProviders(<Landing />)
    expect(screen.getByText('Cloud Aegis')).toBeInTheDocument()
    expect(screen.getByText('CSPM Aggregator')).toBeInTheDocument()
  })

  it('displays flagship and supporting tier badges', () => {
    renderWithProviders(<Landing />)
    const flagshipBadges = screen.getAllByText('flagship')
    const supportingBadges = screen.getAllByText('supporting')
    expect(flagshipBadges.length).toBeGreaterThan(0)
    expect(supportingBadges.length).toBeGreaterThan(0)
  })

  it('displays project description text', () => {
    renderWithProviders(<Landing />)
    expect(screen.getByText(/policy-as-code/i)).toBeInTheDocument()
  })
})
