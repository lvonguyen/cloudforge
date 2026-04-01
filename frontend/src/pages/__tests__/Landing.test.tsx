import { describe, it, expect } from 'vitest'
import { screen } from '@testing-library/react'
import { renderWithProviders } from '@/test/utils'
import Landing from '@/pages/Landing'

describe('Landing', () => {
  it('renders without crashing', async () => {
    renderWithProviders(<Landing />)
    expect(await screen.findByRole('heading', { level: 1 }, { timeout: 10_000 })).toBeInTheDocument()
  }, 10_000)

  it('shows the Aegis Platform heading', () => {
    renderWithProviders(<Landing />)
    expect(screen.getByText(/Aegis Platform/i)).toBeInTheDocument()
  })

  it('shows the Modules section heading', () => {
    renderWithProviders(<Landing />)
    expect(screen.getByText(/^Modules$/i)).toBeInTheDocument()
  })

  it('renders architecture KPI card labels', () => {
    renderWithProviders(<Landing />)
    expect(screen.getAllByText(/Multi-Cloud/i).length).toBeGreaterThan(0)
    expect(screen.getAllByText(/Policy Engine/i).length).toBeGreaterThan(0)
    expect(screen.getAllByText(/AI Providers/i).length).toBeGreaterThan(0)
    expect(screen.getByText(/^Language$/i)).toBeInTheDocument()
  })

  it('renders the 2 core project tiles', () => {
    renderWithProviders(<Landing />)
    expect(screen.getByText('Aegis')).toBeInTheDocument()
    expect(screen.getByText('Posture Management')).toBeInTheDocument()
  })

  it('displays real test count stats', () => {
    renderWithProviders(<Landing />)
    expect(screen.getByText('1,474')).toBeInTheDocument()
    expect(screen.getByText('420')).toBeInTheDocument()
  })

  it('displays project description text', () => {
    renderWithProviders(<Landing />)
    expect(screen.getByText(/policy-as-code/i)).toBeInTheDocument()
  })

  it('does not render Demo Access section when demoAccess is disabled', () => {
    renderWithProviders(<Landing />)
    expect(screen.queryByText('Demo Access')).not.toBeInTheDocument()
  })
})
