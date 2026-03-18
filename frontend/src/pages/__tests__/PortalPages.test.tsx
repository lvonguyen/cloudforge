import { describe, it, expect } from 'vitest'
import { screen, waitFor } from '@testing-library/react'
import { renderWithAuth, renderWithProviders } from '@/test/utils'
import { Route, Routes } from 'react-router-dom'
import PortalDashboard from '@/pages/portal/Dashboard'
import MyRequests from '@/pages/portal/MyRequests'
import RequestDetail from '@/pages/portal/RequestDetail'
import Catalog from '@/pages/portal/Catalog'
import Request from '@/pages/portal/Request'

describe('PortalDashboard', () => {
  it('renders and shows heading after loading', async () => {
    renderWithAuth(<PortalDashboard />)
    await waitFor(() => {
      expect(screen.getByText('My Dashboard')).toBeInTheDocument()
    })
  })
})

describe('MyRequests', () => {
  it('renders without crashing', () => {
    renderWithProviders(<MyRequests />)
    expect(screen.getByRole('heading', { level: 1 })).toBeInTheDocument()
  })

  it('shows the My Requests heading', () => {
    renderWithProviders(<MyRequests />)
    expect(screen.getByText('My Requests')).toBeInTheDocument()
  })
})

describe('RequestDetail', () => {
  it('renders loading state for known ID', () => {
    renderWithProviders(
      <Routes>
        <Route path="/portal/requests/:id" element={<RequestDetail />} />
      </Routes>,
      { route: '/portal/requests/EXC-002' },
    )
    // useException starts loading — component shows spinner with "Loading request…"
    expect(screen.getByText(/loading request/i)).toBeInTheDocument()
  })

  it('renders loading state for unknown ID', () => {
    renderWithProviders(
      <Routes>
        <Route path="/portal/requests/:id" element={<RequestDetail />} />
      </Routes>,
      { route: '/portal/requests/NONEXISTENT' },
    )
    expect(screen.getByText(/loading request/i)).toBeInTheDocument()
  })
})

describe('Catalog', () => {
  it('renders without crashing', () => {
    renderWithProviders(<Catalog />)
    expect(screen.getByRole('heading', { level: 1 })).toBeInTheDocument()
  })

  it('shows the Resource Catalog heading', () => {
    renderWithProviders(<Catalog />)
    expect(screen.getByText('Resource Catalog')).toBeInTheDocument()
  })
})

describe('Request', () => {
  it('renders without crashing', () => {
    renderWithAuth(<Request />)
    expect(screen.getByRole('heading', { level: 1 })).toBeInTheDocument()
  })

  it('shows the New Resource Request heading', () => {
    renderWithAuth(<Request />)
    expect(screen.getByText('New Resource Request')).toBeInTheDocument()
  })
})
