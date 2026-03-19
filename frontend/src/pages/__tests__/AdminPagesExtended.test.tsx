import { describe, it, expect } from 'vitest'
import { screen } from '@testing-library/react'
import { Route, Routes } from 'react-router-dom'
import { renderWithProviders } from '@/test/utils'
import { TracePanelProvider } from '@/lib/trace-panel-context'
import AIAgents from '@/pages/admin/AIAgents'
import AIAgentDetail from '@/pages/admin/AIAgentDetail'
import Exceptions from '@/pages/admin/Exceptions'
import Policies from '@/pages/admin/Policies'
import PolicyDetail from '@/pages/admin/PolicyDetail'
import SystemHealth from '@/pages/admin/SystemHealth'

describe('AIAgents', () => {
  it('renders without crashing', () => {
    renderWithProviders(<AIAgents />)
    expect(screen.getByText(/loading agents|AI Agent Registry/i)).toBeInTheDocument()
  })
})

describe('AIAgentDetail', () => {
  it('renders loading state with route params', () => {
    renderWithProviders(
      <Routes>
        <Route path="/admin/ai-agents/:id" element={<AIAgentDetail />} />
      </Routes>,
      { route: '/admin/ai-agents/agent-001' },
    )
    // H-06: loading state now uses shimmer skeleton instead of text
    expect(document.querySelector('.animate-pulse')).toBeInTheDocument()
  })
})

describe('Exceptions', () => {
  it('renders without crashing', () => {
    renderWithProviders(<Exceptions />)
    expect(screen.getByRole('heading', { level: 1 })).toBeInTheDocument()
  })

  it('shows the Exception Requests heading', () => {
    renderWithProviders(<Exceptions />)
    expect(screen.getByText('Exception Requests')).toBeInTheDocument()
  })
})

describe('Policies', () => {
  it('renders without crashing', () => {
    renderWithProviders(<TracePanelProvider><Policies /></TracePanelProvider>)
    expect(screen.getByText(/loading policies|Policy Manager/i)).toBeInTheDocument()
  })
})

describe('PolicyDetail', () => {
  it('renders not-found state for unknown policy', () => {
    renderWithProviders(
      <TracePanelProvider>
        <Routes>
          <Route path="/admin/policies/:id" element={<PolicyDetail />} />
        </Routes>
      </TracePanelProvider>,
      { route: '/admin/policies/pol-unknown' },
    )
    expect(screen.getByText(/policy not found/i)).toBeInTheDocument()
  })
})

describe('SystemHealth', () => {
  it('renders without crashing', () => {
    renderWithProviders(<SystemHealth />)
    expect(screen.getByRole('heading', { level: 1 })).toBeInTheDocument()
  })

  it('shows the System Health heading', () => {
    renderWithProviders(<SystemHealth />)
    expect(screen.getByText('System Health')).toBeInTheDocument()
  })
})
