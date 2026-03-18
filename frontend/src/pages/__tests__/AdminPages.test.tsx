import { describe, it, expect } from 'vitest'
import { screen } from '@testing-library/react'
import { renderWithProviders } from '@/test/utils'
import { TracePanelProvider } from '@/lib/trace-panel-context'
import Users from '@/pages/admin/Users'
import AuditLog from '@/pages/admin/AuditLog'
import Reports from '@/pages/admin/Reports'

describe('Users', () => {
  it('renders without crashing', () => {
    renderWithProviders(<TracePanelProvider><Users /></TracePanelProvider>)
    expect(screen.getByRole('heading', { level: 1 })).toBeInTheDocument()
  })

  it('shows the User Management heading', () => {
    renderWithProviders(<TracePanelProvider><Users /></TracePanelProvider>)
    expect(screen.getByText('User Management')).toBeInTheDocument()
  })
})

describe('AuditLog', () => {
  it('renders without crashing', () => {
    renderWithProviders(<AuditLog />)
    expect(screen.getByText(/loading audit events/i)).toBeInTheDocument()
  })
})

describe('Reports', () => {
  it('renders without crashing', () => {
    renderWithProviders(<Reports />)
    expect(screen.getByRole('heading', { level: 1 })).toBeInTheDocument()
  })

  it('shows the Reports heading', () => {
    renderWithProviders(<Reports />)
    expect(screen.getByText('Reports')).toBeInTheDocument()
  })
})
