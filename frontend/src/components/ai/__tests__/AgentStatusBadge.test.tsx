import { describe, it, expect } from 'vitest'
import { screen } from '@testing-library/react'
import { renderWithProviders } from '@/test/utils'
import { AgentStatusBadge } from '../AgentStatusBadge'
import type { AgentStatus } from '@/types/ai-governance'

describe('AgentStatusBadge', () => {
  it('renders Active for active status', () => {
    renderWithProviders(<AgentStatusBadge status="active" />)
    expect(screen.getByText('Active')).toBeInTheDocument()
  })

  it('renders Inactive for inactive status', () => {
    renderWithProviders(<AgentStatusBadge status="inactive" />)
    expect(screen.getByText('Inactive')).toBeInTheDocument()
  })

  it('renders Suspended for suspended status', () => {
    renderWithProviders(<AgentStatusBadge status="suspended" />)
    expect(screen.getByText('Suspended')).toBeInTheDocument()
  })

  it('renders Deprecated for deprecated status', () => {
    renderWithProviders(<AgentStatusBadge status="deprecated" />)
    expect(screen.getByText('Deprecated')).toBeInTheDocument()
  })

  it('applies green styling for active status', () => {
    renderWithProviders(<AgentStatusBadge status="active" />)
    const el = screen.getByText('Active')
    expect(el.className).toMatch(/green/)
  })

  it('applies gray styling for inactive status', () => {
    renderWithProviders(<AgentStatusBadge status="inactive" />)
    const el = screen.getByText('Inactive')
    expect(el.className).toMatch(/gray/)
  })

  it('applies red styling for suspended status', () => {
    renderWithProviders(<AgentStatusBadge status="suspended" />)
    const el = screen.getByText('Suspended')
    expect(el.className).toMatch(/red/)
  })

  it('applies yellow styling for deprecated status', () => {
    renderWithProviders(<AgentStatusBadge status="deprecated" />)
    const el = screen.getByText('Deprecated')
    expect(el.className).toMatch(/yellow/)
  })

  it('falls back to inactive config for unknown status', () => {
    renderWithProviders(<AgentStatusBadge status={'unknown' as AgentStatus} />)
    expect(screen.getByText('Inactive')).toBeInTheDocument()
  })
})
