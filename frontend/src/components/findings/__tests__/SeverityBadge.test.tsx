import { describe, it, expect } from 'vitest'
import { screen } from '@testing-library/react'
import { renderWithProviders } from '@/test/utils'
import { SeverityBadge } from '../SeverityBadge'

describe('SeverityBadge', () => {
  it('renders CRITICAL severity', () => {
    renderWithProviders(<SeverityBadge severity="CRITICAL" />)
    expect(screen.getByText('CRITICAL')).toBeInTheDocument()
  })

  it('renders HIGH severity', () => {
    renderWithProviders(<SeverityBadge severity="HIGH" />)
    expect(screen.getByText('HIGH')).toBeInTheDocument()
  })

  it('renders MEDIUM severity', () => {
    renderWithProviders(<SeverityBadge severity="MEDIUM" />)
    expect(screen.getByText('MEDIUM')).toBeInTheDocument()
  })

  it('renders LOW severity', () => {
    renderWithProviders(<SeverityBadge severity="LOW" />)
    expect(screen.getByText('LOW')).toBeInTheDocument()
  })

  it('renders lowercase critical severity', () => {
    renderWithProviders(<SeverityBadge severity="critical" />)
    expect(screen.getByText('CRITICAL')).toBeInTheDocument()
  })

  it('renders unknown severity as raw label', () => {
    renderWithProviders(<SeverityBadge severity="UNKNOWN" />)
    expect(screen.getByText('UNKNOWN')).toBeInTheDocument()
  })

  it('applies red class for CRITICAL', () => {
    renderWithProviders(<SeverityBadge severity="CRITICAL" />)
    const el = screen.getByText('CRITICAL')
    expect(el.className).toMatch(/red/)
  })

  it('applies orange class for HIGH', () => {
    renderWithProviders(<SeverityBadge severity="HIGH" />)
    const el = screen.getByText('HIGH')
    expect(el.className).toMatch(/orange/)
  })

  it('applies yellow class for MEDIUM', () => {
    renderWithProviders(<SeverityBadge severity="MEDIUM" />)
    const el = screen.getByText('MEDIUM')
    expect(el.className).toMatch(/yellow/)
  })

  it('applies blue class for LOW', () => {
    renderWithProviders(<SeverityBadge severity="LOW" />)
    const el = screen.getByText('LOW')
    expect(el.className).toMatch(/blue/)
  })

  it('applies xs size class when size is xs', () => {
    renderWithProviders(<SeverityBadge severity="HIGH" size="xs" />)
    const el = screen.getByText('HIGH')
    expect(el.className).toMatch(/text-\[10px\]|px-1/)
  })
})
