import { describe, it, expect, vi } from 'vitest'
import { screen, fireEvent } from '@testing-library/react'
import { renderWithProviders } from '@/test/utils'
import { CommandPalette } from '../CommandPalette'

const mockNavigate = vi.fn()
vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual('react-router-dom')
  return { ...actual, useNavigate: () => mockNavigate }
})

function renderPalette(open = true, onOpenChange = vi.fn()) {
  return { onOpenChange, ...renderWithProviders(<CommandPalette open={open} onOpenChange={onOpenChange} />) }
}

describe('CommandPalette', () => {
  beforeEach(() => { mockNavigate.mockClear() })

  it('renders and shows Navigate section', () => {
    renderPalette()
    expect(screen.getByText('Navigate')).toBeInTheDocument()
    expect(screen.getByText('Findings')).toBeInTheDocument()
    expect(screen.getByText('Command Center')).toBeInTheDocument()
  })

  it('renders Actions section', () => {
    renderPalette()
    expect(screen.getByText('Actions')).toBeInTheDocument()
    expect(screen.getByText('Export Findings CSV')).toBeInTheDocument()
  })

  it('filters items on query input', () => {
    renderPalette()
    const input = screen.getByPlaceholderText('Type a command or search...')
    fireEvent.change(input, { target: { value: 'find' } })
    expect(screen.getByText('Findings')).toBeInTheDocument()
    expect(screen.queryByText('Compliance')).not.toBeInTheDocument()
  })

  it('shows no results message when query has no match', () => {
    renderPalette()
    const input = screen.getByPlaceholderText('Type a command or search...')
    fireEvent.change(input, { target: { value: 'zzzznothing' } })
    expect(screen.getByText('No results found.')).toBeInTheDocument()
  })

  it('executes navigate on Enter', () => {
    const onOpenChange = vi.fn()
    renderPalette(true, onOpenChange)
    const input = screen.getByPlaceholderText('Type a command or search...')
    fireEvent.keyDown(input, { key: 'Enter' })
    expect(mockNavigate).toHaveBeenCalledWith('/ops')
    expect(onOpenChange).toHaveBeenCalledWith(false)
  })

  it('supports arrow key navigation', () => {
    renderPalette()
    const input = screen.getByPlaceholderText('Type a command or search...')
    fireEvent.keyDown(input, { key: 'ArrowDown' })
    fireEvent.keyDown(input, { key: 'Enter' })
    expect(mockNavigate).toHaveBeenCalledWith('/ops/findings')
  })

  it('does not render content when closed', () => {
    renderPalette(false)
    expect(screen.queryByText('Navigate')).not.toBeInTheDocument()
  })
})
