import { describe, it, expect, vi } from 'vitest'
import { screen, fireEvent } from '@testing-library/react'
import { renderWithProviders } from '@/test/utils'
import { StatusBar } from '../StatusBar'
import type { Finding } from '@/types/compliance'

function makeFinding(severity: string): Partial<Finding> {
  return { severity } as Partial<Finding>
}

describe('StatusBar', () => {
  const baseProps = {
    filteredFindings: [
      makeFinding('CRITICAL'),
      makeFinding('HIGH'),
      makeFinding('HIGH'),
      makeFinding('MEDIUM'),
    ] as Finding[],
    totalFindings: 100,
    attackPathCount: 5,
    toxicComboCount: 2,
  }

  it('renders severity counts', () => {
    renderWithProviders(<StatusBar {...baseProps} />)
    // CRITICAL=1, MEDIUM=1 → two elements with text "1"
    const ones = screen.getAllByText('1')
    expect(ones.length).toBeGreaterThanOrEqual(2) // CRITICAL + MEDIUM
    expect(screen.getByText('2')).toBeInTheDocument() // HIGH
  })

  it('renders total findings and attack path counts', () => {
    renderWithProviders(<StatusBar {...baseProps} />)
    expect(screen.getByText('4/100 findings')).toBeInTheDocument()
    expect(screen.getByText('5 paths')).toBeInTheDocument()
    expect(screen.getByText('2 toxic combos')).toBeInTheDocument()
  })

  it('exposes the summary as an accessible status region', () => {
    renderWithProviders(<StatusBar {...baseProps} />)
    expect(
      screen.getByRole('status', { name: 'Command center status summary' }),
    ).toBeInTheDocument()
  })

  it('renders date inputs when onDateRangeChange provided', () => {
    const onChange = vi.fn()
    renderWithProviders(
      <StatusBar
        {...baseProps}
        dateRange={{ start: null, end: null }}
        onDateRangeChange={onChange}
      />,
    )
    expect(screen.getByLabelText('Start date')).toBeInTheDocument()
    expect(screen.getByLabelText('End date')).toBeInTheDocument()
  })

  it('calls onDateRangeChange when start date changes', () => {
    const onChange = vi.fn()
    renderWithProviders(
      <StatusBar
        {...baseProps}
        dateRange={{ start: null, end: null }}
        onDateRangeChange={onChange}
      />,
    )
    fireEvent.change(screen.getByLabelText('Start date'), { target: { value: '2024-01-01' } })
    expect(onChange).toHaveBeenCalledWith({ start: '2024-01-01', end: null })
  })

  it('shows clear button when date is set', () => {
    const onChange = vi.fn()
    renderWithProviders(
      <StatusBar
        {...baseProps}
        dateRange={{ start: '2024-01-01', end: null }}
        onDateRangeChange={onChange}
      />,
    )
    const clearBtn = screen.getByLabelText('Clear date filter')
    expect(clearBtn).toBeInTheDocument()
    fireEvent.click(clearBtn)
    expect(onChange).toHaveBeenCalledWith({ start: null, end: null })
  })

  it('renders ? shortcut button when onShowShortcuts provided', () => {
    const onShortcuts = vi.fn()
    renderWithProviders(
      <StatusBar {...baseProps} onShowShortcuts={onShortcuts} />,
    )
    const btn = screen.getByLabelText('Keyboard shortcuts')
    expect(btn).toBeInTheDocument()
    fireEvent.click(btn)
    expect(onShortcuts).toHaveBeenCalled()
  })
})
