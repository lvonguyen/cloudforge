import { describe, it, expect, vi, afterEach } from 'vitest'
import { screen } from '@testing-library/react'
import { renderWithProviders } from '@/test/utils'
import { SLACountdown } from '../SLACountdown'

afterEach(() => {
  vi.useRealTimers()
})

describe('SLACountdown', () => {
  it('returns null when neither dueDate nor slaBreach is provided', () => {
    const { container } = renderWithProviders(<SLACountdown />)
    expect(container.firstChild).toBeNull()
  })

  it('shows overdue state for a past date', () => {
    vi.useFakeTimers()
    vi.setSystemTime(new Date('2024-06-01T12:00:00Z'))
    renderWithProviders(<SLACountdown dueDate="2024-05-28T12:00:00Z" />)
    expect(screen.getByText(/overdue/i)).toBeInTheDocument()
    vi.useRealTimers()
  })

  it('shows remaining time for a future date', () => {
    vi.useFakeTimers()
    vi.setSystemTime(new Date('2024-06-01T12:00:00Z'))
    renderWithProviders(<SLACountdown dueDate="2024-06-05T12:00:00Z" />)
    expect(screen.getByText(/left/i)).toBeInTheDocument()
    vi.useRealTimers()
  })

  it('applies red color class when breached', () => {
    vi.useFakeTimers()
    vi.setSystemTime(new Date('2024-06-10T00:00:00Z'))
    renderWithProviders(<SLACountdown dueDate="2024-06-01T00:00:00Z" />)
    const span = screen.getByText(/overdue/i).closest('span')
    expect(span?.className).toMatch(/red/)
    vi.useRealTimers()
  })

  it('uses slaBreach over dueDate when both are provided', () => {
    vi.useFakeTimers()
    vi.setSystemTime(new Date('2024-06-01T12:00:00Z'))
    // slaBreach is in the past (overdue), dueDate is in future
    renderWithProviders(<SLACountdown dueDate="2024-06-10T00:00:00Z" slaBreach="2024-05-28T00:00:00Z" />)
    expect(screen.getByText(/overdue/i)).toBeInTheDocument()
    vi.useRealTimers()
  })

  it('shows day count when overdue by more than 24 hours', () => {
    vi.useFakeTimers()
    vi.setSystemTime(new Date('2024-06-05T12:00:00Z'))
    renderWithProviders(<SLACountdown dueDate="2024-06-01T12:00:00Z" />)
    expect(screen.getByText(/4d overdue/i)).toBeInTheDocument()
    vi.useRealTimers()
  })
})
