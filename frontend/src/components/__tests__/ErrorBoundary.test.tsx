import { describe, it, expect, beforeAll, afterAll, vi } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { ErrorBoundary } from '@/components/ErrorBoundary'

// Suppress expected console.error output from React error boundaries during tests
const originalError = console.error
beforeAll(() => {
  console.error = vi.fn()
})
afterAll(() => {
  console.error = originalError
})

function Bomb({ message }: { message: string }) {
  throw new Error(message)
}

function SafeChild() {
  return <p data-testid="safe-child">All good</p>
}

describe('ErrorBoundary', () => {
  it('renders children when no error is thrown', () => {
    render(
      <MemoryRouter>
        <ErrorBoundary>
          <SafeChild />
        </ErrorBoundary>
      </MemoryRouter>
    )
    expect(screen.getByTestId('safe-child')).toBeInTheDocument()
  })

  it('shows error UI when a child throws', () => {
    render(
      <MemoryRouter>
        <ErrorBoundary>
          <Bomb message="test explosion" />
        </ErrorBoundary>
      </MemoryRouter>
    )
    expect(screen.getByText(/Something went wrong/i)).toBeInTheDocument()
    expect(screen.getByText(/test explosion/i)).toBeInTheDocument()
  })

  it('shows fallbackLabel in the error heading when provided', () => {
    render(
      <MemoryRouter>
        <ErrorBoundary fallbackLabel="Dashboard">
          <Bomb message="boom" />
        </ErrorBoundary>
      </MemoryRouter>
    )
    expect(screen.getByText(/Something went wrong in Dashboard/i)).toBeInTheDocument()
  })

  it('does not include "in" clause when fallbackLabel is omitted', () => {
    render(
      <MemoryRouter>
        <ErrorBoundary>
          <Bomb message="boom" />
        </ErrorBoundary>
      </MemoryRouter>
    )
    const heading = screen.getByRole('heading')
    expect(heading.textContent).toBe('Something went wrong')
  })

  it('"Try again" button resets the error state and re-renders children', () => {
    let shouldThrow = true

    function ConditionalBomb() {
      if (shouldThrow) throw new Error('conditional error')
      return <p data-testid="recovered">Recovered</p>
    }

    const { rerender } = render(
      <MemoryRouter>
        <ErrorBoundary>
          <ConditionalBomb />
        </ErrorBoundary>
      </MemoryRouter>
    )

    expect(screen.getByText(/Something went wrong/i)).toBeInTheDocument()

    shouldThrow = false
    fireEvent.click(screen.getByRole('button', { name: /Try again/i }))

    rerender(
      <MemoryRouter>
        <ErrorBoundary>
          <ConditionalBomb />
        </ErrorBoundary>
      </MemoryRouter>
    )

    expect(screen.getByTestId('recovered')).toBeInTheDocument()
  })

  it('renders the error message from the thrown Error', () => {
    render(
      <MemoryRouter>
        <ErrorBoundary>
          <Bomb message="specific error text" />
        </ErrorBoundary>
      </MemoryRouter>
    )
    expect(screen.getByText('specific error text')).toBeInTheDocument()
  })
})
