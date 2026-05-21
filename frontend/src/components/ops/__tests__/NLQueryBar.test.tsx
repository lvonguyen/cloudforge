import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { screen, fireEvent, waitFor } from '@testing-library/react'
import { renderWithProviders } from '@/test/utils'
import { NLQueryBar } from '../NLQueryBar'

// Mock the apiClient so we control the AI endpoint responses
vi.mock('@/lib/api', async () => {
  const actual = await vi.importActual('@/lib/api')
  return {
    ...actual,
    apiClient: {
      get: vi.fn(),
      post: vi.fn(),
      put: vi.fn(),
      patch: vi.fn(),
      delete: vi.fn(),
    },
  }
})

import { apiClient } from '@/lib/api'

function renderBar(onApplyFilters = vi.fn()) {
  return { onApplyFilters, ...renderWithProviders(<NLQueryBar onApplyFilters={onApplyFilters} />) }
}

describe('NLQueryBar', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  afterEach(() => {
    vi.restoreAllMocks()
  })

  // -------------------------------------------------------
  // 1. Renders search trigger with placeholder text
  // -------------------------------------------------------
  it('renders trigger button with placeholder text', () => {
    renderBar()
    expect(screen.getByText('Ask a question about findings...')).toBeInTheDocument()
  })

  it('renders keyboard shortcut hint in trigger', () => {
    renderBar()
    expect(screen.getByText(/K/)).toBeInTheDocument()
  })

  // -------------------------------------------------------
  // 2. Opens overlay and accepts user input
  // -------------------------------------------------------
  it('opens overlay when trigger button is clicked', () => {
    renderBar()
    fireEvent.click(screen.getByText('Ask a question about findings...'))
    // The NLQ mode button should be visible in the overlay
    expect(screen.getByText('NLQ')).toBeInTheDocument()
    expect(screen.getByText('RQL')).toBeInTheDocument()
  })

  it('renders input with NLQ placeholder when overlay is open', () => {
    renderBar()
    fireEvent.click(screen.getByText('Ask a question about findings...'))
    expect(screen.getByPlaceholderText('e.g. critical AWS misconfigs in production')).toBeInTheDocument()
  })

  it('accepts user input and updates value', () => {
    renderBar()
    fireEvent.click(screen.getByText('Ask a question about findings...'))
    const input = screen.getByPlaceholderText('e.g. critical AWS misconfigs in production')
    fireEvent.change(input, { target: { value: 'critical aws findings' } })
    expect(input).toHaveValue('critical aws findings')
  })

  // -------------------------------------------------------
  // 3. Submits on Enter keypress (NLQ keyword extraction)
  // -------------------------------------------------------
  it('submits on Enter and applies keyword-extracted filters', () => {
    const onApplyFilters = vi.fn()
    renderBar(onApplyFilters)

    fireEvent.click(screen.getByText('Ask a question about findings...'))
    const input = screen.getByPlaceholderText('e.g. critical AWS misconfigs in production')
    fireEvent.change(input, { target: { value: 'critical aws misconfigs' } })
    fireEvent.keyDown(input, { key: 'Enter' })

    expect(onApplyFilters).toHaveBeenCalledWith({
      severity: ['CRITICAL'],
      provider: ['aws'],
      category: ['MISCONFIGURATION'],
    })
  })

  it('does not submit when query is empty', () => {
    const onApplyFilters = vi.fn()
    renderBar(onApplyFilters)

    fireEvent.click(screen.getByText('Ask a question about findings...'))
    const input = screen.getByPlaceholderText('e.g. critical AWS misconfigs in production')
    fireEvent.keyDown(input, { key: 'Enter' })

    expect(onApplyFilters).not.toHaveBeenCalled()
  })

  it('extracts multiple severity and provider keywords', () => {
    const onApplyFilters = vi.fn()
    renderBar(onApplyFilters)

    fireEvent.click(screen.getByText('Ask a question about findings...'))
    const input = screen.getByPlaceholderText('e.g. critical AWS misconfigs in production')
    fireEvent.change(input, { target: { value: 'high and critical azure findings' } })
    fireEvent.keyDown(input, { key: 'Enter' })

    expect(onApplyFilters).toHaveBeenCalledWith(
      expect.objectContaining({
        severity: expect.arrayContaining(['CRITICAL', 'HIGH']),
        provider: ['azure'],
      }),
    )
  })

  it('extracts status keywords from query', () => {
    const onApplyFilters = vi.fn()
    renderBar(onApplyFilters)

    fireEvent.click(screen.getByText('Ask a question about findings...'))
    const input = screen.getByPlaceholderText('e.g. critical AWS misconfigs in production')
    fireEvent.change(input, { target: { value: 'open vulnerabilities' } })
    fireEvent.keyDown(input, { key: 'Enter' })

    expect(onApplyFilters).toHaveBeenCalledWith({
      category: ['VULNERABILITY'],
      status: ['open'],
    })
  })

  // -------------------------------------------------------
  // 4. Shows loading state during AI search
  // -------------------------------------------------------
  it('shows loading state when AI endpoint is called', async () => {
    // Query with no keyword matches forces AI call
    let resolvePost: (value: unknown) => void
    const postPromise = new Promise((resolve) => { resolvePost = resolve })
    vi.mocked(apiClient.post).mockReturnValue(postPromise as Promise<never>)

    const onApplyFilters = vi.fn()
    renderBar(onApplyFilters)

    fireEvent.click(screen.getByText('Ask a question about findings...'))
    const input = screen.getByPlaceholderText('e.g. critical AWS misconfigs in production')
    // Use a query that won't match any keywords
    fireEvent.change(input, { target: { value: 'show me S3 bucket findings' } })
    fireEvent.keyDown(input, { key: 'Enter' })

    // Loading indicator should appear
    await waitFor(() => {
      expect(screen.getByText('Analyzing...')).toBeInTheDocument()
    })

    // Input should be disabled during loading
    expect(input).toBeDisabled()

    // Resolve the promise to clean up
    resolvePost!({ severity: ['HIGH'] })
    await waitFor(() => {
      expect(screen.queryByText('Analyzing...')).not.toBeInTheDocument()
    })
  })

  // -------------------------------------------------------
  // 5. Renders filter pills after search completes
  // -------------------------------------------------------
  it('renders applied filter pills after keyword search', () => {
    const onApplyFilters = vi.fn()
    renderBar(onApplyFilters)

    fireEvent.click(screen.getByText('Ask a question about findings...'))
    const input = screen.getByPlaceholderText('e.g. critical AWS misconfigs in production')
    fireEvent.change(input, { target: { value: 'critical gcp' } })
    fireEvent.keyDown(input, { key: 'Enter' })

    // Filter pills should be visible
    expect(screen.getByText('CRITICAL')).toBeInTheDocument()
    expect(screen.getByText('GCP')).toBeInTheDocument()
    expect(screen.getByText('Interpreted as:')).toBeInTheDocument()
  })

  it('renders applied filter pills after AI search', async () => {
    vi.mocked(apiClient.post).mockResolvedValue({
      severity: ['HIGH'],
      provider: ['aws'],
    })

    const onApplyFilters = vi.fn()
    renderBar(onApplyFilters)

    fireEvent.click(screen.getByText('Ask a question about findings...'))
    const input = screen.getByPlaceholderText('e.g. critical AWS misconfigs in production')
    fireEvent.change(input, { target: { value: 'show me S3 bucket findings' } })
    fireEvent.keyDown(input, { key: 'Enter' })

    await waitFor(() => {
      expect(screen.getByText('HIGH')).toBeInTheDocument()
    })
    expect(screen.getByText('AWS')).toBeInTheDocument()
    expect(screen.getByText('Interpreted as:')).toBeInTheDocument()
  })

  it('clears filters when Clear is clicked', () => {
    const onApplyFilters = vi.fn()
    renderBar(onApplyFilters)

    // Apply a filter first
    fireEvent.click(screen.getByText('Ask a question about findings...'))
    const input = screen.getByPlaceholderText('e.g. critical AWS misconfigs in production')
    fireEvent.change(input, { target: { value: 'critical aws' } })
    fireEvent.keyDown(input, { key: 'Enter' })

    expect(screen.getByText('CRITICAL')).toBeInTheDocument()

    // Click Clear
    fireEvent.click(screen.getByText('Clear'))
    expect(screen.queryByText('CRITICAL')).not.toBeInTheDocument()
    expect(screen.queryByText('Interpreted as:')).not.toBeInTheDocument()
    expect(onApplyFilters).toHaveBeenLastCalledWith({})
  })

  // -------------------------------------------------------
  // RQL mode
  // -------------------------------------------------------
  it('switches to RQL mode and parses structured queries', () => {
    const onApplyFilters = vi.fn()
    renderBar(onApplyFilters)

    fireEvent.click(screen.getByText('Ask a question about findings...'))

    // Switch to RQL mode
    fireEvent.click(screen.getByText('RQL'))
    const input = screen.getByPlaceholderText('severity=CRITICAL AND provider=aws')
    fireEvent.change(input, { target: { value: 'severity=CRITICAL AND provider=aws' } })
    fireEvent.keyDown(input, { key: 'Enter' })

    expect(onApplyFilters).toHaveBeenCalledWith({
      severity: ['CRITICAL'],
      provider: ['aws'],
    })
  })

  it('preserves RQL exclusion filters', () => {
    const onApplyFilters = vi.fn()
    renderBar(onApplyFilters)

    fireEvent.click(screen.getByText('Ask a question about findings...'))
    fireEvent.click(screen.getByText('RQL'))

    const input = screen.getByPlaceholderText('severity=CRITICAL AND provider=aws')
    fireEvent.change(input, { target: { value: 'provider=aws AND status!=resolved' } })
    fireEvent.keyDown(input, { key: 'Enter' })

    expect(onApplyFilters).toHaveBeenCalledWith({
      provider: ['aws'],
      exclude: { status: ['resolved'] },
    })
    expect(screen.getByText('not status: resolved')).toBeInTheDocument()
  })

  it('falls back to text search for invalid RQL', () => {
    const onApplyFilters = vi.fn()
    renderBar(onApplyFilters)

    fireEvent.click(screen.getByText('Ask a question about findings...'))
    fireEvent.click(screen.getByText('RQL'))

    const input = screen.getByPlaceholderText('severity=CRITICAL AND provider=aws')
    fireEvent.change(input, { target: { value: 'just some random text' } })
    fireEvent.keyDown(input, { key: 'Enter' })

    expect(onApplyFilters).toHaveBeenCalledWith({
      text: 'just some random text',
    })
  })

  // -------------------------------------------------------
  // Overlay open/close
  // -------------------------------------------------------
  it('closes overlay on Escape key', () => {
    renderBar()
    fireEvent.click(screen.getByText('Ask a question about findings...'))
    expect(screen.getByText('NLQ')).toBeInTheDocument()

    fireEvent.keyDown(window, { key: 'Escape' })
    // Overlay should be gone — NLQ button no longer visible
    expect(screen.queryByPlaceholderText('e.g. critical AWS misconfigs in production')).not.toBeInTheDocument()
  })

  it('closes overlay when backdrop is clicked', () => {
    renderBar()
    fireEvent.click(screen.getByText('Ask a question about findings...'))
    expect(screen.getByPlaceholderText('e.g. critical AWS misconfigs in production')).toBeInTheDocument()

    // Click the close button
    fireEvent.click(screen.getByLabelText('Close'))
    expect(screen.queryByPlaceholderText('e.g. critical AWS misconfigs in production')).not.toBeInTheDocument()
  })

  it('shows examples text in NLQ mode', () => {
    renderBar()
    fireEvent.click(screen.getByText('Ask a question about findings...'))
    expect(screen.getByText('Examples:')).toBeInTheDocument()
    expect(screen.getByText('critical AWS misconfigs')).toBeInTheDocument()
  })

  it('shows syntax hint in RQL mode', () => {
    renderBar()
    fireEvent.click(screen.getByText('Ask a question about findings...'))
    fireEvent.click(screen.getByText('RQL'))
    expect(screen.getByText('Syntax:')).toBeInTheDocument()
  })

  // -------------------------------------------------------
  // AI fallback on error
  // -------------------------------------------------------
  it('falls back to text search when AI endpoint fails', async () => {
    vi.mocked(apiClient.post).mockRejectedValue(new Error('Network error'))

    const onApplyFilters = vi.fn()
    renderBar(onApplyFilters)

    fireEvent.click(screen.getByText('Ask a question about findings...'))
    const input = screen.getByPlaceholderText('e.g. critical AWS misconfigs in production')
    fireEvent.change(input, { target: { value: 'show me S3 bucket findings' } })
    fireEvent.keyDown(input, { key: 'Enter' })

    await waitFor(() => {
      expect(onApplyFilters).toHaveBeenCalledWith({
        text: 'show me S3 bucket findings',
      })
    })
  })

  it('shows text filter pill on AI fallback', async () => {
    vi.mocked(apiClient.post).mockRejectedValue(new Error('Network error'))

    renderBar()

    fireEvent.click(screen.getByText('Ask a question about findings...'))
    const input = screen.getByPlaceholderText('e.g. critical AWS misconfigs in production')
    fireEvent.change(input, { target: { value: 'show me S3 bucket findings' } })
    fireEvent.keyDown(input, { key: 'Enter' })

    await waitFor(() => {
      expect(screen.getByText('"show me S3 bucket findings"')).toBeInTheDocument()
    })
  })
})
