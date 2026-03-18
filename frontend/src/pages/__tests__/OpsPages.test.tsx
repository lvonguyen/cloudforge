import { describe, it, expect, beforeAll } from 'vitest'
import { screen, waitFor } from '@testing-library/react'
import { Routes, Route } from 'react-router-dom'
import { renderWithProviders, renderWithAuth } from '@/test/utils'
import { TracePanelProvider } from '@/lib/trace-panel-context'

// ReactFlow + recharts need ResizeObserver (jsdom lacks it)
beforeAll(() => {
  global.ResizeObserver = class {
    observe() {}
    unobserve() {}
    disconnect() {}
  }
})

// ---------------------------------------------------------------------------
// 1. AttackPaths
// ---------------------------------------------------------------------------
describe('AttackPaths', () => {
  it('renders loading state', async () => {
    const { default: AttackPaths } = await import('@/pages/ops/AttackPaths')
    renderWithProviders(<AttackPaths />)
    expect(screen.getByText('Computing attack paths...')).toBeInTheDocument()
  })

  it('renders heading after data loads', async () => {
    const { default: AttackPaths } = await import('@/pages/ops/AttackPaths')
    renderWithProviders(<AttackPaths />)
    await waitFor(() => expect(screen.getByText('Attack Paths')).toBeInTheDocument(), { timeout: 10_000 })
  })
})

// ---------------------------------------------------------------------------
// 2. CommandCenter
// ---------------------------------------------------------------------------
describe('CommandCenter', () => {
  it('renders loading or command center shell', async () => {
    const { default: CommandCenter } = await import('@/pages/ops/CommandCenter')
    renderWithProviders(<CommandCenter />)
    // Shows loading while findings load, then the shell
    await waitFor(
      () => expect(
        screen.queryByText('Initializing command center\u2026') ??
        screen.queryByText('Demo data') ??
        document.querySelector('[data-testid]') ??
        document.querySelector('.dark'),
      ).toBeTruthy(),
      { timeout: 10_000 },
    )
  })
})

// ---------------------------------------------------------------------------
// 3. Compliance
// ---------------------------------------------------------------------------
describe('Compliance', () => {
  it('renders loading state', async () => {
    const { default: Compliance } = await import('@/pages/ops/Compliance')
    renderWithProviders(<Compliance />)
    expect(screen.getByText(/loading compliance data/i)).toBeInTheDocument()
  })

  it('renders heading after data loads', async () => {
    const { default: Compliance } = await import('@/pages/ops/Compliance')
    renderWithProviders(<Compliance />)
    await waitFor(() => expect(screen.getByText('Compliance Status')).toBeInTheDocument(), { timeout: 10_000 })
  })
})

// ---------------------------------------------------------------------------
// 4. Containers
// ---------------------------------------------------------------------------
describe('Containers', () => {
  it('renders loading state', async () => {
    const { default: Containers } = await import('@/pages/ops/Containers')
    renderWithProviders(<Containers />)
    expect(screen.getByText('Scanning container topology...')).toBeInTheDocument()
  })

  it('renders heading after data loads', async () => {
    const { default: Containers } = await import('@/pages/ops/Containers')
    renderWithProviders(<Containers />)
    await waitFor(() => expect(screen.getByText('Container Security')).toBeInTheDocument(), { timeout: 10_000 })
  })
})

// ---------------------------------------------------------------------------
// 5. DataClassification
// ---------------------------------------------------------------------------
describe('DataClassification', () => {
  it('renders loading state', async () => {
    const { default: DataClassification } = await import('@/pages/ops/DataClassification')
    renderWithProviders(<DataClassification />)
    expect(screen.getByText('Scanning data assets...')).toBeInTheDocument()
  })

  it('renders heading after data loads', async () => {
    const { default: DataClassification } = await import('@/pages/ops/DataClassification')
    renderWithProviders(<DataClassification />)
    await waitFor(() => expect(screen.getByText('Data Classification')).toBeInTheDocument(), { timeout: 10_000 })
  })
})

// ---------------------------------------------------------------------------
// 6. FindingDetail (needs route param :id)
// ---------------------------------------------------------------------------
describe('FindingDetail', () => {
  it('renders loading state', async () => {
    const { default: FindingDetail } = await import('@/pages/ops/FindingDetail')
    renderWithAuth(
      <TracePanelProvider>
        <Routes>
          <Route path="/ops/findings/:id" element={<FindingDetail />} />
        </Routes>
      </TracePanelProvider>,
      { route: '/ops/findings/f-001' },
    )
    expect(screen.getByText(/loading finding/i)).toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// 7. RemediationDetail (needs route param :id)
// ---------------------------------------------------------------------------
describe('RemediationDetail', () => {
  it('renders loading state', async () => {
    const { default: RemediationDetail } = await import('@/pages/ops/RemediationDetail')
    renderWithProviders(
      <Routes>
        <Route path="/ops/remediation/:id" element={<RemediationDetail />} />
      </Routes>,
      { route: '/ops/remediation/rem-001' },
    )
    expect(screen.getByText(/loading remediation/i)).toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// 8. RemediationQueue
// ---------------------------------------------------------------------------
describe('RemediationQueue', () => {
  it('renders loading state', async () => {
    const { default: RemediationQueue } = await import('@/pages/ops/RemediationQueue')
    renderWithProviders(
      <TracePanelProvider>
        <RemediationQueue />
      </TracePanelProvider>,
    )
    expect(screen.getByText(/loading remediation queue/i)).toBeInTheDocument()
  })

  it('renders heading after data loads', async () => {
    const { default: RemediationQueue } = await import('@/pages/ops/RemediationQueue')
    renderWithProviders(
      <TracePanelProvider>
        <RemediationQueue />
      </TracePanelProvider>,
    )
    await waitFor(() => expect(screen.getByText('Remediation Queue')).toBeInTheDocument(), { timeout: 10_000 })
  })
})

// ---------------------------------------------------------------------------
// 9. SecurityGraph
// ---------------------------------------------------------------------------
describe('SecurityGraph', () => {
  it('renders loading state', async () => {
    const { default: SecurityGraph } = await import('@/pages/ops/SecurityGraph')
    renderWithProviders(<SecurityGraph />)
    expect(screen.getByText('Loading security graph...')).toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// 10. Spend
// ---------------------------------------------------------------------------
describe('Spend', () => {
  it('renders loading state', async () => {
    const { default: Spend } = await import('@/pages/ops/Spend')
    renderWithProviders(<Spend />)
    expect(screen.getByText('Loading cost data...')).toBeInTheDocument()
  })

  it('renders heading after data loads', async () => {
    const { default: Spend } = await import('@/pages/ops/Spend')
    renderWithProviders(<Spend />)
    await waitFor(() => expect(screen.getByText('Spend Management')).toBeInTheDocument(), { timeout: 10_000 })
  })
})

// ---------------------------------------------------------------------------
// 11. AppCatalog
// ---------------------------------------------------------------------------
describe('AppCatalog', () => {
  it('renders heading', async () => {
    const { default: AppCatalog } = await import('@/pages/ops/AppCatalog')
    renderWithProviders(<AppCatalog />)
    expect(screen.getByText('Application Catalog')).toBeInTheDocument()
  })

  it('renders tabs', async () => {
    const { default: AppCatalog } = await import('@/pages/ops/AppCatalog')
    renderWithProviders(<AppCatalog />)
    expect(screen.getByText('Applications')).toBeInTheDocument()
    expect(screen.getByText('Data Classification')).toBeInTheDocument()
  })
})
