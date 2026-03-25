import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, type RenderOptions } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import type { ReactNode } from 'react'
import { AuthProvider } from '@/lib/auth'
import { TracePanelProvider } from '@/lib/trace-panel-context'

export function createTestQueryClient() {
  return new QueryClient({
    defaultOptions: { queries: { retry: false, gcTime: 0 } },
  })
}

export function renderWithProviders(
  ui: ReactNode,
  { route = '/', ...options }: RenderOptions & { route?: string } = {}
) {
  const client = createTestQueryClient()
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[route]}>{ui}</MemoryRouter>
    </QueryClientProvider>,
    options
  )
}

export function renderWithAuth(
  ui: ReactNode,
  { route = '/', ...options }: RenderOptions & { route?: string } = {}
) {
  const client = createTestQueryClient()
  return render(
    <QueryClientProvider client={client}>
      <AuthProvider>
        <TracePanelProvider>
          <MemoryRouter initialEntries={[route]}>{ui}</MemoryRouter>
        </TracePanelProvider>
      </AuthProvider>
    </QueryClientProvider>,
    options
  )
}
