import { describe, it, expect, vi, beforeEach } from 'vitest'
import { screen } from '@testing-library/react'
import { renderWithAuth } from '@/test/utils'

// Mock branding with demo access enabled
vi.mock('@/lib/branding', async (importOriginal) => {
  const mod: Record<string, unknown> = await importOriginal()
  const original = mod.branding as Record<string, unknown>
  return {
    branding: {
      ...original,
      demoAccess: {
        enabled: true,
        email: 'demo-viewer@test.com',
        password: 'demo-pass',
      },
    },
  }
})

import Landing from '@/pages/Landing'

describe('DemoAccessCard (enabled)', () => {
  beforeEach(() => {
    vi.stubEnv('DEV', true)
    sessionStorage.clear()
  })

  it('renders the Demo Access section when enabled', () => {
    renderWithAuth(<Landing />)
    expect(screen.getByText('Demo Access')).toBeInTheDocument()
  })

  it('displays the pre-filled demo email', () => {
    renderWithAuth(<Landing />)
    expect(screen.getByText('demo-viewer@test.com')).toBeInTheDocument()
  })

  it('shows "Sign in as Demo Viewer" button', () => {
    renderWithAuth(<Landing />)
    const button = screen.getByRole('button', { name: /sign in as demo viewer/i })
    expect(button).toBeInTheDocument()
  })
})
