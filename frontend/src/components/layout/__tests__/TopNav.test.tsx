import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, screen } from '@testing-library/react'
import { renderWithAuth } from '@/test/utils'
import { DEMO_SESSION_KEY, TOKEN_KEY, setPreviewRoleOverride } from '@/lib/auth'
import { TopNav } from '../TopNav'

function makeJWT(payload: Record<string, unknown>): string {
  const header = btoa(JSON.stringify({ alg: 'HS256', typ: 'JWT' }))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
  const body = btoa(JSON.stringify(payload))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
  return `${header}.${body}.fakesig`
}

describe('TopNav terminal access', () => {
  beforeEach(() => {
    vi.stubEnv('DEV', true)
    sessionStorage.clear()
    setPreviewRoleOverride(null)
  })

  it('renders the terminal button for operator sessions and toggles active state', () => {
    setPreviewRoleOverride('operator')
    renderWithAuth(<TopNav onMenuClick={() => {}} />)

    const button = screen.getByRole('button', { name: 'Show terminal panel' })
    expect(button).toBeInTheDocument()

    fireEvent.click(button)
    expect(screen.getByRole('button', { name: 'Hide terminal panel' })).toBeInTheDocument()
  })

  it('hides the terminal button for viewer sessions', () => {
    setPreviewRoleOverride('viewer')
    renderWithAuth(<TopNav onMenuClick={() => {}} />)

    expect(screen.queryByRole('button', { name: /terminal panel/i })).not.toBeInTheDocument()
  })

  it('renders the role switcher for a prod demo session even when build-demo mode is off', () => {
    vi.stubEnv('DEV', false)
    vi.stubEnv('VITE_DEMO_MODE', 'false')
    sessionStorage.setItem(TOKEN_KEY, makeJWT({
      email: 'demo@test.com',
      name: 'Demo Viewer',
      groups: ['aegis-admin'],
      exp: Math.floor(Date.now() / 1000) + 3600,
    }))
    sessionStorage.setItem(DEMO_SESSION_KEY, 'true')

    renderWithAuth(<TopNav onMenuClick={() => {}} />)

    expect(screen.getByText('Viewer')).toBeInTheDocument()
  })
})
