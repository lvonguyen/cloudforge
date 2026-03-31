import { describe, it, expect, vi, beforeEach } from 'vitest'
import { screen, waitFor } from '@testing-library/react'
import { renderWithAuth } from '@/test/utils'
import { ProtectedRoute } from '../ProtectedRoute'
import { setPreviewRoleOverride } from '@/lib/auth'

describe('ProtectedRoute', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    sessionStorage.clear()
    // Set DEV mode to true to bypass authentication redirects
    vi.stubEnv('DEV', true)
    setPreviewRoleOverride(null)
  })

  it('renders children when user role is in allowed roles', () => {
    renderWithAuth(
      <ProtectedRoute roles={['admin', 'operator']}>
        <div>Protected Content</div>
      </ProtectedRoute>
    )

    expect(screen.getByText('Protected Content')).toBeInTheDocument()
  })

  it('renders children when user is admin and admin role is allowed', () => {
    renderWithAuth(
      <ProtectedRoute roles={['admin']}>
        <div>Admin Dashboard</div>
      </ProtectedRoute>
    )

    expect(screen.getByText('Admin Dashboard')).toBeInTheDocument()
  })

  it('redirects to home when user role is not in allowed roles', async () => {
    setPreviewRoleOverride('viewer')

    renderWithAuth(
      <ProtectedRoute roles={['admin']}>
        <div>Admin Only</div>
      </ProtectedRoute>,
      { route: '/admin' }
    )

    await waitFor(() => {
      expect(screen.queryByText('Admin Only')).not.toBeInTheDocument()
    })
  })

  it('allows operator access to operator-only routes', () => {
    setPreviewRoleOverride('operator')

    renderWithAuth(
      <ProtectedRoute roles={['operator']}>
        <div>Operator Console</div>
      </ProtectedRoute>
    )

    expect(screen.getByText('Operator Console')).toBeInTheDocument()
  })

  it('allows requester access to requester routes', () => {
    setPreviewRoleOverride('requester')

    renderWithAuth(
      <ProtectedRoute roles={['requester']}>
        <div>Request Portal</div>
      </ProtectedRoute>
    )

    expect(screen.getByText('Request Portal')).toBeInTheDocument()
  })

  it('allows multiple roles to access the same route', () => {
    setPreviewRoleOverride('operator')

    renderWithAuth(
      <ProtectedRoute roles={['admin', 'operator', 'requester']}>
        <div>Shared Content</div>
      </ProtectedRoute>
    )

    expect(screen.getByText('Shared Content')).toBeInTheDocument()
  })

  it('saves return path to sessionStorage in production mode', () => {
    vi.stubEnv('DEV', false)
    sessionStorage.clear()

    renderWithAuth(
      <ProtectedRoute roles={['admin']}>
        <div>Protected</div>
      </ProtectedRoute>,
      { route: '/findings?severity=HIGH' }
    )

    const returnPath = sessionStorage.getItem('aegis_login_return')
    expect(returnPath).toBe('/findings?severity=HIGH')
  })

  it('displays redirecting message in production when not authenticated', () => {
    vi.stubEnv('DEV', false)
    sessionStorage.removeItem('aegis_access_token')

    renderWithAuth(
      <ProtectedRoute roles={['admin']}>
        <div>Protected</div>
      </ProtectedRoute>
    )

    expect(screen.getByText('Redirecting to login...')).toBeInTheDocument()
  })

  it('bypasses auth when VITE_DEMO_MODE is set (demo deployment)', () => {
    vi.stubEnv('DEV', false)
    vi.stubEnv('VITE_DEMO_MODE', 'true')
    setPreviewRoleOverride('admin')

    renderWithAuth(
      <ProtectedRoute roles={['admin']}>
        <div>Demo Content</div>
      </ProtectedRoute>
    )

    expect(screen.getByText('Demo Content')).toBeInTheDocument()
  })
})
