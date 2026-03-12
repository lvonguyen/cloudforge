import { describe, it, expect, vi, beforeEach } from 'vitest'
import { screen, waitFor } from '@testing-library/react'
import { renderWithAuth } from '@/test/utils'
import { ProtectedRoute } from '../ProtectedRoute'
import type { Role } from '@/lib/auth'

describe('ProtectedRoute', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    sessionStorage.clear()
    localStorage.clear()
    // Set DEV mode to true to bypass authentication redirects
    vi.stubEnv('DEV', true)
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
    localStorage.setItem('cloudforge_role', 'viewer')

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
    localStorage.setItem('cloudforge_role', 'operator')

    renderWithAuth(
      <ProtectedRoute roles={['operator']}>
        <div>Operator Console</div>
      </ProtectedRoute>
    )

    expect(screen.getByText('Operator Console')).toBeInTheDocument()
  })

  it('allows requester access to requester routes', () => {
    localStorage.setItem('cloudforge_role', 'requester')

    renderWithAuth(
      <ProtectedRoute roles={['requester']}>
        <div>Request Portal</div>
      </ProtectedRoute>
    )

    expect(screen.getByText('Request Portal')).toBeInTheDocument()
  })

  it('allows multiple roles to access the same route', () => {
    localStorage.setItem('cloudforge_role', 'operator')

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

    const returnPath = sessionStorage.getItem('cloudforge_login_return')
    expect(returnPath).toBe('/findings?severity=HIGH')
  })

  it('displays redirecting message in production when not authenticated', () => {
    vi.stubEnv('DEV', false)
    sessionStorage.removeItem('cloudforge_access_token')

    renderWithAuth(
      <ProtectedRoute roles={['admin']}>
        <div>Protected</div>
      </ProtectedRoute>
    )

    expect(screen.getByText('Redirecting to login...')).toBeInTheDocument()
  })
})
