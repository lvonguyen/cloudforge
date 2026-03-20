import { useEffect } from 'react'
import { Navigate, useLocation } from 'react-router-dom'
import { useAuth, type Role, LOGIN_RETURN_KEY } from '@/lib/auth'

export function ProtectedRoute({ roles, children }: { roles: Role[]; children: React.ReactNode }) {
  const { role, isAuthenticated, login } = useAuth()
  const location = useLocation()

  useEffect(() => {
    if (!isAuthenticated && !import.meta.env.DEV && import.meta.env.VITE_DEMO_MODE !== 'true') {
      sessionStorage.setItem(LOGIN_RETURN_KEY, location.pathname + location.search)
      login()
    }
  }, [isAuthenticated, login, location.pathname, location.search])

  if (!isAuthenticated && !import.meta.env.DEV && import.meta.env.VITE_DEMO_MODE !== 'true') {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <p className="text-sm text-muted-foreground font-mono">Redirecting to login...</p>
      </div>
    )
  }

  if (!roles.includes(role)) return <Navigate to="/" replace />
  return <>{children}</>
}
