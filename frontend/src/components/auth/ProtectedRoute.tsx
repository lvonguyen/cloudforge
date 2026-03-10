import { useEffect } from 'react'
import { Navigate } from 'react-router-dom'
import { useAuth, type Role } from '@/lib/auth'

export function ProtectedRoute({ roles, children }: { roles: Role[]; children: React.ReactNode }) {
  const { role, isAuthenticated, login } = useAuth()

  useEffect(() => {
    if (!isAuthenticated && !import.meta.env.DEV) {
      login()
    }
  }, [isAuthenticated, login])

  if (!isAuthenticated && !import.meta.env.DEV) return null

  if (!roles.includes(role)) return <Navigate to="/" replace />
  return <>{children}</>
}
