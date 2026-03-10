import { Navigate } from 'react-router-dom'
import { useAuth, type Role } from '@/lib/auth'

export function ProtectedRoute({ roles, children }: { roles: Role[]; children: React.ReactNode }) {
  const { role, isAuthenticated, login } = useAuth()

  if (!isAuthenticated && !import.meta.env.DEV) {
    login()
    return null
  }

  if (!roles.includes(role)) return <Navigate to="/" replace />
  return <>{children}</>
}
