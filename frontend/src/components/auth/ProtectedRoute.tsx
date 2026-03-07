import { Navigate } from 'react-router-dom'
import { useAuth, type Role } from '@/lib/auth'

export function ProtectedRoute({ roles, children }: { roles: Role[]; children: React.ReactNode }) {
  const { role } = useAuth()
  if (!roles.includes(role)) return <Navigate to="/" replace />
  return <>{children}</>
}
