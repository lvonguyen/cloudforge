import { createContext, useContext, useState, useEffect, type ReactNode, createElement } from 'react'

export type Role = 'admin' | 'operator' | 'requester'

export interface User {
  name: string
  email: string
  role: Role
}

const DEFAULT_USER: User = {
  name: 'Admin One',
  email: 'admin1@contoso.dev',
  role: 'admin',
}

const STORAGE_KEY = 'cloudforge_role'

// Decode CF Access JWT from CF_Authorization cookie (no signature verification —
// CF Access validates at the edge before traffic reaches us).
function parseCFAccessJWT(): { name: string; email: string } | null {
  const match = document.cookie.match(/(?:^|;\s*)CF_Authorization=([^;]+)/)
  const token = match?.[1]
  if (!token) return null

  try {
    const base64 = token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/')
    const payload = JSON.parse(atob(base64))
    return {
      email: payload.email ?? '',
      name: payload.name || payload.email || '',
    }
  } catch {
    return null
  }
}

interface AuthContextValue {
  user: User
  role: Role
  setRole: (role: Role) => void
  logout: () => void
}

const AuthContext = createContext<AuthContextValue | null>(null)

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User>(() => {
    const savedRole = localStorage.getItem(STORAGE_KEY) as Role | null

    // Production: hydrate identity from CF Access JWT, keep dev role switcher
    if (!import.meta.env.DEV) {
      const cfUser = parseCFAccessJWT()
      if (cfUser) {
        return {
          name: cfUser.name,
          email: cfUser.email,
          role: savedRole ?? DEFAULT_USER.role,
        }
      }
    }

    return { ...DEFAULT_USER, role: savedRole ?? DEFAULT_USER.role }
  })

  const setRole = (role: Role) => {
    localStorage.setItem(STORAGE_KEY, role)
    setUser(prev => ({ ...prev, role }))
  }

  const logout = () => {
    localStorage.removeItem(STORAGE_KEY)
    if (!import.meta.env.DEV) {
      window.location.href = '/cdn-cgi/access/logout'
    } else {
      setUser(DEFAULT_USER)
    }
  }

  useEffect(() => {
    const saved = localStorage.getItem(STORAGE_KEY) as Role | null
    if (saved && saved !== user.role) {
      setUser(prev => ({ ...prev, role: saved }))
    }
  }, [user.role])

  return createElement(AuthContext.Provider, { value: { user, role: user.role, setRole, logout } }, children)
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth must be used within AuthProvider')
  return ctx
}
