import { createContext, useContext, useState, useEffect, type ReactNode, createElement } from 'react'

export type Role = 'admin' | 'operator' | 'requester'

export interface User {
  name: string
  email: string
  role: Role
}

const DEFAULT_USER: User = {
  name: 'Liem VN',
  email: 'liem@cloudforge.dev',
  role: 'admin',
}

const STORAGE_KEY = 'cloudforge_role'

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
    return {
      ...DEFAULT_USER,
      role: savedRole ?? DEFAULT_USER.role,
    }
  })

  const setRole = (role: Role) => {
    localStorage.setItem(STORAGE_KEY, role)
    setUser(prev => ({ ...prev, role }))
  }

  const logout = () => {
    localStorage.removeItem(STORAGE_KEY)
    setUser(DEFAULT_USER)
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
