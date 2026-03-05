import { useState, useEffect } from 'react'
import { Outlet, useLocation } from 'react-router-dom'
import { useAuth, type Role } from '@/lib/auth'
import { TopNav } from './TopNav'
import { Sidebar } from './Sidebar'

const PREFIX_TO_ROLE: [string, Role][] = [
  ['/admin', 'admin'],
  ['/ops', 'operator'],
  ['/portal', 'requester'],
]

export function AppShell() {
  const { pathname } = useLocation()
  const { role, setRole } = useAuth()
  const [mobileOpen, setMobileOpen] = useState(false)

  // Sync role from URL prefix so direct navigation works correctly
  useEffect(() => {
    for (const [prefix, expected] of PREFIX_TO_ROLE) {
      if (pathname.startsWith(prefix) && role !== expected) {
        setRole(expected)
        return
      }
    }
  }, [pathname, role, setRole])

  // Close mobile sidebar on route change
  useEffect(() => {
    setMobileOpen(false)
  }, [pathname])

  return (
    <div className="flex h-screen flex-col overflow-hidden">
      <TopNav onMenuClick={() => setMobileOpen(o => !o)} />
      <div className="flex flex-1 overflow-hidden">
        <Sidebar mobileOpen={mobileOpen} onMobileClose={() => setMobileOpen(false)} />
        <main className="flex-1 overflow-y-auto bg-background p-6">
          <Outlet />
        </main>
      </div>
    </div>
  )
}
