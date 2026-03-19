import { useState, useEffect } from 'react'
import { Outlet, useLocation } from 'react-router-dom'
import { TopNav } from './TopNav'
import { Sidebar } from './Sidebar'
import { Footer } from './Footer'

export function AppShell() {
  const { pathname } = useLocation()
  const [mobileOpen, setMobileOpen] = useState(false)

  // Close mobile sidebar on route change
  useEffect(() => {
    setMobileOpen(false)
  }, [pathname])

  return (
    <div className="flex h-screen flex-col overflow-hidden">
      <a href="#main-content" className="sr-only focus:not-sr-only focus:absolute focus:z-50 focus:px-4 focus:py-2 focus:bg-primary focus:text-primary-foreground">
        Skip to content
      </a>
      <TopNav onMenuClick={() => setMobileOpen(o => !o)} />
      <div className="flex flex-1 overflow-hidden">
        <Sidebar mobileOpen={mobileOpen} onMobileClose={() => setMobileOpen(false)} />
        <div className="flex flex-1 flex-col overflow-hidden">
          <main id="main-content" className={`flex-1 bg-background ${pathname === '/ops' || pathname === '/ops/' ? 'overflow-hidden' : 'overflow-y-auto p-6'}`}>
            <Outlet />
          </main>
          <Footer />
        </div>
      </div>
    </div>
  )
}
