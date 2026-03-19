import { lazy, Suspense, useEffect } from 'react'
import { BrowserRouter, Routes, Route, Outlet } from 'react-router-dom'
import { QueryClientProvider } from '@tanstack/react-query'
import { queryClient } from '@/lib/api'
import { AuthProvider } from '@/lib/auth'
import { ConfigProvider } from '@/lib/config-context'
import { branding } from '@/lib/branding'
import { TracePanelProvider } from '@/lib/trace-panel-context'
import { AppShell } from '@/components/layout/AppShell'
import { ExecutionTracePanel } from '@/components/layout/ExecutionTracePanel'
import { ProtectedRoute } from '@/components/auth/ProtectedRoute'
import { RoutingErrorBoundary } from '@/components/ErrorBoundary'

// Eager (always needed)
import Landing from '@/pages/Landing'
import NotFound from '@/pages/NotFound'

// Admin pages (lazy)
const AdminDashboard = lazy(() => import('@/pages/admin/Dashboard'))
const Policies = lazy(() => import('@/pages/admin/Policies'))
const PolicyDetail = lazy(() => import('@/pages/admin/PolicyDetail'))
const AIAgents = lazy(() => import('@/pages/admin/AIAgents'))
const AIAgentDetail = lazy(() => import('@/pages/admin/AIAgentDetail'))
const Users = lazy(() => import('@/pages/admin/Users'))
const AuditLog = lazy(() => import('@/pages/admin/AuditLog'))
const SystemHealth = lazy(() => import('@/pages/admin/SystemHealth'))

// Operator pages (lazy)
const CommandCenter = lazy(() => import('@/pages/ops/CommandCenter'))
const Findings = lazy(() => import('@/pages/ops/Findings'))
const FindingDetail = lazy(() => import('@/pages/ops/FindingDetail'))
const RemediationQueue = lazy(() => import('@/pages/ops/RemediationQueue'))
const RemediationDetail = lazy(() => import('@/pages/ops/RemediationDetail'))
const Spend = lazy(() => import('@/pages/ops/Spend'))
const Compliance = lazy(() => import('@/pages/ops/Compliance'))
const Containers = lazy(() => import('@/pages/ops/Containers'))
const DataClassification = lazy(() => import('@/pages/ops/DataClassification'))
const Investigations = lazy(() => import('@/pages/ops/Investigations'))
const AppCatalog = lazy(() => import('@/pages/ops/AppCatalog'))
const AttackSurface = lazy(() => import('@/pages/ops/AttackSurface'))
const DataSources = lazy(() => import('@/pages/ops/DataSources'))

// Admin pages (lazy — added Sprint G)
const Exceptions = lazy(() => import('@/pages/admin/Exceptions'))
const Reports = lazy(() => import('@/pages/admin/Reports'))
const Webhooks = lazy(() => import('@/pages/admin/Webhooks'))
const OrgSecretsScan = lazy(() => import('@/pages/admin/OrgSecretsScan'))

// Portal pages (lazy)
const PortalDashboard = lazy(() => import('@/pages/portal/Dashboard'))
const Request = lazy(() => import('@/pages/portal/Request'))
const MyRequests = lazy(() => import('@/pages/portal/MyRequests'))
const RequestDetail = lazy(() => import('@/pages/portal/RequestDetail'))
const Catalog = lazy(() => import('@/pages/portal/Catalog'))
const Callback = lazy(() => import('@/pages/Callback'))

function PageFallback() {
  return (
    <div className="flex items-center justify-center h-64 text-sm text-muted-foreground">
      Loading...
    </div>
  )
}

export default function App() {
  useEffect(() => {
    document.title = `${branding.productName} — Cloud Security Platform`
  }, [])

  return (
    <ConfigProvider>
    <QueryClientProvider client={queryClient}>
      <AuthProvider>
        <TracePanelProvider>
          <BrowserRouter>
            <Routes>
              {/* OAuth callback — outside AppShell */}
              <Route path="/callback" element={<Suspense fallback={<PageFallback />}><Callback /></Suspense>} />
              <Route element={<AppShell />}>
                {/* Platform landing page */}
                <Route index element={<Landing />} />

                {/* Admin routes */}
                <Route element={<ProtectedRoute roles={['admin']}><Outlet /></ProtectedRoute>}>
                  <Route element={<RoutingErrorBoundary fallbackLabel="Admin"><Suspense fallback={<PageFallback />}><Outlet /></Suspense></RoutingErrorBoundary>}>
                    <Route path="/admin" element={<AdminDashboard />} />
                    <Route path="/admin/policies" element={<Policies />} />
                    <Route path="/admin/policies/:id" element={<PolicyDetail />} />
                    <Route path="/admin/ai-agents" element={<AIAgents />} />
                    <Route path="/admin/ai-agents/:id" element={<AIAgentDetail />} />
                    <Route path="/admin/users" element={<Users />} />
                    <Route path="/admin/audit-log" element={<AuditLog />} />
                    <Route path="/admin/system" element={<SystemHealth />} />
                    <Route path="/admin/exceptions" element={<Exceptions />} />
                    <Route path="/admin/reports" element={<Reports />} />
                    <Route path="/admin/webhooks" element={<Webhooks />} />
                    <Route path="/admin/secrets-scan" element={<OrgSecretsScan />} />
                  </Route>
                </Route>

                {/* Viewer-accessible ops routes (read-only) */}
                <Route element={<ProtectedRoute roles={['admin', 'operator', 'viewer']}><Outlet /></ProtectedRoute>}>
                  <Route element={<RoutingErrorBoundary fallbackLabel="Ops"><Suspense fallback={<PageFallback />}><Outlet /></Suspense></RoutingErrorBoundary>}>
                    <Route path="/ops/findings" element={<Findings />} />
                    <Route path="/ops/findings/:id" element={<FindingDetail />} />
                    <Route path="/ops/compliance" element={<Compliance />} />
                    <Route path="/ops/agents" element={<AIAgents />} />
                    <Route path="/ops/agents/:id" element={<AIAgentDetail />} />
                  </Route>
                </Route>

                {/* Operator routes (full ops access) */}
                <Route element={<ProtectedRoute roles={['admin', 'operator']}><Outlet /></ProtectedRoute>}>
                  <Route element={<RoutingErrorBoundary fallbackLabel="Ops"><Suspense fallback={<PageFallback />}><Outlet /></Suspense></RoutingErrorBoundary>}>
                    <Route path="/ops" element={<CommandCenter />} />
                    <Route path="/ops/remediation" element={<RemediationQueue />} />
                    <Route path="/ops/remediation/:id" element={<RemediationDetail />} />
                    <Route path="/ops/costs" element={<Spend />} />
                    <Route path="/ops/containers" element={<Containers />} />
                    <Route path="/ops/data-classification" element={<DataClassification />} />
                    <Route path="/ops/app-catalog" element={<AppCatalog />} />
                    <Route path="/ops/investigations" element={<Investigations />} />
                    <Route path="/ops/attack-surface" element={<AttackSurface />} />
                    <Route path="/ops/data-sources" element={<DataSources />} />
                  </Route>
                </Route>

                {/* Requester / portal routes */}
                <Route element={<ProtectedRoute roles={['admin', 'operator', 'requester']}><Outlet /></ProtectedRoute>}>
                  <Route element={<RoutingErrorBoundary fallbackLabel="Portal"><Suspense fallback={<PageFallback />}><Outlet /></Suspense></RoutingErrorBoundary>}>
                    <Route path="/portal" element={<PortalDashboard />} />
                    <Route path="/portal/request" element={<Request />} />
                    <Route path="/portal/requests" element={<MyRequests />} />
                    <Route path="/portal/requests/:id" element={<RequestDetail />} />
                    <Route path="/portal/catalog" element={<Catalog />} />
                  </Route>
                </Route>

                {/* 404 catch-all */}
                <Route path="*" element={<NotFound />} />
              </Route>
            </Routes>
            <ExecutionTracePanel />
          </BrowserRouter>
        </TracePanelProvider>
      </AuthProvider>
    </QueryClientProvider>
    </ConfigProvider>
  )
}
