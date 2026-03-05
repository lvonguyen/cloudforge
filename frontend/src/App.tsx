import { BrowserRouter, Routes, Route } from 'react-router-dom'
import { QueryClientProvider } from '@tanstack/react-query'
import { queryClient } from '@/lib/api'
import { AuthProvider } from '@/lib/auth'
import { TracePanelProvider } from '@/lib/trace-panel-context'
import { AppShell } from '@/components/layout/AppShell'
import { ExecutionTracePanel } from '@/components/layout/ExecutionTracePanel'

// Landing
import Landing from '@/pages/Landing'

// Admin pages
import AdminDashboard from '@/pages/admin/Dashboard'
import Policies from '@/pages/admin/Policies'
import PolicyDetail from '@/pages/admin/PolicyDetail'
import AIAgents from '@/pages/admin/AIAgents'
import AIAgentDetail from '@/pages/admin/AIAgentDetail'
import Users from '@/pages/admin/Users'
import AuditLog from '@/pages/admin/AuditLog'
import SystemHealth from '@/pages/admin/SystemHealth'

// Operator pages
import CommandCenter from '@/pages/ops/CommandCenter'
import Findings from '@/pages/ops/Findings'
import FindingDetail from '@/pages/ops/FindingDetail'
import RemediationQueue from '@/pages/ops/RemediationQueue'
import Costs from '@/pages/ops/Costs'
import Compliance from '@/pages/ops/Compliance'

// Portal pages
import PortalDashboard from '@/pages/portal/Dashboard'
import Request from '@/pages/portal/Request'
import MyRequests from '@/pages/portal/MyRequests'
import RequestDetail from '@/pages/portal/RequestDetail'
import Catalog from '@/pages/portal/Catalog'

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <AuthProvider>
        <TracePanelProvider>
          <BrowserRouter>
            <Routes>
              <Route element={<AppShell />}>
                {/* Portfolio landing page */}
                <Route index element={<Landing />} />

                {/* Admin routes */}
                <Route path="/admin" element={<AdminDashboard />} />
                <Route path="/admin/policies" element={<Policies />} />
                <Route path="/admin/policies/:id" element={<PolicyDetail />} />
                <Route path="/admin/ai-agents" element={<AIAgents />} />
                <Route path="/admin/ai-agents/:id" element={<AIAgentDetail />} />
                <Route path="/admin/users" element={<Users />} />
                <Route path="/admin/audit-log" element={<AuditLog />} />
                <Route path="/admin/system" element={<SystemHealth />} />

                {/* Operator routes */}
                <Route path="/ops" element={<CommandCenter />} />
                <Route path="/ops/findings" element={<Findings />} />
                <Route path="/ops/findings/:id" element={<FindingDetail />} />
                <Route path="/ops/remediation" element={<RemediationQueue />} />
                <Route path="/ops/costs" element={<Costs />} />
                <Route path="/ops/compliance" element={<Compliance />} />

                {/* Requester / portal routes */}
                <Route path="/portal" element={<PortalDashboard />} />
                <Route path="/portal/request" element={<Request />} />
                <Route path="/portal/requests" element={<MyRequests />} />
                <Route path="/portal/requests/:id" element={<RequestDetail />} />
                <Route path="/portal/catalog" element={<Catalog />} />
              </Route>
            </Routes>
            <ExecutionTracePanel />
          </BrowserRouter>
        </TracePanelProvider>
      </AuthProvider>
    </QueryClientProvider>
  )
}
