import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from '@/components/ui/table'
import { FileCode, CheckCircle2, AlertTriangle, Clock } from 'lucide-react'
import { usePolicies } from '@/hooks/usePolicies'
import { useTracePanel } from '@/lib/trace-panel-context'
import { useActionCooldown } from '@/hooks/useActionCooldown'

const STATUS_CONFIG: Record<string, { icon: typeof CheckCircle2; className: string; label: string }> = {
  active: { icon: CheckCircle2, className: 'text-green-600 dark:text-green-400', label: 'Active' },
  inactive: { icon: AlertTriangle, className: 'text-gray-400 dark:text-gray-500', label: 'Inactive' },
  draft: { icon: Clock, className: 'text-yellow-600 dark:text-yellow-400', label: 'Draft' },
}

const CATEGORY_COLORS: Record<string, string> = {
  provisioning: 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-300',
  tagging: 'bg-gray-100 text-gray-700 dark:bg-gray-900/30 dark:text-gray-300',
  'ai-governance': 'bg-indigo-100 text-indigo-700 dark:bg-indigo-900/30 dark:text-indigo-300',
  security: 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300',
  identity: 'bg-purple-100 text-purple-700 dark:bg-purple-900/30 dark:text-purple-300',
  network: 'bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-300',
  storage: 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-300',
}

export default function Policies() {
  const navigate = useNavigate()
  const [filter, setFilter] = useState<string>('all')

  const { data: allPolicies = [] } = usePolicies()
  const { openTimeline } = useTracePanel()
  const newPolicyCooldown = useActionCooldown({ key: 'new-policy', cooldownMs: 3_000 })
  const filtered = filter === 'all' ? allPolicies : allPolicies.filter(p => p.status === filter)

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold">Policy Manager</h1>
          <p className="text-sm text-muted-foreground mt-0.5">OPA policies enforced at provisioning time</p>
        </div>
        <Button
          size="sm"
          variant="outline"
          className="text-xs gap-1.5"
          disabled={!newPolicyCooldown.canFire}
          onClick={() => {
            if (!newPolicyCooldown.canFire) return
            const now = new Date()
            openTimeline('New Policy', [
              {
                span_id: 'span-policy-1',
                name: 'Initializing Rego template',
                type: 'policy',
                start_time: now.toISOString(),
                end_time: new Date(now.getTime() + 150).toISOString(),
                duration_ms: 150,
                status: 'ok',
                attributes: { step: 'init-rego' },
                events: [],
                data: {},
              },
              {
                span_id: 'span-policy-2',
                name: 'Validating policy namespace',
                type: 'policy',
                start_time: new Date(now.getTime() + 150).toISOString(),
                end_time: new Date(now.getTime() + 350).toISOString(),
                duration_ms: 200,
                status: 'ok',
                attributes: { step: 'validate-namespace' },
                events: [],
                data: {},
              },
              {
                span_id: 'span-policy-3',
                name: 'Registering in OPA engine',
                type: 'policy',
                start_time: new Date(now.getTime() + 350).toISOString(),
                end_time: new Date(now.getTime() + 950).toISOString(),
                duration_ms: 600,
                status: 'ok',
                attributes: { step: 'register-opa' },
                events: [],
                data: {},
              },
              {
                span_id: 'span-policy-4',
                name: 'Policy draft created',
                type: 'policy',
                start_time: new Date(now.getTime() + 950).toISOString(),
                end_time: new Date(now.getTime() + 1050).toISOString(),
                duration_ms: 100,
                status: 'ok',
                attributes: { step: 'draft-created' },
                events: [],
                data: {},
              },
            ])
            newPolicyCooldown.fire()
          }}
        >
          <FileCode className="h-3.5 w-3.5" />{!newPolicyCooldown.canFire ? 'Creating\u2026' : 'New Policy'}
        </Button>
      </div>

      {/* Summary row */}
      <div className="flex gap-2 flex-wrap">
        {['all', 'active', 'draft', 'inactive'].map(f => (
          <button
            key={f}
            onClick={() => setFilter(f)}
            className={`px-3 py-1 text-xs rounded-none font-medium transition-colors capitalize ${
              filter === f ? 'bg-foreground text-background' : 'bg-muted text-muted-foreground hover:bg-muted/80'
            }`}
          >
            {f} {f === 'all' ? `(${allPolicies.length})` : `(${allPolicies.filter(p => p.status === f).length})`}
          </button>
        ))}
      </div>

      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
            {filtered.length} policies
          </CardTitle>
        </CardHeader>
        <CardContent className="p-0 overflow-x-auto">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="text-xs pl-4">Name</TableHead>
                <TableHead className="text-xs hidden md:table-cell">Namespace</TableHead>
                <TableHead className="text-xs">Category</TableHead>
                <TableHead className="text-xs">Status</TableHead>
                <TableHead className="text-xs text-right">Evaluations</TableHead>
                <TableHead className="text-xs text-right">Denials</TableHead>
                <TableHead className="text-xs hidden lg:table-cell">Last Updated</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {filtered.map(pol => {
                const { icon: Icon, className, label } = STATUS_CONFIG[pol.status] ?? STATUS_CONFIG.inactive
                return (
                  <TableRow key={pol.id} className="hover:bg-muted/30 cursor-pointer" onClick={() => navigate(`/admin/policies/${pol.id}`)}>
                    <TableCell className="pl-4">
                      <p className="text-xs font-mono font-medium">{pol.name}</p>
                      <p className="text-[10px] text-muted-foreground">{pol.id}</p>
                    </TableCell>
                    <TableCell className="text-[10px] font-mono text-muted-foreground hidden md:table-cell">{pol.namespace}</TableCell>
                    <TableCell>
                      <Badge variant="secondary" className={`text-[10px] ${CATEGORY_COLORS[pol.category] ?? ''}`}>
                        {pol.category}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      <div className="flex items-center gap-1">
                        <Icon className={`h-3 w-3 ${className}`} />
                        <span className={`text-xs ${className}`}>{label}</span>
                      </div>
                    </TableCell>
                    <TableCell className="text-xs text-right">{pol.evaluations.toLocaleString()}</TableCell>
                    <TableCell className="text-xs text-right">
                      <span className={pol.denials > 0 ? 'text-red-600 dark:text-red-400 font-medium' : 'text-muted-foreground'}>{pol.denials}</span>
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground hidden lg:table-cell">{pol.last_updated}</TableCell>
                  </TableRow>
                )
              })}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  )
}
