import { brandMockData, brandRegistryRefs } from '@/lib/mock-data-utils'
import { useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import policiesData from '@/lib/mock/policies.json'
import { POLICY_DETAILS, generatePolicyDetail } from '@/lib/mock/policy-details'
import { usePolicy } from '@/hooks/usePolicies'
import { highlightRego } from '@/lib/rego-highlight'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Separator } from '@/components/ui/separator'
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from '@/components/ui/table'
import {
  ArrowLeft, Copy, Check, CheckCircle2, AlertTriangle, Clock,
  FileCode, Shield, XCircle,
} from 'lucide-react'

// ── Status / Category config (mirrored from Policies.tsx) ────────────────────

const STATUS_CONFIG: Record<string, { icon: typeof CheckCircle2; className: string; label: string }> = {
  active: { icon: CheckCircle2, className: 'text-green-600 dark:text-green-400', label: 'Active' },
  inactive: { icon: AlertTriangle, className: 'text-gray-400 dark:text-gray-500', label: 'Inactive' },
  draft: { icon: Clock, className: 'text-yellow-600 dark:text-yellow-400', label: 'Draft' },
}

const STATUS_BADGE: Record<string, string> = {
  active: 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300',
  inactive: 'bg-gray-100 text-gray-500 dark:bg-gray-900/30 dark:text-gray-400',
  draft: 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-300',
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

// ── Component ────────────────────────────────────────────────────────────────

export default function PolicyDetail() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const [copied, setCopied] = useState(false)
  const { data: apiPolicy } = usePolicy(id ?? '')

  const policy = (() => {
    if (!id) return undefined
    // Try API data first (summary-level) — enhance with mock detail data
    if (apiPolicy) {
      const detail = POLICY_DETAILS[id] ?? generatePolicyDetail(apiPolicy as any)
      return brandMockData(detail)
    }
    // Fallback to static mock
    if (POLICY_DETAILS[id]) return brandMockData(POLICY_DETAILS[id])
    const summary = policiesData.find((p: { id: string }) => p.id === id)
    if (!summary) return undefined
    return generatePolicyDetail(summary)
  })()

  if (!policy) {
    return (
      <div className="space-y-4 max-w-3xl">
        <Button variant="ghost" size="sm" className="gap-1.5 -ml-2" onClick={() => navigate('/admin/policies')}>
          <ArrowLeft className="h-4 w-4" />All Policies
        </Button>
        <div className="text-sm text-muted-foreground">Policy not found.</div>
      </div>
    )
  }

  const { icon: StatusIcon, className: statusIconClass } = STATUS_CONFIG[policy.status] ?? STATUS_CONFIG.inactive
  const rego = brandRegistryRefs(policy.rego)
  const lines = rego.split('\n')

  function handleCopy() {
    navigator.clipboard.writeText(rego).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    })
  }

  return (
    <div className="space-y-6 pb-10">
      <Button variant="ghost" size="sm" className="gap-1.5 -ml-2" onClick={() => navigate('/admin/policies')}>
        <ArrowLeft className="h-4 w-4" />All Policies
      </Button>

      {/* Header */}
      <div>
        <div className="flex items-center gap-2 flex-wrap mb-2">
          <Badge variant="outline" className="text-[10px] font-mono uppercase tracking-wide rounded-none">{policy.id}</Badge>
          <Badge variant="secondary" className={`text-[10px] font-mono uppercase tracking-wide rounded-none ${STATUS_BADGE[policy.status] ?? ''}`}>
            {policy.status}
          </Badge>
          <Badge variant="secondary" className={`text-[10px] font-mono uppercase tracking-wide rounded-none ${CATEGORY_COLORS[policy.category] ?? ''}`}>
            {policy.category}
          </Badge>
          <Badge variant="outline" className="text-[10px] font-mono rounded-none">v{policy.version}</Badge>
        </div>
        <h1 className="text-xl font-semibold font-mono">{policy.name}</h1>
        <p className="text-sm text-muted-foreground mt-1">{policy.description}</p>
      </div>

      <Separator />

      {/* Two-column layout */}
      <div className="grid grid-cols-1 lg:grid-cols-5 gap-6">
        {/* Left: metadata */}
        <div className="lg:col-span-2">
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
                <div className="flex items-center gap-1.5"><Shield className="h-3.5 w-3.5" />Policy Metadata</div>
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              {[
                { label: 'Namespace', value: policy.namespace },
                { label: 'Category', value: policy.category },
                { label: 'Status', value: policy.status, icon: true },
                { label: 'Evaluations', value: policy.evaluations.toLocaleString() },
                { label: 'Denials', value: String(policy.denials), highlight: policy.denials > 0 },
                { label: 'Last Updated', value: policy.last_updated },
                { label: 'Created', value: policy.created },
                { label: 'Version', value: policy.version },
              ].map(({ label, value, icon, highlight }) => (
                <div key={label} className="flex items-center justify-between py-1 border-b border-border/40 last:border-0">
                  <span className="text-[10px] text-muted-foreground uppercase tracking-wide">{label}</span>
                  {icon ? (
                    <div className="flex items-center gap-1">
                      <StatusIcon className={`h-3 w-3 ${statusIconClass}`} />
                      <span className={`text-xs font-medium capitalize ${statusIconClass}`}>{value}</span>
                    </div>
                  ) : (
                    <span className={`text-xs font-mono font-medium ${highlight ? 'text-red-600 dark:text-red-400' : ''}`}>{value}</span>
                  )}
                </div>
              ))}
            </CardContent>
          </Card>
        </div>

        {/* Right: policy definition */}
        <div className="lg:col-span-3">
          <Card className="overflow-hidden">
            <CardHeader className="pb-2">
              <div className="flex items-center justify-between">
                <CardTitle className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
                  <div className="flex items-center gap-1.5"><FileCode className="h-3.5 w-3.5" />Policy Definition (Rego)</div>
                </CardTitle>
                <Button
                  variant="ghost"
                  size="sm"
                  className="h-7 px-2 text-[10px] gap-1"
                  onClick={handleCopy}
                >
                  {copied ? <Check className="h-3 w-3" /> : <Copy className="h-3 w-3" />}
                  {copied ? 'Copied' : 'Copy'}
                </Button>
              </div>
            </CardHeader>
            <CardContent className="p-0">
              <div className="bg-[#1a1a1a] overflow-x-auto">
                <pre className="text-[12px] leading-5 p-4 font-mono">
                  <code>
                    {lines.map((line, i) => (
                      <div key={i} className="flex">
                        <span className="inline-block w-8 text-right mr-4 text-gray-600 select-none shrink-0">{i + 1}</span>
                        <span className="text-green-400">{highlightRego(line)}</span>
                      </div>
                    ))}
                  </code>
                </pre>
              </div>
            </CardContent>
          </Card>
        </div>
      </div>

      {/* Recent evaluations */}
      {policy.recent_evaluations.length > 0 && (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
              Recent Evaluations
            </CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="text-xs pl-4">Timestamp</TableHead>
                  <TableHead className="text-xs">Resource</TableHead>
                  <TableHead className="text-xs">Result</TableHead>
                  <TableHead className="text-xs">Reason</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {policy.recent_evaluations.map((ev, i) => (
                  <TableRow key={i}>
                    <TableCell className="text-[10px] font-mono text-muted-foreground pl-4 whitespace-nowrap">
                      {formatTimestamp(ev.timestamp)}
                    </TableCell>
                    <TableCell className="text-xs font-mono">{ev.resource}</TableCell>
                    <TableCell>
                      {ev.result === 'allow' ? (
                        <div className="flex items-center gap-1">
                          <CheckCircle2 className="h-3 w-3 text-green-600 dark:text-green-400" />
                          <span className="text-xs text-green-600 dark:text-green-400 font-medium">Allow</span>
                        </div>
                      ) : (
                        <div className="flex items-center gap-1">
                          <XCircle className="h-3 w-3 text-red-600 dark:text-red-400" />
                          <span className="text-xs text-red-600 dark:text-red-400 font-medium">Deny</span>
                        </div>
                      )}
                    </TableCell>
                    <TableCell className="text-[10px] text-muted-foreground max-w-xs truncate">
                      {ev.reason ?? '--'}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      )}

      {/* Recent denials */}
      {policy.recent_denials.length > 0 && (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
              <div className="flex items-center gap-1.5"><AlertTriangle className="h-3.5 w-3.5" />Recent Denials</div>
            </CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="text-xs pl-4">Timestamp</TableHead>
                  <TableHead className="text-xs">Resource</TableHead>
                  <TableHead className="text-xs">Reason</TableHead>
                  <TableHead className="text-xs">Requestor</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {policy.recent_denials.map((d, i) => (
                  <TableRow key={i}>
                    <TableCell className="text-[10px] font-mono text-muted-foreground pl-4 whitespace-nowrap">
                      {formatTimestamp(d.timestamp)}
                    </TableCell>
                    <TableCell className="text-xs font-mono">{d.resource}</TableCell>
                    <TableCell className="text-[10px] text-red-600 dark:text-red-400 max-w-xs truncate">{d.reason}</TableCell>
                    <TableCell className="text-[10px] font-mono text-muted-foreground">{d.requestor}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      )}

      {/* Empty state for draft/inactive */}
      {policy.recent_evaluations.length === 0 && policy.recent_denials.length === 0 && (
        <Card>
          <CardContent className="p-6">
            <p className="text-sm text-muted-foreground text-center">
              No evaluations recorded. This policy is currently <strong>{policy.status}</strong>.
            </p>
          </CardContent>
        </Card>
      )}
    </div>
  )
}

// ── Helpers ──────────────────────────────────────────────────────────────────

function formatTimestamp(iso: string): string {
  const d = new Date(iso)
  return d.toLocaleString('en-US', {
    month: 'short', day: 'numeric',
    hour: '2-digit', minute: '2-digit',
    hour12: false,
  })
}

