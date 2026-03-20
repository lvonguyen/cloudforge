import { useState } from 'react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from '@/components/ui/table'
import { KeyRound, Search, ChevronDown, ChevronRight, AlertTriangle, FileCode, CheckCircle2, LayoutGrid, List } from 'lucide-react'
import { useStartOrgScan } from '@/hooks/useOrgScan'
import type { OrgScanResult, RepoResult } from '@/hooks/useOrgScan'
import { useAuth } from '@/lib/auth'
import { useActionCooldown } from '@/hooks/useActionCooldown'
import { useToast } from '@/hooks/useToast'
import { ToastStack } from '@/components/ui/ToastStack'

const RECENT_SCANS = [
  { id: 'scan-001', org: 'contoso', repos: 12, secrets: 3, critical: 1, high: 2, date: '2026-03-18T14:30:00Z' },
  { id: 'scan-002', org: 'contoso', repos: 12, secrets: 0, critical: 0, high: 0, date: '2026-03-15T09:15:00Z' },
  { id: 'scan-003', org: 'acme-corp', repos: 8, secrets: 7, critical: 3, high: 4, date: '2026-03-12T16:45:00Z' },
  { id: 'scan-004', org: 'contoso', repos: 12, secrets: 1, critical: 0, high: 1, date: '2026-03-08T11:00:00Z' },
]

function formatScanDate(iso: string): string {
  try { return new Date(iso).toLocaleDateString('en-US', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }) }
  catch { return iso }
}

const SEVERITY_COLORS: Record<string, string> = {
  critical: 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300',
  high: 'bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-300',
  medium: 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-300',
  low: 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-300',
}

function RepoSection({ result, defaultOpen }: { result: RepoResult; defaultOpen?: boolean }) {
  const [open, setOpen] = useState(defaultOpen ?? false)
  const critCount = result.findings.filter(f => f.severity === 'critical').length
  const highCount = result.findings.filter(f => f.severity === 'high').length

  return (
    <div className="border border-border">
      <button
        type="button"
        className="w-full flex items-center gap-2 px-4 py-2.5 text-left hover:bg-muted/50 transition-colors"
        onClick={() => setOpen(o => !o)}
      >
        {open ? <ChevronDown className="h-3.5 w-3.5 text-muted-foreground shrink-0" /> : <ChevronRight className="h-3.5 w-3.5 text-muted-foreground shrink-0" />}
        <FileCode className="h-3.5 w-3.5 text-muted-foreground shrink-0" />
        <span className="text-xs font-medium flex-1">{result.repo}</span>
        <span className="text-[10px] text-muted-foreground">{result.findings.length} finding{result.findings.length !== 1 ? 's' : ''}</span>
        {critCount > 0 && <Badge variant="outline" className={`text-[10px] ${SEVERITY_COLORS.critical}`}>{critCount} CRIT</Badge>}
        {highCount > 0 && <Badge variant="outline" className={`text-[10px] ${SEVERITY_COLORS.high}`}>{highCount} HIGH</Badge>}
      </button>
      {open && (
        <div className="border-t border-border divide-y divide-border">
          {result.findings.map((f, i) => (
            <div key={i} className="px-4 py-2.5 pl-10">
              <div className="flex items-center gap-2 mb-1">
                <span className={`text-[10px] font-medium px-1.5 py-0.5 ${SEVERITY_COLORS[f.severity] ?? 'bg-gray-100 text-gray-700'}`}>
                  {f.severity.toUpperCase()}
                </span>
                <span className="text-xs font-medium">{f.pattern_name}</span>
                <Badge variant="outline" className="text-[10px]">{f.type}</Badge>
              </div>
              {f.file && (
                <p className="text-[10px] font-mono text-muted-foreground">
                  {f.file}:{f.line}:{f.column}
                </p>
              )}
              <p className="text-[10px] font-mono text-muted-foreground mt-0.5 bg-muted/50 px-2 py-1">{f.match}</p>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

const REPO_META: Record<string, { visibility: string; platform: string; rotation: string }> = {
  'acme-corp/frontend':         { visibility: 'public',   platform: 'GitHub',  rotation: 'needs-rotation' },
  'acme-corp/backend-api':      { visibility: 'private',  platform: 'GitHub',  rotation: 'expired' },
  'acme-corp/infra-terraform':  { visibility: 'private',  platform: 'GitLab',  rotation: 'active' },
  'contoso/web-app':            { visibility: 'internal', platform: 'GitHub',  rotation: 'active' },
  'contoso/data-pipeline':      { visibility: 'private',  platform: 'GitHub',  rotation: 'needs-rotation' },
}

const VISIBILITY_COLORS: Record<string, string> = {
  public:   'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300',
  private:  'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300',
  internal: 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-300',
}

const ROTATION_COLORS: Record<string, string> = {
  'needs-rotation': 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-300',
  expired:          'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300',
  active:           'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300',
}

function MatrixView({ results }: { results: RepoResult[] }) {
  return (
    <div className="overflow-x-auto">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead className="text-xs pl-4">Repository</TableHead>
            <TableHead className="text-xs">Visibility</TableHead>
            <TableHead className="text-xs">Platform</TableHead>
            <TableHead className="text-xs text-right">Secrets</TableHead>
            <TableHead className="text-xs">Secret Types</TableHead>
            <TableHead className="text-xs">Severity Breakdown</TableHead>
            <TableHead className="text-xs">Rotation Status</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {results.map(r => {
            const meta = REPO_META[r.repo] ?? { visibility: 'private', platform: 'GitHub', rotation: 'active' }
            const types = [...new Set(r.findings.map(f => f.type))]
            const sevCounts = { critical: 0, high: 0, medium: 0, low: 0 } as Record<string, number>
            for (const f of r.findings) sevCounts[f.severity] = (sevCounts[f.severity] ?? 0) + 1
            return (
              <TableRow key={r.repo}>
                <TableCell className="text-xs pl-4 font-medium font-mono">{r.repo}</TableCell>
                <TableCell>
                  <span className={`text-[10px] font-medium px-1.5 py-0.5 ${VISIBILITY_COLORS[meta.visibility] ?? ''}`}>
                    {meta.visibility}
                  </span>
                </TableCell>
                <TableCell className="text-xs text-muted-foreground">{meta.platform}</TableCell>
                <TableCell className="text-xs text-right font-semibold">{r.findings.length}</TableCell>
                <TableCell>
                  <div className="flex gap-1 flex-wrap">
                    {types.map(t => (
                      <Badge key={t} variant="outline" className="text-[10px]">{t}</Badge>
                    ))}
                  </div>
                </TableCell>
                <TableCell>
                  <div className="flex gap-1">
                    {sevCounts.critical > 0 && <span className={`text-[10px] font-medium px-1.5 py-0.5 ${SEVERITY_COLORS.critical}`}>{sevCounts.critical}C</span>}
                    {sevCounts.high > 0 && <span className={`text-[10px] font-medium px-1.5 py-0.5 ${SEVERITY_COLORS.high}`}>{sevCounts.high}H</span>}
                    {sevCounts.medium > 0 && <span className={`text-[10px] font-medium px-1.5 py-0.5 ${SEVERITY_COLORS.medium}`}>{sevCounts.medium}M</span>}
                    {sevCounts.low > 0 && <span className={`text-[10px] font-medium px-1.5 py-0.5 ${SEVERITY_COLORS.low}`}>{sevCounts.low}L</span>}
                    {r.findings.length === 0 && <CheckCircle2 className="h-3.5 w-3.5 text-green-500" />}
                  </div>
                </TableCell>
                <TableCell>
                  <span className={`text-[10px] font-medium px-1.5 py-0.5 ${ROTATION_COLORS[meta.rotation] ?? ''}`}>
                    {meta.rotation}
                  </span>
                </TableCell>
              </TableRow>
            )
          })}
        </TableBody>
      </Table>
    </div>
  )
}

export default function OrgSecretsScan() {
  useAuth()
  const [orgName, setOrgName] = useState('')
  const [repos, setRepos] = useState('')
  const scanMutation = useStartOrgScan()
  const scanCooldown = useActionCooldown({ key: 'org-scan', cooldownMs: 10_000 })
  const { toasts, dismiss } = useToast()

  const result: OrgScanResult | undefined = scanMutation.data

  const [viewMode, setViewMode] = useState<'list' | 'matrix'>('list')
  // Role gate removed — demo viewers have full access (writes are ephemeral)

  function handleScan() {
    if (!orgName.trim() || !scanCooldown.canFire) return
    scanCooldown.fire()
    const repoList = repos.trim() ? repos.split(',').map(r => r.trim()).filter(Boolean) : undefined
    scanMutation.mutate({ org_name: orgName.trim(), repos: repoList })
  }

  return (
    <div className="space-y-6 max-w-4xl">
      <div>
        <h1 className="text-xl font-semibold">Secrets Org Scan</h1>
        <p className="text-sm text-muted-foreground mt-0.5">Scan organization repositories for leaked credentials and API keys</p>
      </div>

      {/* Scan form */}
      <Card>
        <CardContent className="p-4 space-y-3">
          <div>
            <label className="text-[10px] font-medium uppercase tracking-wide text-muted-foreground">Organization</label>
            <div className="relative mt-1">
              <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
              <input
                type="text" value={orgName} onChange={e => setOrgName(e.target.value)}
                onKeyDown={e => { if (e.key === 'Enter') handleScan() }}
                placeholder="Organization name (e.g. acme-corp)"
                className="w-full pl-8 pr-3 py-2 text-sm bg-muted/50 border border-border outline-none"
              />
            </div>
          </div>
          <div>
            <label className="text-[10px] font-medium uppercase tracking-wide text-muted-foreground">Repositories (optional, comma-separated)</label>
            <input
              type="text" value={repos} onChange={e => setRepos(e.target.value)}
              placeholder="Leave blank to scan all repos"
              className="w-full mt-1 px-3 py-2 text-sm bg-muted/50 border border-border outline-none"
            />
          </div>
          <Button
            size="sm" className="gap-1.5 text-xs"
            disabled={!orgName.trim() || !scanCooldown.canFire || scanMutation.isPending}
            onClick={handleScan}
          >
            <KeyRound className="h-3.5 w-3.5" />
            {scanMutation.isPending ? 'Scanning...' : !scanCooldown.canFire ? 'Cooldown...' : 'Scan'}
          </Button>
        </CardContent>
      </Card>

      {/* Recent Scans */}
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-xs font-medium uppercase tracking-wide text-muted-foreground">Recent Scans</CardTitle>
        </CardHeader>
        <CardContent className="p-0 overflow-x-auto">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="text-xs pl-4">Date</TableHead>
                <TableHead className="text-xs">Organization</TableHead>
                <TableHead className="text-xs text-right">Repos</TableHead>
                <TableHead className="text-xs text-right">Secrets Found</TableHead>
                <TableHead className="text-xs">Severity</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {RECENT_SCANS.map(scan => (
                <TableRow key={scan.id}>
                  <TableCell className="text-xs pl-4 text-muted-foreground">{formatScanDate(scan.date)}</TableCell>
                  <TableCell className="text-xs font-medium">{scan.org}</TableCell>
                  <TableCell className="text-xs text-right">{scan.repos}</TableCell>
                  <TableCell className="text-xs text-right">{scan.secrets}</TableCell>
                  <TableCell>
                    {scan.secrets === 0 ? (
                      <CheckCircle2 className="h-3.5 w-3.5 text-green-500" />
                    ) : (
                      <div className="flex gap-1">
                        {scan.critical > 0 && (
                          <Badge variant="outline" className="text-[10px] bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300">
                            {scan.critical} CRIT
                          </Badge>
                        )}
                        {scan.high > 0 && (
                          <Badge variant="outline" className="text-[10px] bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-300">
                            {scan.high} HIGH
                          </Badge>
                        )}
                      </div>
                    )}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      {/* Results */}
      {result && (
        <>
          {/* View toggle */}
          <div className="flex items-center justify-between">
            <h2 className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
              Scan Results — {result.org_name}
            </h2>
            <div className="flex border border-border">
              <button
                onClick={() => setViewMode('list')}
                className={`flex items-center gap-1.5 px-3 py-1.5 text-xs transition-colors ${viewMode === 'list' ? 'bg-muted font-medium' : 'hover:bg-muted/50'}`}
              >
                <List className="h-3.5 w-3.5" /> List
              </button>
              <button
                onClick={() => setViewMode('matrix')}
                className={`flex items-center gap-1.5 px-3 py-1.5 text-xs border-l border-border transition-colors ${viewMode === 'matrix' ? 'bg-muted font-medium' : 'hover:bg-muted/50'}`}
              >
                <LayoutGrid className="h-3.5 w-3.5" /> Matrix
              </button>
            </div>
          </div>

          {/* Summary bar */}
          <div className="grid grid-cols-3 gap-3">
            <div className="border border-border p-3">
              <p className="text-[10px] text-muted-foreground uppercase tracking-wide">Repos Scanned</p>
              <p className="text-lg font-semibold mt-0.5">{result.repos_scanned}</p>
            </div>
            <div className="border border-border p-3">
              <p className="text-[10px] text-muted-foreground uppercase tracking-wide">Total Secrets</p>
              <p className="text-lg font-semibold mt-0.5 text-red-600 dark:text-red-400">{result.total_secrets}</p>
            </div>
            <div className="border border-border p-3">
              <p className="text-[10px] text-muted-foreground uppercase tracking-wide">Severity</p>
              <div className="flex gap-1.5 mt-1">
                {['critical', 'high', 'medium', 'low'].map(sev => {
                  const count = result.results.reduce((s, r) => s + r.findings.filter(f => f.severity === sev).length, 0)
                  if (count === 0) return null
                  return (
                    <span key={sev} className={`text-[10px] font-medium px-1.5 py-0.5 ${SEVERITY_COLORS[sev]}`}>
                      {count} {sev.toUpperCase()}
                    </span>
                  )
                })}
              </div>
            </div>
          </div>

          {/* Repo results tree / matrix */}
          {viewMode === 'list' ? (
            <div className="space-y-2">
              {result.results.map((r, i) => (
                <RepoSection key={r.repo} result={r} defaultOpen={i === 0} />
              ))}
            </div>
          ) : (
            <Card>
              <CardContent className="p-0">
                <MatrixView results={result.results} />
              </CardContent>
            </Card>
          )}

          {/* Errors */}
          {result.errors && result.errors.length > 0 && (
            <Card className="border-yellow-200 dark:border-yellow-800">
              <CardHeader className="pb-2">
                <CardTitle className="text-xs font-medium text-yellow-600 dark:text-yellow-400 flex items-center gap-1.5">
                  <AlertTriangle className="h-3.5 w-3.5" />Scan Errors
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-1">
                {result.errors.map((e, i) => (
                  <p key={i} className="text-xs text-muted-foreground">
                    <span className="font-mono">{e.repo}</span>: {e.message}
                  </p>
                ))}
              </CardContent>
            </Card>
          )}
        </>
      )}

      <ToastStack toasts={toasts} onDismiss={dismiss} />
    </div>
  )
}
