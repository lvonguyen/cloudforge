import { useState } from 'react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from '@/components/ui/table'
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from '@/components/ui/select'
import { KeyRound, Search, ChevronDown, ChevronRight, AlertTriangle, FileCode, CheckCircle2, LayoutGrid, List, Upload, Shield, Lock } from 'lucide-react'
import { useStartOrgScan, useUploadSuspectedSecret } from '@/hooks/useOrgScan'
import type { OrgScanResult, RepoResult, SecretUploadResult } from '@/hooks/useOrgScan'
import { useAuth } from '@/lib/auth'
import { ApiError } from '@/lib/api'
import { useActionCooldown } from '@/hooks/useActionCooldown'
import { useToast } from '@/hooks/useToast'
import { ToastStack } from '@/components/ui/ToastStack'

// ─── Secret type taxonomy ───────────────────────────────────────────────────

const SECRET_TYPES = [
  { value: 'api_token',        label: 'API Token' },
  { value: 'ssh_keypair',      label: 'SSH Keypair' },
  { value: 'oauth_secret',     label: 'OAuth Client Secret' },
  { value: 'aws_access_key',   label: 'AWS Access Key' },
  { value: 'azure_spn',        label: 'Azure SPN' },
  { value: 'gcp_sa_key',       label: 'GCP Service Account Key' },
  { value: 'generic_password', label: 'Generic Password' },
  { value: 'certificate_pem',  label: 'Certificate / PEM' },
] as const

type SecretTypeValue = (typeof SECRET_TYPES)[number]['value']

// ─── Recent scan history (mock) ─────────────────────────────────────────────

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

// ─── Severity + visibility color maps ───────────────────────────────────────

const SEVERITY_COLORS: Record<string, string> = {
  critical: 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300',
  high: 'bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-300',
  medium: 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-300',
  low: 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-300',
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

const EXPOSURE_COLORS: Record<string, string> = {
  public:   'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300',
  internal: 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-300',
  unknown:  'bg-gray-100 text-gray-700 dark:bg-gray-900/30 dark:text-gray-300',
}

// ─── Repo metadata (mock) ───────────────────────────────────────────────────

const REPO_META: Record<string, { visibility: string; platform: string; rotation: string }> = {
  'acme-corp/frontend':         { visibility: 'public',   platform: 'GitHub',  rotation: 'needs-rotation' },
  'acme-corp/backend-api':      { visibility: 'private',  platform: 'GitHub',  rotation: 'expired' },
  'acme-corp/infra-terraform':  { visibility: 'private',  platform: 'GitLab',  rotation: 'active' },
  'contoso/web-app':            { visibility: 'internal', platform: 'GitHub',  rotation: 'active' },
  'contoso/data-pipeline':      { visibility: 'private',  platform: 'GitHub',  rotation: 'needs-rotation' },
}

// ─── RepoSection (list view) ────────────────────────────────────────────────

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

// ─── MatrixView (table view) ────────────────────────────────────────────────

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

// ─── Exposure Analysis Table ────────────────────────────────────────────────
// Aggregates findings by secret type across all repos, showing:
// - instances found in wild
// - secret type
// - exposure level (public/internal/unknown)
// - last documented use date

interface ExposureRow {
  secretType: string
  instances: number
  exposure: 'public' | 'internal' | 'unknown'
  lastSeen: string
}

function deriveExposureRows(results: RepoResult[]): ExposureRow[] {
  const byType = new Map<string, { instances: number; exposure: 'public' | 'internal' | 'unknown'; lastSeen: string }>()

  for (const r of results) {
    const meta = REPO_META[r.repo]
    const vis = meta?.visibility ?? 'unknown'

    for (const f of r.findings) {
      const key = f.type
      const existing = byType.get(key)
      // Promote exposure: public > internal > unknown
      const exposure = vis === 'public' ? 'public' : vis === 'internal' ? 'internal' : 'unknown'
      if (existing) {
        existing.instances++
        if (exposure === 'public') existing.exposure = 'public'
        else if (exposure === 'internal' && existing.exposure === 'unknown') existing.exposure = 'internal'
      } else {
        byType.set(key, { instances: 1, exposure, lastSeen: new Date().toISOString() })
      }
    }
  }

  return Array.from(byType.entries()).map(([secretType, data]) => ({
    secretType,
    ...data,
  }))
}

function ExposureTable({ results }: { results: RepoResult[] }) {
  const rows = deriveExposureRows(results)
  if (rows.length === 0) return null

  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="text-xs font-medium uppercase tracking-wide text-muted-foreground flex items-center gap-1.5">
          <Shield className="h-3.5 w-3.5" />
          Exposure Analysis
        </CardTitle>
      </CardHeader>
      <CardContent className="p-0 overflow-x-auto">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="text-xs pl-4">Secret Type</TableHead>
              <TableHead className="text-xs text-right">Instances Found</TableHead>
              <TableHead className="text-xs">Exposure Level</TableHead>
              <TableHead className="text-xs">Last Documented Use</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {rows.map(row => (
              <TableRow key={row.secretType}>
                <TableCell className="text-xs pl-4 font-medium">{row.secretType}</TableCell>
                <TableCell className="text-xs text-right font-semibold">{row.instances}</TableCell>
                <TableCell>
                  <span className={`text-[10px] font-medium px-1.5 py-0.5 ${EXPOSURE_COLORS[row.exposure] ?? ''}`}>
                    {row.exposure}
                  </span>
                </TableCell>
                <TableCell className="text-xs text-muted-foreground">{formatScanDate(row.lastSeen)}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </CardContent>
    </Card>
  )
}

// ─── Upload Results ─────────────────────────────────────────────────────────

function UploadResults({ data }: { data: SecretUploadResult }) {
  const typeLabel = SECRET_TYPES.find(t => t.value === data.secret_type)?.label ?? data.secret_type

  return (
    <Card className="border-green-200 dark:border-green-800">
      <CardHeader className="pb-2">
        <CardTitle className="text-xs font-medium uppercase tracking-wide text-muted-foreground flex items-center gap-1.5">
          <Lock className="h-3.5 w-3.5" />
          Upload Analysis — {typeLabel}
          <Badge variant="outline" className="text-[10px] bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300 ml-auto">
            ephemeral
          </Badge>
        </CardTitle>
      </CardHeader>
      <CardContent className="p-0 overflow-x-auto">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="text-xs pl-4">Instances Found</TableHead>
              <TableHead className="text-xs">Secret Type</TableHead>
              <TableHead className="text-xs">Exposure Level</TableHead>
              <TableHead className="text-xs">Last Documented Use</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {data.findings.length > 0 ? (
              data.findings.map((f, i) => (
                <TableRow key={i}>
                  <TableCell className="text-xs pl-4 font-semibold">1</TableCell>
                  <TableCell>
                    <div className="flex items-center gap-1.5">
                      <Badge variant="outline" className="text-[10px]">{f.type}</Badge>
                      <span className="text-xs">{f.pattern_name}</span>
                    </div>
                  </TableCell>
                  <TableCell>
                    <span className={`text-[10px] font-medium px-1.5 py-0.5 ${EXPOSURE_COLORS.unknown}`}>
                      unknown
                    </span>
                  </TableCell>
                  <TableCell className="text-xs text-muted-foreground">{formatScanDate(new Date().toISOString())}</TableCell>
                </TableRow>
              ))
            ) : (
              <TableRow>
                <TableCell colSpan={4} className="text-xs text-center py-4 text-muted-foreground">
                  <CheckCircle2 className="h-4 w-4 text-green-500 inline-block mr-1.5 -mt-0.5" />
                  No known secret patterns detected
                </TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>
      </CardContent>
    </Card>
  )
}

// ─── Main Component ─────────────────────────────────────────────────────────

export default function OrgSecretsScan() {
  useAuth()
  const [orgName, setOrgName] = useState('')
  const [repos, setRepos] = useState('')
  const [secretTypeFilter, setSecretTypeFilter] = useState<SecretTypeValue | 'all'>('all')
  const scanMutation = useStartOrgScan()
  const scanCooldown = useActionCooldown({ key: 'org-scan', cooldownMs: 10_000 })
  const { toasts, dismiss } = useToast()

  // Upload form state
  const [uploadType, setUploadType] = useState<SecretTypeValue>('api_token')
  const [uploadContent, setUploadContent] = useState('')
  const uploadMutation = useUploadSuspectedSecret()
  const uploadCooldown = useActionCooldown({ key: 'secret-upload', cooldownMs: 5_000 })

  const result: OrgScanResult | undefined = scanMutation.data
  const uploadResult: SecretUploadResult | undefined = uploadMutation.data

  const [viewMode, setViewMode] = useState<'list' | 'matrix'>('list')

  function handleScan() {
    if (!orgName.trim() || !scanCooldown.canFire) return
    scanCooldown.fire()
    const repoList = repos.trim() ? repos.split(',').map(r => r.trim()).filter(Boolean) : undefined
    scanMutation.mutate({
      org_name: orgName.trim(),
      repos: repoList,
      secret_type: secretTypeFilter !== 'all' ? secretTypeFilter : undefined,
    })
  }

  function handleUpload() {
    if (!uploadContent.trim() || !uploadCooldown.canFire) return
    uploadCooldown.fire()
    uploadMutation.mutate(
      { secret_type: uploadType, content: uploadContent.trim() },
      {
        onSuccess: () => {
          // [SECURITY] Clear the textarea content from state after successful upload.
          setUploadContent('')
        },
      },
    )
  }

  return (
    <div className="space-y-6 max-w-4xl">
      <div>
        <h1 className="text-xl font-semibold">Secrets Org Scan</h1>
        <p className="text-sm text-muted-foreground mt-0.5">Scan organization repositories for leaked credentials and API keys</p>
      </div>

      {/* ── Org Scan form ──────────────────────────────────────────────────── */}
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
          <div>
            <label className="text-[10px] font-medium uppercase tracking-wide text-muted-foreground">Secret Type Filter</label>
            <div className="mt-1">
              <Select value={secretTypeFilter} onValueChange={v => setSecretTypeFilter(v as SecretTypeValue | 'all')}>
                <SelectTrigger size="sm" className="w-full text-xs">
                  <SelectValue placeholder="All secret types" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all" className="text-xs">All secret types</SelectItem>
                  {SECRET_TYPES.map(t => (
                    <SelectItem key={t.value} value={t.value} className="text-xs">{t.label}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
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

      {/* ── Upload Suspected Secret ────────────────────────────────────────── */}
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-xs font-medium uppercase tracking-wide text-muted-foreground flex items-center gap-1.5">
            <Upload className="h-3.5 w-3.5" />
            Upload Suspected Secret
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="flex items-center gap-2 text-[10px] text-muted-foreground bg-muted/50 px-3 py-2 border border-border">
            <Lock className="h-3 w-3 shrink-0" />
            <span>TLS-only upload path. Content is analyzed ephemerally — never persisted to disk or database.</span>
          </div>
          <div>
            <label className="text-[10px] font-medium uppercase tracking-wide text-muted-foreground">Secret Type</label>
            <div className="mt-1">
              <Select value={uploadType} onValueChange={v => setUploadType(v as SecretTypeValue)}>
                <SelectTrigger size="sm" className="w-full text-xs">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {SECRET_TYPES.map(t => (
                    <SelectItem key={t.value} value={t.value} className="text-xs">{t.label}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>
          <div>
            <label className="text-[10px] font-medium uppercase tracking-wide text-muted-foreground">Suspected Secret Content</label>
            <textarea
              value={uploadContent}
              onChange={e => setUploadContent(e.target.value)}
              placeholder="Paste the suspected secret here for analysis..."
              rows={4}
              autoComplete="off"
              spellCheck={false}
              data-lpignore="true"
              data-1p-ignore="true"
              className="w-full mt-1 px-3 py-2 text-sm font-mono bg-muted/50 border border-border outline-none resize-y"
            />
            <p className="text-[10px] text-muted-foreground mt-0.5">Max 64KB. Content is cleared from memory after analysis.</p>
          </div>
          <Button
            size="sm" className="gap-1.5 text-xs"
            disabled={!uploadContent.trim() || !uploadCooldown.canFire || uploadMutation.isPending}
            onClick={handleUpload}
          >
            <Shield className="h-3.5 w-3.5" />
            {uploadMutation.isPending ? 'Analyzing...' : !uploadCooldown.canFire ? 'Cooldown...' : 'Analyze'}
          </Button>
        </CardContent>
      </Card>

      {/* Upload results */}
      {uploadResult && <UploadResults data={uploadResult} />}

      {/* Upload error */}
      {uploadMutation.isError && (
        <Card className="border-red-200 dark:border-red-800">
          <CardContent className="p-4 flex items-center gap-2">
            <AlertTriangle className="h-4 w-4 text-red-500 shrink-0" />
            <p className="text-sm text-red-600 dark:text-red-400">
              {uploadMutation.error instanceof ApiError && uploadMutation.error.status === 403
                ? 'Upload requires operator or admin role.'
                : uploadMutation.error instanceof ApiError && uploadMutation.error.status === 413
                ? 'Content exceeds 64KB limit.'
                : 'Analysis failed — please try again later.'}
            </p>
          </CardContent>
        </Card>
      )}

      {/* ── Recent Scans ───────────────────────────────────────────────────── */}
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

      {/* ── Scan Error ─────────────────────────────────────────────────────── */}
      {scanMutation.isError && (
        <Card className="border-red-200 dark:border-red-800">
          <CardContent className="p-4 flex items-center gap-2">
            <AlertTriangle className="h-4 w-4 text-red-500 shrink-0" />
            <p className="text-sm text-red-600 dark:text-red-400">
              {scanMutation.error instanceof ApiError && scanMutation.error.status === 403
                ? 'Org scan requires admin role.'
                : scanMutation.error instanceof ApiError && scanMutation.error.status === 400
                ? 'Invalid scan request — check the organization name.'
                : 'Scan failed — please try again later.'}
            </p>
          </CardContent>
        </Card>
      )}

      {/* ── Scan Results ───────────────────────────────────────────────────── */}
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

          {/* Exposure Analysis — aggregated by secret type */}
          <ExposureTable results={result.results} />

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
