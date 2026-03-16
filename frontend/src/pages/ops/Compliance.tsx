import { useState } from 'react'
import { useCompliance } from '@/hooks/useCompliance'
import { FrameworkGrid } from '@/components/compliance/FrameworkGrid'
import { FrameworkDetailDrawer } from '@/components/compliance/FrameworkDetailDrawer'
import { Badge } from '@/components/ui/badge'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { ShieldCheck, ShieldAlert, Shield } from 'lucide-react'

const FRAMEWORK_DOC_LINKS: Record<string, string> = {
  'nist-csf':  'https://www.nist.gov/cyberframework',
  'pci-dss':   'https://www.pcisecuritystandards.org/document_library/',
  'hipaa':     'https://www.hhs.gov/hipaa/',
  'iso-27001': 'https://www.iso.org/standard/27001',
  'iso-42001': 'https://www.iso.org/standard/81230.html',
  'tisax':     'https://www.enx.com/en-us/tisax/',
}

// Static last-assessed dates keyed by framework ID — would come from API in production
const LAST_ASSESSED: Record<string, string> = {
  'nist-csf':  '2026-03-01',
  'pci-dss':   '2026-02-28',
  'hipaa':     '2026-02-15',
  'iso-27001': '2026-02-20',
  'iso-42001': '2026-03-05',
  'tisax':     '2026-01-30',
}

function scoreClass(score: number): string {
  if (score >= 90) return 'text-green-600 dark:text-green-400'
  if (score >= 75) return 'text-yellow-600 dark:text-yellow-400'
  return 'text-red-600 dark:text-red-400'
}

export default function Compliance() {
  const { data: frameworks = [], isLoading } = useCompliance()
  const [selectedFramework, setSelectedFramework] = useState<typeof frameworks[number] | null>(null)

  if (isLoading) {
    return <div className="text-sm text-muted-foreground p-4">Loading compliance data…</div>
  }

  const passing = frameworks.filter(f => f.score >= 90).length
  const atRisk = frameworks.filter(f => f.score >= 75 && f.score < 90).length
  const failing = frameworks.filter(f => f.score < 75).length
  const avgScore = frameworks.length > 0
    ? Math.round(frameworks.reduce((s, f) => s + f.score, 0) / frameworks.length)
    : 0

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold">Compliance Status</h1>
          <p className="text-sm text-muted-foreground mt-0.5">{frameworks.length} frameworks tracked</p>
        </div>
        <Badge variant="secondary" className="text-xs">{new Date().toLocaleDateString('en-US', { month: 'short', year: 'numeric' })}</Badge>
      </div>

      {/* Summary KPIs */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <Card>
          <CardContent className="p-4">
            <p className="text-2xl font-bold text-foreground">{avgScore}%</p>
            <p className="text-xs text-muted-foreground mt-0.5">Average Score</p>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4 flex items-center gap-3">
            <ShieldCheck className="h-5 w-5 text-green-600 shrink-0" />
            <div>
              <p className="text-2xl font-bold text-green-600">{passing}</p>
              <p className="text-xs text-muted-foreground">Passing ≥90%</p>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4 flex items-center gap-3">
            <Shield className="h-5 w-5 text-yellow-600 shrink-0" />
            <div>
              <p className="text-2xl font-bold text-yellow-600">{atRisk}</p>
              <p className="text-xs text-muted-foreground">At Risk 75–89%</p>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4 flex items-center gap-3">
            <ShieldAlert className="h-5 w-5 text-red-600 shrink-0" />
            <div>
              <p className="text-2xl font-bold text-red-600">{failing}</p>
              <p className="text-xs text-muted-foreground">Failing &lt;75%</p>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Framework detail cards */}
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-mono uppercase tracking-wide">Framework Details</CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          <div className="divide-y divide-border">
            {frameworks.map(fw => (
              <button
                key={fw.id}
                type="button"
                className="w-full grid grid-cols-4 gap-4 px-4 py-3 text-sm items-center cursor-pointer hover:bg-muted/50 transition-colors text-left"
                onClick={() => setSelectedFramework(fw)}
              >
                <div>
                  <p className="font-medium">{fw.name}</p>
                  <p className="text-xs text-muted-foreground capitalize">{fw.category}</p>
                </div>
                <div className="text-center">
                  <p className="font-mono text-xs text-muted-foreground">Controls</p>
                  <p className="font-semibold">{fw.controls_passing}<span className="text-muted-foreground font-normal">/{fw.total_controls}</span></p>
                </div>
                <div className="text-center">
                  <p className="font-mono text-xs text-muted-foreground">Compliance</p>
                  <p className={`font-semibold ${scoreClass(fw.score)}`}>{fw.score.toFixed(1)}%</p>
                </div>
                <div className="text-right">
                  <p className="font-mono text-xs text-muted-foreground">Last Assessed</p>
                  <p className="text-xs">{LAST_ASSESSED[fw.id] ?? '—'}</p>
                </div>
              </button>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Framework grid */}
      <FrameworkGrid frameworks={frameworks} />

      {/* Table-row drawer (separate from FrameworkGrid's own drawer) */}
      <FrameworkDetailDrawer
        framework={selectedFramework}
        open={selectedFramework !== null}
        onOpenChange={(open) => { if (!open) setSelectedFramework(null) }}
        docLink={selectedFramework ? FRAMEWORK_DOC_LINKS[selectedFramework.id] : undefined}
      />
    </div>
  )
}
