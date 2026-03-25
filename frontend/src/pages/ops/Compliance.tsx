import { useState } from 'react'
import { useCompliance } from '@/hooks/useCompliance'
import { useCompliancePosture, useComplianceControls } from '@/hooks/useCompliancePosture'
import type { PostureFramework, ComplianceControl } from '@/hooks/useCompliancePosture'
import { FrameworkGrid } from '@/components/compliance/FrameworkGrid'
import { FrameworkDetailDrawer } from '@/components/compliance/FrameworkDetailDrawer'
import { Badge } from '@/components/ui/badge'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { ShieldCheck, ShieldAlert, Shield, ChevronDown, ChevronRight, Library, LayoutList } from 'lucide-react'

const FRAMEWORK_METADATA: Record<string, { doc_link: string; last_assessed: string }> = {
  'nist-csf':  { doc_link: 'https://www.nist.gov/cyberframework', last_assessed: '2026-03-01' },
  'pci-dss':   { doc_link: 'https://www.pcisecuritystandards.org/document_library/', last_assessed: '2026-02-28' },
  'hipaa':     { doc_link: 'https://www.hhs.gov/hipaa/', last_assessed: '2026-02-15' },
  'iso-27001': { doc_link: 'https://www.iso.org/standard/27001', last_assessed: '2026-02-20' },
  'iso-42001': { doc_link: 'https://www.iso.org/standard/81230.html', last_assessed: '2026-03-05' },
  'tisax':     { doc_link: 'https://www.enx.com/en-us/tisax/', last_assessed: '2026-01-30' },
}

function scoreClass(score: number): string {
  if (score >= 90) return 'text-green-600 dark:text-green-400'
  if (score >= 75) return 'text-yellow-600 dark:text-yellow-400'
  return 'text-red-600 dark:text-red-400'
}

const SECTOR_COLORS: Record<string, string> = {
  general: 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-300',
  healthcare: 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300',
  finance: 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-300',
  government: 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300',
  ai: 'bg-purple-100 text-purple-700 dark:bg-purple-900/30 dark:text-purple-300',
}

const CONTROL_SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300',
  HIGH: 'bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-300',
  MEDIUM: 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-300',
  LOW: 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-300',
}

function ControlsList({ frameworkId }: { frameworkId: string }) {
  const { data: controls = [], isLoading } = useComplianceControls(frameworkId)

  if (isLoading) return <div className="text-xs text-muted-foreground py-4 px-4">Loading controls...</div>
  if (controls.length === 0) return <div className="text-xs text-muted-foreground py-4 px-4">No controls found.</div>

  return (
    <div className="border-t border-border divide-y divide-border">
      {controls.map((c: ComplianceControl) => (
        <div key={c.id} className="px-4 py-2.5 pl-10">
          <div className="flex items-center gap-2 mb-0.5">
            <code className="text-[10px] font-mono text-muted-foreground">{c.id}</code>
            <span className={`text-[10px] font-medium px-1.5 py-0.5 ${CONTROL_SEVERITY_COLORS[c.severity] ?? ''}`}>{c.severity}</span>
          </div>
          <p className="text-xs font-medium">{c.title}</p>
          <p className="text-[10px] text-muted-foreground mt-0.5">{c.description}</p>
          <div className="flex items-center gap-2 mt-1 text-[10px] text-muted-foreground">
            <span>{c.section}</span>
            <span>·</span>
            <span className="capitalize">{c.category}</span>
          </div>
        </div>
      ))}
    </div>
  )
}

function PostureTab() {
  const { data: posture = [], isLoading } = useCompliancePosture()
  const [expanded, setExpanded] = useState<string | null>(null)

  if (isLoading) return <div className="text-xs text-muted-foreground p-4">Loading posture data...</div>

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {posture.map((fw: PostureFramework) => (
          <Card key={fw.id}>
            <CardContent className="p-4 space-y-2">
              <div className="flex items-center justify-between">
                <p className="text-sm font-semibold">{fw.name}</p>
                <Badge variant="outline" className={`text-[10px] capitalize ${SECTOR_COLORS[fw.sector] ?? ''}`}>{fw.sector}</Badge>
              </div>
              <p className="text-xs text-muted-foreground">{fw.description}</p>
              <div className="flex items-center justify-between pt-2 border-t border-border">
                <div>
                  <p className="text-[10px] text-muted-foreground">Version</p>
                  <p className="text-xs font-medium">{fw.version}</p>
                </div>
                <div className="text-right">
                  <p className="text-[10px] text-muted-foreground">Controls</p>
                  <p className="text-xs font-semibold tabular-nums">{fw.controls}</p>
                </div>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Control drill-down list */}
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
            Control Drill-Down
          </CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          {posture.map((fw: PostureFramework) => (
            <div key={fw.id} className="border-b border-border last:border-b-0">
              <button
                type="button"
                className="w-full flex items-center gap-2 px-4 py-2.5 text-left hover:bg-muted/50 transition-colors"
                onClick={() => setExpanded(expanded === fw.id ? null : fw.id)}
              >
                {expanded === fw.id ? <ChevronDown className="h-3.5 w-3.5 text-muted-foreground shrink-0" /> : <ChevronRight className="h-3.5 w-3.5 text-muted-foreground shrink-0" />}
                <span className="text-xs font-medium flex-1">{fw.name}</span>
                <span className="text-[10px] text-muted-foreground">{fw.controls} controls</span>
              </button>
              {expanded === fw.id && <ControlsList frameworkId={fw.id} />}
            </div>
          ))}
        </CardContent>
      </Card>
    </div>
  )
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

      <Tabs defaultValue="frameworks">
        <TabsList className="bg-transparent border-b border-border rounded-none p-0 w-full justify-start">
          <TabsTrigger value="frameworks" className="gap-1.5 rounded-none border-b-2 border-transparent data-[state=active]:border-primary data-[state=active]:bg-transparent text-xs">
            <LayoutList className="h-3.5 w-3.5" />Frameworks
          </TabsTrigger>
          <TabsTrigger value="posture" className="gap-1.5 rounded-none border-b-2 border-transparent data-[state=active]:border-primary data-[state=active]:bg-transparent text-xs">
            <Library className="h-3.5 w-3.5" />Posture
          </TabsTrigger>
        </TabsList>

        <TabsContent value="frameworks" className="space-y-6 mt-4">
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
                <ShieldCheck className="h-5 w-5 text-green-600 dark:text-green-400 shrink-0" />
                <div>
                  <p className="text-2xl font-bold text-green-600 dark:text-green-400">{passing}</p>
                  <p className="text-xs text-muted-foreground">Passing ≥90%</p>
                </div>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="p-4 flex items-center gap-3">
                <Shield className="h-5 w-5 text-yellow-600 dark:text-yellow-400 shrink-0" />
                <div>
                  <p className="text-2xl font-bold text-yellow-600 dark:text-yellow-400">{atRisk}</p>
                  <p className="text-xs text-muted-foreground">At Risk 75–89%</p>
                </div>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="p-4 flex items-center gap-3">
                <ShieldAlert className="h-5 w-5 text-red-600 dark:text-red-400 shrink-0" />
                <div>
                  <p className="text-2xl font-bold text-red-600 dark:text-red-400">{failing}</p>
                  <p className="text-xs text-muted-foreground">Failing &lt;75%</p>
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Framework score gauges */}
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-mono uppercase tracking-wide">Framework Health</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-4">
                {frameworks.slice(0, 5).map(fw => {
                  const color = fw.score >= 85 ? '#16a34a' : fw.score >= 75 ? '#ca8a04' : fw.score >= 60 ? '#ea580c' : '#dc2626'
                  const trackColor = fw.score >= 85 ? '#16a34a20' : fw.score >= 75 ? '#ca8a0420' : fw.score >= 60 ? '#ea580c20' : '#dc262620'
                  const pct = fw.score / 100
                  const r = 34
                  const circumference = 2 * Math.PI * r
                  const dashLen = circumference * pct
                  const gapLen = circumference - dashLen
                  return (
                    <button
                      key={fw.id}
                      type="button"
                      className="flex flex-col items-center gap-1 cursor-pointer hover:opacity-80 transition-opacity bg-transparent border-none p-0"
                      onClick={() => setSelectedFramework(fw)}
                    >
                      <svg width={80} height={80} viewBox="0 0 80 80" className="rotate-[-90deg]">
                        {/* Track arc (faint) */}
                        <circle cx={40} cy={40} r={r} fill="none" stroke={trackColor} strokeWidth={6} strokeLinecap="round" />
                        {/* Score arc */}
                        <circle
                          cx={40} cy={40} r={r} fill="none"
                          stroke={color} strokeWidth={6} strokeLinecap="round"
                          strokeDasharray={`${dashLen} ${gapLen}`}
                        />
                      </svg>
                      <p className={`text-sm font-bold tabular-nums ${scoreClass(fw.score)}`}>{fw.score}%</p>
                      <p className="text-[10px] text-muted-foreground text-center leading-tight">{fw.name}</p>
                    </button>
                  )
                })}
              </div>
            </CardContent>
          </Card>

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
                      <p className="font-medium text-foreground">{fw.name}</p>
                      <p className="text-xs text-muted-foreground capitalize">{fw.category}</p>
                    </div>
                    <div className="text-center">
                      <p className="font-mono text-xs text-muted-foreground">Controls</p>
                      <p className="font-semibold text-foreground">{fw.controls_passing}<span className="text-muted-foreground font-normal">/{fw.total_controls}</span></p>
                    </div>
                    <div className="text-center">
                      <p className="font-mono text-xs text-muted-foreground">Compliance</p>
                      <p className={`font-semibold ${scoreClass(fw.score)}`}>{fw.score.toFixed(1)}%</p>
                    </div>
                    <div className="text-right">
                      <p className="font-mono text-xs text-muted-foreground">Last Assessed</p>
                      <p className="text-xs">{FRAMEWORK_METADATA[fw.id]?.last_assessed ?? '—'}</p>
                    </div>
                  </button>
                ))}
              </div>
            </CardContent>
          </Card>

          {/* Framework grid */}
          <FrameworkGrid frameworks={frameworks} />
        </TabsContent>

        <TabsContent value="posture" className="space-y-6 mt-4">
          <PostureTab />
        </TabsContent>
      </Tabs>

      {/* Table-row drawer (separate from FrameworkGrid's own drawer) */}
      <FrameworkDetailDrawer
        framework={selectedFramework}
        open={selectedFramework !== null}
        onOpenChange={(open) => { if (!open) setSelectedFramework(null) }}
        docLink={selectedFramework ? FRAMEWORK_METADATA[selectedFramework.id]?.doc_link : undefined}
      />
    </div>
  )
}
