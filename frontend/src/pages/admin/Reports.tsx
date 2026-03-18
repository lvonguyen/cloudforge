import { useFindings } from '@/hooks/useFindings'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { BarChart3, Download, FileText, Shield, Wrench } from 'lucide-react'
import { exportCSV } from '@/lib/export-csv'

const REPORT_CARDS = [
  {
    title: 'Executive Summary',
    description: 'High-level overview of security posture, risk trends, and key metrics for leadership.',
    icon: FileText,
    color: 'text-blue-600 dark:text-blue-400',
    bg: 'bg-blue-50 dark:bg-blue-950/20',
  },
  {
    title: 'Compliance Posture',
    description: 'Framework-by-framework compliance scores, control pass rates, and gap analysis.',
    icon: Shield,
    color: 'text-green-600 dark:text-green-400',
    bg: 'bg-green-50 dark:bg-green-950/20',
  },
  {
    title: 'Remediation Progress',
    description: 'Finding resolution rates, SLA adherence, mean time to remediate, and team velocity.',
    icon: Wrench,
    color: 'text-orange-600 dark:text-orange-400',
    bg: 'bg-orange-50 dark:bg-orange-950/20',
  },
]

export default function Reports() {
  const { data: findings = [] } = useFindings()

  const handleCSVExport = () => {
    if (findings.length === 0) return
    exportCSV(findings)
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold">Reports</h1>
          <p className="text-sm text-muted-foreground mt-0.5">Generate and export security reports</p>
        </div>
        <Button size="sm" variant="outline" className="gap-1.5 text-xs" onClick={handleCSVExport} disabled={findings.length === 0}>
          <Download className="h-3.5 w-3.5" />Export Findings CSV
        </Button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {REPORT_CARDS.map(report => {
          const Icon = report.icon
          return (
            <Card key={report.title}>
              <CardHeader className="pb-2">
                <div className="flex items-center gap-2">
                  <div className={`p-2 rounded ${report.bg}`}>
                    <Icon className={`h-4 w-4 ${report.color}`} />
                  </div>
                  <CardTitle className="text-sm">{report.title}</CardTitle>
                </div>
              </CardHeader>
              <CardContent className="space-y-3">
                <p className="text-xs text-muted-foreground">{report.description}</p>
                <Button
                  size="sm"
                  variant="outline"
                  className="gap-1.5 text-xs w-full"
                  onClick={() => window.print()}
                >
                  <BarChart3 className="h-3.5 w-3.5" />Generate Report
                </Button>
              </CardContent>
            </Card>
          )
        })}
      </div>

      {/* Quick stats */}
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-xs font-medium uppercase tracking-wide text-muted-foreground">Quick Stats</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-center">
            <div>
              <p className="text-2xl font-bold tabular-nums">{findings.length}</p>
              <p className="text-[10px] text-muted-foreground uppercase">Total Findings</p>
            </div>
            <div>
              <p className="text-2xl font-bold tabular-nums text-red-600 dark:text-red-400">
                {findings.filter(f => f.severity === 'CRITICAL').length}
              </p>
              <p className="text-[10px] text-muted-foreground uppercase">Critical</p>
            </div>
            <div>
              <p className="text-2xl font-bold tabular-nums text-green-600 dark:text-green-400">
                {findings.filter(f => f.status === 'resolved').length}
              </p>
              <p className="text-[10px] text-muted-foreground uppercase">Resolved</p>
            </div>
            <div>
              <p className="text-2xl font-bold tabular-nums text-orange-600 dark:text-orange-400">
                {findings.filter(f => f.auto_remediatable).length}
              </p>
              <p className="text-[10px] text-muted-foreground uppercase">Auto-Remediable</p>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
