import { useCompliance } from '@/hooks/useCompliance'
import { FrameworkGrid } from '@/components/compliance/FrameworkGrid'
import { Badge } from '@/components/ui/badge'
import { Card, CardContent } from '@/components/ui/card'
import { ShieldCheck, ShieldAlert, Shield } from 'lucide-react'

export default function Compliance() {
  const { data: frameworks = [], isLoading } = useCompliance()

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

      {/* Framework grid */}
      <FrameworkGrid frameworks={frameworks} />
    </div>
  )
}
