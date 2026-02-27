import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useFindings } from '@/hooks/useFindings'
import { FindingCard } from '@/components/findings/FindingCard'
import { Badge } from '@/components/ui/badge'
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from '@/components/ui/select'

const SEVERITY_TABS = ['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const
type SeverityTab = (typeof SEVERITY_TABS)[number]

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: 'bg-red-100 text-red-800',
  HIGH: 'bg-orange-100 text-orange-800',
  MEDIUM: 'bg-yellow-100 text-yellow-800',
  LOW: 'bg-blue-100 text-blue-800',
}

export default function Findings() {
  const navigate = useNavigate()
  const [severityFilter, setSeverityFilter] = useState<SeverityTab>('ALL')
  const [providerFilter, setProviderFilter] = useState('ALL')
  const [statusFilter, setStatusFilter] = useState('ALL')

  const findingFilters = {
    severity: severityFilter !== 'ALL' ? severityFilter : undefined,
    provider: providerFilter !== 'ALL' ? providerFilter.toLowerCase() : undefined,
    status: statusFilter !== 'ALL' ? statusFilter : undefined,
  }

  const { data: findings = [], isLoading } = useFindings(findingFilters)
  const { data: allFindings = [] } = useFindings()

  const severityCounts = allFindings.reduce<Record<string, number>>((acc, f) => {
    acc[f.severity] = (acc[f.severity] ?? 0) + 1
    return acc
  }, {})

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold">Findings Board</h1>
          <p className="text-sm text-muted-foreground mt-0.5">{allFindings.length} total findings</p>
        </div>
        <div className="flex gap-2">
          {(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const).map(sev => (
            <Badge key={sev} variant="outline" className={`text-[10px] px-1.5 py-0 ${SEVERITY_COLORS[sev] ?? ''}`}>
              {sev[0]}{sev.slice(1).toLowerCase()} {severityCounts[sev] ?? 0}
            </Badge>
          ))}
        </div>
      </div>

      {/* Filters row */}
      <div className="flex flex-wrap gap-3 items-center">
        <div className="flex gap-1">
          {SEVERITY_TABS.map(tab => (
            <button
              key={tab}
              onClick={() => setSeverityFilter(tab)}
              className={`px-3 py-1 text-xs rounded-md font-medium transition-colors ${
                severityFilter === tab
                  ? 'bg-foreground text-background'
                  : 'bg-muted text-muted-foreground hover:bg-muted/80'
              }`}
            >
              {tab}
            </button>
          ))}
        </div>

        <Select value={providerFilter} onValueChange={setProviderFilter}>
          <SelectTrigger className="h-7 w-32 text-xs">
            <SelectValue placeholder="Provider" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="ALL">All Providers</SelectItem>
            <SelectItem value="AWS">AWS</SelectItem>
            <SelectItem value="Azure">Azure</SelectItem>
            <SelectItem value="GCP">GCP</SelectItem>
          </SelectContent>
        </Select>

        <Select value={statusFilter} onValueChange={setStatusFilter}>
          <SelectTrigger className="h-7 w-32 text-xs">
            <SelectValue placeholder="Status" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="ALL">All Status</SelectItem>
            <SelectItem value="open">Open</SelectItem>
            <SelectItem value="in_progress">In Progress</SelectItem>
            <SelectItem value="resolved">Resolved</SelectItem>
          </SelectContent>
        </Select>

        {findings.length !== allFindings.length && (
          <span className="text-xs text-muted-foreground ml-auto">{findings.length} matching</span>
        )}
      </div>

      {/* Results */}
      {isLoading && (
        <p className="text-sm text-muted-foreground">Loading findings…</p>
      )}
      {!isLoading && findings.length === 0 && (
        <p className="text-sm text-muted-foreground">No findings match the selected filters.</p>
      )}
      {!isLoading && findings.length > 0 && (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
          {findings.map(finding => (
            <FindingCard
              key={finding.id}
              finding={finding}
              onClick={() => navigate(`/ops/findings/${finding.id}`)}
            />
          ))}
        </div>
      )}
    </div>
  )
}
