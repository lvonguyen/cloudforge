import { ExternalLink, ShieldCheck } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import type { ComplianceMapping } from '@/types/compliance'

function severityClass(severity: string): string {
  switch (severity.toUpperCase()) {
    case 'CRITICAL':
    case 'HIGH':
      return 'bg-red-100 text-red-700 border-red-200 dark:bg-red-900/30 dark:text-red-300 dark:border-red-800'
    case 'MEDIUM':
      return 'bg-amber-100 text-amber-700 border-amber-200 dark:bg-amber-900/30 dark:text-amber-300 dark:border-amber-800'
    default:
      return 'bg-slate-100 text-slate-700 border-slate-200 dark:bg-slate-900/30 dark:text-slate-300 dark:border-slate-800'
  }
}

export function FindingComplianceList({ mappings }: { mappings: ComplianceMapping[] }) {
  if (mappings.length === 0) return null

  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
          <div className="flex items-center gap-1.5">
            <ShieldCheck className="h-3.5 w-3.5" />
            Compliance Mappings
          </div>
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-3">
        {mappings.map((mapping) => (
          <div
            key={`${mapping.framework_id}-${mapping.control_id}`}
            className="rounded-2xl border border-border/80 bg-muted/20 p-3"
          >
            <div className="flex items-start justify-between gap-3">
              <div className="min-w-0 space-y-1">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="text-sm font-semibold">{mapping.framework_name}</span>
                  <code className="rounded-full border border-border bg-background px-2 py-0.5 text-[10px] font-semibold">
                    {mapping.control_id}
                  </code>
                  <Badge variant="outline" className={`text-[10px] ${severityClass(mapping.severity)}`}>
                    {mapping.severity}
                  </Badge>
                </div>
                <p className="text-sm text-foreground">{mapping.control_title}</p>
                <p className="text-xs text-muted-foreground">
                  Section {mapping.section}
                  {mapping.subsection ? ` · ${mapping.subsection}` : ''}
                </p>
              </div>
              {mapping.url && (
                <a
                  href={mapping.url}
                  target="_blank"
                  rel="noreferrer"
                  className="mt-0.5 inline-flex items-center gap-1 text-xs text-blue-600 hover:text-blue-500 dark:text-blue-400 dark:hover:text-blue-300"
                >
                  Open
                  <ExternalLink className="h-3 w-3" />
                </a>
              )}
            </div>
          </div>
        ))}
      </CardContent>
    </Card>
  )
}
