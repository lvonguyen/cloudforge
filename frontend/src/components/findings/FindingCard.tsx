import { Card, CardContent, CardHeader } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { SeverityBadge } from './SeverityBadge'
import { SLACountdown } from './SLACountdown'
import { ProviderBadge } from '@/components/ui/ProviderBadge'
import type { Finding } from '@/types/compliance'

export function FindingCard({ finding, onClick }: { finding: Finding; onClick?: () => void }) {
  return (
    <Card
      className="cursor-pointer hover:shadow-md hover:-translate-y-0.5 transition-all duration-200"
      onClick={onClick}
    >
      <CardHeader className="pb-2 space-y-1">
        <div className="flex items-start gap-2">
          <SeverityBadge severity={finding.severity} />
          {finding.auto_remediatable && (
            <Badge variant="secondary" className="text-[10px] px-1 py-0 bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300">AUTO</Badge>
          )}
        </div>
        <p className="text-sm font-medium leading-tight line-clamp-2">{finding.title}</p>
      </CardHeader>
      <CardContent className="text-xs text-muted-foreground space-y-1">
        <p className="flex items-center gap-1">{finding.resource_name} · <ProviderBadge provider={finding.cloud_provider} /> {finding.region}</p>
        {finding.cves && finding.cves.length > 0 && (
          <p className="font-mono text-destructive">{finding.cves[0].id} CVSS {finding.cvss?.toFixed(1)}</p>
        )}
        <SLACountdown dueDate={finding.due_date} slaBreach={finding.sla_breach_date} />
      </CardContent>
    </Card>
  )
}
