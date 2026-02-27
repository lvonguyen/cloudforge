import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { StatusBadge } from './StatusBadge'
import type { ExceptionRequest } from '@/types/grc'

export function ExceptionCard({ exception }: { exception: ExceptionRequest }) {
  const age = Math.floor(
    (Date.now() - new Date(exception.created_at).getTime()) / (1000 * 60 * 60 * 24)
  )

  return (
    <Card className="hover:shadow-sm transition-shadow">
      <CardHeader className="pb-2">
        <div className="flex items-center justify-between gap-2">
          <CardTitle className="text-sm font-mono">{exception.id}</CardTitle>
          <StatusBadge status={exception.status} />
        </div>
      </CardHeader>
      <CardContent className="text-sm space-y-1">
        <p className="text-muted-foreground">
          <span className="font-medium text-foreground">{exception.application_id}</span>
          {' — '}{exception.policy_violated}
        </p>
        <p className="text-muted-foreground line-clamp-2">{exception.resource_requested}</p>
        <p className="text-xs text-muted-foreground">{age}d ago · {exception.requestor_email}</p>
      </CardContent>
    </Card>
  )
}
