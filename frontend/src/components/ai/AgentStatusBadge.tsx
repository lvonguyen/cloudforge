import { Badge } from '@/components/ui/badge'
import { cn } from '@/lib/utils'
import type { AgentStatus } from '@/types/ai-governance'

const STATUS_CONFIG: Record<AgentStatus, { label: string; className: string; dot: string }> = {
  active: { label: 'Active', className: 'bg-green-100 text-green-800 border-green-200', dot: 'bg-green-500' },
  inactive: { label: 'Inactive', className: 'bg-gray-100 text-gray-600 border-gray-200', dot: 'bg-gray-400' },
  suspended: { label: 'Suspended', className: 'bg-red-100 text-red-800 border-red-200', dot: 'bg-red-500' },
  deprecated: { label: 'Deprecated', className: 'bg-yellow-100 text-yellow-700 border-yellow-200', dot: 'bg-yellow-500' },
}

export function AgentStatusBadge({ status }: { status: AgentStatus }) {
  const config = STATUS_CONFIG[status] ?? STATUS_CONFIG.inactive
  return (
    <Badge variant="outline" className={cn('flex items-center gap-1.5 text-xs', config.className)}>
      <span className={cn('h-1.5 w-1.5 rounded-full', config.dot)} />
      {config.label}
    </Badge>
  )
}
