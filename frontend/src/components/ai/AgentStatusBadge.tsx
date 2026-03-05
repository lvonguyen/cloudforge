import { Badge } from '@/components/ui/badge'
import { cn } from '@/lib/utils'
import type { AgentStatus } from '@/types/ai-governance'

const STATUS_CONFIG: Record<AgentStatus, { label: string; className: string; dot: string }> = {
  active: { label: 'Active', className: 'bg-green-100 text-green-800 border-green-200 dark:bg-green-900/30 dark:text-green-300 dark:border-green-800', dot: 'bg-green-500 dark:bg-green-400' },
  inactive: { label: 'Inactive', className: 'bg-gray-100 text-gray-600 border-gray-200 dark:bg-gray-900/30 dark:text-gray-400 dark:border-gray-800', dot: 'bg-gray-400 dark:bg-gray-500' },
  suspended: { label: 'Suspended', className: 'bg-red-100 text-red-800 border-red-200 dark:bg-red-900/30 dark:text-red-300 dark:border-red-800', dot: 'bg-red-500 dark:bg-red-400' },
  deprecated: { label: 'Deprecated', className: 'bg-yellow-100 text-yellow-700 border-yellow-200 dark:bg-yellow-900/30 dark:text-yellow-300 dark:border-yellow-800', dot: 'bg-yellow-500 dark:bg-yellow-400' },
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
