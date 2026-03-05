import { Badge } from '@/components/ui/badge'
import { cn } from '@/lib/utils'

const SEVERITY_CONFIG: Record<string, { label: string; className: string }> = {
  CRITICAL: { label: 'CRITICAL', className: 'bg-red-100 text-red-800 border-red-300 dark:bg-red-900/30 dark:text-red-300 dark:border-red-800 font-bold' },
  HIGH: { label: 'HIGH', className: 'bg-orange-100 text-orange-800 border-orange-300 dark:bg-orange-900/30 dark:text-orange-300 dark:border-orange-800' },
  MEDIUM: { label: 'MEDIUM', className: 'bg-yellow-100 text-yellow-800 border-yellow-300 dark:bg-yellow-900/30 dark:text-yellow-300 dark:border-yellow-800' },
  LOW: { label: 'LOW', className: 'bg-blue-100 text-blue-800 border-blue-300 dark:bg-blue-900/30 dark:text-blue-300 dark:border-blue-800' },
  critical: { label: 'CRITICAL', className: 'bg-red-100 text-red-800 border-red-300 dark:bg-red-900/30 dark:text-red-300 dark:border-red-800 font-bold' },
  high: { label: 'HIGH', className: 'bg-orange-100 text-orange-800 border-orange-300 dark:bg-orange-900/30 dark:text-orange-300 dark:border-orange-800' },
  medium: { label: 'MEDIUM', className: 'bg-yellow-100 text-yellow-800 border-yellow-300 dark:bg-yellow-900/30 dark:text-yellow-300 dark:border-yellow-800' },
  low: { label: 'LOW', className: 'bg-blue-100 text-blue-800 border-blue-300 dark:bg-blue-900/30 dark:text-blue-300 dark:border-blue-800' },
}

export function SeverityBadge({ severity, size = 'sm' }: { severity: string; size?: 'xs' | 'sm' }) {
  const config = SEVERITY_CONFIG[severity] ?? { label: severity, className: 'bg-gray-100 text-gray-600 dark:bg-gray-900/30 dark:text-gray-400' }
  return (
    <Badge
      variant="outline"
      className={cn(config.className, size === 'xs' && 'text-[10px] px-1 py-0')}
    >
      {config.label}
    </Badge>
  )
}
