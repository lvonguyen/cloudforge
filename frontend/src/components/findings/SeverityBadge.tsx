import { Badge } from '@/components/ui/badge'
import { cn } from '@/lib/utils'

const SEVERITY_CONFIG: Record<string, { label: string; className: string }> = {
  CRITICAL: { label: 'CRITICAL', className: 'bg-red-100 text-red-800 border-red-300 font-bold' },
  HIGH: { label: 'HIGH', className: 'bg-orange-100 text-orange-800 border-orange-300' },
  MEDIUM: { label: 'MEDIUM', className: 'bg-yellow-100 text-yellow-800 border-yellow-300' },
  LOW: { label: 'LOW', className: 'bg-blue-100 text-blue-800 border-blue-300' },
  critical: { label: 'CRITICAL', className: 'bg-red-100 text-red-800 border-red-300 font-bold' },
  high: { label: 'HIGH', className: 'bg-orange-100 text-orange-800 border-orange-300' },
  medium: { label: 'MEDIUM', className: 'bg-yellow-100 text-yellow-800 border-yellow-300' },
  low: { label: 'LOW', className: 'bg-blue-100 text-blue-800 border-blue-300' },
}

export function SeverityBadge({ severity, size = 'sm' }: { severity: string; size?: 'xs' | 'sm' }) {
  const config = SEVERITY_CONFIG[severity] ?? { label: severity, className: 'bg-gray-100 text-gray-600' }
  return (
    <Badge
      variant="outline"
      className={cn(config.className, size === 'xs' && 'text-[10px] px-1 py-0')}
    >
      {config.label}
    </Badge>
  )
}
