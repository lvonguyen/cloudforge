import { AlertTriangle, XCircle, Info } from 'lucide-react'
import { cn } from '@/lib/utils'
import type { PolicyViolation } from '@/types/policy'

interface Props {
  violation: PolicyViolation
  onRequestException?: () => void
}

const SEVERITY_CONFIG = {
  critical: { icon: XCircle, className: 'bg-red-50 border-red-200 text-red-800', iconClass: 'text-red-500' },
  high: { icon: AlertTriangle, className: 'bg-orange-50 border-orange-200 text-orange-800', iconClass: 'text-orange-500' },
  medium: { icon: AlertTriangle, className: 'bg-yellow-50 border-yellow-200 text-yellow-800', iconClass: 'text-yellow-500' },
  low: { icon: Info, className: 'bg-blue-50 border-blue-200 text-blue-800', iconClass: 'text-blue-500' },
}

export function PolicyViolationBanner({ violation, onRequestException }: Props) {
  const config = SEVERITY_CONFIG[violation.severity as keyof typeof SEVERITY_CONFIG] ?? SEVERITY_CONFIG.medium
  const Icon = config.icon

  return (
    <div className={cn('flex items-start gap-3 rounded-md border p-3 text-sm', config.className)}>
      <Icon className={cn('h-4 w-4 mt-0.5 shrink-0', config.iconClass)} />
      <div className="flex-1 space-y-1">
        <p className="font-medium">{violation.code}: {violation.message}</p>
        <p className="text-xs opacity-80">{violation.remediation}</p>
      </div>
      {onRequestException && (
        <button
          onClick={onRequestException}
          className="text-xs underline underline-offset-2 hover:no-underline shrink-0"
        >
          Request Exception
        </button>
      )}
    </div>
  )
}
