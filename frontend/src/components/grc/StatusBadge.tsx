import { Badge } from '@/components/ui/badge'
import { cn } from '@/lib/utils'
import type { ApprovalStatus } from '@/types/grc'

const STATUS_CONFIG: Record<ApprovalStatus, { label: string; className: string }> = {
  PENDING: { label: 'Pending', className: 'bg-yellow-100 text-yellow-800 border-yellow-200' },
  APPROVED: { label: 'Approved', className: 'bg-green-100 text-green-800 border-green-200' },
  REJECTED: { label: 'Rejected', className: 'bg-red-100 text-red-800 border-red-200' },
  EXPIRED: { label: 'Expired', className: 'bg-gray-100 text-gray-600 border-gray-200' },
  REVOKED: { label: 'Revoked', className: 'bg-orange-100 text-orange-800 border-orange-200' },
}

export function StatusBadge({ status }: { status: ApprovalStatus }) {
  const config = STATUS_CONFIG[status] ?? STATUS_CONFIG.PENDING
  return (
    <Badge variant="outline" className={cn('text-xs font-medium', config.className)}>
      {config.label}
    </Badge>
  )
}
