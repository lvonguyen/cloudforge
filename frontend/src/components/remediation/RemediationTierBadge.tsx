import { Badge } from '@/components/ui/badge'
import { cn } from '@/lib/utils'

const TIER_CONFIG: Record<number, { label: string; className: string }> = {
  1: { label: 'Tier 1', className: 'bg-green-100 text-green-800 border-green-300 dark:bg-green-900/30 dark:text-green-300 dark:border-green-800' },
  2: { label: 'Tier 2', className: 'bg-yellow-100 text-yellow-800 border-yellow-300 dark:bg-yellow-900/30 dark:text-yellow-300 dark:border-yellow-800' },
  3: { label: 'Tier 3', className: 'bg-red-100 text-red-800 border-red-300 dark:bg-red-900/30 dark:text-red-300 dark:border-red-800' },
}

export function RemediationTierBadge({ tier }: { tier: number }) {
  const config = TIER_CONFIG[tier] ?? TIER_CONFIG[3]
  return (
    <Badge variant="outline" className={cn('text-xs', config.className)}>
      {config.label}
    </Badge>
  )
}
