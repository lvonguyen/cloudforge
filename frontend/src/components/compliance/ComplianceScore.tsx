import { cn } from '@/lib/utils'

interface Props {
  score: number
  size?: 'sm' | 'md'
}

export function ComplianceScore({ score, size = 'md' }: Props) {
  const color =
    score >= 90 ? 'text-green-600 dark:text-green-400' :
    score >= 75 ? 'text-yellow-600 dark:text-yellow-400' :
    score >= 60 ? 'text-orange-600 dark:text-orange-400' : 'text-red-600 dark:text-red-400'

  return (
    <span className={cn('font-bold tabular-nums', color, size === 'sm' ? 'text-sm' : 'text-lg')}>
      {score.toFixed(1)}%
    </span>
  )
}
