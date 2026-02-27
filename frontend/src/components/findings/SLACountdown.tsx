import { Clock } from 'lucide-react'
import { cn } from '@/lib/utils'

interface Props {
  dueDate?: string
  slaBreach?: string
}

export function SLACountdown({ dueDate, slaBreach }: Props) {
  if (!dueDate && !slaBreach) return null

  const target = slaBreach ?? dueDate
  const ms = new Date(target!).getTime() - Date.now()
  const breached = ms < 0

  const days = Math.abs(Math.floor(ms / (1000 * 60 * 60 * 24)))
  const hours = Math.abs(Math.floor((ms % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60)))

  let label: string
  if (breached) {
    label = days > 0 ? `${days}d overdue` : `${hours}h overdue`
  } else {
    label = days > 0 ? `${days}d left` : `${hours}h left`
  }

  return (
    <span className={cn('flex items-center gap-1 text-xs font-medium', breached ? 'text-red-600' : 'text-muted-foreground')}>
      <Clock className="h-3 w-3" />
      {label}
    </span>
  )
}
