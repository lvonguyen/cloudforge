import { Badge } from '@/components/ui/badge'
import { cn } from '@/lib/utils'

export const PROVIDER_COLORS: Record<string, string> = {
  aws: 'bg-orange-500/20 text-orange-300 font-semibold',
  azure: 'bg-blue-500/20 text-blue-300 font-semibold',
  gcp: 'bg-green-500/20 text-green-300 font-semibold',
}

export function ProviderBadge({ provider, className }: { provider: string; className?: string }) {
  return (
    <Badge variant="secondary" className={cn('text-xs', PROVIDER_COLORS[provider], className)}>
      {provider.toUpperCase()}
    </Badge>
  )
}
