import { Badge } from '@/components/ui/badge'
import { ProviderIcon } from './ProviderIcon'
import { cn } from '@/lib/utils'

export const PROVIDER_COLORS: Record<string, string> = {
  aws: 'bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-300',
  azure: 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-300',
  gcp: 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300',
}

export function ProviderBadge({ provider, className }: { provider: string; className?: string }) {
  return (
    <Badge variant="secondary" className={cn('text-[10px]', PROVIDER_COLORS[provider], className)}>
      <ProviderIcon provider={provider} className="h-3 w-3" />
      {provider.toUpperCase()}
    </Badge>
  )
}
