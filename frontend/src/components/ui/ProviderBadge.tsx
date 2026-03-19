import { cn } from '@/lib/utils'
import { ProviderIcon } from '@/components/ui/ProviderIcon'

export const PROVIDER_COLORS: Record<string, string> = {
  aws: 'bg-zinc-100 dark:bg-zinc-800',
  azure: 'bg-zinc-100 dark:bg-zinc-800',
  gcp: 'bg-zinc-100 dark:bg-zinc-800',
}

export function ProviderBadge({ provider, className }: { provider: string; className?: string }) {
  return (
    <span className={cn('inline-flex items-center justify-center rounded-md p-1', PROVIDER_COLORS[provider], className)} title={provider.toUpperCase()}>
      <ProviderIcon provider={provider} className="h-5 w-5" />
    </span>
  )
}
