import { cn } from '@/lib/utils'
import { ProviderIcon } from '@/components/ui/ProviderIcon'

export function ProviderBadge({ provider, className }: { provider: string; className?: string }) {
  return (
    <span className={cn('inline-flex items-center justify-center', className)} title={provider.toUpperCase()}>
      <ProviderIcon provider={provider} className="h-6 w-6" />
    </span>
  )
}
