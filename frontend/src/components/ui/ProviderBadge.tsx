import { cn } from '@/lib/utils'
import { ProviderIcon } from '@/components/ui/ProviderIcon'

const SIZE_MAP = {
  sm: 'h-4 w-4',
  md: 'h-5 w-5',
  lg: 'h-6 w-6',
} as const

export function ProviderBadge({
  provider,
  size = 'lg',
  className,
}: {
  provider: string
  size?: 'sm' | 'md' | 'lg'
  className?: string
}) {
  return (
    <span
      className={cn(
        'inline-flex items-center justify-center rounded-sm bg-transparent px-0.5 py-0.5',
        className,
      )}
      title={provider.toUpperCase()}
    >
      <ProviderIcon provider={provider} className={SIZE_MAP[size]} />
    </span>
  )
}
