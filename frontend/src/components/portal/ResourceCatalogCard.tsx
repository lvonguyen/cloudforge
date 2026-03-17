import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { ProviderBadge } from '@/components/ui/ProviderBadge'

interface CatalogItem {
  id: string
  name: string
  description: string
  provider: string
  resourceType: string
  estimatedMonthlyCost?: string
  icon_path?: string
}

const PROVIDER_BORDER: Record<string, string> = {
  aws: 'border-l-4 border-l-orange-400/60',
  azure: 'border-l-4 border-l-blue-400/60',
  gcp: 'border-l-4 border-l-green-400/60',
}

export function ResourceCatalogCard({ item, onSelect }: { item: CatalogItem; onSelect?: () => void }) {
  return (
    <Card className={`cursor-pointer hover:shadow-md hover:-translate-y-0.5 transition-all duration-200 relative ${PROVIDER_BORDER[item.provider] ?? ''}`}>
      <CardHeader className="pb-2">
        <div className="flex items-start gap-2">
          {item.icon_path ? (
            <img src={item.icon_path} alt="" className="h-8 w-8 shrink-0 object-contain" />
          ) : null}
          <CardTitle className="text-sm truncate flex-1">{item.name}</CardTitle>
          <ProviderBadge provider={item.provider} />
        </div>
      </CardHeader>
      <CardContent className="space-y-2">
        <p className="text-xs text-muted-foreground line-clamp-2 min-h-[2.5rem]">{item.description}</p>
        {item.estimatedMonthlyCost && (
          <p className="text-xs text-muted-foreground">Est. {item.estimatedMonthlyCost}/mo</p>
        )}
        {onSelect && (
          <Button size="sm" variant="outline" className="w-full text-xs h-7" onClick={onSelect}>
            Select
          </Button>
        )}
      </CardContent>
    </Card>
  )
}
