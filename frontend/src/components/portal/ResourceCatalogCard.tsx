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
}

export function ResourceCatalogCard({ item, onSelect }: { item: CatalogItem; onSelect?: () => void }) {
  return (
    <Card className="cursor-pointer hover:shadow-md hover:-translate-y-0.5 transition-all duration-200">
      <CardHeader className="pb-2">
        <div className="flex items-center justify-between">
          <CardTitle className="text-sm">{item.name}</CardTitle>
          <ProviderBadge provider={item.provider} />
        </div>
      </CardHeader>
      <CardContent className="space-y-2">
        <p className="text-xs text-muted-foreground">{item.description}</p>
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
