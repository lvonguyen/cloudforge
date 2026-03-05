import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'

interface CatalogItem {
  id: string
  name: string
  description: string
  provider: string
  resourceType: string
  estimatedMonthlyCost?: string
}

export function ResourceCatalogCard({ item, onSelect }: { item: CatalogItem; onSelect?: () => void }) {
  const PROVIDER_COLORS: Record<string, string> = {
    aws: 'bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-300',
    azure: 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-300',
    gcp: 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300',
  }

  return (
    <Card className="hover:shadow-sm transition-shadow">
      <CardHeader className="pb-2">
        <div className="flex items-center justify-between">
          <CardTitle className="text-sm">{item.name}</CardTitle>
          <Badge variant="secondary" className={`text-[10px] ${PROVIDER_COLORS[item.provider] ?? ''}`}>
            {item.provider.toUpperCase()}
          </Badge>
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
