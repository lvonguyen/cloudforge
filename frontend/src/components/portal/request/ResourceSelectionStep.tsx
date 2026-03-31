import { ResourceCatalogCard } from '@/components/portal/ResourceCatalogCard'
import { Label } from '@/components/ui/label'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { REGIONS, SERVICE_MODELS } from './request-shared'
import type { RequestCatalogItem } from './request-shared'

export function ResourceSelectionStep({
  selectedId,
  onSelect,
  provider,
  onProviderChange,
  region,
  onRegionChange,
  serviceModel,
  onServiceModelChange,
  catalog,
}: {
  selectedId: string
  onSelect: (id: string) => void
  provider: string
  onProviderChange: (provider: string) => void
  region: string
  onRegionChange: (region: string) => void
  serviceModel: string
  onServiceModelChange: (serviceModel: string) => void
  catalog: RequestCatalogItem[]
}) {
  const regions = REGIONS[provider] ?? []
  const filteredCatalog = provider ? catalog.filter(item => item.provider === provider) : catalog

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-3 gap-4">
        <div className="space-y-1.5">
          <Label>Cloud Provider</Label>
          <Select value={provider} onValueChange={onProviderChange}>
            <SelectTrigger className="w-full">
              <SelectValue placeholder="Select provider" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="aws">AWS</SelectItem>
              <SelectItem value="azure">Azure</SelectItem>
              <SelectItem value="gcp">GCP</SelectItem>
            </SelectContent>
          </Select>
        </div>
        <div className="space-y-1.5">
          <Label>Region</Label>
          <Select value={region} onValueChange={onRegionChange} disabled={!provider}>
            <SelectTrigger className="w-full">
              <SelectValue placeholder="Select region" />
            </SelectTrigger>
            <SelectContent>
              {regions.map((value) => (
                <SelectItem key={value} value={value}>{value}</SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
        <div className="space-y-1.5">
          <Label>Service Model</Label>
          <Select value={serviceModel} onValueChange={onServiceModelChange}>
            <SelectTrigger className="w-full">
              <SelectValue placeholder="Select model" />
            </SelectTrigger>
            <SelectContent>
              {SERVICE_MODELS.map((value) => (
                <SelectItem key={value} value={value}>{value}</SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
      </div>

      <div>
        <h2 className="mb-3 text-sm font-semibold">Select Resource Type</h2>
        <div className="grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-4" role="list" aria-label="Available resource types">
          {filteredCatalog.map((item) => (
            <div key={item.id} role="listitem">
              <button
                type="button"
                className={`w-full cursor-pointer rounded-none ring-2 transition-all ${
                  selectedId === item.id ? 'ring-primary' : 'ring-transparent hover:ring-muted-foreground/30'
                }`}
                onClick={() => {
                  onSelect(item.id)
                  onProviderChange(item.provider)
                }}
                aria-pressed={selectedId === item.id}
                aria-label={`Select ${item.name} on ${item.provider.toUpperCase()}`}
              >
                <ResourceCatalogCard item={item} />
              </button>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
