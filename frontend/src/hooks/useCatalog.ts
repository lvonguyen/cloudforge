import { useQuery } from '@tanstack/react-query'
import { apiClient } from '@/lib/api'
import type { CatalogModule } from '@/types/catalog'

export function useCatalog(filters?: { provider?: string; category?: string; search?: string }) {
  const params = new URLSearchParams()
  if (filters?.provider) params.set('provider', filters.provider)
  if (filters?.category) params.set('category', filters.category)
  if (filters?.search) params.set('search', filters.search)
  const qs = params.toString()
  return useQuery({
    queryKey: ['catalog', 'modules', filters],
    queryFn: async () => {
      try {
        return await apiClient.get<CatalogModule[]>(`/catalog/modules${qs ? `?${qs}` : ''}`)
      } catch {
        const mod = await import('@/lib/mock/catalog.json')
        return mod.default as CatalogModule[]
      }
    },
  })
}
