import { useQuery } from '@tanstack/react-query'
import { apiClient, ApiError } from '@/lib/api'
import type { CatalogModule } from '@/types/catalog'
import catalogData from '@/lib/mock/catalog.json'

function filterCatalog(data: CatalogModule[], filters?: { provider?: string; category?: string; search?: string }): CatalogModule[] {
  let result = data
  if (filters?.provider) result = result.filter(m => m.provider === filters.provider)
  if (filters?.category) result = result.filter(m => m.category === filters.category)
  if (filters?.search) {
    const q = filters.search.toLowerCase()
    result = result.filter(m => m.name.toLowerCase().includes(q) || m.description.toLowerCase().includes(q))
  }
  return result
}

export function useCatalog(filters?: { provider?: string; category?: string; search?: string }) {
  const params = new URLSearchParams()
  if (filters?.provider) params.set('provider', filters.provider)
  if (filters?.category) params.set('category', filters.category)
  if (filters?.search) params.set('search', filters.search)
  const qs = params.toString()
  return useQuery({
    queryKey: ['catalog', 'modules', filters],
    queryFn: async () => {
      if (import.meta.env.VITE_DEMO_MODE === 'true') {
        return filterCatalog(catalogData as CatalogModule[], filters)
      }
      try {
        return await apiClient.get<CatalogModule[]>(`/catalog/modules${qs ? `?${qs}` : ''}`)
      } catch (err) {
        if (err instanceof ApiError && err.status < 500) throw err
        if (import.meta.env.PROD && import.meta.env.VITE_DEMO_MODE !== 'true') throw err
        console.warn('[useCatalog] API unavailable, using mock data')
        return filterCatalog(catalogData as CatalogModule[], filters)
      }
    },
  })
}
