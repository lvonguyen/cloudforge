import { useQuery } from '@tanstack/react-query'
import { apiClient, ApiError } from '@/lib/api'
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
      } catch (err) {
        if (err instanceof ApiError && err.status < 500) throw err
        console.warn('[useCatalog] API unavailable, using mock data')
        const mod = await import('@/lib/mock/catalog.json')
        let data = mod.default as CatalogModule[]
        if (filters?.provider) data = data.filter(m => m.provider === filters.provider)
        if (filters?.category) data = data.filter(m => m.category === filters.category)
        if (filters?.search) {
          const q = filters.search.toLowerCase()
          data = data.filter(m => m.name.toLowerCase().includes(q) || m.description.toLowerCase().includes(q))
        }
        return data
      }
    },
  })
}
