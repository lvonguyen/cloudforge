import { useQuery } from '@tanstack/react-query'
import { apiClient } from '@/lib/api'

export function useCompliance() {
  return useQuery({
    queryKey: ['compliance', 'frameworks'],
    queryFn: () => apiClient.get('/compliance/frameworks'),
  })
}
