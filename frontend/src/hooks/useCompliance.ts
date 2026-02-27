import { useQuery } from '@tanstack/react-query'
import frameworksData from '@/lib/mock/frameworks.json'

export function useCompliance() {
  return useQuery({
    queryKey: ['compliance', 'frameworks'],
    queryFn: async () => frameworksData,
  })
}
