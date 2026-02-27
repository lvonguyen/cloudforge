import { useQuery } from '@tanstack/react-query'
import type { RemediationRecord } from '@/types/remediation'

// Stub: returns empty until backend endpoints are available
export function useRemediations() {
  return useQuery({
    queryKey: ['remediations'],
    queryFn: async (): Promise<RemediationRecord[]> => [],
  })
}
