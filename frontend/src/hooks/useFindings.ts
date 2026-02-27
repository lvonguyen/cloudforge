import { useQuery } from '@tanstack/react-query'
import findingsData from '@/lib/mock/findings.json'
import type { Finding } from '@/types/compliance'

const findings = findingsData as Finding[]

export function useFindings(filters?: { severity?: string; provider?: string; status?: string }) {
  return useQuery({
    queryKey: ['findings', filters],
    queryFn: async () => {
      let result = findings
      if (filters?.severity) result = result.filter(f => f.severity === filters.severity)
      if (filters?.provider) result = result.filter(f => f.cloud_provider === filters.provider)
      if (filters?.status) result = result.filter(f => f.status === filters.status)
      return result
    },
  })
}

export function useFinding(id: string) {
  return useQuery({
    queryKey: ['findings', id],
    queryFn: async () => findings.find(f => f.id === id) ?? null,
    enabled: Boolean(id),
  })
}
