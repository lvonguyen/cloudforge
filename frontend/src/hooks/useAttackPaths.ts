import { useQuery } from '@tanstack/react-query'
import { apiClient, ApiError } from '@/lib/api'
import { computeMockAttackPaths } from '@/lib/mock-attack-paths'
import type { Finding } from '@/types/compliance'
import type { AttackPath, AttackPathStats, PaginatedResponse } from '@/types/attack-path'

const R2_FINDINGS_URL =
  'https://pub-878a225fb2464e2ab2e3b08d0603e04b.r2.dev/mock/findings.json'

const EMPTY_STATS: AttackPathStats = {
  total_findings: 0, findings_in_paths: 0, isolated_findings: 0,
  coverage_percent: 0, total_paths: 0, critical_paths: 0,
  high_paths: 0, medium_paths: 0, by_provider: {},
}

// Cached mock attack paths — computed once from findings data
let mockCache: { paths: AttackPath[]; stats: AttackPathStats } | null = null

async function getMockAttackPaths(): Promise<{ paths: AttackPath[]; stats: AttackPathStats }> {
  if (mockCache) return mockCache

  // Fetch findings from R2 (same source as useFindings fallback)
  let findings: Finding[]
  try {
    const res = await fetch(R2_FINDINGS_URL)
    if (!res.ok) throw new Error(`R2: ${res.status}`)
    findings = await res.json()
  } catch {
    // Fall back to local mock
    const res = await fetch('/mock/findings.json')
    if (!res.ok) return { paths: [], stats: EMPTY_STATS }
    findings = await res.json()
  }

  console.warn('[useAttackPaths] Computing mock attack paths from', findings.length, 'findings')
  mockCache = computeMockAttackPaths(findings)
  return mockCache
}

async function fetchAttackPaths(page: number, perPage: number): Promise<PaginatedResponse<AttackPath>> {
  try {
    return await apiClient.get<PaginatedResponse<AttackPath>>(`/attack-paths?page=${page}&per_page=${perPage}`)
  } catch (err) {
    if (err instanceof ApiError && err.status < 500) throw err
    if (import.meta.env.PROD) throw err
    console.warn('[useAttackPaths] API unavailable, computing from findings')
    const { paths } = await getMockAttackPaths()
    const start = (page - 1) * perPage
    const data = paths.slice(start, start + perPage)
    return {
      data,
      page,
      per_page: perPage,
      total: paths.length,
      total_pages: Math.ceil(paths.length / perPage),
    }
  }
}

async function fetchAttackPathStats(): Promise<AttackPathStats> {
  try {
    return await apiClient.get<AttackPathStats>('/attack-paths/stats')
  } catch (err) {
    if (err instanceof ApiError && err.status < 500) throw err
    if (import.meta.env.PROD) throw err
    console.warn('[useAttackPathStats] API unavailable, computing from findings')
    const { stats } = await getMockAttackPaths()
    return stats
  }
}

export function useAttackPaths(page = 1, perPage = 20) {
  return useQuery({
    queryKey: ['attack-paths', page, perPage],
    queryFn: () => fetchAttackPaths(page, perPage),
  })
}

export function useAttackPath(id: string) {
  return useQuery({
    queryKey: ['attack-paths', id],
    queryFn: async () => {
      try {
        return await apiClient.get<AttackPath>(`/attack-paths/${id}`)
      } catch (err) {
        if (err instanceof ApiError && err.status < 500) throw err
        if (import.meta.env.PROD) throw err
        const { paths } = await getMockAttackPaths()
        return paths.find(p => p.id === id) ?? null
      }
    },
    enabled: Boolean(id),
  })
}

export function useAttackPathStats() {
  return useQuery({
    queryKey: ['attack-paths', 'stats'],
    queryFn: () => fetchAttackPathStats(),
  })
}
