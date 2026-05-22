import { useQuery } from '@tanstack/react-query'
import { apiClient, ApiError, shouldPreferLocalMockAssets } from '@/lib/api'
import { isDemoMode } from '@/lib/runtime'
import type { AttackPath, AttackPathStats, PaginatedResponse } from '@/types/attack-path'

const R2_BASE = 'https://pub-878a225fb2464e2ab2e3b08d0603e04b.r2.dev/mock'

const EMPTY_STATS: AttackPathStats = {
  total_findings: 0, findings_in_paths: 0, isolated_findings: 0,
  coverage_percent: 0, total_paths: 0, critical_paths: 0,
  high_paths: 0, medium_paths: 0, by_provider: {},
}

// Singleflight cache: coalesces concurrent calls and allows invalidation
let mockCachePromise: Promise<{ paths: AttackPath[]; stats: AttackPathStats }> | null = null
let mockCacheKey: string | null = null

async function getMockAttackPaths(): Promise<{ paths: AttackPath[]; stats: AttackPathStats }> {
  const cacheKey = isDemoMode()
    ? 'demo'
    : shouldPreferLocalMockAssets() ? 'local-first' : 'remote-first'

  if (mockCachePromise && mockCacheKey === cacheKey) return mockCachePromise
  mockCacheKey = cacheKey
  mockCachePromise = loadMockAttackPaths().catch(err => { mockCachePromise = null; throw err })
  return mockCachePromise
}

async function loadMockAttackPaths(): Promise<{ paths: AttackPath[]; stats: AttackPathStats }> {
  const preferLocal = shouldPreferLocalMockAssets()
  const precomputedSources = preferLocal
    ? ['/mock/attack-paths.json', `${R2_BASE}/attack-paths.json`]
    : [`${R2_BASE}/attack-paths.json`, '/mock/attack-paths.json']

  for (const source of precomputedSources) {
    try {
      const res = await fetch(source)
      if (res.ok) {
        const data = await res.json()
        if (data.paths?.length > 0) {
          const origin = source.startsWith('/mock') ? 'local mock' : 'R2'
          console.warn('[useAttackPaths] Using pre-computed paths from', origin + ':', data.paths.length, 'paths')
          return { paths: data.paths, stats: data.stats }
        }
      }
    } catch { /* fall through */ }
  }

  // Final fallback: compute client-side from findings (slow for large datasets)
  try {
    const { computeMockAttackPaths } = await import('@/lib/mock-attack-paths')
    let findings
    const findingSources = preferLocal
      ? ['/mock/findings.json', `${R2_BASE}/findings.json`]
      : [`${R2_BASE}/findings.json`, '/mock/findings.json']
    for (const source of findingSources) {
      try {
        const res = await fetch(source)
        if (!res.ok) throw new Error(`mock source: ${res.status}`)
        findings = await res.json()
        break
      } catch {
        continue
      }
    }
    if (!findings) return { paths: [], stats: EMPTY_STATS }
    console.warn('[useAttackPaths] Computing mock paths client-side from', findings.length, 'findings')
    return computeMockAttackPaths(findings)
  } catch {
    return { paths: [], stats: EMPTY_STATS }
  }
}

function paginateMockPaths(paths: AttackPath[], page: number, perPage: number): PaginatedResponse<AttackPath> {
  const start = (page - 1) * perPage
  return {
    data: paths.slice(start, start + perPage),
    page,
    per_page: perPage,
    total: paths.length,
    total_pages: Math.ceil(paths.length / perPage),
  }
}

async function fetchAttackPaths(page: number, perPage: number): Promise<PaginatedResponse<AttackPath>> {
  if (isDemoMode()) {
    const { paths } = await getMockAttackPaths()
    return paginateMockPaths(paths, page, perPage)
  }

  try {
    return await apiClient.get<PaginatedResponse<AttackPath>>(`/attack-paths?page=${page}&per_page=${perPage}`)
  } catch (err) {
    if (err instanceof ApiError && err.status < 500) throw err
    if (import.meta.env.PROD && !isDemoMode()) throw err
    console.warn('[useAttackPaths] API unavailable, using mock paths')
    const { paths } = await getMockAttackPaths()
    return paginateMockPaths(paths, page, perPage)
  }
}

// computeStatsFromPaths derives stats directly from the path list, ensuring
// stats always reflect the actual paths the list endpoint will display.
// This fixes the disconnect where pre-computed stats came from a different
// findings snapshot than the paths array.
function computeStatsFromPaths(paths: AttackPath[]): AttackPathStats {
  const byProvider: Record<string, number> = {}
  const findingIDs = new Set<string>()
  let critical = 0, high = 0, medium = 0

  for (const p of paths) {
    if (p.severity === 'CRITICAL') critical++
    else if (p.severity === 'HIGH') high++
    else medium++

    if (p.nodes?.length > 0) {
      const provider = p.nodes[0].provider
      byProvider[provider] = (byProvider[provider] ?? 0) + 1
    }
    for (const fid of p.finding_ids ?? []) {
      findingIDs.add(fid)
    }
  }

  const findingsInPaths = findingIDs.size
  return {
    total_findings: findingsInPaths, // in mock mode, we only know about findings in paths
    findings_in_paths: findingsInPaths,
    isolated_findings: 0,
    coverage_percent: paths.length > 0 ? 100 : 0,
    total_paths: paths.length,
    critical_paths: critical,
    high_paths: high,
    medium_paths: medium,
    by_provider: byProvider,
  }
}

async function fetchAttackPathStats(): Promise<AttackPathStats> {
  if (isDemoMode()) {
    const { paths } = await getMockAttackPaths()
    return computeStatsFromPaths(paths)
  }

  try {
    return await apiClient.get<AttackPathStats>('/attack-paths/stats')
  } catch (err) {
    if (err instanceof ApiError && err.status < 500) throw err
    if (import.meta.env.PROD && !isDemoMode()) throw err
    console.warn('[useAttackPathStats] API unavailable, deriving stats from paths')
    const { paths } = await getMockAttackPaths()
    return computeStatsFromPaths(paths)
  }
}

export function useAttackPaths(page = 1, perPage = 20, opts?: { enabled?: boolean }) {
  return useQuery({
    queryKey: ['attack-paths', page, perPage],
    queryFn: () => fetchAttackPaths(page, perPage),
    staleTime: 5 * 60 * 1000, // 5 min — attack paths change infrequently
    enabled: opts?.enabled ?? true,
  })
}

export function useAttackPath(id: string) {
  return useQuery({
    queryKey: ['attack-paths', id],
    queryFn: async () => {
      if (isDemoMode()) {
        const { paths } = await getMockAttackPaths()
        return paths.find(p => p.id === id) ?? null
      }

      try {
        return await apiClient.get<AttackPath>(`/attack-paths/${id}`)
      } catch (err) {
        if (err instanceof ApiError && err.status < 500) throw err
        if (import.meta.env.PROD && !isDemoMode()) throw err
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
