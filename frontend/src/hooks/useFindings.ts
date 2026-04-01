import { useQuery, useMutation, useQueries, useQueryClient } from '@tanstack/react-query'
import { apiClient, ApiError, isMockFallbackEnabled, unwrapPaginated } from '@/lib/api'
import type { Finding } from '@/types/compliance'

const R2_FINDINGS_URL =
  'https://pub-878a225fb2464e2ab2e3b08d0603e04b.r2.dev/mock/findings.json'

const UNIFORM_R2_SIGNATURE = {
  total: 20_000,
  severity: {
    CRITICAL: 2_000,
    HIGH: 5_000,
    MEDIUM: 7_000,
    LOW: 6_000,
  },
  status: {
    open: 12_500,
    in_progress: 3_750,
    resolved: 2_500,
    suppressed: 1_250,
  },
  autoRemediatable: 6_000,
}

const DEMO_KEEP_RATIO_BY_SEVERITY: Record<string, number> = {
  CRITICAL: 0.9345,
  HIGH: 0.9621,
  MEDIUM: 0.9464,
  LOW: 0.9753,
}

function countBy<T extends string>(items: Finding[], key: (finding: Finding) => T): Record<string, number> {
  const counts: Record<string, number> = {}
  for (const item of items) counts[key(item)] = (counts[key(item)] ?? 0) + 1
  return counts
}

function sameCounts(actual: Record<string, number>, expected: Record<string, number>): boolean {
  const keys = new Set([...Object.keys(actual), ...Object.keys(expected)])
  for (const key of keys) {
    if ((actual[key] ?? 0) !== (expected[key] ?? 0)) return false
  }
  return true
}

function stableUnitInterval(input: string): number {
  let hash = 2166136261
  for (let i = 0; i < input.length; i += 1) {
    hash ^= input.charCodeAt(i)
    hash = Math.imul(hash, 16777619)
  }
  return (hash >>> 0) / 0xffffffff
}

export function normalizeDemoFindings(findings: Finding[]): Finding[] {
  if (findings.length !== UNIFORM_R2_SIGNATURE.total) return findings

  const severity = countBy(findings, (finding) => finding.severity)
  const status = countBy(findings, (finding) => finding.status)
  const autoRemediatable = findings.filter((finding) => finding.auto_remediatable).length

  const looksLikeUniformR2Corpus =
    sameCounts(severity, UNIFORM_R2_SIGNATURE.severity) &&
    sameCounts(status, UNIFORM_R2_SIGNATURE.status) &&
    autoRemediatable === UNIFORM_R2_SIGNATURE.autoRemediatable

  if (!looksLikeUniformR2Corpus) return findings

  return findings.filter((finding) => {
    const threshold = DEMO_KEEP_RATIO_BY_SEVERITY[finding.severity] ?? 0.96
    return stableUnitInterval(`${finding.id}:${finding.severity}:${finding.status}`) <= threshold
  })
}

async function fetchR2Findings(): Promise<Finding[]> {
  const res = await fetch(R2_FINDINGS_URL)
  if (!res.ok) throw new Error(`R2 fetch failed: ${res.status}`)
  return normalizeDemoFindings(await res.json())
}

async function fetchLocalMockFindings(): Promise<Finding[]> {
  const res = await fetch('/mock/findings.json')
  if (!res.ok) throw new Error(`Local mock fetch failed: ${res.status}`)
  return res.json()
}

const SESSION_SOURCE_KEY = 'aegis_findings_source'

async function fetchMockFindings(): Promise<Finding[]> {
  const preferred = sessionStorage.getItem(SESSION_SOURCE_KEY)

  // Re-use the source that worked earlier in this session
  if (preferred === 'r2') return fetchR2Findings()
  if (preferred === 'local') return fetchLocalMockFindings()

  try {
    const data = await fetchR2Findings()
    sessionStorage.setItem(SESSION_SOURCE_KEY, 'r2')
    return data
  } catch {
    console.warn('[useFindings] R2 unavailable, falling back to local mock')
    const data = await fetchLocalMockFindings()
    sessionStorage.setItem(SESSION_SOURCE_KEY, 'local')
    return data
  }
}

interface FetchFindingsResult {
  data: Finding[]
  usingMockData: boolean
}

async function fetchFindings(filters?: { severity?: string; provider?: string; status?: string }): Promise<FetchFindingsResult> {
  if (import.meta.env.VITE_DEMO_MODE === 'true') {
    const data = await fetchMockFindings()
    return { data, usingMockData: true }
  }
  const params = new URLSearchParams()
  if (filters?.severity) params.set('severity', filters.severity)
  if (filters?.provider) params.set('provider', filters.provider)
  if (filters?.status) params.set('status', filters.status)
  const qs = params.toString()
  try {
    const raw = await apiClient.get<Finding[] | { data: Finding[] }>(`/findings${qs ? `?${qs}` : ''}`)
    const data = unwrapPaginated(raw)
    sessionStorage.setItem(SESSION_SOURCE_KEY, 'api')
    return { data, usingMockData: false }
  } catch (err) {
    if (err instanceof ApiError && err.status < 500) throw err
    if (!isMockFallbackEnabled()) throw err
    console.warn('[useFindings] API unavailable, using mock data')
    const data = await fetchMockFindings()
    return { data, usingMockData: true }
  }
}

async function fetchFindingById(id: string): Promise<Finding | null> {
  if (import.meta.env.VITE_DEMO_MODE === 'true') {
    const findings = await fetchMockFindings()
    return findings.find((f) => f.id === id) ?? null
  }
  try {
    return await apiClient.get<Finding>(`/findings/${id}`)
  } catch (err) {
    if (err instanceof ApiError && err.status < 500) throw err
    if (!isMockFallbackEnabled()) throw err
    console.warn('[useFinding] API unavailable, using mock data')
    const findings = await fetchMockFindings()
    return findings.find((f) => f.id === id) ?? null
  }
}

export function useFindings(filters?: { severity?: string; provider?: string; status?: string }) {
  const query = useQuery({
    queryKey: ['findings', filters],
    queryFn: () => fetchFindings(filters),
  })
  return {
    ...query,
    data: query.data?.data,
    isUsingMockData: query.isSuccess && (query.data?.usingMockData ?? false),
  }
}

export function useEnrichFinding() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (findingId: string) => {
      return apiClient.post<Finding>(`/findings/${findingId}/enrich`, {})
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['findings'] })
    },
  })
}

export interface ThreatIntelEnrichment {
  epss_score: number
  epss_percentile: number
  kev_exploited: boolean
  kev_date_added?: string
  greynoise_classification?: string
  greynoise_noise: boolean
  hibp_breach_count?: number
  otx_pulse_count?: number
  otx_tags?: string[]
  enriched_at: string
}

interface FindingEnrichmentResponse {
  finding_id: string
  root_cause: string
  impact: string
  remediation: string
  related_controls: string[]
  threat_intel?: ThreatIntelEnrichment
  enriched_at: string
}

export function useFindingEnrichment(findingId: string) {
  return useQuery({
    queryKey: ['enrichment', findingId],
    queryFn: async () => {
      return apiClient.post<FindingEnrichmentResponse>(`/findings/${findingId}/enrich`, {})
    },
    enabled: Boolean(findingId),
    staleTime: 5 * 60 * 1000,
    retry: false,
  })
}

export interface FindingsStats {
  total: number
  by_severity: Record<string, number>
  by_status: Record<string, number>
  by_provider: Record<string, number>
  sla_breached: number
  auto_remedial: number
}

export function useFindingsStats() {
  return useQuery({
    queryKey: ['findings', 'stats'],
    queryFn: async () => {
      try {
        return await apiClient.get<FindingsStats>('/findings/stats')
      } catch (err) {
        if (err instanceof ApiError && err.status < 500) throw err
        if (!isMockFallbackEnabled()) throw err
        return null
      }
    },
    staleTime: 30_000, // 30s — stats are cheap but change on ingest
  })
}

export function useFinding(id: string) {
  return useQuery({
    queryKey: ['findings', id],
    queryFn: () => fetchFindingById(id),
    enabled: Boolean(id),
  })
}

export function useFindingsByIds(ids: string[], enabled = true) {
  const uniqueIds = Array.from(new Set(ids.filter(Boolean)))
  const queries = useQueries({
    queries: uniqueIds.map((id) => ({
      queryKey: ['findings', id],
      queryFn: () => fetchFindingById(id),
      enabled: enabled && Boolean(id),
      staleTime: 5 * 60 * 1000,
    })),
  })

  return {
    queries,
    data: queries
      .map((query) => query.data)
      .filter((finding): finding is Finding => Boolean(finding)),
    isLoading: queries.some((query) => query.isLoading),
    isError: queries.some((query) => query.isError),
  }
}
