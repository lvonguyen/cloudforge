import { keepPreviousData, useQuery, useMutation, useQueries, useQueryClient } from '@tanstack/react-query'
import { apiClient, ApiError, isMockFallbackEnabled, shouldPreferLocalMockAssets } from '@/lib/api'
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
const MAX_LOCAL_FINDINGS_PAGE_SIZE = 1000

async function fetchMockFindings(): Promise<Finding[]> {
  const preferred = sessionStorage.getItem(SESSION_SOURCE_KEY)
  const preferLocal = shouldPreferLocalMockAssets()

  // Re-use the source that worked earlier in this session
  if (preferred === 'r2' && !preferLocal) return fetchR2Findings()
  if (preferred === 'local') return fetchLocalMockFindings()

  const sources: Array<{ key: 'local' | 'r2'; fetcher: () => Promise<Finding[]> }> = preferLocal
    ? [
        { key: 'local', fetcher: fetchLocalMockFindings },
        { key: 'r2', fetcher: fetchR2Findings },
      ]
    : [
        { key: 'r2', fetcher: fetchR2Findings },
        { key: 'local', fetcher: fetchLocalMockFindings },
      ]

  let lastError: unknown = null
  for (const source of sources) {
    try {
      const data = await source.fetcher()
      sessionStorage.setItem(SESSION_SOURCE_KEY, source.key)
      return data
    } catch (error) {
      lastError = error
      continue
    }
  }

  throw lastError instanceof Error ? lastError : new Error('Mock findings unavailable for frontend fallback')
}

interface FetchFindingsResult {
  data: Finding[]
  usingMockData: boolean
  page: number
  perPage: number
  total: number
  totalPages: number
}

export interface FindingsQueryParams {
  severity?: string
  provider?: string
  status?: string
  page?: number
  perPage?: number
  sort?: string
  order?: 'asc' | 'desc'
}

interface FindingsPageEnvelope {
  data: Finding[]
  page: number
  per_page: number
  total: number
  total_pages: number
}

export interface FindingsStats {
  total: number
  by_severity: Record<string, number>
  by_status: Record<string, number>
  by_provider: Record<string, number>
  by_category?: Record<string, number>
  sla_breached: number
  auto_remedial: number
}

function isDemoMode(): boolean {
  return import.meta.env.VITE_DEMO_MODE === 'true'
}

function compareFindings(a: Finding, b: Finding, field: string, order: 'asc' | 'desc' = 'asc'): number {
  const direction = order === 'desc' ? -1 : 1
  const severityRank: Record<string, number> = { INFO: 0, LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 }

  let base = 0
  switch (field) {
    case 'severity':
      base = (severityRank[a.severity] ?? 0) - (severityRank[b.severity] ?? 0)
      break
    case 'ai_risk':
    case 'ai_risk_score':
      base = a.ai_risk_score - b.ai_risk_score
      break
    case 'first_found_at':
      base = a.first_found_at.localeCompare(b.first_found_at)
      break
    case 'status':
      base = a.status.localeCompare(b.status)
      break
    case 'title':
      base = a.title.localeCompare(b.title)
      break
    default:
      base = 0
  }
  return base * direction
}

function paginateLocalFindings(findings: Finding[], params?: FindingsQueryParams): FindingsPageEnvelope {
  const page = Math.max(params?.page ?? 1, 1)
  const perPage = Math.min(
    Math.max(params?.perPage ?? (findings.length || 1), 1),
    MAX_LOCAL_FINDINGS_PAGE_SIZE,
  )
  const filtered = findings.filter((finding) => {
    if (params?.severity && finding.severity !== params.severity) return false
    if (params?.provider && finding.cloud_provider !== params.provider) return false
    if (params?.status && finding.status !== params.status) return false
    return true
  })
  const sorted = [...filtered]
  if (params?.sort) {
    sorted.sort((a, b) => compareFindings(a, b, params.sort ?? '', params.order ?? 'asc'))
  }

  const total = sorted.length
  const totalPages = Math.max(Math.ceil(total / perPage), 1)
  const boundedPage = Math.min(page, totalPages)
  const start = (boundedPage - 1) * perPage
  const data = sorted.slice(start, start + perPage)

  return {
    data,
    page: boundedPage,
    per_page: perPage,
    total,
    total_pages: totalPages,
  }
}

function toFetchResult(payload: Finding[] | FindingsPageEnvelope, usingMockData: boolean): FetchFindingsResult {
  if (Array.isArray(payload)) {
    return {
      data: payload,
      usingMockData,
      page: 1,
      perPage: payload.length,
      total: payload.length,
      totalPages: 1,
    }
  }

  return {
    data: payload.data,
    usingMockData,
    page: payload.page,
    perPage: payload.per_page,
    total: payload.total,
    totalPages: payload.total_pages,
  }
}

async function fetchFindings(filters?: FindingsQueryParams): Promise<FetchFindingsResult> {
  if (isDemoMode()) {
    const data = await fetchMockFindings()
    return toFetchResult(paginateLocalFindings(data, filters), true)
  }
  const params = new URLSearchParams()
  if (filters?.severity) params.set('severity', filters.severity)
  if (filters?.provider) params.set('provider', filters.provider)
  if (filters?.status) params.set('status', filters.status)
  if (filters?.page) params.set('page', String(filters.page))
  if (filters?.perPage) params.set('per_page', String(filters.perPage))
  if (filters?.sort) params.set('sort', filters.sort)
  if (filters?.order) params.set('order', filters.order)
  const qs = params.toString()
  try {
    const raw = await apiClient.get<Finding[] | FindingsPageEnvelope>(`/findings${qs ? `?${qs}` : ''}`)
    sessionStorage.setItem(SESSION_SOURCE_KEY, 'api')
    return toFetchResult(raw, false)
  } catch (err) {
    if (err instanceof ApiError && err.status < 500) throw err
    if (!isMockFallbackEnabled()) throw err
    console.warn('[useFindings] API unavailable, using mock data')
    const data = await fetchMockFindings()
    return toFetchResult(paginateLocalFindings(data, filters), true)
  }
}

async function fetchFindingById(id: string): Promise<Finding | null> {
  if (isDemoMode()) {
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

export function useFindings(filters?: FindingsQueryParams) {
  const query = useQuery({
    queryKey: ['findings', filters],
    queryFn: () => fetchFindings(filters),
    placeholderData: keepPreviousData,
    staleTime: 30_000,
  })
  return {
    ...query,
    data: query.data?.data,
    total: query.data?.total ?? 0,
    page: query.data?.page ?? filters?.page ?? 1,
    perPage: query.data?.perPage ?? filters?.perPage ?? 0,
    totalPages: query.data?.totalPages ?? 1,
    isUsingMockData: query.isSuccess && (query.data?.usingMockData ?? false),
  }
}

export function useEnrichFinding() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (findingId: string) => {
      if (isDemoMode()) {
        return fetchFindingById(findingId)
      }
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

interface FindingCodeToCloudProvenance {
  repository_url?: string
  repository_name?: string
  repository_provider?: string
  branch?: string
  commit_sha?: string
  build_system?: string
  pipeline_name?: string
  pipeline_run_id?: string
  pipeline_run_url?: string
  artifact?: string
}

interface FindingEnrichmentResponse {
  finding_id: string
  root_cause: string
  impact: string
  remediation: string
  related_controls: string[]
  threat_intel?: ThreatIntelEnrichment
  code_to_cloud?: FindingCodeToCloudProvenance
  enriched_at: string
}

export function useFindingEnrichment(findingId: string) {
  return useQuery({
    queryKey: ['enrichment', findingId],
    queryFn: async () => {
      if (isDemoMode()) return null
      return apiClient.post<FindingEnrichmentResponse>(`/findings/${findingId}/enrich`, {})
    },
    enabled: Boolean(findingId),
    staleTime: 5 * 60 * 1000,
    retry: false,
  })
}

function isTerminalFinding(finding: Finding): boolean {
  return ['resolved', 'suppressed'].includes(finding.status) ||
    ['closed', 'suppressed', 'false_positive', 'risk_accepted', 'wont_fix'].includes(finding.workflow_status)
}

function computeFindingsStats(findings: Finding[]): FindingsStats {
  const now = Date.now()

  return {
    total: findings.length,
    by_severity: countBy(findings, (finding) => finding.severity),
    by_status: countBy(findings, (finding) => finding.status),
    by_provider: countBy(findings, (finding) => finding.cloud_provider),
    by_category: countBy(findings, (finding) => finding.category),
    sla_breached: findings.filter((finding) => {
      const breachDate = finding.sla_breach_date ?? finding.due_date
      if (!breachDate || isTerminalFinding(finding)) return false

      const breachTimestamp = Date.parse(breachDate)
      return !Number.isNaN(breachTimestamp) && breachTimestamp <= now
    }).length,
    auto_remedial: findings.filter((finding) => finding.auto_remediatable).length,
  }
}

export function useFindingsStats() {
  return useQuery({
    queryKey: ['findings', 'stats'],
    queryFn: async () => {
      if (isDemoMode()) {
        try {
          const findings = await fetchMockFindings()
          return computeFindingsStats(findings)
        } catch {
          console.warn('[useFindingsStats] Mock stats unavailable in demo mode')
          return null
        }
      }

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
