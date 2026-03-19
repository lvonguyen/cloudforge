import { useQuery } from '@tanstack/react-query'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { CheckCircle2, AlertTriangle, XCircle, Clock } from 'lucide-react'

interface ComponentHealth {
  status: string
  message: string
  last_checked: string
  latency_ms: number
}

interface HealthResponse {
  status: string
  timestamp: string
  version: string
  uptime: string
  components: Record<string, ComponentHealth>
}

interface ServiceStatus {
  name: string
  description: string
  status: 'healthy' | 'degraded' | 'down'
  latency_ms?: number
  uptime: string
  last_check: string
}

const STATUS_CONFIG: Record<string, { icon: typeof CheckCircle2; color: string; badge: string; dot: string }> = {
  healthy: { icon: CheckCircle2, color: 'text-green-600 dark:text-green-400', badge: 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300', dot: 'bg-green-500' },
  degraded: { icon: AlertTriangle, color: 'text-yellow-600 dark:text-yellow-400', badge: 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-300', dot: 'bg-yellow-500' },
  down: { icon: XCircle, color: 'text-red-600 dark:text-red-400', badge: 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300', dot: 'bg-red-500' },
  unhealthy: { icon: XCircle, color: 'text-red-600 dark:text-red-400', badge: 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300', dot: 'bg-red-500' },
}

const STATIC_FALLBACK: ServiceStatus[] = [
  { name: 'OPA Policy Engine', description: 'Policy evaluation sidecar', status: 'healthy', latency_ms: 4, uptime: '99.98%', last_check: '2m ago' },
  { name: 'AI Agent Runtime', description: 'Agent orchestration layer', status: 'healthy', latency_ms: 18, uptime: '99.91%', last_check: '5m ago' },
  { name: 'Findings Ingestion', description: 'CSPM/SIEM feed processor', status: 'healthy', latency_ms: 22, uptime: '99.95%', last_check: '1m ago' },
  { name: 'Remediation Dispatcher', description: 'Async remediation queue', status: 'degraded', latency_ms: 340, uptime: '97.4%', last_check: '12m ago' },
  { name: 'Compliance Engine', description: 'Framework mapping + scoring', status: 'healthy', latency_ms: 11, uptime: '100%', last_check: '3m ago' },
  { name: 'API Gateway', description: 'REST API + auth middleware', status: 'healthy', latency_ms: 6, uptime: '99.99%', last_check: '30s ago' },
  { name: 'Trace Collector', description: 'OTEL span ingestion', status: 'healthy', latency_ms: 8, uptime: '99.97%', last_check: '45s ago' },
  { name: 'Cost Analyzer', description: 'FinOps aggregation pipeline', status: 'down', latency_ms: undefined, uptime: '—', last_check: '—' },
]

function normalizeStatus(s: string): 'healthy' | 'degraded' | 'down' {
  if (s === 'healthy') return 'healthy'
  if (s === 'degraded') return 'degraded'
  return 'down'
}

function componentLabel(key: string): string {
  const labels: Record<string, string> = {
    redis: 'Redis Cache',
    postgres: 'PostgreSQL',
    opa: 'OPA Policy Engine',
    api: 'API Gateway',
    workflow: 'Remediation Dispatcher',
    finops: 'Cost Analyzer',
  }
  return labels[key] ?? key.charAt(0).toUpperCase() + key.slice(1)
}

function componentDescription(key: string): string {
  const descs: Record<string, string> = {
    redis: 'Rate limiter + session cache',
    postgres: 'Primary data store',
    opa: 'Policy evaluation sidecar',
    api: 'REST API + auth middleware',
    workflow: 'Async remediation queue',
    finops: 'FinOps aggregation pipeline',
  }
  return descs[key] ?? 'Backend component'
}

function formatLastChecked(iso: string): string {
  if (!iso) return '—'
  try {
    const diff = Math.round((Date.now() - new Date(iso).getTime()) / 1000)
    if (diff < 60) return `${diff}s ago`
    return `${Math.round(diff / 60)}m ago`
  } catch {
    return '—'
  }
}

function ServiceCard({ svc, isFallback }: { svc: ServiceStatus; isFallback?: boolean }) {
  const cfg = STATUS_CONFIG[svc.status] ?? STATUS_CONFIG.healthy
  const { icon: Icon, color, badge, dot } = cfg
  return (
    <Card className={svc.status === 'down' ? 'border-red-200 dark:border-red-800' : svc.status === 'degraded' ? 'border-yellow-200 dark:border-yellow-800' : ''}>
      <CardHeader className="pb-2">
        <div className="flex items-start justify-between gap-2">
          <div className="flex items-center gap-2">
            <div className={`h-2 w-2 rounded-full ${dot} mt-0.5 shrink-0`} />
            <CardTitle className="text-sm">{svc.name}</CardTitle>
          </div>
          <span className={`text-[10px] font-medium px-2 py-0.5 rounded-full ${badge} shrink-0`}>{svc.status}</span>
        </div>
      </CardHeader>
      <CardContent className="space-y-2 pt-0">
        <p className="text-xs text-muted-foreground">{svc.description}</p>
        {isFallback && (
          <p className="text-[10px] text-muted-foreground/60 italic" title="Static fallback — start backend for live data">Reference data only</p>
        )}
        <div className="grid grid-cols-3 gap-2 pt-1">
          <div>
            <p className={`text-sm font-bold ${svc.latency_ms !== undefined ? (svc.latency_ms > 100 ? 'text-yellow-600 dark:text-yellow-400' : 'text-green-600 dark:text-green-400') : 'text-red-600 dark:text-red-400'}`}>
              {svc.latency_ms !== undefined ? `${svc.latency_ms}ms` : '—'}
            </p>
            <p className="text-[10px] text-muted-foreground">Latency</p>
          </div>
          <div>
            <p className="text-sm font-bold">{svc.uptime}</p>
            <p className="text-[10px] text-muted-foreground">Uptime</p>
          </div>
          <div>
            <div className="flex items-center gap-0.5">
              <Icon className={`h-3 w-3 ${color}`} />
              <p className="text-[10px] text-muted-foreground">{svc.last_check}</p>
            </div>
            <p className="text-[10px] text-muted-foreground">Checked</p>
          </div>
        </div>
      </CardContent>
    </Card>
  )
}

function SkeletonCard() {
  return (
    <Card>
      <CardHeader className="pb-2">
        <div className="flex items-start justify-between gap-2">
          <div className="flex items-center gap-2">
            <div className="h-2 w-2 rounded-full bg-muted animate-pulse mt-0.5 shrink-0" />
            <div className="h-4 w-32 bg-muted animate-pulse rounded" />
          </div>
          <div className="h-4 w-14 bg-muted animate-pulse rounded-full" />
        </div>
      </CardHeader>
      <CardContent className="space-y-2 pt-0">
        <div className="h-3 w-40 bg-muted animate-pulse rounded" />
        <div className="grid grid-cols-3 gap-2 pt-1">
          {[0, 1, 2].map(i => (
            <div key={i} className="space-y-1">
              <div className="h-4 w-10 bg-muted animate-pulse rounded" />
              <div className="h-2 w-8 bg-muted animate-pulse rounded" />
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  )
}

export default function SystemHealth() {
  const { data, isLoading, isError, dataUpdatedAt } = useQuery<HealthResponse>({
    queryKey: ['health'],
    queryFn: async () => {
      const res = await fetch('/health')
      if (!res.ok) throw new Error('Health check failed')
      return res.json() as Promise<HealthResponse>
    },
    refetchInterval: 30_000,
  })

  const hasComponents = data && Object.keys(data.components).length > 0

  const services: ServiceStatus[] = hasComponents
    ? Object.entries(data.components).map(([key, comp]) => ({
        name: componentLabel(key),
        description: comp.message || componentDescription(key),
        status: normalizeStatus(comp.status),
        latency_ms: comp.latency_ms > 0 ? Math.round(comp.latency_ms / 1_000_000) : undefined,
        uptime: '—',
        last_check: formatLastChecked(comp.last_checked),
      }))
    : STATIC_FALLBACK

  const summary = {
    healthy: services.filter(s => s.status === 'healthy').length,
    degraded: services.filter(s => s.status === 'degraded').length,
    down: services.filter(s => s.status === 'down').length,
  }

  const usingFallback = !hasComponents
  const lastRefreshed = dataUpdatedAt
    ? new Date(dataUpdatedAt).toLocaleTimeString()
    : isError
      ? `Offline since ${new Date().toLocaleTimeString()}`
      : 'connecting…'

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold">System Health</h1>
          <p className="text-sm text-muted-foreground mt-0.5">Service status — live checks every 30s</p>
        </div>
        <div className="flex items-center gap-2 text-xs text-muted-foreground">
          {usingFallback && (
            <span className="text-[10px] font-medium px-2 py-0.5 rounded-none bg-zinc-100 text-zinc-600 dark:bg-zinc-800 dark:text-zinc-400">Simulated data</span>
          )}
          <Clock className="h-3.5 w-3.5" />
          {isLoading ? 'loading…' : lastRefreshed}
        </div>
      </div>

      {isError && (
        <div className="rounded-none border border-yellow-200 dark:border-yellow-800 bg-yellow-50 dark:bg-yellow-950/20 px-4 py-3 text-sm text-yellow-800 dark:text-yellow-300">
          <p className="font-medium">Backend offline</p>
          <p className="mt-0.5 text-xs">Cannot reach /health. Showing static fallback data. Start the backend with <code className="font-mono">make dev</code>.</p>
        </div>
      )}

      {data && !hasComponents && (
        <div className="rounded-none border border-zinc-200 dark:border-zinc-700 bg-zinc-50 dark:bg-zinc-900/20 px-4 py-3 text-sm text-zinc-600 dark:text-zinc-400">
          <p className="font-medium">No live component data</p>
          <p className="mt-0.5 text-xs">Backend returned no components (memory provider). Showing static reference data.</p>
        </div>
      )}

      {!isLoading && (summary.degraded > 0 || summary.down > 0) && (
        <div className="rounded-none border border-yellow-200 dark:border-yellow-800 bg-yellow-50 dark:bg-yellow-950/20 px-4 py-3 text-sm text-yellow-800 dark:text-yellow-300">
          <p className="font-medium">Action required</p>
          <ul className="mt-1 list-disc pl-4 text-xs space-y-0.5">
            {services.filter(s => s.status !== 'healthy').map(s => (
              <li key={s.name}><strong>{s.name}</strong> — {s.status}. Last seen {s.last_check}.</li>
            ))}
          </ul>
        </div>
      )}

      {/* Summary bar */}
      <div className="flex gap-3">
        <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-none bg-green-50 dark:bg-green-950/20 text-green-700 dark:text-green-300 text-xs font-medium">
          <CheckCircle2 className="h-3.5 w-3.5" />{summary.healthy} healthy
        </div>
        <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-none bg-yellow-50 dark:bg-yellow-950/20 text-yellow-700 dark:text-yellow-300 text-xs font-medium">
          <AlertTriangle className="h-3.5 w-3.5" />{summary.degraded} degraded
        </div>
        <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-none bg-red-600 text-white dark:bg-red-700 dark:text-white text-xs font-medium">
          <XCircle className="h-3.5 w-3.5" />{summary.down} down
        </div>
      </div>

      {/* Service grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
        {isLoading
          ? Array.from({ length: 6 }, (_, i) => <SkeletonCard key={i} />)
          : services.map(svc => <ServiceCard key={svc.name} svc={svc} isFallback={usingFallback} />)
        }
      </div>
    </div>
  )
}
