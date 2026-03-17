import { useState, useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Card, CardContent, CardHeader } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { ChevronDown, ChevronRight, Box, Server, Shield, AlertTriangle } from 'lucide-react'
import { apiClient, ApiError } from '@/lib/api'
import { ProviderBadge } from '@/components/ui/ProviderBadge'

interface ContainerVuln {
  cve_id: string
  severity: string
  package: string
  version: string
  fixed_in?: string
  cvss: number
}

interface Container {
  id: string
  name: string
  image: string
  registry: string
  status: string
  vuln_count: number
  vulns?: ContainerVuln[]
}

interface Pod {
  id: string
  name: string
  namespace: string
  status: string
  containers: Container[]
}

interface Namespace {
  name: string
  pods: Pod[]
}

interface Cluster {
  name: string
  provider: string
  region: string
  namespaces: Namespace[]
}

interface TopologyResponse {
  clusters: Cluster[]
}

const EMPTY_TOPOLOGY: TopologyResponse = { clusters: [] }

async function fetchContainers(): Promise<TopologyResponse> {
  try {
    return await apiClient.get<TopologyResponse>('/containers')
  } catch (err) {
    if (err instanceof ApiError && err.status < 500) throw err
    if (import.meta.env.PROD) throw err
    return EMPTY_TOPOLOGY
  }
}

function useContainers() {
  return useQuery({
    queryKey: ['containers'],
    queryFn: fetchContainers,
  })
}

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300',
  HIGH: 'bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-300',
  MEDIUM: 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-300',
  LOW: 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-300',
}

function VulnCountBadge({ count }: { count: number }) {
  if (count === 0) return <Badge variant="outline" className="text-[10px] px-1.5 py-0 rounded-none bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300">Clean</Badge>
  const color = count >= 5 ? 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300' :
    count >= 2 ? 'bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-300' :
    'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-300'
  return <Badge variant="outline" className={`text-[10px] px-1.5 py-0 rounded-none ${color}`}>{count} vuln{count !== 1 ? 's' : ''}</Badge>
}

export default function Containers() {
  const { data, isLoading, isError } = useContainers()
  const [expandedClusters, setExpandedClusters] = useState<Set<string>>(new Set())
  const [expandedPods, setExpandedPods] = useState<Set<string>>(new Set())
  const [expandedContainers, setExpandedContainers] = useState<Set<string>>(new Set())

  const clusters = data?.clusters ?? []

  const stats = useMemo(() => {
    let totalPods = 0, totalContainers = 0, totalVulns = 0, criticalVulns = 0
    for (const c of clusters) {
      for (const ns of c.namespaces) {
        totalPods += ns.pods.length
        for (const p of ns.pods) {
          totalContainers += p.containers.length
          for (const ct of p.containers) {
            totalVulns += ct.vuln_count
            criticalVulns += (ct.vulns ?? []).filter(v => v.severity === 'CRITICAL').length
          }
        }
      }
    }
    return { clusters: clusters.length, pods: totalPods, containers: totalContainers, vulns: totalVulns, critical: criticalVulns }
  }, [clusters])

  function toggleSet(set: Set<string>, key: string): Set<string> {
    const next = new Set(set)
    if (next.has(key)) next.delete(key); else next.add(key)
    return next
  }

  if (isLoading) return <div className="text-sm text-muted-foreground p-6">Scanning container topology...</div>
  if (isError) return <div className="text-sm text-destructive p-6">Failed to load container data.</div>

  return (
    <div className="space-y-6 max-w-5xl">
      <div>
        <h1 className="text-xl font-semibold">Container Security</h1>
        <p className="text-sm text-muted-foreground mt-0.5">
          {stats.clusters} clusters · {stats.pods} pods · {stats.containers} containers
        </p>
      </div>

      {/* Stats bar */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        {[
          { label: 'Clusters', value: stats.clusters },
          { label: 'Pods', value: stats.pods },
          { label: 'Containers', value: stats.containers },
          { label: 'Vulnerabilities', value: stats.vulns },
          { label: 'Critical CVEs', value: stats.critical },
        ].map(({ label, value }) => (
          <div key={label} className="border border-border p-3">
            <p className="text-[10px] text-muted-foreground uppercase tracking-wide">{label}</p>
            <p className={`text-lg font-semibold mt-0.5 ${label === 'Critical CVEs' && value > 0 ? 'text-red-600 dark:text-red-400' : ''}`}>{value}</p>
          </div>
        ))}
      </div>

      {/* Cluster tree */}
      <div className="space-y-2">
        {clusters.map(cluster => {
          const clusterExpanded = expandedClusters.has(cluster.name)
          return (
            <Card key={cluster.name} className="rounded-none">
              <button
                className="w-full flex items-center gap-2 p-3 text-left hover:bg-muted/30 transition-colors"
                onClick={() => setExpandedClusters(s => toggleSet(s, cluster.name))}
              >
                {clusterExpanded ? <ChevronDown className="h-3.5 w-3.5 shrink-0" /> : <ChevronRight className="h-3.5 w-3.5 shrink-0" />}
                <Server className="h-4 w-4 text-muted-foreground shrink-0" />
                <span className="text-sm font-semibold flex-1">{cluster.name}</span>
                <ProviderBadge provider={cluster.provider} />
                <span className="text-[10px] text-muted-foreground">{cluster.region}</span>
              </button>
              {clusterExpanded && (
                <CardContent className="pt-0 pb-3 px-3">
                  {cluster.namespaces.map(ns => (
                    <div key={ns.name} className="ml-6 border-l border-border pl-3 mt-2">
                      <p className="text-[10px] font-semibold uppercase tracking-wide text-muted-foreground mb-1">{ns.name}</p>
                      {ns.pods.map(pod => {
                        const podExpanded = expandedPods.has(pod.id)
                        const podVulns = pod.containers.reduce((sum, c) => sum + c.vuln_count, 0)
                        return (
                          <div key={pod.id} className="mb-1">
                            <button
                              className="w-full flex items-center gap-2 py-1.5 px-2 text-left hover:bg-muted/20 transition-colors text-xs"
                              onClick={() => setExpandedPods(s => toggleSet(s, pod.id))}
                            >
                              {podExpanded ? <ChevronDown className="h-3 w-3 shrink-0" /> : <ChevronRight className="h-3 w-3 shrink-0" />}
                              <Box className="h-3.5 w-3.5 text-muted-foreground shrink-0" />
                              <span className="font-medium flex-1">{pod.name}</span>
                              <span className="text-[10px] text-muted-foreground">{pod.containers.length} container{pod.containers.length !== 1 ? 's' : ''}</span>
                              <VulnCountBadge count={podVulns} />
                            </button>
                            {podExpanded && (
                              <div className="ml-8 space-y-1 mt-1">
                                {pod.containers.map(container => {
                                  const ctExpanded = expandedContainers.has(container.id)
                                  return (
                                    <div key={container.id}>
                                      <button
                                        className="w-full flex items-center gap-2 py-1 px-2 text-left hover:bg-muted/20 transition-colors text-xs"
                                        onClick={() => setExpandedContainers(s => toggleSet(s, container.id))}
                                      >
                                        {container.vuln_count > 0
                                          ? (ctExpanded ? <ChevronDown className="h-3 w-3 shrink-0" /> : <ChevronRight className="h-3 w-3 shrink-0" />)
                                          : <Shield className="h-3 w-3 text-green-500 shrink-0" />
                                        }
                                        <span className="font-mono text-[11px] flex-1 truncate">{container.image}</span>
                                        <span className="text-[10px] text-muted-foreground">{container.registry}</span>
                                        <VulnCountBadge count={container.vuln_count} />
                                      </button>
                                      {ctExpanded && container.vulns && container.vulns.length > 0 && (
                                        <div className="ml-6 mt-1 space-y-1 mb-2">
                                          {container.vulns.map(v => (
                                            <div key={v.cve_id} className="flex items-center gap-2 text-[11px] px-2 py-1 bg-muted/30">
                                              <Badge variant="outline" className={`text-[9px] px-1 py-0 rounded-none ${SEVERITY_COLORS[v.severity] ?? ''}`}>
                                                {v.severity}
                                              </Badge>
                                              <code className="font-mono text-red-600 dark:text-red-400">{v.cve_id}</code>
                                              <span className="text-muted-foreground">{v.package} {v.version}</span>
                                              {v.fixed_in && <span className="text-green-600 dark:text-green-400">Fix: {v.fixed_in}</span>}
                                              <span className="ml-auto font-mono">CVSS {v.cvss.toFixed(1)}</span>
                                            </div>
                                          ))}
                                        </div>
                                      )}
                                    </div>
                                  )
                                })}
                              </div>
                            )}
                          </div>
                        )
                      })}
                    </div>
                  ))}
                </CardContent>
              )}
            </Card>
          )
        })}
      </div>

      {clusters.length === 0 && (
        <div className="text-center py-12 text-muted-foreground">
          <AlertTriangle className="h-8 w-8 mx-auto mb-2 opacity-40" />
          <p className="text-sm">No container clusters detected.</p>
        </div>
      )}
    </div>
  )
}
