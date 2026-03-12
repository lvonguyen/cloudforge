import { useState, useMemo } from 'react'
import { useDebounce } from '@/hooks/useDebounce'
import { useNavigate } from 'react-router-dom'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import {
  Server, Database, Box, HardDrive, Zap, Network, Globe, Layers,
  Mail, Container, BarChart3, Search, CheckCircle2, Clock,
  Shield, Cpu, Activity, GitBranch,
  type LucideIcon,
} from 'lucide-react'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { useCatalog } from '@/hooks/useCatalog'
import { ProviderBadge } from '@/components/ui/ProviderBadge'
import { ProviderIcon } from '@/components/ui/ProviderIcon'
import type { CatalogModule } from '@/types/catalog'

const ICON_MAP: Record<string, LucideIcon> = {
  'server': Server,
  'database': Database,
  'box': Box,
  'hard-drive': HardDrive,
  'zap': Zap,
  'network': Network,
  'globe': Globe,
  'layers': Layers,
  'mail': Mail,
  'container': Container,
  'bar-chart-3': BarChart3,
  'shield': Shield,
  'cpu': Cpu,
  'activity': Activity,
  'git-branch': GitBranch,
}

const COMPLIANCE_COLORS: Record<string, string> = {
  SOC2: 'bg-indigo-100 text-indigo-700 dark:bg-indigo-900/30 dark:text-indigo-300',
  HIPAA: 'bg-rose-100 text-rose-700 dark:bg-rose-900/30 dark:text-rose-300',
  PCI: 'bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-300',
  FedRAMP: 'bg-sky-100 text-sky-700 dark:bg-sky-900/30 dark:text-sky-300',
}

const PROVIDER_FILTER = ['ALL', 'aws', 'azure', 'gcp'] as const
const CATEGORIES = ['All', 'compute', 'storage', 'database', 'network', 'serverless', 'container', 'messaging', 'analytics', 'security', 'observability', 'ai-ml', 'cicd'] as const

export default function Catalog() {
  const navigate = useNavigate()
  const [providerFilter, setProviderFilter] = useState<string>('ALL')
  const [categoryFilter, setCategoryFilter] = useState<string>('All')
  const [searchTerm, setSearchTerm] = useState('')
  const debouncedSearch = useDebounce(searchTerm, 300)

  const { data: modules = [], isLoading } = useCatalog(
    providerFilter !== 'ALL' ? { provider: providerFilter } : undefined
  )

  const filtered = useMemo(() => {
    let result = modules
    if (categoryFilter !== 'All') {
      result = result.filter(m => m.category === categoryFilter)
    }
    if (debouncedSearch.trim()) {
      const q = debouncedSearch.toLowerCase()
      result = result.filter(m =>
        m.name.toLowerCase().includes(q) ||
        m.description.toLowerCase().includes(q) ||
        m.tags.some(t => t.toLowerCase().includes(q))
      )
    }
    return result
  }, [modules, categoryFilter, debouncedSearch])

  const providerCounts = useMemo(() => {
    const counts: Record<string, number> = { ALL: modules.length }
    for (const m of modules) {
      counts[m.provider] = (counts[m.provider] ?? 0) + 1
    }
    return counts
  }, [modules])

  const categoryCounts = useMemo(() => {
    const counts: Record<string, number> = { All: modules.length }
    for (const m of modules) {
      counts[m.category] = (counts[m.category] ?? 0) + 1
    }
    return counts
  }, [modules])

  function handleRequest(module: CatalogModule) {
    navigate('/portal/request', { state: { preselect: module.id, preselectProvider: module.provider } })
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold">Resource Catalog</h1>
        <p className="text-sm text-muted-foreground mt-0.5">Terraform golden modules — policy-compliant by default</p>
      </div>

      {/* Search */}
      <div className="relative max-w-md">
        <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
        <Input
          placeholder="Search modules..."
          value={searchTerm}
          onChange={e => setSearchTerm(e.target.value)}
          className="pl-9"
        />
      </div>

      {/* CSP provider dropdown */}
      <div className="flex items-center gap-3">
        <Select value={providerFilter} onValueChange={setProviderFilter}>
          <SelectTrigger size="sm" className="w-48">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="ALL">All Providers ({providerCounts.ALL})</SelectItem>
            {(['aws', 'azure', 'gcp'] as const).map(p => (
              <SelectItem key={p} value={p}>
                <ProviderIcon provider={p} className="h-4 w-4" />
                {p.toUpperCase()} ({providerCounts[p] ?? 0})
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      {/* Category tabs */}
      <div className="flex gap-1 flex-wrap">
        {CATEGORIES.map(cat => (
          <button
            key={cat}
            onClick={() => setCategoryFilter(cat)}
            className={`px-3 py-1 text-xs rounded-none font-medium transition-colors capitalize ${
              categoryFilter === cat ? 'bg-foreground text-background' : 'bg-muted text-muted-foreground hover:bg-muted/80'
            }`}
          >
            {cat} {categoryCounts[cat] != null ? `(${categoryCounts[cat]})` : '(0)'}
          </button>
        ))}
      </div>

      {/* Module cards */}
      {isLoading ? (
        <div className="text-sm text-muted-foreground py-8 text-center">Loading catalog...</div>
      ) : filtered.length === 0 ? (
        <div className="text-sm text-muted-foreground py-8 text-center">No modules match your filters.</div>
      ) : (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
          {filtered.map(module => {
            const Icon = ICON_MAP[module.icon] ?? Server
            return (
              <Card key={module.id} className="hover:shadow-sm transition-shadow">
                <CardHeader className="pb-2">
                  <div className="flex items-start justify-between gap-2">
                    <div className="flex items-center gap-2">
                      <div className="h-8 w-8 rounded-none bg-muted flex items-center justify-center shrink-0">
                        <Icon className="h-4 w-4 text-muted-foreground" />
                      </div>
                      <div>
                        <CardTitle className="text-sm leading-snug">{module.name}</CardTitle>
                        <p className="text-[10px] text-muted-foreground font-mono">{module.version}</p>
                      </div>
                    </div>
                    <ProviderBadge provider={module.provider} className="shrink-0" />
                  </div>
                </CardHeader>
                <CardContent className="space-y-3">
                  <p className="text-xs text-muted-foreground leading-relaxed">{module.description}</p>

                  <div className="flex flex-wrap gap-1">
                    {module.tags.map(tag => (
                      <span key={tag} className="text-[10px] bg-muted rounded px-1.5 py-0.5 font-mono">{tag}</span>
                    ))}
                  </div>

                  {/* Compliance badges */}
                  <div className="flex flex-wrap gap-1">
                    {module.compliance_tags.map(tag => (
                      <Badge key={tag} variant="secondary" className={`text-[9px] px-1.5 py-0 ${COMPLIANCE_COLORS[tag] ?? ''}`}>
                        {tag}
                      </Badge>
                    ))}
                    {module.auto_approved && (
                      <Badge variant="secondary" className="text-[9px] px-1.5 py-0 bg-emerald-100 text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-300">
                        <CheckCircle2 className="h-2.5 w-2.5 mr-0.5" />
                        Auto-approved
                      </Badge>
                    )}
                  </div>

                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <span className="text-xs text-muted-foreground">{module.cost_estimate}</span>
                      <span className="text-[10px] text-muted-foreground flex items-center gap-0.5">
                        <Clock className="h-3 w-3" />{module.provisioning_time}
                      </span>
                    </div>
                    <Button size="sm" className="text-xs h-7" onClick={() => handleRequest(module)}>
                      Request
                    </Button>
                  </div>
                </CardContent>
              </Card>
            )
          })}
        </div>
      )}
    </div>
  )
}
