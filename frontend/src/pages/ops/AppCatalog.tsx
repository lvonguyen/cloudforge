import { useState, useMemo, lazy, Suspense } from 'react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from '@/components/ui/table'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Sheet, SheetContent, SheetHeader, SheetTitle, SheetDescription } from '@/components/ui/sheet'
import { Database, AppWindow, Filter, Search, X } from 'lucide-react'
import { ProviderBadge } from '@/components/ui/ProviderBadge'
import appCatalogData from '@/lib/mock/app-catalog.json'

const DataClassification = lazy(() => import('@/pages/ops/DataClassification'))

interface AppEntry {
  id: string
  name: string
  vendor: string
  owner: string
  lob: string
  criticality: string
  type: string
  sla_hours: number
  description: string
  data_classification: string
  users_count: number
  csp_hosting: string
  environments: string[]
  tech_contact: string
  business_contact: string
  dependencies: string[]
  compliance_frameworks: string[]
  rto_hours: number
  rpo_hours: number
  last_pentest: string
  lifecycle_status: string
}

const CRITICALITY_COLORS: Record<string, string> = {
  P1: 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300',
  P2: 'bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-300',
  P3: 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-300',
  P4: 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-300',
}

const TYPE_COLORS: Record<string, string> = {
  saas: 'bg-violet-100 text-violet-700 dark:bg-violet-900/30 dark:text-violet-300',
  cots: 'bg-cyan-100 text-cyan-700 dark:bg-cyan-900/30 dark:text-cyan-300',
  custom: 'bg-emerald-100 text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-300',
  internal: 'bg-zinc-100 text-zinc-700 dark:bg-zinc-900/30 dark:text-zinc-300',
}

const CATEGORIES = ['All', 'Internal Infra', 'Shared Services', 'LOB Apps', 'SaaS', 'COTS', 'Custom'] as const

function categoryFilter(app: AppEntry, category: string): boolean {
  if (category === 'All') return true
  if (category === 'Internal Infra') return app.type === 'internal' && app.lob === 'Infrastructure'
  if (category === 'Shared Services') return app.type === 'internal' && app.lob !== 'Infrastructure'
  if (category === 'LOB Apps') return app.lob !== 'Infrastructure' && app.lob !== 'IT' && (app.type === 'custom' || app.type === 'internal')
  return app.type === category.toLowerCase()
}

const LIFECYCLE_COLORS: Record<string, string> = {
  active: 'bg-emerald-100 text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-300',
  deprecated: 'bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-300',
  sunset: 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300',
}

function formatDate(iso: string): string {
  try {
    return new Date(iso).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' })
  } catch {
    return iso
  }
}

function formatHours(h: number): string {
  if (h < 1) return `${Math.round(h * 60)}min`
  return `${h}h`
}

export default function AppCatalog() {
  const apps = appCatalogData as AppEntry[]
  const [search, setSearch] = useState('')
  const [category, setCategory] = useState('All')
  const [selectedApp, setSelectedApp] = useState<AppEntry | null>(null)

  const appNameMap = useMemo(() => {
    const map = new Map<string, string>()
    for (const a of apps) map.set(a.id, a.name)
    return map
  }, [apps])

  const filtered = useMemo(() => {
    let result = apps
    if (category !== 'All') result = result.filter(a => categoryFilter(a, category))
    if (search) {
      const q = search.toLowerCase()
      result = result.filter(a =>
        a.name.toLowerCase().includes(q) ||
        a.vendor.toLowerCase().includes(q) ||
        a.owner.toLowerCase().includes(q) ||
        a.lob.toLowerCase().includes(q)
      )
    }
    return result
  }, [apps, search, category])

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold">Application Catalog</h1>
        <p className="text-sm text-muted-foreground mt-0.5">Registered applications and data classification</p>
      </div>

      <Tabs defaultValue="applications">
        <TabsList className="bg-transparent border-b border-border rounded-none p-0 w-full justify-start">
          <TabsTrigger value="applications" className="gap-1.5 rounded-none border-b-2 border-transparent data-[state=active]:border-primary data-[state=active]:bg-transparent text-xs">
            <AppWindow className="h-3.5 w-3.5" />Applications
          </TabsTrigger>
          <TabsTrigger value="data-classification" className="gap-1.5 rounded-none border-b-2 border-transparent data-[state=active]:border-primary data-[state=active]:bg-transparent text-xs">
            <Database className="h-3.5 w-3.5" />Data Classification
          </TabsTrigger>
        </TabsList>

        <TabsContent value="applications" className="space-y-4 mt-4">
          {/* Filters */}
          <div className="flex items-center gap-3 flex-wrap">
            <div className="relative flex-1 max-w-xs">
              <Search className="absolute left-2 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
              <input
                type="text"
                value={search}
                onChange={e => setSearch(e.target.value)}
                placeholder="Search applications..."
                aria-label="Search applications"
                className="w-full pl-7 pr-7 py-1.5 text-xs bg-muted/50 border border-border outline-none"
              />
              {search && (
                <button onClick={() => setSearch('')} aria-label="Clear search" className="absolute right-2 top-1/2 -translate-y-1/2">
                  <X className="h-3 w-3 text-muted-foreground" />
                </button>
              )}
            </div>
            <div className="flex items-center gap-1">
              <Filter className="h-3.5 w-3.5 text-muted-foreground" />
              {CATEGORIES.map(cat => (
                <button
                  key={cat}
                  onClick={() => setCategory(cat)}
                  className={`text-[10px] px-2 py-1 transition-colors ${
                    category === cat
                      ? 'bg-primary text-primary-foreground'
                      : 'bg-muted/50 text-muted-foreground hover:bg-muted'
                  }`}
                >
                  {cat}
                </button>
              ))}
            </div>
          </div>

          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium">{filtered.length} application{filtered.length !== 1 ? 's' : ''}</CardTitle>
            </CardHeader>
            <CardContent className="p-0">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="text-xs pl-4">Name</TableHead>
                    <TableHead className="text-xs">Owner</TableHead>
                    <TableHead className="text-xs">LoB</TableHead>
                    <TableHead className="text-xs">Criticality</TableHead>
                    <TableHead className="text-xs">Type</TableHead>
                    <TableHead className="text-xs">SLA</TableHead>
                    <TableHead className="text-xs">Classification</TableHead>
                    <TableHead className="text-xs">Hosting</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {filtered.length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={8} className="text-center text-xs text-muted-foreground py-8">
                        No applications match this filter.
                      </TableCell>
                    </TableRow>
                  ) : (
                    filtered.map(app => (
                      <TableRow key={app.id} className="cursor-pointer hover:bg-muted/30" onClick={() => setSelectedApp(app)}>
                        <TableCell className="pl-4">
                          <div>
                            <p className="text-xs font-medium">{app.name}</p>
                            <p className="text-[10px] text-muted-foreground truncate max-w-[200px]">{app.description}</p>
                          </div>
                        </TableCell>
                        <TableCell className="text-xs">{app.owner}</TableCell>
                        <TableCell className="text-xs text-muted-foreground">{app.lob}</TableCell>
                        <TableCell>
                          <Badge variant="outline" className={`text-[10px] ${CRITICALITY_COLORS[app.criticality] ?? ''}`}>
                            {app.criticality}
                          </Badge>
                        </TableCell>
                        <TableCell>
                          <Badge variant="outline" className={`text-[10px] ${TYPE_COLORS[app.type] ?? ''}`}>
                            {app.type.toUpperCase()}
                          </Badge>
                        </TableCell>
                        <TableCell className="text-xs tabular-nums">{app.sla_hours}h</TableCell>
                        <TableCell>
                          <Badge variant="outline" className="text-[10px]">{app.data_classification}</Badge>
                        </TableCell>
                        <TableCell>{['AWS', 'Azure', 'GCP'].includes(app.csp_hosting) ? <ProviderBadge provider={app.csp_hosting.toLowerCase()} /> : <span className="text-xs text-muted-foreground">{app.csp_hosting}</span>}</TableCell>
                      </TableRow>
                    ))
                  )}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="data-classification" className="mt-4">
          <Suspense fallback={<div className="text-xs text-muted-foreground p-4">Loading data classification...</div>}>
            <DataClassification />
          </Suspense>
        </TabsContent>
      </Tabs>

      {/* CMDB Detail Drawer */}
      <Sheet open={!!selectedApp} onOpenChange={open => { if (!open) setSelectedApp(null) }}>
        <SheetContent side="right" className="overflow-y-auto">
          {selectedApp && (
            <>
              <SheetHeader>
                <SheetTitle className="text-sm">{selectedApp.name}</SheetTitle>
                <SheetDescription className="flex items-center gap-2 text-[10px]">
                  <span className="text-muted-foreground">{selectedApp.vendor}</span>
                  <Badge variant="outline" className={`text-[9px] ${TYPE_COLORS[selectedApp.type] ?? ''}`}>{selectedApp.type.toUpperCase()}</Badge>
                  <Badge variant="outline" className={`text-[9px] ${CRITICALITY_COLORS[selectedApp.criticality] ?? ''}`}>{selectedApp.criticality}</Badge>
                  <Badge variant="outline" className={`text-[9px] ${LIFECYCLE_COLORS[selectedApp.lifecycle_status] ?? ''}`}>{selectedApp.lifecycle_status.toUpperCase()}</Badge>
                </SheetDescription>
              </SheetHeader>

              <div className="px-4 pb-6 space-y-5">
                {/* Overview */}
                <section>
                  <p className="text-[10px] uppercase tracking-wide text-muted-foreground mb-2">Overview</p>
                  <div className="grid grid-cols-2 gap-3">
                    <div>
                      <p className="text-[10px] text-muted-foreground">Description</p>
                      <p className="text-xs">{selectedApp.description}</p>
                    </div>
                    <div className="space-y-2">
                      <div>
                        <p className="text-[10px] text-muted-foreground">Owner</p>
                        <p className="text-xs font-medium">{selectedApp.owner}</p>
                      </div>
                      <div>
                        <p className="text-[10px] text-muted-foreground">LoB</p>
                        <p className="text-xs">{selectedApp.lob}</p>
                      </div>
                      <div>
                        <p className="text-[10px] text-muted-foreground">Users</p>
                        <p className="text-xs tabular-nums">{selectedApp.users_count.toLocaleString()}</p>
                      </div>
                    </div>
                  </div>
                  <div className="grid grid-cols-2 gap-3 mt-2">
                    <div>
                      <p className="text-[10px] text-muted-foreground">Classification</p>
                      <Badge variant="outline" className="text-[10px]">{selectedApp.data_classification}</Badge>
                    </div>
                    <div>
                      <p className="text-[10px] text-muted-foreground">Hosting</p>
                      {['AWS', 'Azure', 'GCP'].includes(selectedApp.csp_hosting)
                        ? <ProviderBadge provider={selectedApp.csp_hosting.toLowerCase()} />
                        : <span className="text-xs">{selectedApp.csp_hosting}</span>
                      }
                    </div>
                  </div>
                </section>

                {/* Contacts */}
                <section>
                  <p className="text-[10px] uppercase tracking-wide text-muted-foreground mb-2">Contacts</p>
                  <div className="grid grid-cols-2 gap-3">
                    <div>
                      <p className="text-[10px] text-muted-foreground">Technical</p>
                      <p className="text-xs font-mono">{selectedApp.tech_contact}</p>
                    </div>
                    <div>
                      <p className="text-[10px] text-muted-foreground">Business</p>
                      <p className="text-xs font-mono">{selectedApp.business_contact}</p>
                    </div>
                  </div>
                </section>

                {/* Environments */}
                <section>
                  <p className="text-[10px] uppercase tracking-wide text-muted-foreground mb-2">Environments</p>
                  <div className="flex gap-1.5">
                    {selectedApp.environments.map(env => (
                      <Badge key={env} variant="outline" className="text-[10px]">{env}</Badge>
                    ))}
                  </div>
                </section>

                {/* SLA & Recovery */}
                <section>
                  <p className="text-[10px] uppercase tracking-wide text-muted-foreground mb-2">SLA & Recovery</p>
                  <div className="grid grid-cols-3 gap-3">
                    <div className="bg-muted/30 border border-border p-2">
                      <p className="text-[10px] text-muted-foreground">SLA</p>
                      <p className="text-sm font-semibold tabular-nums">{formatHours(selectedApp.sla_hours)}</p>
                    </div>
                    <div className="bg-muted/30 border border-border p-2">
                      <p className="text-[10px] text-muted-foreground">RTO</p>
                      <p className="text-sm font-semibold tabular-nums">{formatHours(selectedApp.rto_hours)}</p>
                    </div>
                    <div className="bg-muted/30 border border-border p-2">
                      <p className="text-[10px] text-muted-foreground">RPO</p>
                      <p className="text-sm font-semibold tabular-nums">{formatHours(selectedApp.rpo_hours)}</p>
                    </div>
                  </div>
                </section>

                {/* Compliance */}
                {selectedApp.compliance_frameworks.length > 0 && (
                  <section>
                    <p className="text-[10px] uppercase tracking-wide text-muted-foreground mb-2">Compliance</p>
                    <div className="flex gap-1.5 flex-wrap">
                      {selectedApp.compliance_frameworks.map(fw => (
                        <Badge key={fw} variant="outline" className="text-[10px]">{fw}</Badge>
                      ))}
                    </div>
                  </section>
                )}

                {/* Dependencies */}
                {selectedApp.dependencies.length > 0 && (
                  <section>
                    <p className="text-[10px] uppercase tracking-wide text-muted-foreground mb-2">Dependencies</p>
                    <div className="space-y-1">
                      {selectedApp.dependencies.map(depId => (
                        <p key={depId} className="text-xs text-muted-foreground">
                          <span className="mr-1">&rarr;</span>
                          <span className="font-medium text-foreground">{appNameMap.get(depId) ?? depId}</span>
                        </p>
                      ))}
                    </div>
                  </section>
                )}

                {/* Security */}
                <section>
                  <p className="text-[10px] uppercase tracking-wide text-muted-foreground mb-2">Security</p>
                  <div className="grid grid-cols-2 gap-3">
                    <div>
                      <p className="text-[10px] text-muted-foreground">Last Pentest</p>
                      <p className="text-xs">{formatDate(selectedApp.last_pentest)}</p>
                    </div>
                    <div>
                      <p className="text-[10px] text-muted-foreground">Lifecycle</p>
                      <Badge variant="outline" className={`text-[10px] ${LIFECYCLE_COLORS[selectedApp.lifecycle_status] ?? ''}`}>
                        {selectedApp.lifecycle_status.toUpperCase()}
                      </Badge>
                    </div>
                  </div>
                </section>
              </div>
            </>
          )}
        </SheetContent>
      </Sheet>
    </div>
  )
}
