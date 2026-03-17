import { useState, useMemo } from 'react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from '@/components/ui/table'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Database, AppWindow, Filter, Search, X } from 'lucide-react'
import appCatalogData from '@/lib/mock/app-catalog.json'

// Lazy-load existing DataClassification page content
import { lazy, Suspense } from 'react'
const DataClassification = lazy(() => import('@/pages/ops/DataClassification'))

interface AppEntry {
  id: string
  name: string
  owner: string
  lob: string
  criticality: string
  type: string
  sla_hours: number
  description: string
  data_classification: string
  users_count: number
  csp_hosting: string
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

export default function AppCatalog() {
  const apps = appCatalogData as AppEntry[]
  const [search, setSearch] = useState('')
  const [category, setCategory] = useState('All')

  const filtered = useMemo(() => {
    let result = apps
    if (category !== 'All') result = result.filter(a => categoryFilter(a, category))
    if (search) {
      const q = search.toLowerCase()
      result = result.filter(a =>
        a.name.toLowerCase().includes(q) ||
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
                className="w-full pl-7 pr-7 py-1.5 text-xs bg-muted/50 border border-border outline-none"
              />
              {search && (
                <button onClick={() => setSearch('')} className="absolute right-2 top-1/2 -translate-y-1/2">
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
                      <TableRow key={app.id}>
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
                        <TableCell className="text-xs text-muted-foreground">{app.csp_hosting}</TableCell>
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
    </div>
  )
}
