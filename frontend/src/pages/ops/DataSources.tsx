import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Cloud, Box, Settings, CheckCircle2 } from 'lucide-react'
import type { LucideIcon } from 'lucide-react'

interface Adapter {
  id: string
  name: string
  description: string
  icon: LucideIcon
  iconColor: string
  iconBg: string
  formats: string[]
  status: 'active' | 'available' | 'coming_soon'
  sampleFindings: number
}

const ADAPTERS: Adapter[] = [
  {
    id: 'prowler',
    name: 'Prowler',
    description: 'AWS, Azure, GCP security posture assessment. Supports CIS benchmarks, NIST, PCI-DSS, HIPAA, and custom checks.',
    icon: Cloud,
    iconColor: 'text-orange-600 dark:text-orange-400',
    iconBg: 'bg-orange-50 dark:bg-orange-950/20',
    formats: ['JSON', 'CSV', 'OCSF'],
    status: 'active',
    sampleFindings: 2340,
  },
  {
    id: 'trivy',
    name: 'Trivy',
    description: 'Container image and filesystem vulnerability scanner. Detects OS packages, language-specific packages, and IaC misconfigurations.',
    icon: Box,
    iconColor: 'text-cyan-600 dark:text-cyan-400',
    iconBg: 'bg-cyan-50 dark:bg-cyan-950/20',
    formats: ['JSON', 'SARIF', 'CycloneDX'],
    status: 'active',
    sampleFindings: 856,
  },
  {
    id: 'aws-config',
    name: 'AWS Config',
    description: 'AWS resource configuration recording and compliance evaluation. Monitors configuration changes and evaluates against rules.',
    icon: Settings,
    iconColor: 'text-amber-600 dark:text-amber-400',
    iconBg: 'bg-amber-50 dark:bg-amber-950/20',
    formats: ['JSON', 'Config Rules'],
    status: 'available',
    sampleFindings: 1120,
  },
]

const STATUS_CONFIG: Record<string, { label: string; color: string }> = {
  active: { label: 'Active', color: 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300' },
  available: { label: 'Available', color: 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-300' },
  coming_soon: { label: 'Coming Soon', color: 'bg-gray-100 text-gray-700 dark:bg-gray-900/30 dark:text-gray-300' },
}

export default function DataSources() {
  return (
    <div className="space-y-6 max-w-4xl">
      <div>
        <h1 className="text-xl font-semibold">Data Sources</h1>
        <p className="text-sm text-muted-foreground mt-0.5">
          Ingestion adapters for normalizing security findings from third-party scanners
        </p>
      </div>

      {/* Summary */}
      <div className="grid grid-cols-3 gap-3">
        <div className="border border-border p-3">
          <p className="text-[10px] text-muted-foreground uppercase tracking-wide">Adapters</p>
          <p className="text-lg font-semibold mt-0.5">{ADAPTERS.length}</p>
        </div>
        <div className="border border-border p-3">
          <p className="text-[10px] text-muted-foreground uppercase tracking-wide">Active</p>
          <p className="text-lg font-semibold mt-0.5 text-green-600 dark:text-green-400">
            {ADAPTERS.filter(a => a.status === 'active').length}
          </p>
        </div>
        <div className="border border-border p-3">
          <p className="text-[10px] text-muted-foreground uppercase tracking-wide">Total Findings Ingested</p>
          <p className="text-lg font-semibold mt-0.5">
            {ADAPTERS.reduce((s, a) => s + a.sampleFindings, 0).toLocaleString()}
          </p>
        </div>
      </div>

      {/* Adapter cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {ADAPTERS.map(adapter => {
          const Icon = adapter.icon
          const statusCfg = STATUS_CONFIG[adapter.status]
          return (
            <Card key={adapter.id}>
              <CardHeader className="pb-2">
                <div className="flex items-start justify-between">
                  <div className="flex items-center gap-2">
                    <div className={`p-2 rounded ${adapter.iconBg}`}>
                      <Icon className={`h-4 w-4 ${adapter.iconColor}`} />
                    </div>
                    <CardTitle className="text-sm">{adapter.name}</CardTitle>
                  </div>
                  <span className={`text-[10px] font-medium px-2 py-0.5 ${statusCfg.color}`}>
                    {statusCfg.label}
                  </span>
                </div>
              </CardHeader>
              <CardContent className="space-y-3">
                <p className="text-xs text-muted-foreground leading-relaxed">{adapter.description}</p>
                <div>
                  <p className="text-[10px] text-muted-foreground uppercase tracking-wide mb-1">Supported Formats</p>
                  <div className="flex flex-wrap gap-1">
                    {adapter.formats.map(fmt => (
                      <Badge key={fmt} variant="outline" className="text-[10px]">{fmt}</Badge>
                    ))}
                  </div>
                </div>
                <div className="flex items-center justify-between pt-2 border-t border-border">
                  <div>
                    <p className="text-[10px] text-muted-foreground">Findings ingested</p>
                    <p className="text-sm font-semibold tabular-nums">{adapter.sampleFindings.toLocaleString()}</p>
                  </div>
                  {adapter.status === 'active' && (
                    <div className="flex items-center gap-1 text-[10px] text-green-600 dark:text-green-400">
                      <CheckCircle2 className="h-3 w-3" />Connected
                    </div>
                  )}
                </div>
              </CardContent>
            </Card>
          )
        })}
      </div>

      <div className="text-xs text-muted-foreground border border-border px-3 py-2">
        File upload and adapter selection for <code className="font-mono">POST /api/v1/findings/ingest</code> will be added in a future sprint.
      </div>
    </div>
  )
}
