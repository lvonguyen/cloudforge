import { useState, useMemo, useCallback } from 'react'
import { ChevronDown, ChevronRight } from 'lucide-react'
import {
  useCommandCenter,
  parseLayerKey,
  layerKey,
} from '@/contexts/CommandCenterContext'
import type { Finding } from '@/types/compliance'
import type { AttackPath } from '@/types/attack-path'

// ---------------------------------------------------------------------------
// Props
// ---------------------------------------------------------------------------

interface DataLayersPanelProps {
  findings: Finding[]
  attackPaths: AttackPath[]
}

// ---------------------------------------------------------------------------
// Faceted counting helpers
// ---------------------------------------------------------------------------

/** Which values are enabled for a given layer group? */
function enabledValues(layers: Record<string, boolean>, group: string): Set<string> {
  const result = new Set<string>()
  for (const [key, on] of Object.entries(layers)) {
    if (!on) continue
    const parsed = parseLayerKey(key)
    if (parsed.group === group) result.add(parsed.value)
  }
  return result
}

/** Does a finding pass the filter for a single layer group? */
function matchesGroup(f: Finding, layers: Record<string, boolean>, group: string): boolean {
  const vals = enabledValues(layers, group)
  if (vals.size === 0) return true // no filter = pass all
  switch (group) {
    case 'severity':    return vals.has(f.severity)
    case 'provider':    return vals.has(f.cloud_provider)
    case 'environment': return vals.has(f.environment_type)
    default:            return true
  }
}

const FILTER_GROUPS = ['severity', 'provider', 'environment', 'compliance', 'workflow', 'time', 'risk'] as const

/** Does a finding pass the filter for a single layer group? */
function matchesGroupExtended(f: Finding, layers: Record<string, boolean>, group: string): boolean {
  const vals = enabledValues(layers, group)
  if (vals.size === 0) return true
  switch (group) {
    case 'compliance':
      return f.compliance_mappings?.some(m => vals.has(m.framework_id)) ?? false
    case 'workflow':
      return vals.has(f.workflow_status)
    case 'time': {
      const ageMs = Date.now() - new Date(f.first_found_at).getTime()
      const ageHours = ageMs / 3_600_000
      if (vals.has('1h') && ageHours <= 1) return true
      if (vals.has('4h') && ageHours <= 4) return true
      if (vals.has('24h') && ageHours <= 24) return true
      if (vals.has('7d') && ageHours <= 168) return true
      if (vals.has('30d') && ageHours <= 720) return true
      return false
    }
    case 'risk': {
      if (vals.has('critical') && f.ai_risk_score >= 8) return true
      if (vals.has('high') && f.ai_risk_score >= 6 && f.ai_risk_score < 8) return true
      if (vals.has('medium') && f.ai_risk_score >= 4 && f.ai_risk_score < 6) return true
      if (vals.has('low') && f.ai_risk_score < 4) return true
      return false
    }
    default:
      return matchesGroup(f, layers, group)
  }
}

/** Filter findings applying all groups EXCEPT excludeGroup (for faceted counts). */
function facetedFilter(findings: Finding[], layers: Record<string, boolean>, excludeGroup: string): Finding[] {
  return findings.filter(f =>
    FILTER_GROUPS.every(g => g === excludeGroup || matchesGroupExtended(f, layers, g)),
  )
}

function countBy<T>(items: T[], keyFn: (item: T) => string): Record<string, number> {
  const result: Record<string, number> = {}
  for (const item of items) {
    const key = keyFn(item)
    result[key] = (result[key] ?? 0) + 1
  }
  return result
}

// ---------------------------------------------------------------------------
// Sub-components
// ---------------------------------------------------------------------------

function LayerGroup({
  label,
  defaultOpen = true,
  count,
  children,
}: {
  label: string
  defaultOpen?: boolean
  count?: number
  children: React.ReactNode
}) {
  const [open, setOpen] = useState(defaultOpen)
  const Icon = open ? ChevronDown : ChevronRight

  return (
    <div>
      <button
        onClick={() => setOpen(!open)}
        className="flex w-full items-center gap-1.5 py-1.5 text-left hover:bg-[#161b22]/50 px-3 -mx-3 transition-colors"
      >
        <Icon className="h-3 w-3 shrink-0 text-gray-500" />
        <span className="text-[10px] font-semibold uppercase tracking-widest text-gray-500 flex-1">
          {label}
        </span>
        {count !== undefined && (
          <span className="text-[10px] font-mono text-gray-600 tabular-nums">{count}</span>
        )}
      </button>
      {open && <div className="ml-4 space-y-px pb-1">{children}</div>}
    </div>
  )
}

const SEVERITY_DOT: Record<string, string> = {
  CRITICAL: 'bg-red-400',
  HIGH:     'bg-orange-400',
  MEDIUM:   'bg-yellow-500',
  LOW:      'bg-blue-400',
}

const PROVIDER_DOT: Record<string, string> = {
  aws:   'bg-orange-400',
  azure: 'bg-blue-400',
  gcp:   'bg-green-400',
}

function LayerToggle({
  label,
  count,
  checked,
  onChange,
  dotColor,
}: {
  label: string
  count: number
  checked: boolean
  onChange: () => void
  dotColor?: string
}) {
  return (
    <label className="flex items-center gap-2 py-0.5 px-3 -mx-3 text-xs cursor-pointer hover:bg-[#161b22]/40 transition-colors select-none">
      <input
        type="checkbox"
        checked={checked}
        onChange={onChange}
        className="h-3 w-3 accent-amber-500 shrink-0"
      />
      {dotColor && <span className={`h-1.5 w-1.5 shrink-0 ${dotColor}`} />}
      <span className={`flex-1 truncate ${checked ? 'text-gray-200' : 'text-gray-500'}`}>
        {label}
      </span>
      <span className="text-[10px] font-mono text-gray-600 tabular-nums">
        {count.toLocaleString()}
      </span>
    </label>
  )
}

function InfoRow({ label, value }: { label: string; value: string | number }) {
  return (
    <div className="flex items-center justify-between px-3 -mx-3 py-0.5 text-xs">
      <span className="text-gray-500">{label}</span>
      <span className="font-mono text-gray-400 tabular-nums">{typeof value === 'number' ? value.toLocaleString() : value}</span>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Threat Intel drill-down — per-feed status with counts and EPSS histogram
// ---------------------------------------------------------------------------

const FEED_DOT: Record<string, string> = {
  EPSS: 'bg-violet-400',
  KEV: 'bg-red-400',
  GreyNoise: 'bg-cyan-400',
  HIBP: 'bg-amber-400',
  OTX: 'bg-emerald-400',
  'ATT&CK': 'bg-blue-400',
}

const FEED_STATUS_LABEL: Record<string, string> = {
  active: 'Active',
  'no-data': 'No data',
  'enrichment-only': 'Per-finding',
}

function ThreatIntelDrillDown({ findings, attackPaths }: { findings: Finding[]; attackPaths: AttackPath[] }) {
  const [expanded, setExpanded] = useState<string | null>(null)

  const kevCount = useMemo(() => findings.filter(f => f.exploit_available).length, [findings])
  const epssHigh = useMemo(() => findings.filter(f => f.epss !== undefined && f.epss > 0.5).length, [findings])
  const epssMed = useMemo(() => findings.filter(f => f.epss !== undefined && f.epss > 0.1 && f.epss <= 0.5).length, [findings])
  const epssLow = useMemo(() => findings.filter(f => f.epss !== undefined && f.epss > 0 && f.epss <= 0.1).length, [findings])
  const attackMapped = useMemo(() => attackPaths.filter(p => p.mitre_tactics.length > 0).length, [attackPaths])
  const uniqueTactics = useMemo(() => new Set(attackPaths.flatMap(p => p.mitre_tactics)).size, [attackPaths])

  const feeds = useMemo(() => [
    { id: 'EPSS', label: 'EPSS Scores', count: epssHigh + epssMed + epssLow, status: epssHigh + epssMed + epssLow > 0 ? 'active' : 'no-data' },
    { id: 'KEV', label: 'CISA KEV', count: kevCount, status: kevCount > 0 ? 'active' : 'no-data' },
    { id: 'GreyNoise', label: 'GreyNoise', count: null, status: 'enrichment-only' },
    { id: 'HIBP', label: 'HIBP', count: null, status: 'enrichment-only' },
    { id: 'OTX', label: 'AlienVault OTX', count: null, status: 'enrichment-only' },
    { id: 'ATT&CK', label: 'MITRE ATT&CK', count: attackMapped, status: attackMapped > 0 ? 'active' : 'no-data' },
  ], [epssHigh, epssMed, epssLow, kevCount, attackMapped])

  return (
    <div className="space-y-px">
      {feeds.map(feed => (
        <div key={feed.id}>
          <button
            onClick={() => setExpanded(expanded === feed.id ? null : feed.id)}
            className="flex items-center gap-2 w-full py-0.5 px-3 -mx-3 text-xs hover:bg-[#161b22]/40 transition-colors cursor-pointer"
          >
            <span className={`h-1.5 w-1.5 shrink-0 ${FEED_DOT[feed.id] ?? 'bg-gray-400'}`} />
            <span className={`flex-1 truncate ${feed.status === 'active' ? 'text-gray-200' : 'text-gray-500'}`}>
              {feed.label}
            </span>
            <span className="text-[10px] font-mono text-gray-600 tabular-nums">
              {feed.count != null ? feed.count.toLocaleString() : FEED_STATUS_LABEL[feed.status]}
            </span>
          </button>
          {expanded === feed.id && (
            <div className="ml-6 py-1 space-y-0.5 text-[10px] text-gray-500">
              {feed.id === 'EPSS' && (
                <>
                  <InfoRow label="High (>0.5)" value={epssHigh} />
                  <InfoRow label="Medium (0.1-0.5)" value={epssMed} />
                  <InfoRow label="Low (<0.1)" value={epssLow} />
                </>
              )}
              {feed.id === 'KEV' && (
                <>
                  <InfoRow label="Actively exploited" value={kevCount} />
                  <InfoRow label="% of findings" value={findings.length > 0 ? `${((kevCount / findings.length) * 100).toFixed(1)}%` : '0%'} />
                </>
              )}
              {feed.id === 'ATT&CK' && (
                <>
                  <InfoRow label="Paths with tactics" value={attackMapped} />
                  <InfoRow label="Unique tactics" value={uniqueTactics} />
                </>
              )}
              {(feed.id === 'GreyNoise' || feed.id === 'HIBP' || feed.id === 'OTX') && (
                <p className="px-3 -mx-3 italic">Available per-finding via AI enrichment</p>
              )}
            </div>
          )}
        </div>
      ))}
    </div>
  )
}

// ---------------------------------------------------------------------------
// Main component
// ---------------------------------------------------------------------------

export function DataLayersPanel({ findings, attackPaths }: DataLayersPanelProps) {
  const { state, dispatch } = useCommandCenter()
  const { activeLayers } = state

  const toggle = useCallback(
    (group: string, value: string) => {
      const key = layerKey(group, value)
      dispatch({ type: 'TOGGLE_LAYER', payload: { layerId: key, enabled: !activeLayers[key] } })
    },
    [dispatch, activeLayers],
  )

  // Faceted counts — memoized over 20K findings
  const severityCounts = useMemo(
    () => countBy(facetedFilter(findings, activeLayers, 'severity'), f => f.severity),
    [findings, activeLayers],
  )
  const providerCounts = useMemo(
    () => countBy(facetedFilter(findings, activeLayers, 'provider'), f => f.cloud_provider),
    [findings, activeLayers],
  )
  const envCounts = useMemo(
    () => countBy(facetedFilter(findings, activeLayers, 'environment'), f => f.environment_type),
    [findings, activeLayers],
  )
  const complianceCounts = useMemo(() => {
    const base = facetedFilter(findings, activeLayers, 'compliance')
    const counts: Record<string, number> = {}
    for (const fw of ['nist-csf', 'pci-dss', 'soc2', 'hipaa', 'iso-27001', 'cis']) {
      counts[fw] = base.filter(f => f.compliance_mappings?.some(m => m.framework_id === fw)).length
    }
    return counts
  }, [findings, activeLayers])
  const workflowCounts = useMemo(
    () => countBy(facetedFilter(findings, activeLayers, 'workflow'), f => f.workflow_status),
    [findings, activeLayers],
  )

  // Read-only aggregate counts
  const toxicComboCount = useMemo(
    () => findings.filter(f => f.toxic_combo_details).length,
    [findings],
  )
  const activeFilterCount = useMemo(
    () => Object.values(activeLayers).filter(Boolean).length,
    [activeLayers],
  )

  return (
    <div className="flex flex-col h-full bg-[#0a0a0f] text-gray-300">
      {/* Header */}
      <div className="px-3 py-2.5 border-b border-[#1e2330]">
        <div className="text-[10px] font-semibold uppercase tracking-widest text-gray-500">
          Data Layers
        </div>
        <div className="text-[10px] text-gray-600 mt-0.5">
          {activeFilterCount} active filters
        </div>
      </div>

      {/* Scrollable layer groups */}
      <div className="flex-1 overflow-y-auto px-3 py-2 space-y-1">
        {/* Severity */}
        <LayerGroup label="Findings" count={findings.length}>
          {(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const).map(sev => (
            <LayerToggle
              key={sev}
              label={sev[0] + sev.slice(1).toLowerCase()}
              count={severityCounts[sev] ?? 0}
              checked={!!activeLayers[layerKey('severity', sev)]}
              onChange={() => toggle('severity', sev)}
              dotColor={SEVERITY_DOT[sev]}
            />
          ))}
        </LayerGroup>

        {/* Cloud Providers */}
        <LayerGroup label="Providers">
          {(['aws', 'azure', 'gcp'] as const).map(p => (
            <LayerToggle
              key={p}
              label={p.toUpperCase()}
              count={providerCounts[p] ?? 0}
              checked={!!activeLayers[layerKey('provider', p)]}
              onChange={() => toggle('provider', p)}
              dotColor={PROVIDER_DOT[p]}
            />
          ))}
        </LayerGroup>

        {/* Environments */}
        <LayerGroup label="Environments">
          {(['production', 'staging', 'development', 'sandbox'] as const).map(env => (
            <LayerToggle
              key={env}
              label={env[0].toUpperCase() + env.slice(1)}
              count={envCounts[env] ?? 0}
              checked={!!activeLayers[layerKey('environment', env)]}
              onChange={() => toggle('environment', env)}
            />
          ))}
        </LayerGroup>

        {/* Compliance — memoized base set to avoid N*6 iteration */}
        <LayerGroup label="Compliance" defaultOpen={false}>
          {(['nist-csf', 'pci-dss', 'soc2', 'hipaa', 'iso-27001', 'cis'] as const).map(fw => (
            <LayerToggle
              key={fw}
              label={fw.toUpperCase()}
              count={complianceCounts[fw] ?? 0}
              checked={!!activeLayers[layerKey('compliance', fw)]}
              onChange={() => toggle('compliance', fw)}
            />
          ))}
        </LayerGroup>

        {/* Workflow Status — memoized base set */}
        <LayerGroup label="Workflow" defaultOpen={false}>
          {(['new', 'triaged', 'assigned', 'in_progress'] as const).map(ws => (
            <LayerToggle
              key={ws}
              label={ws.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase())}
              count={workflowCounts[ws] ?? 0}
              checked={!!activeLayers[layerKey('workflow', ws)]}
              onChange={() => toggle('workflow', ws)}
            />
          ))}
        </LayerGroup>

        {/* Time Presets */}
        <LayerGroup label="Time Window" defaultOpen={false}>
          {([['1h', 'Last Hour'], ['4h', 'Last 4 Hours'], ['24h', 'Last 24 Hours'], ['7d', 'Last 7 Days'], ['30d', 'Last 30 Days']] as const).map(([key, label]) => {
            const count = facetedFilter(findings, activeLayers, 'time').filter(f => {
              const ageMs = Date.now() - new Date(f.first_found_at).getTime()
              const limits: Record<string, number> = { '1h': 3_600_000, '4h': 14_400_000, '24h': 86_400_000, '7d': 604_800_000, '30d': 2_592_000_000 }
              return ageMs <= (limits[key] ?? Infinity)
            }).length
            return (
              <LayerToggle
                key={key}
                label={label}
                count={count}
                checked={!!activeLayers[layerKey('time', key)]}
                onChange={() => toggle('time', key)}
              />
            )
          })}
        </LayerGroup>

        {/* Risk Score */}
        <LayerGroup label="AI Risk Score" defaultOpen={false}>
          {([['critical', 'Critical (8-10)', 'bg-red-400'], ['high', 'High (6-8)', 'bg-orange-400'], ['medium', 'Medium (4-6)', 'bg-yellow-500'], ['low', 'Low (0-4)', 'bg-blue-400']] as const).map(([key, label, dot]) => {
            const ranges: Record<string, [number, number]> = { critical: [8, 11], high: [6, 8], medium: [4, 6], low: [0, 4] }
            const [lo, hi] = ranges[key] ?? [0, 11]
            const count = facetedFilter(findings, activeLayers, 'risk')
              .filter(f => f.ai_risk_score >= lo && f.ai_risk_score < hi).length
            return (
              <LayerToggle
                key={key}
                label={label}
                count={count}
                checked={!!activeLayers[layerKey('risk', key)]}
                onChange={() => toggle('risk', key)}
                dotColor={dot}
              />
            )
          })}
        </LayerGroup>

        {/* Attack Paths — read-only */}
        <LayerGroup label="Attack Paths" defaultOpen={false} count={attackPaths.length}>
          <InfoRow label="Critical" value={attackPaths.filter(p => p.severity === 'CRITICAL').length} />
          <InfoRow label="High" value={attackPaths.filter(p => p.severity === 'HIGH').length} />
          <InfoRow label="AI Enriched" value={attackPaths.filter(p => p.ai_enriched).length} />
        </LayerGroup>

        {/* Toxic Combinations — read-only */}
        <LayerGroup label="Toxic Combos" defaultOpen={false} count={toxicComboCount}>
          <InfoRow
            label="Unique types"
            value={new Set(
              findings
                .filter(f => f.toxic_combo_details)
                .map(f => f.toxic_combo_details!.combo_type),
            ).size}
          />
        </LayerGroup>

        {/* Threat Intel — drillable feed status */}
        <LayerGroup label="Threat Intel" defaultOpen={false}>
          <ThreatIntelDrillDown findings={findings} attackPaths={attackPaths} />
        </LayerGroup>
      </div>
    </div>
  )
}
