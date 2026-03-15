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

const FILTER_GROUPS = ['severity', 'provider', 'environment'] as const

/** Filter findings applying all groups EXCEPT excludeGroup (for faceted counts). */
function facetedFilter(findings: Finding[], layers: Record<string, boolean>, excludeGroup: string): Finding[] {
  return findings.filter(f =>
    FILTER_GROUPS.every(g => g === excludeGroup || matchesGroup(f, layers, g)),
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

        {/* Threat Intel — read-only */}
        <LayerGroup label="Threat Intel" defaultOpen={false}>
          <InfoRow label="CISA KEV matches" value={findings.filter(f => f.exploit_available).length} />
          <InfoRow label="EPSS > 0.5" value={findings.filter(f => f.epss !== undefined && f.epss > 0.5).length} />
          <InfoRow label="ATT&CK mapped" value={attackPaths.filter(p => p.mitre_tactics.length > 0).length} />
        </LayerGroup>
      </div>
    </div>
  )
}
