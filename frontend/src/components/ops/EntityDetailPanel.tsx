import { useState, useMemo } from 'react'
import { Link } from 'react-router-dom'
import { ChevronDown, ChevronRight, X, ExternalLink, Sparkles, Loader2 } from 'lucide-react'
import { useCommandCenter } from '@/contexts/CommandCenterContext'
import { Badge } from '@/components/ui/badge'
import { SEVERITY_COLORS } from '@/lib/severity'
import { useEnrichFinding } from '@/hooks/useFindings'
import type { Finding } from '@/types/compliance'
import type { AttackPath } from '@/types/attack-path'
import type { RemediationRecord } from '@/types/remediation'
import {
  formatDate,
  formatDateTime,
  formatWorkflowStatus,
  getFindingSlaState,
} from '@/components/ops/finding-detail/helpers'
import { buildFindingTimeline } from '@/components/ops/finding-detail/timeline'

// ---------------------------------------------------------------------------
// Props
// ---------------------------------------------------------------------------

interface EntityDetailPanelProps {
  attackPaths: AttackPath[]
  remediations: RemediationRecord[]
}

// ---------------------------------------------------------------------------
// Collapsible section
// ---------------------------------------------------------------------------

function Section({
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
    <div className="border-t border-[#1e2330]">
      <button
        onClick={() => setOpen(!open)}
        className="flex w-full items-center gap-1.5 py-2 px-4 text-left hover:bg-[#161b22]/40 transition-colors"
      >
        <Icon className="h-3 w-3 shrink-0 text-gray-500" />
        <span className="text-[10px] font-semibold uppercase tracking-widest text-gray-500 flex-1">
          {label}
        </span>
        {count !== undefined && (
          <span className="text-[10px] font-mono text-gray-600">{count}</span>
        )}
      </button>
      {open && <div className="px-4 pb-3 space-y-1">{children}</div>}
    </div>
  )
}

function KV({ label, value, mono }: { label: string; value: React.ReactNode; mono?: boolean }) {
  return (
    <div className="flex items-baseline justify-between gap-2 text-xs">
      <span className="text-gray-500 shrink-0">{label}</span>
      <span className={`text-gray-200 text-right truncate ${mono ? 'font-mono text-[11px]' : ''}`}>
        {value}
      </span>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Finding detail
// ---------------------------------------------------------------------------

function FindingDetail({
  finding,
  attackPaths,
  remediations,
}: {
  finding: Finding
  attackPaths: AttackPath[]
  remediations: RemediationRecord[]
}) {
  const relatedPaths = useMemo(
    () => attackPaths.filter(p => p.finding_ids.includes(finding.id)),
    [attackPaths, finding.id],
  )
  const remediation = useMemo(
    () => remediations.find(r => r.finding_id === finding.id),
    [remediations, finding.id],
  )
  const slaState = useMemo(() => getFindingSlaState(finding), [finding])
  const timeline = useMemo(
    () => buildFindingTimeline(finding, { relatedPaths }),
    [finding, relatedPaths],
  )
  const primaryPath = relatedPaths[0]
  const mappedControls = useMemo(
    () => finding.compliance_mappings?.map(mapping => `${mapping.framework_name} ${mapping.control_id}`).slice(0, 4) ?? [],
    [finding.compliance_mappings],
  )

  const scoreColor =
    finding.ai_risk_score >= 9 ? 'text-red-400' :
    finding.ai_risk_score >= 7 ? 'text-orange-400' :
    finding.ai_risk_score >= 4 ? 'text-yellow-400' :
    'text-blue-400'

  return (
    <>
      {/* Overview */}
      <Section label="Overview">
        <KV label="Status" value={formatWorkflowStatus(finding.workflow_status)} />
        <KV label="CSP" value={finding.cloud_provider.toUpperCase()} />
        <KV label="Account" value={finding.account_id} mono />
        <KV label="Region" value={finding.region} mono />
        <KV label="Resource" value={finding.resource_name} mono />
        <KV label="Type" value={finding.category} />
        <KV label="First Seen" value={new Date(finding.first_found_at).toLocaleDateString()} />
        <KV label="Due" value={formatDate(finding.due_date)} />
        <KV label="SLA" value={slaState.label} />
        <KV label="Owner" value={finding.assignee?.user_name ?? 'Unassigned'} />
        <KV
          label="Risk Score"
          value={<span className={scoreColor}>{finding.ai_risk_score.toFixed(1)}</span>}
        />
        {finding.epss !== undefined && (
          <KV label="EPSS" value={finding.epss.toFixed(3)} mono />
        )}
        {finding.exploit_available && (
          <KV label="KEV" value={<span className="text-red-400">Yes</span>} />
        )}
      </Section>

      {/* AI Enrichment */}
      {finding.ai_risk_rationale ? (
        <Section label="AI Enrichment" defaultOpen>
          <div className="flex items-center gap-1 mb-1">
            <Sparkles className="h-3 w-3 text-violet-400" />
            <span className="text-[10px] font-semibold text-violet-400 uppercase tracking-wide">
              AI Analysis
            </span>
          </div>
          <p className="text-xs text-gray-400 leading-relaxed">{finding.ai_risk_rationale}</p>
          {finding.ai_contextual_factors?.length > 0 && (
            <div className="flex flex-wrap gap-1 mt-2">
              {finding.ai_contextual_factors.map(f => (
                <span key={f} className="text-[9px] font-mono bg-[#161b22] text-gray-400 px-1.5 py-0.5">
                  {f}
                </span>
              ))}
            </div>
          )}
        </Section>
      ) : (
        <Section label="AI Enrichment" defaultOpen>
          <EnrichButton findingId={finding.id} />
        </Section>
      )}

      {/* Toxic Combinations */}
      {finding.toxic_combo_details && (
        <Section label="Toxic Combinations" count={1}>
          <div className="text-xs text-gray-400 space-y-1">
            <KV label="Type" value={finding.toxic_combo_details.combo_type} />
            <p className="text-gray-500 text-[11px] leading-relaxed">
              {finding.toxic_combo_details.description}
            </p>
            <KV label="Blast Radius" value={finding.toxic_combo_details.blast_radius} />
            <KV label="Exploit Potential" value={finding.toxic_combo_details.exploit_potential} />
          </div>
        </Section>
      )}

      {/* Attack Paths */}
      {relatedPaths.length > 0 && (
        <Section label="Attack Paths" count={relatedPaths.length} defaultOpen={false}>
          {primaryPath && (
            <div className="mb-2 rounded border border-[#1e2330] bg-[#111318] px-2 py-2">
              <div className="flex items-center gap-2 text-[10px] uppercase tracking-wide text-gray-500">
                <span>Primary chain</span>
                <span className="text-gray-700">/</span>
                <span>{primaryPath.hop_count} hops</span>
                <span className="text-gray-700">/</span>
                <span>{primaryPath.score.toFixed(0)} score</span>
              </div>
              <p className="mt-1 text-xs text-gray-300">{primaryPath.entry_point.resource_name} -> {primaryPath.target.resource_name}</p>
            </div>
          )}
          {relatedPaths.map(p => (
            <Link
              key={p.id}
              to={`/ops/attack-paths`}
              className="flex items-center gap-2 text-xs text-gray-400 hover:text-gray-200 py-0.5 transition-colors"
            >
              <span className="font-mono text-[10px]">{p.id.slice(0, 8)}</span>
              <span className="flex-1 truncate">{p.title}</span>
              <Badge variant="outline" className={`text-[9px] px-1 py-0 ${SEVERITY_COLORS[p.severity] ?? ''}`}>
                {p.severity}
              </Badge>
            </Link>
          ))}
        </Section>
      )}

      <Section label="Security Graph" defaultOpen={false}>
        <KV label="Workflow" value={formatWorkflowStatus(finding.workflow_status)} />
        <KV label="SLA Detail" value={slaState.detail} />
        <KV label="Latest Seen" value={formatDateTime(finding.last_seen_at)} />
        <KV label="Mapped Controls" value={finding.compliance_mappings?.length ?? 0} />
        <KV label="MITRE" value={finding.mitre_techniques?.length ?? 0} />
        {mappedControls.length > 0 && (
          <div className="flex flex-wrap gap-1 pt-2">
            {mappedControls.map(control => (
              <span key={control} className="text-[9px] font-mono bg-[#161b22] text-gray-400 px-1.5 py-0.5">
                {control}
              </span>
            ))}
          </div>
        )}
      </Section>

      <Section label="Signals" defaultOpen={false}>
        <KV label="Attack Paths" value={relatedPaths.length > 0 ? `${relatedPaths.length} linked` : 'None'} />
        <KV label="Remediation" value={remediation ? formatWorkflowStatus(remediation.status) : 'Not started'} />
        <KV label="Handler" value={remediation?.handler ?? (finding.auto_remediatable ? 'Auto available' : 'Manual')} mono={Boolean(remediation?.handler)} />
        <KV label="Workflow" value={formatWorkflowStatus(finding.workflow_status)} />
      </Section>

      {/* Remediation */}
      <Section label="Remediation" defaultOpen={remediation !== undefined}>
        {remediation ? (
          <>
            <KV label="Handler" value={remediation.handler} mono />
            <KV label="Tier" value={remediation.tier} />
            <KV label="Status" value={remediation.status.replace(/_/g, ' ')} />
            <Link
              to={`/ops/remediation/${remediation.id}`}
              className="flex items-center gap-1 text-[10px] text-amber-500 hover:text-amber-400 mt-1 transition-colors"
            >
              View details <ExternalLink className="h-2.5 w-2.5" />
            </Link>
          </>
        ) : (
          <div className="text-xs text-gray-600">
            {finding.auto_remediatable ? 'Auto-remediatable — no action taken' : 'Manual remediation required'}
          </div>
        )}
      </Section>

      {/* Compliance */}
      {finding.compliance_mappings && finding.compliance_mappings.length > 0 && (
        <Section label="Compliance" count={finding.compliance_mappings.length} defaultOpen={false}>
          {finding.compliance_mappings.slice(0, 6).map(m => (
            <div key={`${m.framework_id}-${m.control_id}`} className="space-y-1 rounded border border-[#1e2330] bg-[#111318] px-2 py-2">
              <div className="flex items-center gap-2 text-xs">
                <span className="text-red-500">✕</span>
                <span className="text-gray-300">{m.framework_name}</span>
                <span className="font-mono text-[10px] text-gray-500">{m.control_id}</span>
                <span className="ml-auto text-[10px] uppercase tracking-wide text-gray-500">{m.severity}</span>
              </div>
              <p className="text-[11px] text-gray-400 leading-relaxed">{m.control_title}</p>
            </div>
          ))}
          {finding.compliance_mappings.length > 6 && (
            <div className="text-[10px] text-gray-600 mt-1">
              +{finding.compliance_mappings.length - 6} more
            </div>
          )}
        </Section>
      )}

      {/* Timeline */}
      <Section label="Timeline" defaultOpen={false}>
        <div className="space-y-1.5">
          {timeline.slice(0, 5).map((event) => (
            <TimelineEntry key={event.id} date={event.time} label={event.label} filled={event.id !== 'sla-due'} />
          ))}
          {timeline.length === 0 && <TimelineEntry label="Pending resolution" filled={false} />}
        </div>
      </Section>
    </>
  )
}

function TimelineEntry({ date, label, filled }: { date?: string; label: string; filled: boolean }) {
      return (
        <div className="flex items-center gap-2 text-xs">
          <span className={`h-2 w-2 shrink-0 border ${filled ? 'bg-gray-400 border-gray-400' : 'border-gray-600 bg-transparent'}`} />
      {date && <span className="text-[10px] font-mono text-gray-600 shrink-0">{formatDateTime(date)}</span>}
          <span className="text-gray-400">{label}</span>
        </div>
      )
}

// ---------------------------------------------------------------------------
// Attack Path detail
// ---------------------------------------------------------------------------

function AttackPathDetail({ path }: { path: AttackPath }) {
  const scoreColor =
    path.severity === 'CRITICAL' ? 'text-red-400' :
    path.severity === 'HIGH' ? 'text-orange-400' :
    'text-yellow-400'

  return (
    <>
      <Section label="Overview">
        <KV label="Score" value={<span className={scoreColor}>{path.score.toFixed(0)}</span>} />
        <KV label="Hops" value={path.hop_count} />
        <KV label="Entry" value={path.entry_point.resource_name} mono />
        <KV label="Target" value={path.target.resource_name} mono />
        <KV label="Findings" value={path.finding_ids.length} />
      </Section>

      {path.ai_enriched && path.ai_description && (
        <Section label="AI Analysis">
          <div className="flex items-center gap-1 mb-1">
            <Sparkles className="h-3 w-3 text-violet-400" />
            <span className="text-[10px] font-semibold text-violet-400 uppercase tracking-wide">AI</span>
          </div>
          <p className="text-xs text-gray-400 leading-relaxed">{path.ai_description}</p>
          {path.ai_likelihood && (
            <KV label="Likelihood" value={path.ai_likelihood.toUpperCase()} />
          )}
        </Section>
      )}

      {path.mitre_tactics.length > 0 && (
        <Section label="MITRE ATT&CK" count={path.mitre_tactics.length} defaultOpen={false}>
          <div className="flex flex-wrap gap-1">
            {path.mitre_tactics.map(t => (
              <span key={t} className="text-[9px] font-mono bg-[#161b22] text-gray-400 px-1.5 py-0.5">
                {t}
              </span>
            ))}
          </div>
        </Section>
      )}

      {/* Node chain */}
      <Section label="Resource Chain" count={path.nodes.length} defaultOpen={false}>
        {path.nodes.map(n => (
          <div key={n.id} className="flex items-center gap-2 text-xs py-0.5">
            <span className={`h-1.5 w-1.5 shrink-0 ${
              n.severity === 'CRITICAL' ? 'bg-red-400' :
              n.severity === 'HIGH' ? 'bg-orange-400' :
              n.severity === 'MEDIUM' ? 'bg-yellow-500' : 'bg-blue-400'
            }`} />
            <span className="text-gray-400 truncate flex-1">{n.resource_name}</span>
            <span className="text-[10px] font-mono text-gray-600">{n.region}</span>
          </div>
        ))}
      </Section>

      {/* Finding references */}
      <Section label="Findings" count={path.finding_ids.length} defaultOpen={false}>
        <div className="flex flex-wrap gap-1">
          {path.finding_ids.map(fid => (
            <Link
              key={fid}
              to={`/ops/findings/${fid}`}
              className="text-[10px] font-mono bg-[#161b22] text-gray-400 px-1.5 py-0.5 hover:text-gray-200 transition-colors"
            >
              {fid}
            </Link>
          ))}
        </div>
      </Section>
    </>
  )
}

// ---------------------------------------------------------------------------
// Enrich button — triggers AI enrichment via Bedrock
// ---------------------------------------------------------------------------

function EnrichButton({ findingId }: { findingId: string }) {
  const enrichMutation = useEnrichFinding()

  return (
    <button
      onClick={() => enrichMutation.mutate(findingId)}
      disabled={enrichMutation.isPending}
      className="flex items-center gap-1.5 text-[10px] font-medium text-violet-400 hover:text-violet-300 bg-violet-500/10 border border-violet-500/20 px-2.5 py-1 transition-colors disabled:opacity-50"
    >
      {enrichMutation.isPending ? (
        <Loader2 className="h-3 w-3 animate-spin" />
      ) : (
        <Sparkles className="h-3 w-3" />
      )}
      {enrichMutation.isPending ? 'Enriching…' : 'Enrich with AI'}
    </button>
  )
}

// ---------------------------------------------------------------------------
// Main component
// ---------------------------------------------------------------------------

export function EntityDetailPanel({ attackPaths, remediations }: EntityDetailPanelProps) {
  const { state, dispatch } = useCommandCenter()
  const { selectedEntity } = state

  if (!selectedEntity) return null

  const severityClass =
    selectedEntity.type === 'finding'
      ? SEVERITY_COLORS[selectedEntity.data.severity] ?? ''
      : selectedEntity.type === 'attack-path'
        ? SEVERITY_COLORS[selectedEntity.data.severity] ?? ''
        : ''

  const title =
    selectedEntity.type === 'finding'
      ? selectedEntity.data.id
      : selectedEntity.data.title

  const subtitle =
    selectedEntity.type === 'finding'
      ? selectedEntity.data.title
      : selectedEntity.data.description

  return (
    <div className="flex flex-col h-full bg-[#0a0a0f] text-gray-300">
      {/* Header */}
      <div className="flex items-start gap-2 px-4 py-3 border-b border-[#1e2330]">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1">
            <Badge variant="outline" className={`text-[9px] px-1.5 py-0 ${severityClass}`}>
              {selectedEntity.type === 'finding'
                ? selectedEntity.data.severity
                : selectedEntity.data.severity}
            </Badge>
            <span className="text-[10px] text-gray-500 uppercase">
              {selectedEntity.type === 'finding'
                ? selectedEntity.data.cloud_provider.toUpperCase()
                : `${selectedEntity.data.hop_count} hops`}
            </span>
          </div>
          <div className="text-xs font-mono font-medium text-gray-200 truncate">{title}</div>
          <div className="text-[11px] text-gray-500 mt-0.5 line-clamp-2">{subtitle}</div>
        </div>
        <button
          onClick={() => dispatch({ type: 'SELECT_ENTITY', payload: null })}
          className="shrink-0 p-1 text-gray-500 hover:text-gray-300 transition-colors"
          aria-label="Close detail panel"
        >
          <X className="h-3.5 w-3.5" />
        </button>
      </div>

      {/* Scrollable sections */}
      <div className="flex-1 overflow-y-auto">
        {selectedEntity.type === 'finding' && (
          <FindingDetail
            finding={selectedEntity.data}
            attackPaths={attackPaths}
            remediations={remediations}
          />
        )}
        {selectedEntity.type === 'attack-path' && (
          <AttackPathDetail path={selectedEntity.data} />
        )}
      </div>

      {/* Footer action */}
      <div className="px-4 py-2 border-t border-[#1e2330]">
        <Link
          to={
            selectedEntity.type === 'finding'
              ? `/ops/findings/${selectedEntity.data.id}`
              : '/ops/attack-paths'
          }
          className="flex items-center justify-center gap-1 text-[10px] text-amber-500 hover:text-amber-400 font-medium uppercase tracking-wide transition-colors"
        >
          Open full view <ExternalLink className="h-2.5 w-2.5" />
        </Link>
      </div>
    </div>
  )
}
