import { useState, useMemo, useCallback, useEffect } from 'react'
import { type Node, type Edge, Position, MarkerType } from '@xyflow/react'
import '@xyflow/react/dist/style.css'
import { BaseGraphView } from '@/components/ops/BaseGraphView'
import { useFindings } from '@/hooks/useFindings'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { Search, X, Shield, Server, Database, Key, Globe, ChevronRight, CalendarClock, UserRound, Route, FileCheck2, Link2, TriangleAlert, Sparkles, TimerReset } from 'lucide-react'
import { SEVERITY_COLORS_BORDERED as SEVERITY_COLORS } from '@/lib/severity'
import { ProviderBadge } from '@/components/ui/ProviderBadge'
import { useTracePanel } from '@/lib/trace-panel-context'
import { buildTraceTimeline } from '@/lib/trace-helpers'
import type { InvestigationEntityType } from '@/types/investigation'
import type { Finding } from '@/types/compliance'

const FINDING_TYPE_ICONS: Record<string, typeof Shield> = {
  network: Globe,
  storage: Database,
  identity: Key,
  compute: Server,
  database: Database,
  container: Server,
  serverless: Server,
}

const EDGE_LABELS: Record<InvestigationEntityType, string> = {
  finding: '',
  assignee: 'assigned to',
  technical_contact: 'owned by',
  resource: 'affects',
  compliance_mapping: 'maps to',
  impacted_resource: 'impacts',
}

const SEVERITY_BORDER_WEIGHT: Record<string, number> = {
  CRITICAL: 3,
  HIGH: 2,
  MEDIUM: 1.5,
  LOW: 1,
}

const ENTITY_COLORS: Record<InvestigationEntityType, { bg: string; border: string; text: string }> = {
  finding:            { bg: '#fff1f2', border: '#dc2626', text: '#991b1b' },
  assignee:           { bg: '#eff6ff', border: '#2563eb', text: '#1d4ed8' },
  technical_contact:  { bg: '#f5f3ff', border: '#7c3aed', text: '#6d28d9' },
  resource:           { bg: '#fffbeb', border: '#d97706', text: '#b45309' },
  compliance_mapping: { bg: '#f0fdf4', border: '#16a34a', text: '#15803d' },
  impacted_resource:  { bg: '#fff7ed', border: '#ea580c', text: '#c2410c' },
}

const ENTITY_META: Record<InvestigationEntityType, { label: string; icon: typeof Shield; summary: string }> = {
  finding: { label: 'Finding', icon: Shield, summary: 'Anchor node. Start here, then validate owner, control coverage, and impact chain.' },
  assignee: { label: 'Assignee', icon: UserRound, summary: 'Operational owner responsible for triage, execution, and SLA adherence.' },
  technical_contact: { label: 'Technical contact', icon: UserRound, summary: 'Domain contact who can confirm implementation details and remediation blast radius.' },
  resource: { label: 'Primary resource', icon: Server, summary: 'Primary asset carrying the finding. Use this to confirm scope and affected surface.' },
  compliance_mapping: { label: 'Control mapping', icon: FileCheck2, summary: 'Mapped policy or framework control that turns technical risk into audit exposure.' },
  impacted_resource: { label: 'Impacted resource', icon: Route, summary: 'Downstream asset touched by the same weakness, dependency, or reachable path.' },
}

const GRAPH_GUIDE: InvestigationEntityType[] = ['finding', 'assignee', 'resource', 'compliance_mapping', 'impacted_resource']

function formatDateLabel(value?: string) {
  if (!value) return 'Not set'
  const parsed = new Date(value)
  if (Number.isNaN(parsed.getTime())) return value
  return parsed.toLocaleDateString(undefined, { month: 'short', day: 'numeric' })
}

function describeFindingPriority(finding: Finding) {
  const factors = [
    finding.assignee ? `Owned by ${finding.assignee.user_name}` : 'Ownership gap',
    `${finding.compliance_mappings?.length ?? 0} control link${finding.compliance_mappings?.length === 1 ? '' : 's'}`,
    `${finding.impacted_resources?.length ?? 0} downstream resource${finding.impacted_resources?.length === 1 ? '' : 's'}`,
  ]
  return factors.join(' · ')
}

function getInvestigationScore(finding: Finding): number {
  const severityScore: Record<string, number> = {
    CRITICAL: 40,
    HIGH: 28,
    MEDIUM: 16,
    LOW: 8,
  }

  return (
    (severityScore[finding.severity] ?? 0) +
    Math.round(finding.ai_risk_score * 5) +
    (finding.toxic_combo_details ? 26 : 0) +
    (finding.exploit_available ? 18 : 0) +
    Math.min(finding.impacted_resources?.length ?? 0, 5) * 3 +
    Math.min(finding.compliance_mappings?.length ?? 0, 4) * 2 +
    (finding.environment_type === 'production' ? 6 : 0)
  )
}

function deriveInvestigationSeverity(finding: Finding): 'CRITICAL' | 'HIGH' {
  return getInvestigationScore(finding) >= 80 ? 'CRITICAL' : 'HIGH'
}

function isInvestigationCandidate(finding: Finding): boolean {
  return (
    finding.severity === 'CRITICAL' ||
    finding.severity === 'HIGH' ||
    finding.toxic_combo_details !== undefined ||
    finding.exploit_available ||
    (finding.impacted_resources?.length ?? 0) > 0
  )
}

function describeNodeImportance(type: InvestigationEntityType, data: Record<string, unknown>) {
  switch (type) {
    case 'finding':
      return 'Use this node to decide whether the rest of the graph is ownership work, control work, or blast-radius work.'
    case 'assignee':
      return data.name === 'Unassigned'
        ? 'This is a triage gap. Assigning ownership is the fastest way to reduce operator drag.'
        : 'This tells you who is on the hook for remediation and whether the current route matches the actual owning team.'
    case 'technical_contact':
      return 'Use the technical contact to validate whether the alert maps to the real service boundary and rollout path.'
    case 'resource':
      return 'This is the primary asset under investigation. Confirm its environment, provider, and exposure before escalating.'
    case 'compliance_mapping':
      return 'This shows which control narrative the finding will roll up into for audit and governance reporting.'
    case 'impacted_resource':
      return 'Use impacted resources to judge whether the issue is isolated or part of a broader service chain.'
    default:
      return ''
  }
}

export default function Investigations() {
  const { data: findings = [], isLoading } = useFindings({ page: 1, perPage: 1000, sort: 'ai_risk', order: 'desc' })
  const [searchParams] = useSearchParams()
  const [selectedFindingId, setSelectedFindingId] = useState<string | null>(() => searchParams.get('findingId'))
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null)
  const [searchQuery, setSearchQuery] = useState('')
  const navigate = useNavigate()
  const { openTimeline } = useTracePanel()

  const investigationCandidates = useMemo(
    () =>
      [...findings]
        .filter(isInvestigationCandidate)
        .sort((a, b) => getInvestigationScore(b) - getInvestigationScore(a)),
    [findings],
  )

  // Auto-select first finding when none is selected and findings are loaded
  useEffect(() => {
    if (!selectedFindingId && investigationCandidates.length > 0) {
      setSelectedFindingId(investigationCandidates[0].id)
    }
  }, [selectedFindingId, investigationCandidates])

  const filteredFindings = useMemo(() => {
    if (!searchQuery) return investigationCandidates.slice(0, 50)
    const q = searchQuery.toLowerCase()
    return investigationCandidates.filter(f =>
      f.title.toLowerCase().includes(q) ||
      f.resource_name.toLowerCase().includes(q) ||
      f.id.toLowerCase().includes(q)
    ).slice(0, 50)
  }, [investigationCandidates, searchQuery])
  const selectedFinding = useMemo(
    () => investigationCandidates.find(f => f.id === selectedFindingId) ?? null,
    [investigationCandidates, selectedFindingId],
  )
  const openGraphQueryTimeline = useCallback(() => {
    if (!selectedFinding) return

    openTimeline(`Graph Query: ${selectedFinding.title}`, buildTraceTimeline([
      {
        id: 'investigation-root',
        name: `agent:investigation-graph:${selectedFinding.id}`,
        type: 'agent',
        durationMs: 140,
        attributes: { finding_id: selectedFinding.id, provider: selectedFinding.cloud_provider },
      },
      {
        parentSpanId: 'investigation-root',
        name: 'retrieval:load-owner-and-resource-context',
        type: 'retrieval',
        durationMs: 120,
        attributes: { assignee: selectedFinding.assignee?.user_name ?? 'unassigned' },
      },
      {
        parentSpanId: 'investigation-root',
        name: 'chain:compose-investigation-graph',
        type: 'chain',
        durationMs: 160,
        attributes: {
          impacted_resources: selectedFinding.impacted_resources?.length ?? 0,
          controls: selectedFinding.compliance_mappings?.length ?? 0,
        },
      },
      {
        parentSpanId: 'investigation-root',
        name: 'policy:highlight-priority-signals',
        type: 'policy',
        durationMs: 80,
        attributes: { exploit_available: selectedFinding.exploit_available },
      },
    ]))
  }, [openTimeline, selectedFinding])
  const analystBrief = useMemo(() => {
    if (!selectedFinding) return null
    const contextualSeverity = deriveInvestigationSeverity(selectedFinding)
    return {
      posture: `Contextual ${contextualSeverity} · ${describeFindingPriority(selectedFinding)}`,
      rationale: selectedFinding.ai_risk_rationale || 'Use the graph to validate owner, control linkage, and downstream blast radius.',
      workflow: selectedFinding.assignee
        ? `Confirm ${selectedFinding.assignee.user_name}'s team owns the path, then validate control and impact coverage.`
        : 'Claim ownership first, then validate control coverage and impacted dependencies before opening the full finding.',
    }
  }, [selectedFinding])

  const { graphNodes, graphEdges } = useMemo(() => {
    const finding = investigationCandidates.find(f => f.id === selectedFindingId)
    if (!finding) return { graphNodes: [], graphEdges: [] }

    const findingId = finding.id
    const contextualSeverity = deriveInvestigationSeverity(finding)
    const nodes: Node[] = []
    const edges: Edge[] = []
    const laneIndex: Record<InvestigationEntityType, number> = {
      finding: 0,
      assignee: 0,
      technical_contact: 0,
      resource: 0,
      compliance_mapping: 0,
      impacted_resource: 0,
    }
    const borderWeight = SEVERITY_BORDER_WEIGHT[finding.severity] ?? 1

    // Finding-type icon
    const TypeIcon = FINDING_TYPE_ICONS[finding.resource_type] ?? Shield

    // Central finding node
    nodes.push({
      id: findingId,
      position: { x: 120, y: 220 },
      sourcePosition: Position.Right,
      targetPosition: Position.Left,
      data: {
        label: (
          <div className="px-3 py-2 min-w-[220px]" style={{ background: '#fff1f2', border: `${borderWeight}px solid #dc2626` }}>
            <div className="flex items-center gap-1.5 mb-0.5">
              <TypeIcon className="h-3 w-3" style={{ color: '#991b1b' }} />
              <span className="text-[10px] text-red-900 font-medium truncate flex-1">{finding.title}</span>
            </div>
            <div className="text-[9px] text-red-800/80">{contextualSeverity} · {finding.category} · {finding.cloud_provider.toUpperCase()}</div>
          </div>
        ),
        entityType: 'finding' as InvestigationEntityType,
          entityData: {
            id: finding.id,
            title: finding.title,
            severity: contextualSeverity,
            category: finding.category,
            cloud_provider: finding.cloud_provider,
            resource_name: finding.resource_name,
            resource_type: finding.resource_type,
            recommendation: finding.remediation?.slice(0, 200),
            status: finding.status,
            workflow_status: finding.workflow_status,
            first_found_at: finding.first_found_at,
            last_seen_at: finding.last_seen_at,
            due_date: finding.due_date,
            impacted_resources_count: finding.impacted_resources?.length ?? 0,
            compliance_count: finding.compliance_mappings?.length ?? 0,
            assignee: finding.assignee?.user_name,
          },
        },
        style: { padding: 0, borderRadius: 0, background: 'transparent', border: 'none' },
    })

    function addEntity(type: InvestigationEntityType, id: string, label: string, sublabel?: string, entityData?: Record<string, unknown>) {
      const slot = laneIndex[type]
      laneIndex[type]++

      const laneConfig: Record<InvestigationEntityType, { x: number; y: number; step: number }> = {
        finding: { x: 120, y: 220, step: 0 },
        assignee: { x: 430, y: 160, step: 120 },
        technical_contact: { x: 430, y: 340, step: 120 },
        resource: { x: 430, y: 40, step: 120 },
        compliance_mapping: { x: 760, y: 40, step: 104 },
        impacted_resource: { x: 760, y: 260, step: 104 },
      }
      const config = laneConfig[type]
      const x = config.x
      const y = config.y + slot * config.step

      const colors = ENTITY_COLORS[type]
      nodes.push({
        id,
        position: { x, y },
        data: {
          label: (
            <div className="px-2 py-1.5 min-w-[150px]" style={{ background: colors.bg, border: `1px solid ${colors.border}` }}>
              <div className="text-[9px] uppercase tracking-wide" style={{ color: colors.text }}>{type.replace('_', ' ')}</div>
              <div className="text-[10px] text-slate-900 font-medium truncate">{label}</div>
              {sublabel && <div className="text-[9px] text-slate-500 truncate">{sublabel}</div>}
            </div>
          ),
          entityType: type,
          entityData: entityData ?? { label, sublabel },
        },
        style: { padding: 0, borderRadius: 0, background: 'transparent', border: 'none' },
      })

      const edgeLabel = EDGE_LABELS[type]
      edges.push({
        id: `${findingId}->${id}`,
        source: findingId,
        target: id,
        label: edgeLabel || undefined,
        animated: true,
        style: { stroke: colors.border, strokeWidth: 2.2 },
        labelStyle: edgeLabel ? { fontSize: 8, fill: '#475569' } : undefined,
        labelBgStyle: edgeLabel ? { fill: '#ffffff', fillOpacity: 0.92 } : undefined,
        labelBgPadding: edgeLabel ? [2, 4] as [number, number] : undefined,
        markerEnd: { type: MarkerType.ArrowClosed, color: colors.border, width: 14, height: 14 },
      })
    }

    // Assignee (or fallback "Unassigned" placeholder)
    if (finding.assignee) {
      addEntity('assignee', `assignee-${finding.assignee.user_id}`, finding.assignee.user_name, finding.assignee.team, {
        name: finding.assignee.user_name, email: finding.assignee.user_email, team: finding.assignee.team,
        assigned_at: finding.assignee.assigned_at, due_date: finding.due_date,
      })
    } else {
      addEntity('assignee', `assignee-unassigned-${findingId}`, 'Unassigned', 'Pending triage', {
        name: 'Unassigned', team: 'N/A', status: 'Awaiting assignment',
      })
    }

    // Technical contact
    if (finding.technical_contact) {
      addEntity('technical_contact', `tc-${finding.technical_contact.email}`, finding.technical_contact.name, finding.technical_contact.team, {
        name: finding.technical_contact.name, email: finding.technical_contact.email, team: finding.technical_contact.team,
      })
    }

    // Primary resource
    addEntity('resource', `res-${finding.resource_id}`, finding.resource_name, finding.resource_type, {
      name: finding.resource_name, type: finding.resource_type, region: finding.region, account_id: finding.account_id, finding_count: 1,
    })

    // Compliance mappings (or inferred fallback)
    if (finding.compliance_mappings && finding.compliance_mappings.length > 0) {
      for (const cm of finding.compliance_mappings.slice(0, 3)) {
        addEntity('compliance_mapping', `comp-${cm.framework_id}-${cm.control_id}`, `${cm.framework_name} ${cm.control_id}`, cm.control_title?.slice(0, 40), {
          framework_name: cm.framework_name, control_id: cm.control_id, control_title: cm.control_title,
          section: cm.section, subsection: cm.subsection, severity: cm.severity, url: cm.url,
        })
      }
    } else {
      // Infer compliance mapping from category
      const catMap: Record<string, { framework: string; control: string; title: string }> = {
        identity: { framework: 'CIS', control: 'CIS 5.1', title: 'Identity & Access Management' },
        network: { framework: 'CIS', control: 'CIS 9.1', title: 'Network Security Configuration' },
        storage: { framework: 'CIS', control: 'CIS 3.1', title: 'Data Protection at Rest' },
        compute: { framework: 'CIS', control: 'CIS 7.1', title: 'Compute Resource Hardening' },
        database: { framework: 'CIS', control: 'CIS 3.4', title: 'Database Security' },
        container: { framework: 'CIS', control: 'CIS 8.1', title: 'Container Security' },
      }
      const inferred = catMap[finding.resource_type] ?? catMap[finding.category] ?? { framework: 'NIST CSF', control: 'PR.IP-1', title: 'Security Baseline' }
      addEntity('compliance_mapping', `comp-inferred-${findingId}`, `${inferred.framework} ${inferred.control}`, inferred.title, {
        framework_name: inferred.framework, control_id: inferred.control, control_title: inferred.title, inferred: true,
      })
    }

    // Impacted resources
    if (finding.impacted_resources && finding.impacted_resources.length > 0) {
      for (const ir of finding.impacted_resources.slice(0, 3)) {
        addEntity('impacted_resource', `ir-${ir.resource_id}`, ir.resource_name, ir.resource_type, {
          name: ir.resource_name, type: ir.resource_type, relationship: ir.relationship, impact_level: ir.impact_level,
        })
      }
    }

    return { graphNodes: nodes, graphEdges: edges }
  }, [investigationCandidates, selectedFindingId])

  const handleNodeClick = useCallback((nodeId: string) => {
    setSelectedNodeId(prev => prev === nodeId ? null : nodeId)
  }, [])

  const selectedNodeData = useMemo(() => {
    if (!selectedNodeId) return null
    const node = graphNodes.find(n => n.id === selectedNodeId)
    if (!node?.data) return null
    return {
      entityType: node.data.entityType as InvestigationEntityType,
      entityData: node.data.entityData as Record<string, unknown>,
    }
  }, [selectedNodeId, graphNodes])
  const selectedNodeMeta = selectedNodeData ? ENTITY_META[selectedNodeData.entityType] : null

  function renderNodeDetail(type: InvestigationEntityType, data: Record<string, unknown>) {
    const field = (label: string, value: unknown) => {
      if (!value) return null
      return (
        <div>
          <p className="text-[10px] uppercase tracking-wide text-muted-foreground">{label}</p>
          <p className="text-xs font-medium">{String(value)}</p>
        </div>
      )
    }

    switch (type) {
      case 'finding':
        return (
          <div className="space-y-2 text-xs">
            <Badge variant="outline" className={`text-[10px] ${SEVERITY_COLORS[String(data.severity)] ?? ''}`}>
              {String(data.severity)}
            </Badge>
            {field('Title', data.title)}
            {field('Category', data.category)}
            {field('Provider', data.cloud_provider)}
            {field('Resource', data.resource_name)}
            {field('Resource Type', data.resource_type)}
            {field('Status', data.status)}
            {field('Workflow', data.workflow_status)}
            {field('Assignee', data.assignee)}
            {field('First Seen', data.first_found_at)}
            {field('Last Seen', data.last_seen_at)}
            {field('Due Date', data.due_date)}
            {field('Impacted Resources', data.impacted_resources_count)}
            {field('Compliance Links', data.compliance_count)}
            {data.recommendation ? (
              <div>
                <p className="text-[10px] uppercase tracking-wide text-muted-foreground">Recommendation</p>
                <p className="text-[10px] leading-relaxed text-muted-foreground bg-muted/30 p-2 border border-border">{String(data.recommendation)}</p>
              </div>
            ) : null}
            <button
              onClick={() => navigate(`/ops/findings/${data.id}`)}
              className="text-[10px] text-blue-400 hover:text-blue-300 underline"
            >
              View Finding →
            </button>
          </div>
        )
      case 'resource':
        return (
          <div className="space-y-2 text-xs">
            {field('Name', data.name)}
            {field('Type', data.type)}
            {field('Region', data.region)}
            {field('Account', data.account_id)}
          </div>
        )
      case 'compliance_mapping':
        return (
          <div className="space-y-2 text-xs">
            {field('Framework', data.framework_name)}
            {field('Control', data.control_id)}
            {field('Title', data.control_title)}
            {field('Section', data.section)}
            {field('Subsection', data.subsection)}
            {data.severity ? <Badge variant="outline" className="text-[10px]">{String(data.severity)}</Badge> : null}
            {data.url ? (
              <a href={String(data.url)} target="_blank" rel="noopener noreferrer" className="text-[10px] text-blue-400 hover:text-blue-300 underline block">
                Reference →
              </a>
            ) : null}
          </div>
        )
      case 'assignee':
        return (
          <div className="space-y-2 text-xs">
            {field('Name', data.name)}
            {field('Email', data.email)}
            {field('Team', data.team)}
            {field('Assigned', data.assigned_at)}
            {field('Due Date', data.due_date)}
          </div>
        )
      case 'technical_contact':
        return (
          <div className="space-y-2 text-xs">
            {field('Name', data.name)}
            {field('Email', data.email)}
            {field('Team', data.team)}
          </div>
        )
      case 'impacted_resource':
        return (
          <div className="space-y-2 text-xs">
            {field('Name', data.name)}
            {field('Type', data.type)}
            {field('Relationship', data.relationship)}
            {field('Impact Level', data.impact_level)}
          </div>
        )
      default:
        return null
    }
  }

  if (isLoading) return <div className="text-sm text-muted-foreground p-4">Loading investigations...</div>

  return (
    <div className="flex h-full gap-0">
      {/* Left panel — finding search */}
      <div className="w-80 border-r border-border bg-background flex flex-col shrink-0">
        <div className="p-4 border-b border-border space-y-3">
          <h1 className="text-sm font-semibold">Investigation Queue</h1>
          <div className="flex flex-wrap items-center gap-2 text-[10px] text-muted-foreground">
            <span>{filteredFindings.length} contextual cases in focus</span>
            {selectedFinding && (
              <>
                <span aria-hidden="true">·</span>
                <span className="font-mono">{selectedFinding.id.slice(0, 12)}</span>
              </>
            )}
          </div>
          <div className="relative">
            <Search className="absolute left-2 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
            <input
              type="text"
              value={searchQuery}
              onChange={e => setSearchQuery(e.target.value)}
              placeholder="Search findings..."
              className="w-full pl-7 pr-2 py-1.5 text-xs bg-muted/50 border border-border outline-none"
            />
            {searchQuery && (
              <button type="button" onClick={() => setSearchQuery('')} className="absolute right-2 top-1/2 -translate-y-1/2">
                <X className="h-3 w-3 text-muted-foreground" />
              </button>
            )}
          </div>
          <div className="rounded-xl border border-border/70 bg-muted/20 p-3">
            <div className="flex items-center gap-2 text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">
              <Sparkles className="h-3.5 w-3.5" />
              Analyst workflow
            </div>
            <p className="mt-2 text-[11px] leading-relaxed text-foreground">
              Start from contextual critical and high cases only. Confirm owner, validate the primary resource, then trace control and downstream impact before opening the full case.
            </p>
            {selectedFinding && (
              <Button
                type="button"
                size="sm"
                variant="outline"
                className="mt-3 gap-1.5 text-[11px]"
                onClick={openGraphQueryTimeline}
              >
                <TimerReset className="h-3.5 w-3.5" />
                Trace graph query
              </Button>
            )}
          </div>
        </div>
        <div className="flex-1 overflow-y-auto">
          {filteredFindings.map(f => (
            <button
              key={f.id}
              type="button"
              onClick={() => { setSelectedFindingId(f.id); setSelectedNodeId(null) }}
              onDoubleClick={() => navigate(`/ops/findings/${f.id}`)}
              aria-pressed={selectedFindingId === f.id}
              className={`w-full text-left px-4 py-2.5 border-b border-border hover:bg-muted/30 transition-colors group/item ${selectedFindingId === f.id ? 'bg-muted/50 border-l-2 border-l-primary' : ''}`}
            >
              <div className="flex items-center gap-1.5 mb-0.5">
                <Badge variant="outline" className={`text-[9px] px-1 py-0 ${SEVERITY_COLORS[deriveInvestigationSeverity(f)] ?? ''}`}>
                  {deriveInvestigationSeverity(f)}
                </Badge>
                <ProviderBadge provider={f.cloud_provider} />
                <span className="text-[10px] text-muted-foreground font-mono">{f.id.slice(0, 12)}</span>
              </div>
              <div className="flex items-center gap-1.5">
                {(() => { const TypeIcon = FINDING_TYPE_ICONS[f.resource_type] ?? Shield; return <TypeIcon className="h-3 w-3 text-muted-foreground shrink-0" /> })()}
                <p className="text-xs font-medium truncate">{f.title}</p>
              </div>
              <div className="flex items-center justify-between">
                <p className="text-[10px] text-muted-foreground truncate">{f.resource_name} · Score {getInvestigationScore(f)}</p>
                <span
                  role="button"
                  tabIndex={0}
                  onClick={(e) => { e.stopPropagation(); navigate(`/ops/findings/${f.id}`) }}
                  onKeyDown={(e) => { if (e.key === 'Enter') { e.stopPropagation(); navigate(`/ops/findings/${f.id}`) } }}
                  className="p-0.5 hover:bg-muted rounded-sm opacity-0 group-hover/item:opacity-100 transition-opacity shrink-0"
                >
                  <ChevronRight className="h-3 w-3 text-muted-foreground" />
                </span>
              </div>
            </button>
          ))}
        </div>
      </div>

      {/* Graph area */}
      <div className="flex-1 relative">
        {selectedFindingId ? (
          <>
            {selectedFinding && (
              <div className="pointer-events-none absolute left-4 top-4 z-10 max-w-md rounded-[24px] border border-border/80 bg-background/95 p-4 shadow-[0_18px_48px_rgba(15,23,42,0.12)] backdrop-blur-sm">
                <div className="flex items-center gap-2 flex-wrap">
                  <Badge variant="outline" className={`text-[10px] px-1.5 py-0 ${SEVERITY_COLORS[deriveInvestigationSeverity(selectedFinding)] ?? ''}`}>
                    {deriveInvestigationSeverity(selectedFinding)}
                  </Badge>
                  <ProviderBadge provider={selectedFinding.cloud_provider} />
                  <span className="text-[10px] font-mono text-muted-foreground">{selectedFinding.id}</span>
                </div>
                <p className="mt-2 text-sm font-semibold leading-snug">{selectedFinding.title}</p>
                <p className="mt-1 text-xs text-muted-foreground">{selectedFinding.resource_name} · {selectedFinding.resource_type}</p>
                {analystBrief && (
                  <>
                    <div className="mt-3 rounded-xl border border-border/70 bg-muted/20 px-3 py-2">
                      <p className="text-[10px] uppercase tracking-wide text-muted-foreground">Analyst briefing</p>
                      <p className="mt-1 text-[11px] text-foreground">{analystBrief.posture}</p>
                      <p className="mt-1 text-[10px] leading-relaxed text-muted-foreground">{analystBrief.rationale}</p>
                    </div>
                    <div className="mt-2 flex items-start gap-2 rounded-xl border border-amber-200/80 bg-amber-50/80 px-3 py-2 text-[10px] text-amber-900">
                      <TriangleAlert className="mt-0.5 h-3.5 w-3.5 shrink-0" />
                      <span>{analystBrief.workflow}</span>
                    </div>
                  </>
                )}
                <div className="mt-3 grid grid-cols-2 gap-2 text-[10px]">
                  <div className="rounded-xl border border-border/70 bg-muted/30 px-2.5 py-2">
                    <div className="flex items-center gap-1 text-muted-foreground">
                      <UserRound className="h-3 w-3" />Owner
                    </div>
                    <p className="mt-1 text-xs font-medium text-foreground">{selectedFinding.assignee?.user_name ?? 'Unassigned'}</p>
                  </div>
                  <div className="rounded-xl border border-border/70 bg-muted/30 px-2.5 py-2">
                    <div className="flex items-center gap-1 text-muted-foreground">
                      <CalendarClock className="h-3 w-3" />Due
                    </div>
                    <p className="mt-1 text-xs font-medium text-foreground">{formatDateLabel(selectedFinding.due_date)}</p>
                  </div>
                  <div className="rounded-xl border border-border/70 bg-muted/30 px-2.5 py-2">
                    <div className="flex items-center gap-1 text-muted-foreground">
                      <Route className="h-3 w-3" />Impacted
                    </div>
                    <p className="mt-1 text-xs font-medium text-foreground">{selectedFinding.impacted_resources?.length ?? 0} linked resources</p>
                  </div>
                  <div className="rounded-xl border border-border/70 bg-muted/30 px-2.5 py-2">
                    <div className="flex items-center gap-1 text-muted-foreground">
                      <Shield className="h-3 w-3" />Compliance
                    </div>
                    <p className="mt-1 text-xs font-medium text-foreground">{selectedFinding.compliance_mappings?.length ?? 0} mapped controls</p>
                  </div>
                </div>
              </div>
            )}
            <div className="pointer-events-none absolute right-4 top-4 z-10 w-72 rounded-[24px] border border-border/80 bg-background/95 p-4 shadow-[0_18px_48px_rgba(15,23,42,0.12)] backdrop-blur-sm">
              <div className="flex items-center gap-2 text-xs font-semibold">
                <Link2 className="h-3.5 w-3.5 text-muted-foreground" />
                How to read this graph
              </div>
              <p className="mt-2 text-[11px] leading-relaxed text-muted-foreground">
                The graph is laid out as finding {'->'} owner {'->'} primary asset {'->'} controls {'->'} downstream impact. Use it to prove whether a finding is isolated, owned, and audit-relevant.
              </p>
              <div className="mt-3 grid grid-cols-1 gap-2">
                {GRAPH_GUIDE.map((type) => {
                  const meta = ENTITY_META[type]
                  const Icon = meta.icon
                  const colors = ENTITY_COLORS[type]
                  return (
                    <div key={type} className="flex items-start gap-2 rounded-xl border border-border/70 bg-muted/20 px-2.5 py-2">
                      <div className="mt-0.5 flex h-6 w-6 shrink-0 items-center justify-center rounded-full" style={{ background: colors.bg, border: `1px solid ${colors.border}`, color: colors.text }}>
                        <Icon className="h-3.5 w-3.5" />
                      </div>
                      <div className="min-w-0">
                        <p className="text-[11px] font-semibold text-foreground">{meta.label}</p>
                        <p className="text-[10px] leading-relaxed text-muted-foreground">{meta.summary}</p>
                      </div>
                    </div>
                  )
                })}
              </div>
            </div>
            <BaseGraphView nodes={graphNodes} edges={graphEdges} onNodeClick={handleNodeClick} height="h-full" tone="light" />
          </>
        ) : (
          <div className="flex items-center justify-center h-full text-muted-foreground">
            <div className="text-center">
              <Shield className="h-8 w-8 mx-auto mb-2 opacity-30" />
              <p className="text-sm">Select a finding to investigate</p>
              <p className="text-[10px] mt-1">Entity relationships will appear here</p>
            </div>
          </div>
        )}
      </div>

      {/* Right detail panel */}
      {selectedNodeData && (
        <div className="w-72 border-l border-border bg-background p-4 space-y-3 shrink-0 overflow-y-auto">
          <div className="flex items-center justify-between">
            <h3 className="text-xs font-semibold">{selectedNodeData.entityType.replace('_', ' ').replace(/\b\w/g, c => c.toUpperCase())} Detail</h3>
            <button type="button" onClick={() => setSelectedNodeId(null)} className="p-0.5 hover:bg-muted">
              <X className="h-3.5 w-3.5" />
            </button>
          </div>
          {selectedNodeMeta && (
            <div className="rounded-xl border border-border/70 bg-muted/20 p-3">
              {(() => {
                const Icon = selectedNodeMeta.icon
                return (
              <div className="flex items-center gap-2">
                <div className="flex h-7 w-7 items-center justify-center rounded-full border border-border/70 bg-background">
                  <Icon className="h-3.5 w-3.5 text-foreground" />
                </div>
                <div>
                  <p className="text-[10px] uppercase tracking-wide text-muted-foreground">{selectedNodeMeta.label}</p>
                  <p className="text-xs font-medium text-foreground">Why this node matters</p>
                </div>
              </div>
                )
              })()}
              <p className="mt-2 text-[11px] leading-relaxed text-muted-foreground">
                {describeNodeImportance(selectedNodeData.entityType, selectedNodeData.entityData)}
              </p>
            </div>
          )}
          <div className="rounded-xl border border-border/70 bg-muted/20 px-3 py-2 text-[10px] text-muted-foreground">
            Use this rail to confirm ownership, control mappings, and downstream impact before opening the full finding page.
          </div>
          {renderNodeDetail(selectedNodeData.entityType, selectedNodeData.entityData)}
        </div>
      )}
    </div>
  )
}
