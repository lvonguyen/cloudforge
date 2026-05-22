import { useState, useMemo, useCallback } from 'react'
import { type Node, type Edge, Position, MarkerType } from '@xyflow/react'
import '@xyflow/react/dist/style.css'
import { BaseGraphView } from '@/components/ops/BaseGraphView'
import { useFindings } from '@/hooks/useFindings'
import { useMediaQuery } from '@/hooks/useMediaQuery'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { Search, X, Shield, Server, Database, Key, Globe, ChevronRight, ChevronDown, CalendarClock, UserRound, Route, FileCheck2, Link2, TriangleAlert, Sparkles, TimerReset } from 'lucide-react'
import { SEVERITY_COLORS_BORDERED as SEVERITY_COLORS } from '@/lib/severity'
import { ProviderBadge } from '@/components/ui/ProviderBadge'
import { useTracePanel } from '@/lib/trace-panel-context'
import { buildTraceTimeline } from '@/lib/trace-helpers'
import { inferFindingThreatContextSignals } from '@/lib/threat-context'
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
  exposure_surface: 'enters through',
  assignee: 'assigned to',
  technical_contact: 'owned by',
  resource: 'affects',
  network_boundary: 'bounded by',
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
  exposure_surface:   { bg: '#eff6ff', border: '#0284c7', text: '#0369a1' },
  assignee:           { bg: '#eff6ff', border: '#2563eb', text: '#1d4ed8' },
  technical_contact:  { bg: '#f5f3ff', border: '#7c3aed', text: '#6d28d9' },
  resource:           { bg: '#fffbeb', border: '#d97706', text: '#b45309' },
  network_boundary:   { bg: '#ecfeff', border: '#0f766e', text: '#0f766e' },
  compliance_mapping: { bg: '#f0fdf4', border: '#16a34a', text: '#15803d' },
  impacted_resource:  { bg: '#fff7ed', border: '#ea580c', text: '#c2410c' },
}

const ENTITY_META: Record<InvestigationEntityType, { label: string; icon: typeof Shield; summary: string }> = {
  finding: { label: 'Finding', icon: Shield, summary: 'Anchor node. Start here, then validate owner, control coverage, and impact chain.' },
  exposure_surface: { label: 'Exposure surface', icon: Globe, summary: 'Internet-reachable or externally reachable edge inferred from finding context.' },
  assignee: { label: 'Assignee', icon: UserRound, summary: 'Operational owner responsible for triage, execution, and SLA adherence.' },
  technical_contact: { label: 'Technical contact', icon: UserRound, summary: 'Domain contact who can confirm implementation details and remediation blast radius.' },
  resource: { label: 'Primary resource', icon: Server, summary: 'Primary asset carrying the finding. Use this to confirm scope and affected surface.' },
  network_boundary: { label: 'Network boundary', icon: Shield, summary: 'Provider network controls that should be checked before assuming unrestricted reachability.' },
  compliance_mapping: { label: 'Control mapping', icon: FileCheck2, summary: 'Mapped policy or framework control that turns technical risk into audit exposure.' },
  impacted_resource: { label: 'Impacted resource', icon: Route, summary: 'Downstream asset touched by the same weakness, dependency, or reachable path.' },
}

const GRAPH_GUIDE: InvestigationEntityType[] = ['finding', 'exposure_surface', 'assignee', 'resource', 'network_boundary', 'compliance_mapping', 'impacted_resource']
const INVESTIGATION_SAMPLE_SIZE = 100

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
    case 'exposure_surface':
      return 'This is the inferred edge of exposure. Validate whether the finding is really internet- or externally reachable before escalating blast radius.'
    case 'assignee':
      return data.name === 'Unassigned'
        ? 'This is a triage gap. Assigning ownership is the fastest way to reduce operator drag.'
        : 'This tells you who is on the hook for remediation and whether the current route matches the actual owning team.'
    case 'technical_contact':
      return 'Use the technical contact to validate whether the alert maps to the real service boundary and rollout path.'
    case 'resource':
      return 'This is the primary asset under investigation. Confirm its environment, provider, and exposure before escalating.'
    case 'network_boundary':
      return 'This inferred control boundary tells you what network policy or segmentation layer should be checked before you trust the attack narrative.'
    case 'compliance_mapping':
      return 'This shows which control narrative the finding will roll up into for audit and governance reporting.'
    case 'impacted_resource':
      return 'Use impacted resources to judge whether the issue is isolated or part of a broader service chain.'
    default:
      return ''
  }
}

export default function Investigations() {
  const { data: findings = [], isLoading } = useFindings({ page: 1, perPage: INVESTIGATION_SAMPLE_SIZE, sort: 'ai_risk', order: 'desc' })
  const [searchParams] = useSearchParams()
  const [selectedFindingId, setSelectedFindingId] = useState<string | null>(() => searchParams.get('findingId'))
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null)
  const [searchQuery, setSearchQuery] = useState('')
  const [summaryPanelPreference, setSummaryPanelPreference] = useState<'auto' | 'expanded' | 'collapsed'>('auto')
  const [guidePanelPreference, setGuidePanelPreference] = useState<'auto' | 'expanded' | 'collapsed'>('auto')
  const navigate = useNavigate()
  const { openTimeline } = useTracePanel()
  const isCompactBoard = useMediaQuery('(max-width: 1400px)')

  const investigationCandidates = useMemo(
    () =>
      [...findings]
        .filter(isInvestigationCandidate)
        .sort((a, b) => getInvestigationScore(b) - getInvestigationScore(a)),
    [findings],
  )

  const effectiveSelectedFindingId = selectedFindingId ?? investigationCandidates[0]?.id ?? null

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
    () => investigationCandidates.find(f => f.id === effectiveSelectedFindingId) ?? null,
    [effectiveSelectedFindingId, investigationCandidates],
  )
  const summaryCollapsed =
    summaryPanelPreference === 'auto' ? isCompactBoard : summaryPanelPreference === 'collapsed'
  const guideCollapsed =
    guidePanelPreference === 'auto' ? isCompactBoard : guidePanelPreference === 'collapsed'
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
  const selectedThreatContext = useMemo(
    () => selectedFinding ? inferFindingThreatContextSignals(selectedFinding) : null,
    [selectedFinding],
  )

  const { graphNodes, graphEdges } = useMemo(() => {
    const finding = investigationCandidates.find(f => f.id === effectiveSelectedFindingId)
    if (!finding) return { graphNodes: [], graphEdges: [] }

    const findingId = finding.id
    const findingResourceType = finding.resource_type
    const contextualSeverity = deriveInvestigationSeverity(finding)
    const nodes: Node[] = []
    const edges: Edge[] = []
    const nodePositions = new Map<string, { x: number; y: number }>()
    const laneIndex: Record<InvestigationEntityType, number> = {
      finding: 0,
      exposure_surface: 0,
      assignee: 0,
      technical_contact: 0,
      resource: 0,
      network_boundary: 0,
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
    nodePositions.set(findingId, { x: 120, y: 220 })

    function addEntity(
      type: InvestigationEntityType,
      id: string,
      label: string,
      sublabel?: string,
      entityData?: Record<string, unknown>,
      sourceId = findingId,
    ) {
      const slot = laneIndex[type]
      laneIndex[type]++

      const laneConfig: Record<InvestigationEntityType, { x: number; y: number; step: number }> = {
        finding: { x: 120, y: 220, step: 0 },
        exposure_surface: { x: 430, y: 70, step: 104 },
        assignee: { x: 430, y: 240, step: 104 },
        resource: { x: 760, y: 70, step: 104 },
        network_boundary: { x: 760, y: 240, step: 104 },
        technical_contact: { x: 760, y: 360, step: 104 },
        compliance_mapping: { x: 1090, y: 70, step: 100 },
        impacted_resource: { x: 1090, y: 250, step: 100 },
      }
      const config = laneConfig[type]
      const x = config.x
      const y = config.y + slot * config.step
      const dx = x - 120
      const dy = y - 220
      const targetPosition =
        Math.abs(dx) >= Math.abs(dy)
          ? (dx >= 0 ? Position.Left : Position.Right)
          : (dy >= 0 ? Position.Top : Position.Bottom)
      const iconType = String(entityData?.type ?? findingResourceType).toLowerCase()
      const EntityIcon =
        type === 'resource' || type === 'impacted_resource'
          ? (FINDING_TYPE_ICONS[iconType] ?? Server)
          : ENTITY_META[type].icon

      const colors = ENTITY_COLORS[type]
      nodes.push({
        id,
        position: { x, y },
        sourcePosition: dx >= 0 ? Position.Right : Position.Left,
        targetPosition,
        data: {
          label: (
          <div className="px-2 py-1.5 min-w-[168px]" style={{ background: colors.bg, border: `1px solid ${colors.border}` }}>
              <div className="flex items-center gap-1.5 text-[9px] uppercase tracking-wide" style={{ color: colors.text }}>
                <EntityIcon className="h-3 w-3" />
                <span>{type.replace('_', ' ')}</span>
              </div>
              <div className="mt-0.5 text-[10px] text-slate-900 font-medium truncate">{label}</div>
              {sublabel && <div className="text-[9px] text-slate-500 truncate">{sublabel}</div>}
            </div>
          ),
          entityType: type,
          entityData: entityData ?? { label, sublabel },
        },
        style: { padding: 0, borderRadius: 0, background: 'transparent', border: 'none' },
      })
      nodePositions.set(id, { x, y })

      const edgeLabel = EDGE_LABELS[type]
      edges.push({
        id: `${sourceId}->${id}`,
        source: sourceId,
        target: id,
        type: 'smoothstep',
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

    const contextSignals = inferFindingThreatContextSignals(finding)
    const resourceNodeId = `res-${finding.resource_id}`
    let resourceSourceId = findingId

    if (contextSignals.exposureSurface) {
      const exposureId = `exposure-${findingId}`
      addEntity('exposure_surface', exposureId, contextSignals.exposureSurface.label, contextSignals.exposureSurface.detail, {
        ...contextSignals.exposureSurface,
        provider: finding.cloud_provider,
      }, findingId)
      resourceSourceId = exposureId
    }

    if (contextSignals.networkBoundary) {
      const boundaryId = `boundary-${findingId}`
      addEntity('network_boundary', boundaryId, contextSignals.networkBoundary.label, contextSignals.networkBoundary.detail, {
        ...contextSignals.networkBoundary,
        provider: finding.cloud_provider,
      }, resourceSourceId)
      resourceSourceId = boundaryId
    }

    // Primary resource
    addEntity('resource', resourceNodeId, finding.resource_name, finding.resource_type, {
      name: finding.resource_name, type: finding.resource_type, region: finding.region, account_id: finding.account_id, finding_count: 1,
    }, resourceSourceId)

    // Technical contact
    if (finding.technical_contact) {
      addEntity('technical_contact', `tc-${finding.technical_contact.email}`, finding.technical_contact.name, finding.technical_contact.team, {
        name: finding.technical_contact.name, email: finding.technical_contact.email, team: finding.technical_contact.team,
      }, resourceNodeId)
    }

    // Compliance mappings (or inferred fallback)
    if (finding.compliance_mappings && finding.compliance_mappings.length > 0) {
      for (const cm of finding.compliance_mappings.slice(0, 3)) {
        addEntity('compliance_mapping', `comp-${cm.framework_id}-${cm.control_id}`, `${cm.framework_name} ${cm.control_id}`, cm.control_title?.slice(0, 40), {
          framework_name: cm.framework_name, control_id: cm.control_id, control_title: cm.control_title,
          section: cm.section, subsection: cm.subsection, severity: cm.severity, url: cm.url,
        }, resourceNodeId)
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
      }, resourceNodeId)
    }

    // Impacted resources
    if (finding.impacted_resources && finding.impacted_resources.length > 0) {
      for (const ir of finding.impacted_resources.slice(0, 3)) {
        addEntity('impacted_resource', `ir-${ir.resource_id}`, ir.resource_name, ir.resource_type, {
          name: ir.resource_name, type: ir.resource_type, relationship: ir.relationship, impact_level: ir.impact_level,
        }, resourceNodeId)
      }
    }

    return { graphNodes: nodes, graphEdges: edges }
  }, [effectiveSelectedFindingId, investigationCandidates])

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
      case 'exposure_surface':
      case 'network_boundary':
        return (
          <div className="space-y-2 text-xs">
            {field('Label', data.label)}
            {field('Detail', data.detail)}
            {field('Evidence', Array.isArray(data.evidence) ? data.evidence.join(' · ') : data.evidence)}
            {field('Provider', data.provider)}
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
              aria-pressed={effectiveSelectedFindingId === f.id}
              className={`w-full text-left px-4 py-2.5 border-b border-border hover:bg-muted/30 transition-colors group/item ${effectiveSelectedFindingId === f.id ? 'bg-muted/50 border-l-2 border-l-primary' : ''}`}
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
        {effectiveSelectedFindingId ? (
          <>
            {selectedFinding && (
              <div className={`pointer-events-auto absolute left-4 top-4 z-10 rounded-[24px] border border-border/80 bg-background/95 shadow-[0_18px_48px_rgba(15,23,42,0.12)] backdrop-blur-sm ${summaryCollapsed ? 'w-auto max-w-[14rem] p-3' : 'w-full max-w-sm p-4 xl:max-w-md'}`}>
                <div className="flex items-start justify-between gap-3">
                  <div className="min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <Badge variant="outline" className={`text-[10px] px-1.5 py-0 ${SEVERITY_COLORS[deriveInvestigationSeverity(selectedFinding)] ?? ''}`}>
                        {deriveInvestigationSeverity(selectedFinding)}
                      </Badge>
                      <ProviderBadge provider={selectedFinding.cloud_provider} />
                      <span className="text-[10px] font-mono text-muted-foreground">{selectedFinding.id}</span>
                    </div>
                    <p className="mt-2 text-sm font-semibold leading-snug">{summaryCollapsed ? 'Case summary' : selectedFinding.title}</p>
                    {summaryCollapsed ? (
                      <p className="mt-1 text-[11px] text-muted-foreground">{selectedFinding.resource_name}</p>
                    ) : (
                      <p className="mt-1 text-xs text-muted-foreground">{selectedFinding.resource_name} · {selectedFinding.resource_type}</p>
                    )}
                  </div>
                  <Button
                    type="button"
                    variant="ghost"
                    size="sm"
                    aria-expanded={!summaryCollapsed}
                    aria-label={summaryCollapsed ? 'Expand case summary' : 'Collapse case summary'}
                    onClick={() => setSummaryPanelPreference(current => {
                      if (current === 'auto') return isCompactBoard ? 'expanded' : 'collapsed'
                      return summaryCollapsed ? 'expanded' : 'collapsed'
                    })}
                    className="h-7 shrink-0 rounded-full px-2 text-[11px]"
                  >
                    {summaryCollapsed ? 'Show' : 'Hide'}
                    <ChevronDown className={`ml-1 h-3.5 w-3.5 transition-transform ${summaryCollapsed ? '-rotate-90' : ''}`} />
                  </Button>
                </div>
                {!summaryCollapsed && (
                  <>
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
                    {(selectedThreatContext?.exposureSurface || selectedThreatContext?.networkBoundary) && (
                      <div className="mt-3 rounded-xl border border-sky-200/80 bg-sky-50/70 px-3 py-2">
                        <p className="text-[10px] uppercase tracking-wide text-sky-700">Inferred context cues</p>
                        <div className="mt-2 flex flex-wrap gap-2">
                          {selectedThreatContext.exposureSurface && (
                            <span className="inline-flex items-center gap-1 rounded-full border border-sky-300 bg-white px-2 py-0.5 text-[10px] font-medium text-sky-700">
                              <Globe className="h-3 w-3" />
                              {selectedThreatContext.exposureSurface.label}
                            </span>
                          )}
                          {selectedThreatContext.networkBoundary && (
                            <span className="inline-flex items-center gap-1 rounded-full border border-teal-300 bg-white px-2 py-0.5 text-[10px] font-medium text-teal-700">
                              <Shield className="h-3 w-3" />
                              {selectedThreatContext.networkBoundary.label}
                            </span>
                          )}
                        </div>
                      </div>
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
                  </>
                )}
              </div>
            )}
            <div className={`pointer-events-auto absolute right-4 top-4 z-10 rounded-[24px] border border-border/80 bg-background/95 shadow-[0_18px_48px_rgba(15,23,42,0.12)] backdrop-blur-sm ${guideCollapsed ? 'w-auto max-w-[13rem] p-3' : 'w-64 p-4 xl:w-72'}`}>
              <div className="flex items-start justify-between gap-3">
                <div className="min-w-0">
                  <div className="flex items-center gap-2 text-xs font-semibold">
                    <Link2 className="h-3.5 w-3.5 text-muted-foreground" />
                    How to read this graph
                  </div>
                  {guideCollapsed && (
                    <p className="mt-1 text-[11px] text-muted-foreground">Open the graph legend and reading order.</p>
                  )}
                </div>
                <Button
                  type="button"
                  variant="ghost"
                  size="sm"
                  aria-expanded={!guideCollapsed}
                  aria-label={guideCollapsed ? 'Expand graph guide' : 'Collapse graph guide'}
                  onClick={() => setGuidePanelPreference(current => {
                    if (current === 'auto') return isCompactBoard ? 'expanded' : 'collapsed'
                    return guideCollapsed ? 'expanded' : 'collapsed'
                  })}
                  className="h-7 shrink-0 rounded-full px-2 text-[11px]"
                >
                  {guideCollapsed ? 'Show' : 'Hide'}
                  <ChevronDown className={`ml-1 h-3.5 w-3.5 transition-transform ${guideCollapsed ? '-rotate-90' : ''}`} />
                </Button>
              </div>
              {!guideCollapsed && (
                <>
                  <p className="mt-2 text-[11px] leading-relaxed text-muted-foreground">
                    The graph starts at the finding, then steps through inferred exposure or boundary cues when present. Ownership and the primary asset stay central, while the asset branches into technical context, controls, and downstream impact so you can judge reachability, audit exposure, and blast radius in one pass.
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
                </>
              )}
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
