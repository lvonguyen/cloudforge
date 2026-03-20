import { useState, useMemo, useCallback, useEffect } from 'react'
import { type Node, type Edge, Position, MarkerType } from '@xyflow/react'
import '@xyflow/react/dist/style.css'
import { BaseGraphView } from '@/components/ops/BaseGraphView'
import { useFindings } from '@/hooks/useFindings'
import { Badge } from '@/components/ui/badge'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { Search, X, Shield, Server, Database, Key, Globe, ChevronRight } from 'lucide-react'
import { SEVERITY_COLORS_BORDERED as SEVERITY_COLORS } from '@/lib/severity'
import { ProviderBadge } from '@/components/ui/ProviderBadge'
import type { InvestigationEntityType } from '@/types/investigation'

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
  finding:            { bg: '#1e1e2e', border: '#ef4444', text: '#fca5a5' },
  assignee:           { bg: '#1e1e2e', border: '#3b82f6', text: '#93c5fd' },
  technical_contact:  { bg: '#1e1e2e', border: '#8b5cf6', text: '#c4b5fd' },
  resource:           { bg: '#1e1e2e', border: '#f59e0b', text: '#fcd34d' },
  compliance_mapping: { bg: '#1e1e2e', border: '#22c55e', text: '#86efac' },
  impacted_resource:  { bg: '#1e1e2e', border: '#f97316', text: '#fdba74' },
}

export default function Investigations() {
  const { data: findings = [], isLoading } = useFindings()
  const [searchParams] = useSearchParams()
  const [selectedFindingId, setSelectedFindingId] = useState<string | null>(() => searchParams.get('findingId'))
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null)
  const [searchQuery, setSearchQuery] = useState('')
  const navigate = useNavigate()

  // Auto-select first finding when none is selected and findings are loaded
  useEffect(() => {
    if (!selectedFindingId && findings.length > 0) {
      setSelectedFindingId(findings[0].id)
    }
  }, [selectedFindingId, findings])

  const filteredFindings = useMemo(() => {
    if (!searchQuery) return findings.slice(0, 50)
    const q = searchQuery.toLowerCase()
    return findings.filter(f =>
      f.title.toLowerCase().includes(q) ||
      f.resource_name.toLowerCase().includes(q) ||
      f.id.toLowerCase().includes(q)
    ).slice(0, 50)
  }, [findings, searchQuery])

  const { graphNodes, graphEdges } = useMemo(() => {
    const finding = findings.find(f => f.id === selectedFindingId)
    if (!finding) return { graphNodes: [], graphEdges: [] }

    const findingId = finding.id
    const nodes: Node[] = []
    const edges: Edge[] = []
    let entityIndex = 0

    // Count total entities to compute radius
    let totalEntities = 1 // resource is always present
    if (finding.assignee) totalEntities++
    if (finding.technical_contact) totalEntities++
    totalEntities += Math.min(finding.compliance_mappings?.length ?? 0, 3)
    totalEntities += Math.min(finding.impacted_resources?.length ?? 0, 3)
    const radius = Math.max(180, 140 + totalEntities * 20)
    const borderWeight = SEVERITY_BORDER_WEIGHT[finding.severity] ?? 1

    // Finding-type icon
    const TypeIcon = FINDING_TYPE_ICONS[finding.resource_type] ?? Shield

    // Central finding node
    nodes.push({
      id: findingId,
      position: { x: 400, y: 300 },
      sourcePosition: Position.Right,
      targetPosition: Position.Left,
      data: {
        label: (
          <div className="px-3 py-2 min-w-[180px]" style={{ background: '#1e1e2e', border: `${borderWeight}px solid #ef4444` }}>
            <div className="flex items-center gap-1.5 mb-0.5">
              <TypeIcon className="h-3 w-3" style={{ color: '#fca5a5' }} />
              <span className="text-[10px] text-red-300 font-medium truncate flex-1">{finding.title}</span>
            </div>
            <div className="text-[9px] text-gray-400">{finding.severity} · {finding.category} · {finding.cloud_provider.toUpperCase()}</div>
          </div>
        ),
        entityType: 'finding' as InvestigationEntityType,
        entityData: {
          id: finding.id,
          title: finding.title,
          severity: finding.severity,
          category: finding.category,
          cloud_provider: finding.cloud_provider,
          resource_name: finding.resource_name,
          resource_type: finding.resource_type,
          recommendation: finding.remediation?.slice(0, 200),
        },
      },
      style: { padding: 0, borderRadius: 0, background: 'transparent', border: 'none' },
    })

    function addEntity(type: InvestigationEntityType, id: string, label: string, sublabel?: string, entityData?: Record<string, unknown>) {
      const angle = (entityIndex / totalEntities) * 2 * Math.PI - Math.PI / 2
      const x = 400 + radius * Math.cos(angle)
      const y = 300 + radius * Math.sin(angle)
      entityIndex++

      const colors = ENTITY_COLORS[type]
      nodes.push({
        id,
        position: { x, y },
        data: {
          label: (
            <div className="px-2 py-1.5 min-w-[120px]" style={{ background: colors.bg, border: `1px solid ${colors.border}` }}>
              <div className="text-[9px] uppercase tracking-wide" style={{ color: colors.text }}>{type.replace('_', ' ')}</div>
              <div className="text-[10px] text-gray-300 font-medium truncate">{label}</div>
              {sublabel && <div className="text-[9px] text-gray-500 truncate">{sublabel}</div>}
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
        style: { stroke: colors.border, strokeWidth: 1 },
        labelStyle: edgeLabel ? { fontSize: 8, fill: '#6b7280' } : undefined,
        labelBgStyle: edgeLabel ? { fill: '#0a0a0f', fillOpacity: 0.9 } : undefined,
        labelBgPadding: edgeLabel ? [2, 4] as [number, number] : undefined,
        markerEnd: { type: MarkerType.ArrowClosed, color: colors.border, width: 10, height: 10 },
      })
    }

    // Assignee
    if (finding.assignee) {
      addEntity('assignee', `assignee-${finding.assignee.user_id}`, finding.assignee.user_name, finding.assignee.team, {
        name: finding.assignee.user_name, email: finding.assignee.user_email, team: finding.assignee.team,
        assigned_at: finding.assignee.assigned_at, due_date: finding.due_date,
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

    // Compliance mappings
    if (finding.compliance_mappings) {
      for (const cm of finding.compliance_mappings.slice(0, 3)) {
        addEntity('compliance_mapping', `comp-${cm.framework_id}-${cm.control_id}`, `${cm.framework_name} ${cm.control_id}`, cm.control_title?.slice(0, 40), {
          framework_name: cm.framework_name, control_id: cm.control_id, control_title: cm.control_title,
          section: cm.section, subsection: cm.subsection, severity: cm.severity, url: cm.url,
        })
      }
    }

    // Impacted resources
    if (finding.impacted_resources) {
      for (const ir of finding.impacted_resources.slice(0, 3)) {
        addEntity('impacted_resource', `ir-${ir.resource_id}`, ir.resource_name, ir.resource_type, {
          name: ir.resource_name, type: ir.resource_type, relationship: ir.relationship, impact_level: ir.impact_level,
        })
      }
    }

    return { graphNodes: nodes, graphEdges: edges }
  }, [findings, selectedFindingId])

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
          <h1 className="text-sm font-semibold">Investigation Board</h1>
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
              <button onClick={() => setSearchQuery('')} className="absolute right-2 top-1/2 -translate-y-1/2">
                <X className="h-3 w-3 text-muted-foreground" />
              </button>
            )}
          </div>
        </div>
        <div className="flex-1 overflow-y-auto">
          {filteredFindings.map(f => (
            <button
              key={f.id}
              onClick={() => { setSelectedFindingId(f.id); setSelectedNodeId(null) }}
              onDoubleClick={() => navigate(`/ops/findings/${f.id}`)}
              className={`w-full text-left px-4 py-2.5 border-b border-border hover:bg-muted/30 transition-colors group/item ${selectedFindingId === f.id ? 'bg-muted/50 border-l-2 border-l-primary' : ''}`}
            >
              <div className="flex items-center gap-1.5 mb-0.5">
                <Badge variant="outline" className={`text-[9px] px-1 py-0 ${SEVERITY_COLORS[f.severity] ?? ''}`}>
                  {f.severity}
                </Badge>
                <ProviderBadge provider={f.cloud_provider} />
                <span className="text-[10px] text-muted-foreground font-mono">{f.id.slice(0, 12)}</span>
              </div>
              <div className="flex items-center gap-1.5">
                {(() => { const TypeIcon = FINDING_TYPE_ICONS[f.resource_type] ?? Shield; return <TypeIcon className="h-3 w-3 text-muted-foreground shrink-0" /> })()}
                <p className="text-xs font-medium truncate">{f.title}</p>
              </div>
              <div className="flex items-center justify-between">
                <p className="text-[10px] text-muted-foreground truncate">{f.resource_name}</p>
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
          <BaseGraphView nodes={graphNodes} edges={graphEdges} onNodeClick={handleNodeClick} height="h-full" />
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
            <button onClick={() => setSelectedNodeId(null)} className="p-0.5 hover:bg-muted">
              <X className="h-3.5 w-3.5" />
            </button>
          </div>
          {renderNodeDetail(selectedNodeData.entityType, selectedNodeData.entityData)}
        </div>
      )}
    </div>
  )
}
