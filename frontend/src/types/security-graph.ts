export interface SecurityGraphNode {
  id: string
  resource_id: string
  resource_name: string
  resource_type: string
  provider: string
  region: string
  finding_count: number
  max_severity: string
}

export interface SecurityGraphEdge {
  source: string
  target: string
  relationship: 'impacted_by' | 'related_finding' | 'toxic_combo' | 'same_account'
}

// Backend-aligned types from GET /api/v1/graph/neighborhood and /graph/stats (ADR-020)

export type NodeType = 'finding' | 'resource' | 'control' | 'issue' | 'account' | 'compliance_framework'
export type EdgeType = 'affects' | 'violates' | 'maps_to' | 'evaluated_by' | 'materializes_to' | 'belongs_to' | 'same_account' | 'same_region'

export interface GraphNode {
  id: string
  type: NodeType
  label: string
  props?: Record<string, string>
}

export interface GraphEdgeView {
  source: string
  target: string
  type: EdgeType
}

export interface GraphQueryResult {
  nodes: GraphNode[]
  edges: GraphEdgeView[]
}

export interface GraphStats {
  vertices: Record<string, number>
  edges: Record<string, number>
  total_vertices: number
  total_edges: number
}
