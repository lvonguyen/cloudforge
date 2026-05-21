export interface AttackPathNode {
  id: string
  finding_id: string
  resource_id: string
  resource_name: string
  resource_type: string
  internet_facing?: boolean
  subnet?: string
  network_boundary?: string
  provider: string
  account_id: string
  region: string
  severity: string
  category: string
  label: string
}

export interface AttackPathEdge {
  id: string
  source: string
  target: string
  label: string
  edge_type: string
}

export interface AttackPath {
  id: string
  title: string
  description: string
  entry_point_type?: string
  severity: string
  score: number
  hop_count: number
  entry_point: AttackPathNode
  target: AttackPathNode
  nodes: AttackPathNode[]
  edges: AttackPathEdge[]
  mitre_tactics: string[]
  finding_ids: string[]
  mission_context?: string
  mission_impact?: string
  risk_factors?: string[]
  control_gaps?: string[]
  recommended_breaks?: string[]
  evidence_mode?: string
  rollback_summary?: string
  choke_points?: string[]
  control_mappings?: string[]

  // AI-enriched fields (present when Bedrock AI is enabled)
  ai_description?: string
  ai_remediation?: string
  ai_likelihood?: string
  ai_confidence?: number
  ai_validated?: boolean
  ai_risk_narrative?: string
  ai_enriched: boolean
  low_confidence?: boolean
}

export interface PaginatedResponse<T> {
  data: T[]
  page: number
  per_page: number
  total: number
  total_pages: number
}

export interface AttackPathStats {
  total_findings: number
  findings_in_paths: number
  isolated_findings: number
  coverage_percent: number
  total_paths: number
  critical_paths: number
  high_paths: number
  medium_paths: number
  by_provider: Record<string, number>
}
