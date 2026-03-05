export interface AttackPathNode {
  id: string
  finding_id: string
  resource_id: string
  resource_name: string
  resource_type: string
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
  severity: string
  score: number
  hop_count: number
  entry_point: AttackPathNode
  target: AttackPathNode
  nodes: AttackPathNode[]
  edges: AttackPathEdge[]
  mitre_tactics: string[]
  finding_ids: string[]
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
