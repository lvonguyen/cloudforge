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
