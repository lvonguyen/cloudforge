export type IssueSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'
export type IssueStatusType = 'OPEN' | 'ACKNOWLEDGED' | 'IN_PROGRESS' | 'RESOLVED' | 'SUPPRESSED'

export interface Issue {
  id: string
  title: string
  description: string
  severity: IssueSeverity
  risk_score: number
  blast_radius: number
  status: IssueStatusType
  control_id?: string
  resource_id?: string
  account_id?: string
  provider?: string
  assignee_id?: string
  ticket_id?: string
  ticket_url?: string
  sla_breach_at?: string
  exposure_paths: number
  tenant_id: string
  created_at: string
  updated_at: string
  resolved_at?: string
}

export interface IssueDetail {
  issue: Issue
  finding_ids: string[]
}

export interface IssueListResult {
  data: Issue[]
  page: number
  per_page: number
  total: number
  total_pages: number
}

export interface IssueStats {
  by_severity: Record<string, number>
  by_status: Record<string, number>
  by_provider: Record<string, number>
  total: number
  open_count: number
  sla_breach_count: number
}

export interface IssueUpdate {
  status?: IssueStatusType
  assignee_id?: string
  ticket_id?: string
  ticket_url?: string
}
