export type RemediationStatus = 'pending' | 'in_progress' | 'completed' | 'failed' | 'skipped'

export interface RemediationResult {
  finding_id: string
  success: boolean
  message: string
  resource_id: string
  actions: string[]
  started_at: string
  completed_at: string
  duration: string
  error?: string
  rollback_available?: boolean
  rollback_window_expires_at?: string
  rollback_actions?: string[]
}

export interface ValidationResult {
  finding_id: string
  is_compliant: boolean
  message: string
  evidence: string[]
  validated_at: string
  recheck_after?: string
}

export interface DryRunResult {
  finding_id: string
  would_succeed: boolean
  planned_actions: string[]
  prerequisites_met: boolean
  warnings?: string[]
  estimated_impact: string
  rollback_plan?: string[]
  validation_checks?: string[]
  estimated_rollback_window?: string
}

export interface RollbackState {
  finding_id: string
  resource_id: string
  region: string
  account_id: string
  pre_state: Record<string, unknown>
  captured_at: string
}

export interface RollbackResult {
  finding_id: string
  success: boolean
  message: string
  actions: string[]
  rolled_back_at: string
  error?: string
}

export interface RollbackPlan {
  mode: 'sdk' | 'script' | 'manual'
  status: 'available' | 'manual' | 'expired' | 'not_available'
  state_id?: string
  window_expires_at?: string
  approval_required?: boolean
  command?: string
  actions: string[]
}

export interface TicketComment {
  id: string
  ticket_id: string
  author: string
  body: string
  created_at: string
}

export interface TicketSyncResult {
  ticket_id: string
  status: string
  synced_at: string
}

export interface RemediationRecord {
  id: string
  finding_id: string
  domain: string
  handler: string
  tier: number
  status: RemediationStatus
  result?: RemediationResult
  validation?: ValidationResult
  rollback?: RollbackPlan
  asana_task_url?: string
  created_at: string
  updated_at: string
}
