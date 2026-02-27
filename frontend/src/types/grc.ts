export type ExceptionType =
  | 'UNAPPROVED_REGION'
  | 'OVERSIZED_INSTANCE'
  | 'RESTRICTED_SERVICE'
  | 'NETWORK_EXPOSURE'
  | 'DATA_RESIDENCY'
  | 'OTHER'

export type ApprovalStatus = 'PENDING' | 'APPROVED' | 'REJECTED' | 'EXPIRED' | 'REVOKED'

export interface RiskAssessment {
  risk_level: string
  impact: string
  likelihood: string
  residual_risk: string
  assessed_by: string
  assessed_at: string
}

export interface Approver {
  email: string
  role: string
  decision: ApprovalStatus
  comments?: string
  decided_at?: string
}

export interface ExceptionRequest {
  id: string
  application_id: string
  requestor_email: string
  request_type: ExceptionType
  policy_violated: string
  resource_requested: string
  business_case: string
  risk_assessment?: RiskAssessment
  compensating_controls?: string[]
  status: ApprovalStatus
  approver_chain: Approver[]
  expiration_date?: string
  created_at: string
  updated_at: string
  metadata?: Record<string, string>
}

export interface ExceptionValidation {
  valid: boolean
  exception_id?: string
  expires_at?: string
  reason?: string
}
