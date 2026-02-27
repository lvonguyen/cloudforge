export interface PolicyInput {
  application_id: string
  resource_type: string
  cloud_provider: string
  region: string
  configuration: Record<string, unknown>
  tags: Record<string, string>
  requested_by: string
}

export interface PolicyViolation {
  code: string
  message: string
  severity: string
  remediation: string
}

export interface PolicyResult {
  allowed: boolean
  denials: PolicyViolation[]
  warnings: PolicyViolation[]
  suggestions: string[]
}
