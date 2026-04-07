export type ResourceType =
  | 'compute' | 'network' | 'storage' | 'database'
  | 'identity' | 'container' | 'serverless' | 'messaging'
  | 'security' | 'monitoring' | 'other'

export type CloudProvider = 'aws' | 'gcp' | 'azure' | 'oci' | 'alicloud' | 'private' | 'multi-cloud' | 'none'

export type EnvironmentType =
  | 'production' | 'staging' | 'development' | 'qa'
  | 'uat' | 'sandbox' | 'disaster-recovery'

export type FindingCategory =
  | 'VULNERABILITY' | 'MISCONFIGURATION' | 'THREAT' | 'COMPLIANCE'
  | 'DATA_PROTECTION' | 'IDENTITY' | 'NETWORK' | 'COMPUTE'
  | 'STORAGE' | 'CONTAINER' | 'SERVERLESS' | 'DATABASE'

export type WorkflowStatus =
  | 'new' | 'triaged' | 'assigned' | 'in_progress' | 'pending_info'
  | 'pending_approval' | 'remediated' | 'verified' | 'closed'
  | 'reopened' | 'suppressed' | 'false_positive' | 'risk_accepted' | 'wont_fix'

export interface CVEReference {
  id: string
  url: string
  nvd_url: string
  mitre_url: string
  description: string
  cvss: number
  cvss_vector: string
  cvss_version: string
  epss: number
  cisa_known_exploited: boolean
  published: string
  modified: string
}

export interface ComplianceMapping {
  framework_id: string
  framework_name: string
  control_id: string
  control_title: string
  section: string
  subsection?: string
  severity: string
  url: string
}

export interface RemediationStep {
  order: number
  title: string
  description: string
  command?: string
  platform?: string
  automated: boolean
}

export interface Contact {
  name: string
  email: string
  team?: string
  phone?: string
  slack_id?: string
  on_call_url?: string
}

export interface ImpactedResource {
  resource_id: string
  resource_name: string
  resource_type: ResourceType
  relationship: string
  impact_level: string
}

export interface AssigneeInfo {
  user_id: string
  user_email: string
  user_name: string
  team: string
  assigned_at: string
  assigned_by: string
  due_date?: string
  escalated: boolean
  escalated_to?: string
  escalated_at?: string
}

export interface ToxicComboDetails {
  combo_type: string
  description: string
  related_findings: string[]
  attack_vector: string
  attack_path: string[]
  exploit_potential: string
  blast_radius: string
  mitre_techniques: string[]
}

export interface Finding {
  id: string
  source: string
  source_finding_id: string
  type: string
  title: string
  description: string
  resource_type: ResourceType
  resource_id: string
  resource_name: string
  resource_arn?: string
  hostname?: string
  ip_address?: string
  internet_facing?: boolean
  subnet?: string
  network_boundary?: string
  platform: string
  cloud_provider: CloudProvider
  region: string
  availability_zone?: string
  account_id: string
  account_name?: string
  environment_type: EnvironmentType
  impacted_resources?: ImpactedResource[]
  static_severity: string
  severity: string
  ai_risk_score: number
  ai_risk_level: string
  ai_risk_rationale: string
  ai_contextual_factors: string[]
  cvss?: number
  cvss_vector?: string
  epss?: number
  exploit_available: boolean
  cves?: CVEReference[]
  cwes?: string[]
  compliance_mappings?: ComplianceMapping[]
  mitre_tactics?: string[]
  mitre_techniques?: string[]
  toxic_combo_details?: ToxicComboDetails
  remediation: string
  remediation_steps?: RemediationStep[]
  auto_remediatable: boolean
  category: FindingCategory
  status: string
  workflow_status: WorkflowStatus
  assignee?: AssigneeInfo
  suppressed: boolean
  suppression_reason?: string
  technical_contact?: Contact
  service_name: string
  line_of_business: string
  cost_center?: string
  team?: string
  application?: string
  first_found_at: string
  last_seen_at: string
  resolved_at?: string
  due_date?: string
  sla_breach_date?: string
  deduplication_key: string
  canonical_rule_id: string
  ticket_id?: string
  ticket_url?: string
  tags?: Record<string, string>
}
