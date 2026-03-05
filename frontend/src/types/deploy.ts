export type DeployPhase =
  | 'idle'
  | 'planning'
  | 'creating'
  | 'configuring'
  | 'verifying'
  | 'live'
  | 'teardown'
  | 'complete'
  | 'error'

export interface DeployEvent {
  timestamp: string
  phase: DeployPhase
  message: string
  detail?: string
}

export interface TerraformPlanResource {
  address: string
  mode: 'managed'
  type: string
  name: string
  provider: string
  change: {
    actions: ('create' | 'update' | 'delete')[]
    before: Record<string, unknown> | null
    after: Record<string, unknown>
  }
}

export interface TerraformPlan {
  format_version: string
  terraform_version: string
  planned_values: {
    root_module: {
      resources: TerraformPlanResource[]
    }
  }
  resource_changes: TerraformPlanResource[]
}

export interface DeployPreviewConfig {
  resourceType: string
  provider: string
  region: string
  appId: string
  configuration: Record<string, unknown>
}
