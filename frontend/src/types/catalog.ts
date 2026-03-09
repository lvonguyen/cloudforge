export interface CatalogModule {
  id: string
  name: string
  description: string
  provider: 'aws' | 'azure' | 'gcp'
  resource_type: string
  version: string
  cost_estimate: string
  tags: string[]
  icon: string
  category: string
  compliance_tags: string[]
  auto_approved: boolean
  provisioning_time: string
}
