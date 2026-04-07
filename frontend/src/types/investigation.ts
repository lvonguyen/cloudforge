export type InvestigationEntityType =
  | 'finding'
  | 'exposure_surface'
  | 'assignee'
  | 'technical_contact'
  | 'resource'
  | 'network_boundary'
  | 'compliance_mapping'
  | 'impacted_resource'

export interface InvestigationEntity {
  id: string
  type: InvestigationEntityType
  label: string
  sublabel?: string
  severity?: string
}
