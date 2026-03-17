export type InvestigationEntityType =
  | 'finding'
  | 'assignee'
  | 'technical_contact'
  | 'resource'
  | 'compliance_mapping'
  | 'impacted_resource'

export interface InvestigationEntity {
  id: string
  type: InvestigationEntityType
  label: string
  sublabel?: string
  severity?: string
}
