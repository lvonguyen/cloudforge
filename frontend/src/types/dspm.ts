export type DataSensitivity = 'PUBLIC' | 'INTERNAL' | 'CONFIDENTIAL' | 'RESTRICTED' | 'PII' | 'PHI' | 'PCI'
export type DataStoreType = 'object_storage' | 'database' | 'data_warehouse' | 'file_share' | 'message_queue'
export type ScanStatus = 'scanned' | 'pending' | 'failed' | 'not_configured'

export interface DataAsset {
  id: string
  name: string
  resource_id: string
  resource_type: DataStoreType
  cloud_provider: string
  region: string
  account_id: string
  sensitivity: DataSensitivity
  scan_status: ScanStatus
  record_count?: number
  size_bytes?: number
  findings_count: number
  last_scanned_at?: string
  encryption_enabled: boolean
  public_access: boolean
}
