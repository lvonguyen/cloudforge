import { useState, useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from '@/components/ui/table'
import { Lock, Unlock, Eye, AlertTriangle } from 'lucide-react'
import { apiClient, ApiError } from '@/lib/api'
import { ProviderBadge } from '@/components/ui/ProviderBadge'
import type { DataAsset, DataSensitivity, ScanStatus } from '@/types/dspm'

// Mock data for development — replaced by real API in production.
const MOCK_ASSETS: DataAsset[] = [
  { id: 'da-001', name: 'customer-pii-bucket', resource_id: 'arn:aws:s3:::customer-pii-prod', resource_type: 'object_storage', cloud_provider: 'aws', region: 'us-east-1', account_id: '111222333444', sensitivity: 'PII', scan_status: 'scanned', record_count: 2_340_000, size_bytes: 48_000_000_000, findings_count: 3, last_scanned_at: '2026-03-14T08:00:00Z', encryption_enabled: true, public_access: false },
  { id: 'da-002', name: 'analytics-warehouse', resource_id: 'projects/analytics/datasets/events', resource_type: 'data_warehouse', cloud_provider: 'gcp', region: 'us-central1', account_id: 'analytics-prod', sensitivity: 'INTERNAL', scan_status: 'scanned', record_count: 890_000_000, size_bytes: 320_000_000_000, findings_count: 0, last_scanned_at: '2026-03-13T22:00:00Z', encryption_enabled: true, public_access: false },
  { id: 'da-003', name: 'patient-records-db', resource_id: 'arn:aws:rds:us-west-2:555666777888:db/patient-db', resource_type: 'database', cloud_provider: 'aws', region: 'us-west-2', account_id: '555666777888', sensitivity: 'PHI', scan_status: 'scanned', record_count: 450_000, size_bytes: 12_000_000_000, findings_count: 1, last_scanned_at: '2026-03-14T06:30:00Z', encryption_enabled: true, public_access: false },
  { id: 'da-004', name: 'payment-card-vault', resource_id: 'arn:aws:dynamodb:eu-west-1:999888777666:table/card-tokens', resource_type: 'database', cloud_provider: 'aws', region: 'eu-west-1', account_id: '999888777666', sensitivity: 'PCI', scan_status: 'scanned', record_count: 1_200_000, size_bytes: 3_500_000_000, findings_count: 0, last_scanned_at: '2026-03-14T07:15:00Z', encryption_enabled: true, public_access: false },
  { id: 'da-005', name: 'marketing-assets', resource_id: 'arn:aws:s3:::marketing-public', resource_type: 'object_storage', cloud_provider: 'aws', region: 'us-east-1', account_id: '111222333444', sensitivity: 'PUBLIC', scan_status: 'scanned', record_count: 15_000, size_bytes: 2_400_000_000, findings_count: 2, last_scanned_at: '2026-03-12T10:00:00Z', encryption_enabled: false, public_access: true },
  { id: 'da-006', name: 'hr-fileshare', resource_id: '/subscriptions/abc/resourceGroups/hr/providers/Microsoft.Storage/storageAccounts/hrfiles', resource_type: 'file_share', cloud_provider: 'azure', region: 'eastus2', account_id: 'sub-abc-def', sensitivity: 'CONFIDENTIAL', scan_status: 'pending', findings_count: 0, encryption_enabled: true, public_access: false },
  { id: 'da-007', name: 'event-stream', resource_id: 'arn:aws:sqs:us-east-1:111222333444:events-queue', resource_type: 'message_queue', cloud_provider: 'aws', region: 'us-east-1', account_id: '111222333444', sensitivity: 'INTERNAL', scan_status: 'not_configured', findings_count: 0, encryption_enabled: true, public_access: false },
  { id: 'da-008', name: 'compliance-docs', resource_id: 'arn:aws:s3:::compliance-restricted', resource_type: 'object_storage', cloud_provider: 'aws', region: 'us-gov-west-1', account_id: '444333222111', sensitivity: 'RESTRICTED', scan_status: 'failed', findings_count: 0, encryption_enabled: true, public_access: false },
]

async function fetchDataAssets(): Promise<DataAsset[]> {
  try {
    const resp = await apiClient.get<{ data: DataAsset[] }>('/data-classification/assets')
    return resp.data
  } catch (err) {
    if (err instanceof ApiError && err.status < 500) throw err
    if (import.meta.env.PROD) throw err
    return MOCK_ASSETS
  }
}

function useDataAssets() {
  return useQuery({ queryKey: ['data-classification'], queryFn: fetchDataAssets })
}

const SENSITIVITY_COLORS: Record<DataSensitivity, string> = {
  PUBLIC: 'bg-gray-100 text-gray-700 dark:bg-gray-900/30 dark:text-gray-300',
  INTERNAL: 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-300',
  CONFIDENTIAL: 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-300',
  RESTRICTED: 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300',
  PII: 'bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-300',
  PHI: 'bg-purple-100 text-purple-700 dark:bg-purple-900/30 dark:text-purple-300',
  PCI: 'bg-pink-100 text-pink-700 dark:bg-pink-900/30 dark:text-pink-300',
}

const SCAN_STATUS_COLORS: Record<ScanStatus, string> = {
  scanned: 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300',
  pending: 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-300',
  failed: 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300',
  not_configured: 'bg-gray-100 text-gray-700 dark:bg-gray-900/30 dark:text-gray-300',
}

function formatBytes(bytes?: number): string {
  if (bytes == null) return '—'
  if (bytes >= 1e12) return `${(bytes / 1e12).toFixed(1)} TB`
  if (bytes >= 1e9) return `${(bytes / 1e9).toFixed(1)} GB`
  if (bytes >= 1e6) return `${(bytes / 1e6).toFixed(1)} MB`
  return `${(bytes / 1e3).toFixed(0)} KB`
}

function formatCount(n?: number): string {
  if (n == null) return '—'
  return n.toLocaleString()
}

export default function DataClassification() {
  const { data: assets = [], isLoading, isError } = useDataAssets()
  const [sensitivityFilter, setSensitivityFilter] = useState<DataSensitivity | 'ALL'>('ALL')

  const filtered = sensitivityFilter === 'ALL'
    ? assets
    : assets.filter(a => a.sensitivity === sensitivityFilter)

  const stats = useMemo(() => {
    const sensitive = assets.filter(a => ['PII', 'PHI', 'PCI', 'RESTRICTED', 'CONFIDENTIAL'].includes(a.sensitivity)).length
    const encrypted = assets.filter(a => a.encryption_enabled).length
    const publicAccess = assets.filter(a => a.public_access).length
    const unscanned = assets.filter(a => a.scan_status !== 'scanned').length
    return { total: assets.length, sensitive, encrypted, publicAccess, unscanned }
  }, [assets])

  if (isLoading) return <div className="text-sm text-muted-foreground p-6">Scanning data assets...</div>
  if (isError) return <div className="text-sm text-destructive p-6">Failed to load data classification.</div>

  const SENSITIVITY_OPTIONS: (DataSensitivity | 'ALL')[] = ['ALL', 'PCI', 'PHI', 'PII', 'RESTRICTED', 'CONFIDENTIAL', 'INTERNAL', 'PUBLIC']

  return (
    <div className="space-y-6 max-w-5xl">
      <div>
        <h1 className="text-xl font-semibold">Data Classification</h1>
        <p className="text-sm text-muted-foreground mt-0.5">
          {stats.total} data assets · {stats.sensitive} sensitive
        </p>
      </div>

      {/* Stats bar */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        {[
          { label: 'Total Assets', value: stats.total },
          { label: 'Sensitive', value: stats.sensitive },
          { label: 'Encrypted', value: stats.encrypted },
          { label: 'Public Access', value: stats.publicAccess, warn: stats.publicAccess > 0 },
          { label: 'Unscanned', value: stats.unscanned, warn: stats.unscanned > 0 },
        ].map(({ label, value, warn }) => (
          <div key={label} className="border border-border p-3">
            <p className="text-[10px] text-muted-foreground uppercase tracking-wide">{label}</p>
            <p className={`text-lg font-semibold mt-0.5 ${warn ? 'text-red-600 dark:text-red-400' : ''}`}>{value}</p>
          </div>
        ))}
      </div>

      {/* Sensitivity filter pills */}
      <div className="flex items-center gap-1.5 flex-wrap">
        {SENSITIVITY_OPTIONS.map(s => (
          <button
            key={s}
            onClick={() => setSensitivityFilter(s)}
            className={`text-[10px] font-medium px-2.5 py-1 border transition-colors ${
              sensitivityFilter === s
                ? 'bg-foreground text-background border-foreground'
                : 'border-border text-muted-foreground hover:text-foreground'
            }`}
          >
            {s}
          </button>
        ))}
      </div>

      {/* Assets table */}
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
            Data Assets {sensitivityFilter !== 'ALL' && `— ${sensitivityFilter}`}
          </CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="text-xs pl-4">Name</TableHead>
                <TableHead className="text-xs">Provider</TableHead>
                <TableHead className="text-xs">Type</TableHead>
                <TableHead className="text-xs">Sensitivity</TableHead>
                <TableHead className="text-xs">Scan</TableHead>
                <TableHead className="text-xs text-right">Records</TableHead>
                <TableHead className="text-xs text-right">Size</TableHead>
                <TableHead className="text-xs text-center">Enc</TableHead>
                <TableHead className="text-xs text-center">Pub</TableHead>
                <TableHead className="text-xs text-right pr-4">Findings</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {filtered.map(asset => (
                <TableRow key={asset.id}>
                  <TableCell className="text-xs pl-4">
                    <div>
                      <span className="font-medium">{asset.name}</span>
                      <p className="text-[10px] text-muted-foreground font-mono truncate max-w-[200px]">{asset.resource_id}</p>
                    </div>
                  </TableCell>
                  <TableCell><ProviderBadge provider={asset.cloud_provider} /></TableCell>
                  <TableCell className="text-xs text-muted-foreground">{asset.resource_type.replace('_', ' ')}</TableCell>
                  <TableCell>
                    <Badge variant="outline" className={`text-[10px] px-1.5 py-0 rounded-none ${SENSITIVITY_COLORS[asset.sensitivity]}`}>
                      {asset.sensitivity}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    <span className={`text-[10px] font-medium px-1.5 py-0.5 rounded-none ${SCAN_STATUS_COLORS[asset.scan_status]}`}>
                      {asset.scan_status.replace('_', ' ')}
                    </span>
                  </TableCell>
                  <TableCell className="text-xs text-right tabular-nums">{formatCount(asset.record_count)}</TableCell>
                  <TableCell className="text-xs text-right tabular-nums">{formatBytes(asset.size_bytes)}</TableCell>
                  <TableCell className="text-center">
                    {asset.encryption_enabled
                      ? <Lock className="h-3.5 w-3.5 text-green-500 mx-auto" />
                      : <Unlock className="h-3.5 w-3.5 text-red-500 mx-auto" />
                    }
                  </TableCell>
                  <TableCell className="text-center">
                    {asset.public_access
                      ? <Eye className="h-3.5 w-3.5 text-red-500 mx-auto" />
                      : <span className="text-[10px] text-muted-foreground">—</span>
                    }
                  </TableCell>
                  <TableCell className={`text-xs text-right pr-4 tabular-nums ${asset.findings_count > 0 ? 'text-red-600 dark:text-red-400 font-medium' : 'text-muted-foreground'}`}>
                    {asset.findings_count}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      {filtered.length === 0 && (
        <div className="text-center py-12 text-muted-foreground">
          <AlertTriangle className="h-8 w-8 mx-auto mb-2 opacity-40" />
          <p className="text-sm">No data assets match the current filter.</p>
        </div>
      )}
    </div>
  )
}
