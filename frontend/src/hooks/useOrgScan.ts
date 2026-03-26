import { useMutation } from '@tanstack/react-query'
import { apiClient, ApiError } from '@/lib/api'
import { useToast } from '@/hooks/useToast'

export interface SecretFinding {
  pattern_id: string
  pattern_name: string
  type: string
  severity: string
  line: number
  column: number
  match: string
  context: string
  file?: string
}

export interface RepoResult {
  repo: string
  findings: SecretFinding[]
}

export interface OrgScanResult {
  org_name: string
  repos_scanned: number
  total_secrets: number
  results: RepoResult[]
  errors?: { repo: string; message: string }[]
}

export interface SecretUploadResult {
  secret_type: string
  findings: SecretFinding[]
  count: number
  ephemeral: boolean
}

const MOCK_RESULT: OrgScanResult = {
  org_name: 'acme-corp',
  repos_scanned: 3,
  total_secrets: 6,
  results: [
    {
      repo: 'acme-corp/frontend',
      findings: [
        { pattern_id: 'aws-access-key', pattern_name: 'AWS Access Key', type: 'credential', severity: 'critical', line: 12, column: 1, match: 'AKIA****REDACTED', context: 'AWS_ACCESS_KEY_ID=AKIA****REDACTED', file: '.env.example' },
        { pattern_id: 'generic-api-key', pattern_name: 'Generic API Key', type: 'api_key', severity: 'high', line: 45, column: 10, match: 'sk-****REDACTED', context: 'api_key: sk-****REDACTED', file: 'config/defaults.yaml' },
      ],
    },
    {
      repo: 'acme-corp/backend-api',
      findings: [
        { pattern_id: 'aws-access-key', pattern_name: 'AWS Access Key', type: 'credential', severity: 'critical', line: 12, column: 1, match: 'AKIA****REDACTED', context: 'AWS_ACCESS_KEY_ID=AKIA****REDACTED', file: '.env.example' },
        { pattern_id: 'generic-api-key', pattern_name: 'Generic API Key', type: 'api_key', severity: 'high', line: 45, column: 10, match: 'sk-****REDACTED', context: 'api_key: sk-****REDACTED', file: 'config/defaults.yaml' },
      ],
    },
    {
      repo: 'acme-corp/infra-terraform',
      findings: [
        { pattern_id: 'aws-access-key', pattern_name: 'AWS Access Key', type: 'credential', severity: 'critical', line: 12, column: 1, match: 'AKIA****REDACTED', context: 'AWS_ACCESS_KEY_ID=AKIA****REDACTED', file: '.env.example' },
        { pattern_id: 'generic-api-key', pattern_name: 'Generic API Key', type: 'api_key', severity: 'high', line: 45, column: 10, match: 'sk-****REDACTED', context: 'api_key: sk-****REDACTED', file: 'config/defaults.yaml' },
      ],
    },
  ],
}

export function useStartOrgScan() {
  const { toast } = useToast()
  const isDev = import.meta.env.DEV
  const isDemo = import.meta.env.VITE_DEMO_MODE === 'true'

  return useMutation({
    mutationFn: async (req: { org_name: string; repos?: string[]; secret_type?: string }) => {
      try {
        return await apiClient.post<OrgScanResult>('/secrets/org-scan', req)
      } catch (err) {
        // Always propagate RBAC 403 — even in demo mode, respect the authz boundary.
        if (err instanceof ApiError && err.status === 403) throw err
        // In dev/demo mode, fall back to mock for network/5xx errors so the
        // scan produces visible results when the backend is unavailable.
        if (isDev || isDemo) {
          console.warn('[useStartOrgScan] API unavailable, using mock data')
          return { ...MOCK_RESULT, org_name: req.org_name }
        }
        // In production (non-demo), propagate all errors — don't show mock
        // data as if it were real scan results.
        if (err instanceof ApiError && err.status < 500) throw err
        throw err
      }
    },
    onSuccess: (data) => {
      toast(`Scan complete: ${data.total_secrets} secret${data.total_secrets !== 1 ? 's' : ''} found in ${data.repos_scanned} repo${data.repos_scanned !== 1 ? 's' : ''}`)
    },
    onError: (err: Error) => {
      if (err instanceof ApiError && err.status === 403) {
        toast('Org scan requires admin role', 'error')
      } else {
        toast('Scan failed', 'error')
      }
    },
  })
}

const MOCK_UPLOAD_RESULT: SecretUploadResult = {
  secret_type: 'aws_access_key',
  findings: [
    {
      pattern_id: 'aws-access-key',
      pattern_name: 'AWS Access Key',
      type: 'credential',
      severity: 'critical',
      line: 1,
      column: 1,
      match: '****REDACTED',
      context: 'Matched known secret pattern',
    },
  ],
  count: 1,
  ephemeral: true,
}

export function useUploadSuspectedSecret() {
  const { toast } = useToast()
  const isDev = import.meta.env.DEV
  const isDemo = import.meta.env.VITE_DEMO_MODE === 'true'

  return useMutation({
    mutationFn: async (req: { secret_type: string; content: string }) => {
      try {
        return await apiClient.post<SecretUploadResult>('/secrets/upload', req)
      } catch (err) {
        if (err instanceof ApiError && err.status === 403) throw err
        if (isDev || isDemo) {
          console.warn('[useUploadSuspectedSecret] API unavailable, using mock')
          return { ...MOCK_UPLOAD_RESULT, secret_type: req.secret_type }
        }
        throw err
      }
    },
    onSuccess: (data) => {
      toast(`Analysis complete: ${data.count} pattern match${data.count !== 1 ? 'es' : ''} found (ephemeral — nothing persisted)`)
    },
    onError: (err: Error) => {
      if (err instanceof ApiError && err.status === 403) {
        toast('Upload requires operator or admin role', 'error')
      } else {
        toast('Analysis failed', 'error')
      }
    },
  })
}
