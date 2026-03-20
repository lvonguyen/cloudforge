import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiClient, ApiError, fetchWithMockFallback } from '@/lib/api'
import { useToast } from '@/hooks/useToast'

export interface ExposedService {
  port: number
  protocol: string
  banner?: string
  tls: boolean
}

export interface Certificate {
  subject: string
  issuer: string
  not_before: string
  not_after: string
  sans?: string[]
}

export interface ASMAsset {
  id: string
  hostname: string
  ip: string
  services: ExposedService[]
  certs?: Certificate[]
  first_seen: string
  last_seen: string
}

interface ScanResult {
  domain: string
  assets: ASMAsset[]
  scanned_at: string
}

const MOCK_ASSETS: ASMAsset[] = [
  {
    id: 'asset-example-web', hostname: 'www.example.com', ip: '10.123.45.67',
    services: [
      { port: 443, protocol: 'https', tls: true },
      { port: 80, protocol: 'http', tls: false },
    ],
    certs: [{ subject: 'www.example.com', issuer: "Let's Encrypt", not_before: '2026-01-15T00:00:00Z', not_after: '2026-04-15T00:00:00Z', sans: ['www.example.com', 'example.com'] }],
    first_seen: '2026-03-18T10:00:00Z', last_seen: '2026-03-18T10:00:00Z',
  },
  {
    id: 'asset-example-api', hostname: 'api.example.com', ip: '10.123.45.68',
    services: [{ port: 443, protocol: 'https', tls: true }],
    certs: [{ subject: 'api.example.com', issuer: "Let's Encrypt", not_before: '2026-02-01T00:00:00Z', not_after: '2026-05-01T00:00:00Z' }],
    first_seen: '2026-03-18T10:00:00Z', last_seen: '2026-03-18T10:00:00Z',
  },
  {
    id: 'asset-example-bastion', hostname: 'bastion.example.com', ip: '10.123.45.69',
    services: [{ port: 22, protocol: 'ssh', banner: 'OpenSSH_8.9', tls: false }],
    first_seen: '2026-03-18T10:00:00Z', last_seen: '2026-03-18T10:00:00Z',
  },
  {
    id: 'asset-s3-public', hostname: 'assets.example.com.s3.amazonaws.com', ip: '52.216.100.35',
    services: [{ port: 443, protocol: 'https', tls: true }],
    certs: [{ subject: '*.s3.amazonaws.com', issuer: 'Amazon RSA 2048 M02', not_before: '2026-01-01T00:00:00Z', not_after: '2027-01-01T00:00:00Z' }],
    first_seen: '2026-02-10T14:00:00Z', last_seen: '2026-03-19T08:00:00Z',
  },
  {
    id: 'asset-cdn', hostname: 'cdn.example.com', ip: '13.224.0.12',
    services: [{ port: 443, protocol: 'https', tls: true }],
    certs: [{ subject: 'cdn.example.com', issuer: 'Amazon RSA 2048 M02', not_before: '2026-02-15T00:00:00Z', not_after: '2026-08-15T00:00:00Z', sans: ['cdn.example.com', '*.cdn.example.com'] }],
    first_seen: '2026-01-20T09:00:00Z', last_seen: '2026-03-19T08:00:00Z',
  },
  {
    id: 'asset-rds', hostname: 'db-prod.cluster-abc123.us-east-1.rds.amazonaws.com', ip: '10.0.3.42',
    services: [{ port: 5432, protocol: 'postgresql', tls: true }],
    first_seen: '2026-01-05T12:00:00Z', last_seen: '2026-03-19T08:00:00Z',
  },
  {
    id: 'asset-alb', hostname: 'app-lb-1234567890.us-east-1.elb.amazonaws.com', ip: '54.210.45.123',
    services: [
      { port: 443, protocol: 'https', tls: true },
      { port: 80, protocol: 'http', tls: false },
    ],
    certs: [{ subject: 'app.example.com', issuer: 'Amazon RSA 2048 M02', not_before: '2026-03-01T00:00:00Z', not_after: '2027-03-01T00:00:00Z', sans: ['app.example.com', '*.app.example.com'] }],
    first_seen: '2026-02-01T16:00:00Z', last_seen: '2026-03-19T08:00:00Z',
  },
  {
    id: 'asset-k8s-api', hostname: 'k8s-api.example.com', ip: '10.0.1.100',
    services: [{ port: 6443, protocol: 'https', banner: 'Kubernetes API v1.29', tls: true }],
    certs: [{ subject: 'k8s-api.example.com', issuer: 'kubernetes-ca', not_before: '2026-01-10T00:00:00Z', not_after: '2027-01-10T00:00:00Z' }],
    first_seen: '2026-01-10T00:00:00Z', last_seen: '2026-03-19T08:00:00Z',
  },
  {
    id: 'asset-azure-blob', hostname: 'examplestorage.blob.core.windows.net', ip: '20.150.38.228',
    services: [{ port: 443, protocol: 'https', tls: true }],
    certs: [{ subject: '*.blob.core.windows.net', issuer: 'Microsoft RSA TLS CA 02', not_before: '2026-02-20T00:00:00Z', not_after: '2027-02-20T00:00:00Z' }],
    first_seen: '2026-03-01T11:00:00Z', last_seen: '2026-03-19T08:00:00Z',
  },
  {
    id: 'asset-gcp-cloudrun', hostname: 'svc-prod-abcdef-uc.a.run.app', ip: '216.239.36.53',
    services: [{ port: 443, protocol: 'https', tls: true }],
    certs: [{ subject: '*.a.run.app', issuer: 'GTS CA 1C3', not_before: '2026-03-05T00:00:00Z', not_after: '2026-06-05T00:00:00Z' }],
    first_seen: '2026-03-05T08:00:00Z', last_seen: '2026-03-19T08:00:00Z',
  },
]

export function useScanDomain() {
  const qc = useQueryClient()
  const { toast } = useToast()
  return useMutation({
    mutationFn: (domain: string) =>
      apiClient.post<ScanResult>('/asm/scan', { domain }),
    onSuccess: (data) => {
      void qc.invalidateQueries({ queryKey: ['asm', 'assets'] })
      toast(`Scan complete: ${data.assets.length} asset${data.assets.length !== 1 ? 's' : ''} found`)
    },
    onError: (err: Error) => {
      if (err instanceof ApiError && err.status === 403) {
        toast('ASM scan requires operator or admin role', 'error')
      } else {
        toast('Scan failed', 'error')
      }
    },
  })
}

export function useASMAssets() {
  return useQuery({
    queryKey: ['asm', 'assets'],
    queryFn: () => fetchWithMockFallback<ASMAsset[]>(
      '/asm/assets',
      () => Promise.resolve({ default: MOCK_ASSETS }),
      'useASMAssets',
    ),
  })
}
