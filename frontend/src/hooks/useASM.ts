import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiClient, ApiError } from '@/lib/api'
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
    queryFn: async () => {
      try {
        return await apiClient.get<ASMAsset[]>('/asm/assets')
      } catch (err) {
        if (err instanceof ApiError && err.status < 500) throw err
        console.warn('[useASMAssets] API unavailable, using mock data')
        return MOCK_ASSETS
      }
    },
  })
}
