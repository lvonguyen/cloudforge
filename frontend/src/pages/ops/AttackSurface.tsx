import { useState } from 'react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from '@/components/ui/table'
import { Globe, Search, Shield, AlertTriangle } from 'lucide-react'
import { useScanDomain, useASMAssets } from '@/hooks/useASM'
import type { ASMAsset, Certificate } from '@/hooks/useASM'
import { useActionCooldown } from '@/hooks/useActionCooldown'
import { useToast } from '@/hooks/useToast'
import { ToastStack } from '@/components/ui/ToastStack'

const PROTOCOL_COLORS: Record<string, string> = {
  https: 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300',
  http: 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-300',
  ssh: 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-300',
  dns: 'bg-purple-100 text-purple-700 dark:bg-purple-900/30 dark:text-purple-300',
  smtp: 'bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-300',
}

function certExpiryClass(cert: Certificate): string {
  const daysLeft = Math.ceil((new Date(cert.not_after).getTime() - Date.now()) / 86_400_000)
  if (daysLeft < 0) return 'text-red-700 bg-red-100 dark:text-red-300 dark:bg-red-900/30'
  if (daysLeft < 30) return 'text-red-600 bg-red-50 dark:text-red-400 dark:bg-red-900/20'
  if (daysLeft < 90) return 'text-yellow-600 bg-yellow-50 dark:text-yellow-400 dark:bg-yellow-900/20'
  return 'text-green-600 bg-green-50 dark:text-green-400 dark:bg-green-900/20'
}

function certDaysLeft(cert: Certificate): string {
  const days = Math.ceil((new Date(cert.not_after).getTime() - Date.now()) / 86_400_000)
  if (days < 0) return `Expired ${Math.abs(days)}d ago`
  return `${days}d`
}

export default function AttackSurface() {
  const [domain, setDomain] = useState('')
  const scanMutation = useScanDomain()
  const { data: assets = [], isLoading } = useASMAssets()
  const scanCooldown = useActionCooldown({ key: 'asm-scan', cooldownMs: 10_000 })
  const { toasts, dismiss } = useToast()

  function handleScan() {
    if (!domain.trim() || !scanCooldown.canFire) return
    scanCooldown.fire()
    scanMutation.mutate(domain.trim())
  }

  const displayAssets = scanMutation.data?.assets ?? assets

  return (
    <div className="space-y-6 max-w-5xl">
      <div>
        <h1 className="text-xl font-semibold">Attack Surface</h1>
        <p className="text-sm text-muted-foreground mt-0.5">
          External asset discovery and certificate monitoring
        </p>
      </div>

      {/* Scan bar */}
      <Card>
        <CardContent className="p-4">
          <div className="flex gap-2">
            <div className="relative flex-1">
              <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
              <input
                type="text"
                value={domain}
                onChange={e => setDomain(e.target.value)}
                onKeyDown={e => { if (e.key === 'Enter') handleScan() }}
                placeholder="Enter domain to scan (e.g. example.com)"
                className="w-full pl-8 pr-3 py-2 text-sm bg-muted/50 border border-border outline-none"
              />
            </div>
            <Button
              size="sm"
              className="gap-1.5 text-xs shrink-0"
              disabled={!domain.trim() || !scanCooldown.canFire || scanMutation.isPending}
              onClick={handleScan}
            >
              <Globe className="h-3.5 w-3.5" />
              {scanMutation.isPending ? 'Scanning...' : !scanCooldown.canFire ? 'Cooldown...' : 'Scan'}
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* Summary stats */}
      {displayAssets.length > 0 && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          <div className="border border-border p-3">
            <p className="text-[10px] text-muted-foreground uppercase tracking-wide">Assets</p>
            <p className="text-lg font-semibold mt-0.5">{displayAssets.length}</p>
          </div>
          <div className="border border-border p-3">
            <p className="text-[10px] text-muted-foreground uppercase tracking-wide">Services</p>
            <p className="text-lg font-semibold mt-0.5">{displayAssets.reduce((s, a) => s + a.services.length, 0)}</p>
          </div>
          <div className="border border-border p-3">
            <p className="text-[10px] text-muted-foreground uppercase tracking-wide">Certificates</p>
            <p className="text-lg font-semibold mt-0.5">{displayAssets.reduce((s, a) => s + (a.certs?.length ?? 0), 0)}</p>
          </div>
          <div className="border border-border p-3">
            <p className="text-[10px] text-muted-foreground uppercase tracking-wide">Expiring (&lt;30d)</p>
            <p className="text-lg font-semibold mt-0.5 text-red-600 dark:text-red-400">
              {displayAssets.reduce((s, a) => s + (a.certs?.filter(c => {
                const d = Math.ceil((new Date(c.not_after).getTime() - Date.now()) / 86_400_000)
                return d >= 0 && d < 30
              }).length ?? 0), 0)}
            </p>
          </div>
        </div>
      )}

      {/* Assets table */}
      <Card>
        <CardHeader className="pb-2">
          <div className="flex items-center gap-2">
            <Shield className="h-4 w-4 text-muted-foreground" />
            <CardTitle className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
              Discovered Assets
            </CardTitle>
          </div>
        </CardHeader>
        <CardContent className="p-0">
          {isLoading && displayAssets.length === 0 ? (
            <div className="text-xs text-muted-foreground p-6 text-center">Loading assets...</div>
          ) : displayAssets.length === 0 ? (
            <div className="flex flex-col items-center py-12 text-muted-foreground">
              <Globe className="h-8 w-8 opacity-40 mb-2" />
              <p className="text-sm">No assets discovered yet.</p>
              <p className="text-xs mt-1">Enter a domain above to scan.</p>
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="text-xs pl-4">Hostname</TableHead>
                  <TableHead className="text-xs">IP</TableHead>
                  <TableHead className="text-xs">Services</TableHead>
                  <TableHead className="text-xs">Cert Expiry</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {displayAssets.map((asset: ASMAsset) => (
                  <TableRow key={asset.id}>
                    <TableCell className="text-xs font-mono pl-4">{asset.hostname}</TableCell>
                    <TableCell className="text-xs font-mono text-muted-foreground">{asset.ip}</TableCell>
                    <TableCell>
                      <div className="flex flex-wrap gap-1">
                        {asset.services.map(svc => (
                          <span
                            key={`${svc.port}-${svc.protocol}`}
                            className={`text-[10px] font-medium px-1.5 py-0.5 ${PROTOCOL_COLORS[svc.protocol] ?? 'bg-gray-100 text-gray-700 dark:bg-gray-900/30 dark:text-gray-300'}`}
                          >
                            {svc.protocol.toUpperCase()}:{svc.port}
                          </span>
                        ))}
                      </div>
                    </TableCell>
                    <TableCell>
                      {asset.certs && asset.certs.length > 0 ? (
                        <div className="flex flex-wrap gap-1">
                          {asset.certs.map((cert, ci) => (
                            <span key={ci} className={`text-[10px] font-medium px-1.5 py-0.5 ${certExpiryClass(cert)}`}>
                              {certDaysLeft(cert)}
                            </span>
                          ))}
                        </div>
                      ) : (
                        <span className="text-[10px] text-muted-foreground">--</span>
                      )}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      {/* Warning for assets without TLS */}
      {displayAssets.some(a => a.services.some(s => s.protocol === 'http' || (!s.tls && s.protocol !== 'ssh'))) && (
        <div className="flex items-center gap-2 text-xs text-yellow-600 dark:text-yellow-400 border border-yellow-200 dark:border-yellow-800 px-3 py-2">
          <AlertTriangle className="h-3.5 w-3.5 shrink-0" />
          <span>Some services are exposed without TLS encryption.</span>
        </div>
      )}

      <ToastStack toasts={toasts} onDismiss={dismiss} />
    </div>
  )
}
