import { useState } from 'react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from '@/components/ui/table'
import { Link2, Plus, Trash2, ChevronRight, X, CheckCircle2, XCircle, Clock } from 'lucide-react'
import { useWebhooks, useCreateWebhook, useDeleteWebhook, useWebhookDeliveries, WEBHOOK_EVENTS } from '@/hooks/useWebhooks'
import type { WebhookEndpoint } from '@/hooks/useWebhooks'
import { useToast } from '@/hooks/useToast'
import { ToastStack } from '@/components/ui/ToastStack'

const STATUS_FILTERS = ['all', 'active', 'failed'] as const
type StatusFilter = (typeof STATUS_FILTERS)[number]

function formatDate(iso: string): string {
  try { return new Date(iso).toLocaleDateString('en-US', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }) }
  catch { return iso }
}

function DeliveryDrawer({ endpoint, onClose }: { endpoint: WebhookEndpoint; onClose: () => void }) {
  const { data: deliveries = [] } = useWebhookDeliveries(endpoint.id)

  return (
    <div className="fixed inset-0 z-50">
      <div className="absolute inset-0 bg-black/40" onClick={onClose} />
      <div className="absolute right-0 top-0 h-full w-full max-w-md bg-background border-l border-border shadow-lg overflow-y-auto">
        <div className="flex items-center justify-between px-4 py-3 border-b border-border">
          <div>
            <p className="text-sm font-medium">Deliveries</p>
            <p className="text-[10px] text-muted-foreground font-mono truncate max-w-[300px]">{endpoint.url}</p>
          </div>
          <button onClick={onClose} className="text-muted-foreground hover:text-foreground">
            <X className="h-4 w-4" />
          </button>
        </div>
        <div className="p-4 space-y-2">
          {deliveries.length === 0 ? (
            <p className="text-xs text-muted-foreground py-8 text-center">No deliveries yet.</p>
          ) : (
            deliveries.map(d => (
              <Card key={d.id}>
                <CardContent className="p-3">
                  <div className="flex items-center gap-2 mb-1">
                    {d.status === 'success' ? (
                      <CheckCircle2 className="h-3.5 w-3.5 text-green-500 shrink-0" />
                    ) : d.status === 'failed' ? (
                      <XCircle className="h-3.5 w-3.5 text-red-500 shrink-0" />
                    ) : (
                      <Clock className="h-3.5 w-3.5 text-yellow-500 shrink-0" />
                    )}
                    <Badge variant="outline" className="text-[10px]">{d.event_type}</Badge>
                    {d.status_code ? (
                      <span className={`text-[10px] font-mono ${d.status_code < 400 ? 'text-green-600 dark:text-green-400' : 'text-red-600 dark:text-red-400'}`}>{d.status_code}</span>
                    ) : null}
                    <span className="text-[10px] text-muted-foreground ml-auto">{d.duration_ms}ms</span>
                  </div>
                  <p className="text-[10px] text-muted-foreground">{formatDate(d.attempted_at)}</p>
                  {d.error && <p className="text-[10px] text-red-600 dark:text-red-400 mt-1">{d.error}</p>}
                </CardContent>
              </Card>
            ))
          )}
        </div>
      </div>
    </div>
  )
}

function RegisterModal({ onClose }: { onClose: () => void }) {
  const [url, setUrl] = useState('')
  const [secret, setSecret] = useState('')
  const [selectedEvents, setSelectedEvents] = useState<string[]>([])
  const createWebhook = useCreateWebhook()

  function toggleEvent(evt: string) {
    setSelectedEvents(prev =>
      prev.includes(evt) ? prev.filter(e => e !== evt) : [...prev, evt]
    )
  }

  function handleSubmit() {
    if (!url.trim()) return
    createWebhook.mutate(
      { url: url.trim(), secret: secret.trim(), events: selectedEvents },
      { onSuccess: () => onClose() },
    )
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      <div className="absolute inset-0 bg-black/40" onClick={onClose} />
      <div className="relative bg-background border border-border shadow-lg w-full max-w-md p-6 space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="text-sm font-semibold">Register Webhook</h2>
          <button onClick={onClose} aria-label="Close" className="text-muted-foreground hover:text-foreground"><X className="h-4 w-4" /></button>
        </div>
        <div className="space-y-3">
          <div>
            <label className="text-[10px] font-medium uppercase tracking-wide text-muted-foreground">Endpoint URL</label>
            <input
              type="url" value={url} onChange={e => setUrl(e.target.value)}
              placeholder="https://hooks.example.com/webhook"
              className="w-full mt-1 px-3 py-1.5 text-xs bg-muted/50 border border-border outline-none"
            />
          </div>
          <div>
            <label className="text-[10px] font-medium uppercase tracking-wide text-muted-foreground">Signing Secret</label>
            <input
              type="password" value={secret} onChange={e => setSecret(e.target.value)}
              placeholder="whsec_..."
              className="w-full mt-1 px-3 py-1.5 text-xs bg-muted/50 border border-border outline-none"
            />
          </div>
          <div>
            <label className="text-[10px] font-medium uppercase tracking-wide text-muted-foreground">
              Events {selectedEvents.length > 0 ? `(${selectedEvents.length})` : '(all if none selected)'}
            </label>
            <div className="flex flex-wrap gap-1 mt-1">
              {WEBHOOK_EVENTS.map(evt => (
                <button
                  key={evt}
                  onClick={() => toggleEvent(evt)}
                  className={`text-[10px] px-2 py-0.5 border transition-colors ${
                    selectedEvents.includes(evt)
                      ? 'bg-foreground text-background border-foreground'
                      : 'border-border text-muted-foreground hover:text-foreground'
                  }`}
                >
                  {evt}
                </button>
              ))}
            </div>
          </div>
        </div>
        <div className="flex justify-end gap-2">
          <Button size="sm" variant="outline" className="text-xs" onClick={onClose}>Cancel</Button>
          <Button size="sm" className="text-xs" disabled={!url.trim() || createWebhook.isPending} onClick={handleSubmit}>
            {createWebhook.isPending ? 'Registering...' : 'Register'}
          </Button>
        </div>
      </div>
    </div>
  )
}

export default function Webhooks() {
  const { data: endpoints = [], isLoading } = useWebhooks()
  const deleteWebhook = useDeleteWebhook()
  const [statusFilter, setStatusFilter] = useState<StatusFilter>('all')
  const [showRegister, setShowRegister] = useState(false)
  const [selectedEndpoint, setSelectedEndpoint] = useState<WebhookEndpoint | null>(null)
  const [confirmDelete, setConfirmDelete] = useState<string | null>(null)
  const { toasts, dismiss } = useToast()

  const filtered = statusFilter === 'all'
    ? endpoints
    : statusFilter === 'active'
      ? endpoints.filter(e => e.active)
      : endpoints.filter(e => !e.active)

  if (isLoading) return <div className="text-sm text-muted-foreground p-6">Loading webhooks...</div>

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold">Webhooks</h1>
          <p className="text-sm text-muted-foreground mt-0.5">{endpoints.length} endpoint{endpoints.length !== 1 ? 's' : ''} registered</p>
        </div>
        <Button size="sm" className="gap-1.5 text-xs" onClick={() => setShowRegister(true)}>
          <Plus className="h-3.5 w-3.5" />Register Endpoint
        </Button>
      </div>

      <div className="flex items-center gap-1">
        {STATUS_FILTERS.map(sf => (
          <button
            key={sf}
            onClick={() => setStatusFilter(sf)}
            className={`text-xs px-3 py-1 transition-colors capitalize ${
              statusFilter === sf
                ? 'bg-primary text-primary-foreground'
                : 'bg-muted/50 text-muted-foreground hover:bg-muted'
            }`}
          >
            {sf}
          </button>
        ))}
      </div>

      <Card>
        <CardHeader className="pb-2">
          <div className="flex items-center gap-2">
            <Link2 className="h-4 w-4 text-muted-foreground" />
            <CardTitle className="text-sm font-medium">{filtered.length} endpoint{filtered.length !== 1 ? 's' : ''}</CardTitle>
          </div>
        </CardHeader>
        <CardContent className="p-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="text-xs pl-4">URL</TableHead>
                <TableHead className="text-xs">Events</TableHead>
                <TableHead className="text-xs">Status</TableHead>
                <TableHead className="text-xs">Created</TableHead>
                <TableHead className="text-xs w-20" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {filtered.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={5} className="text-center text-xs text-muted-foreground py-8">
                    No webhook endpoints registered.
                  </TableCell>
                </TableRow>
              ) : (
                filtered.map(ep => (
                  <TableRow
                    key={ep.id}
                    className="cursor-pointer hover:bg-muted/50"
                    onClick={() => setSelectedEndpoint(ep)}
                  >
                    <TableCell className="text-xs pl-4 font-mono truncate max-w-[300px]">{ep.url}</TableCell>
                    <TableCell>
                      <div className="flex flex-wrap gap-0.5">
                        {ep.events.slice(0, 3).map(e => (
                          <Badge key={e} variant="outline" className="text-[10px]">{e}</Badge>
                        ))}
                        {ep.events.length > 3 && (
                          <Badge variant="outline" className="text-[10px]">+{ep.events.length - 3}</Badge>
                        )}
                      </div>
                    </TableCell>
                    <TableCell>
                      <span className={`text-[10px] font-medium px-2 py-0.5 ${
                        ep.active
                          ? 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300'
                          : 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300'
                      }`}>
                        {ep.active ? 'active' : 'failed'}
                      </span>
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground">{formatDate(ep.created_at)}</TableCell>
                    <TableCell>
                      <div className="flex items-center gap-1" onClick={e => e.stopPropagation()}>
                        <button
                          onClick={() => setSelectedEndpoint(ep)}
                          className="p-1 text-muted-foreground hover:text-foreground"
                          aria-label="View deliveries"
                        >
                          <ChevronRight className="h-3.5 w-3.5" />
                        </button>
                        {confirmDelete === ep.id ? (
                          <Button
                            size="sm" variant="destructive" className="text-[10px] h-6 px-2"
                            disabled={deleteWebhook.isPending}
                            onClick={() => {
                              deleteWebhook.mutate(ep.id, { onSuccess: () => setConfirmDelete(null) })
                            }}
                          >
                            Confirm
                          </Button>
                        ) : (
                          <button
                            onClick={() => setConfirmDelete(ep.id)}
                            className="p-1 text-muted-foreground hover:text-red-600 dark:hover:text-red-400"
                            aria-label="Delete endpoint"
                          >
                            <Trash2 className="h-3.5 w-3.5" />
                          </button>
                        )}
                      </div>
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      {showRegister && <RegisterModal onClose={() => setShowRegister(false)} />}
      {selectedEndpoint && <DeliveryDrawer endpoint={selectedEndpoint} onClose={() => setSelectedEndpoint(null)} />}
      <ToastStack toasts={toasts} onDismiss={dismiss} />
    </div>
  )
}
