import { useState } from 'react'
import { Card, CardContent } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Separator } from '@/components/ui/separator'
import { ProviderBadge } from '@/components/ui/ProviderBadge'
import {
  useFindingTicket,
  useTicketComments,
  useAddTicketComment,
  useSyncTicketStatus,
} from '@/hooks/useIntegrations'
import {
  ExternalLink,
  RefreshCw,
  CheckCircle2,
  Send,
  Clock,
  User,
  Hash,
  AlertTriangle,
  MessageSquare,
} from 'lucide-react'

const TICKET_STATUS_COLORS: Record<string, string> = {
  open: 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-300',
  in_progress: 'bg-indigo-100 text-indigo-700 dark:bg-indigo-900/30 dark:text-indigo-300',
  resolved: 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300',
  closed: 'bg-gray-100 text-gray-700 dark:bg-gray-900/30 dark:text-gray-300',
}

const PRIORITY_COLORS: Record<string, string> = {
  critical: 'bg-red-100 text-red-800 border-red-300 dark:bg-red-900/30 dark:text-red-300 dark:border-red-800',
  high: 'bg-orange-100 text-orange-800 border-orange-300 dark:bg-orange-900/30 dark:text-orange-300 dark:border-orange-800',
  medium: 'bg-yellow-100 text-yellow-800 border-yellow-300 dark:bg-yellow-900/30 dark:text-yellow-300 dark:border-yellow-800',
  low: 'bg-blue-100 text-blue-800 border-blue-300 dark:bg-blue-900/30 dark:text-blue-300 dark:border-blue-800',
}

function formatRelativeTime(iso: string): string {
  const ts = new Date(iso).getTime()
  if (isNaN(ts)) return '--'
  const diff = Date.now() - ts
  if (diff < 0) return 'upcoming'
  const mins = Math.floor(diff / 60_000)
  if (mins < 1) return 'just now'
  if (mins < 60) return `${mins}m ago`
  const hours = Math.floor(mins / 60)
  if (hours < 24) return `${hours}h ago`
  const days = Math.floor(hours / 24)
  return `${days}d ago`
}

function computeSlaCountdown(createdAt: string, priority: string): { text: string; overdue: boolean } {
  const ts = new Date(createdAt).getTime()
  if (isNaN(ts)) return { text: '--', overdue: false }
  const slaHours: Record<string, number> = { critical: 4, high: 24, medium: 72, low: 168 }
  const hours = slaHours[priority.toLowerCase()] ?? 72
  const deadline = new Date(createdAt).getTime() + hours * 60 * 60 * 1000
  const remaining = deadline - Date.now()

  if (remaining <= 0) {
    const overdueHours = Math.abs(Math.floor(remaining / (60 * 60 * 1000)))
    return { text: `${overdueHours}h overdue`, overdue: true }
  }

  const remHours = Math.floor(remaining / (60 * 60 * 1000))
  if (remHours < 1) {
    const remMins = Math.floor(remaining / 60_000)
    return { text: `${remMins}m remaining`, overdue: false }
  }
  if (remHours >= 24) {
    const days = Math.floor(remHours / 24)
    return { text: `${days}d ${remHours % 24}h remaining`, overdue: false }
  }
  return { text: `${remHours}h remaining`, overdue: false }
}

interface TicketViewportContentProps {
  findingId: string
  className?: string
}

export function TicketViewportContent({ findingId, className }: TicketViewportContentProps) {
  const { data: ticket, isLoading: ticketLoading, isError: ticketError } = useFindingTicket(findingId)
  const { data: comments = [] } = useTicketComments(findingId)
  const addComment = useAddTicketComment(findingId)
  const syncStatus = useSyncTicketStatus(findingId)
  const [commentBody, setCommentBody] = useState('')

  const sla = ticket ? computeSlaCountdown(ticket.created_at, ticket.priority) : null

  return (
    <div className={className}>
      {/* -- Header -- */}
      <div className="px-4 pt-4 pb-2 space-y-1.5">
        <div className="flex items-center gap-2 flex-wrap">
          {ticket && (
            <>
              <Badge
                variant="outline"
                className={`text-[10px] ${TICKET_STATUS_COLORS[ticket.status] ?? TICKET_STATUS_COLORS.open}`}
              >
                {ticket.status.replace(/_/g, ' ')}
              </Badge>
              <ProviderBadge provider={ticket.provider} className="h-4 w-4" />
            </>
          )}
          {sla && (
            <span className={`inline-flex items-center gap-1 text-[10px] font-medium ${sla.overdue ? 'text-red-600 dark:text-red-400' : 'text-muted-foreground'}`}>
              <Clock className="h-3 w-3" />
              {sla.text}
            </span>
          )}
        </div>
        <h3 className="text-base font-semibold leading-snug">
          {ticket?.title ?? 'Remediation Ticket'}
        </h3>
        <p className="text-xs font-mono text-muted-foreground">
          {ticket?.external_id ?? '--'}
        </p>
      </div>

      {/* -- Scrollable Content -- */}
      <div className="flex-1 overflow-y-auto px-4 space-y-4">
        {/* Ticket Summary Card */}
        {ticket ? (
          <Card>
            <CardContent className="p-3 space-y-3">
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <p className="text-[10px] text-muted-foreground uppercase tracking-wide">Priority</p>
                  <Badge
                    variant="outline"
                    className={`text-[10px] mt-0.5 ${PRIORITY_COLORS[ticket.priority.toLowerCase()] ?? ''}`}
                  >
                    {ticket.priority}
                  </Badge>
                </div>
                <div>
                  <p className="text-[10px] text-muted-foreground uppercase tracking-wide">Assignee</p>
                  <div className="flex items-center gap-1 mt-0.5">
                    <User className="h-3 w-3 text-muted-foreground" />
                    <span className="text-sm font-medium">{ticket.assignee ?? 'Unassigned'}</span>
                  </div>
                </div>
                <div>
                  <p className="text-[10px] text-muted-foreground uppercase tracking-wide">External ID</p>
                  <div className="flex items-center gap-1 mt-0.5">
                    <Hash className="h-3 w-3 text-muted-foreground" />
                    <code className="text-xs font-mono">{ticket.external_id}</code>
                  </div>
                </div>
                <div>
                  <p className="text-[10px] text-muted-foreground uppercase tracking-wide">Updated</p>
                  <p className="text-sm font-medium mt-0.5">{formatRelativeTime(ticket.updated_at)}</p>
                </div>
              </div>
              {ticket.url && (
                <a
                  href={ticket.url}
                  target="_blank"
                  rel="noreferrer"
                  className="inline-flex items-center gap-1 text-xs text-blue-600 dark:text-blue-400 hover:underline"
                >
                  <ExternalLink className="h-3 w-3" />
                  Open in {ticket.provider}
                </a>
              )}
            </CardContent>
          </Card>
        ) : (
          <Card>
            <CardContent className="p-4 flex items-center gap-2 text-muted-foreground">
              {ticketLoading ? (
                <>
                  <RefreshCw className="h-4 w-4 animate-spin" />
                  <span className="text-xs">Loading ticket data...</span>
                </>
              ) : ticketError ? (
                <>
                  <AlertTriangle className="h-4 w-4 text-red-500" />
                  <span className="text-xs">Failed to load ticket. Try refreshing.</span>
                </>
              ) : (
                <>
                  <AlertTriangle className="h-4 w-4" />
                  <span className="text-xs">No ticket data available.</span>
                </>
              )}
            </CardContent>
          </Card>
        )}

        <Separator />

        {/* Activity Timeline */}
        <div>
          <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground mb-3 flex items-center gap-1.5">
            <MessageSquare className="h-3.5 w-3.5" />
            Activity ({comments.length})
          </p>

          {comments.length === 0 ? (
            <div className="text-center py-6">
              <MessageSquare className="h-6 w-6 text-muted-foreground/30 mx-auto mb-2" />
              <p className="text-xs text-muted-foreground">No activity yet</p>
            </div>
          ) : (
            <div className="space-y-3">
              {comments.map((c) => (
                <div key={c.id} className="relative pl-4 border-l-2 border-muted">
                  <div className="absolute -left-[5px] top-1 h-2 w-2 rounded-full bg-muted-foreground/30" />
                  <div className="flex items-center gap-2 mb-0.5">
                    <span className="text-xs font-medium">{c.author}</span>
                    <span className="text-[10px] text-muted-foreground">
                      {formatRelativeTime(c.created_at)}
                    </span>
                  </div>
                  <p className="text-sm text-foreground/90 leading-relaxed">{c.body}</p>
                </div>
              ))}
            </div>
          )}
        </div>

        <Separator />

        {/* Add Comment Form */}
        <div>
          <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground mb-2">
            Add Comment
          </p>
          <textarea
            value={commentBody}
            onChange={(e) => setCommentBody(e.target.value)}
            placeholder="Type a comment..."
            rows={3}
            className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-ring resize-none"
          />
          <div className="flex justify-end mt-2">
            <Button
              size="sm"
              className="text-xs gap-1.5"
              disabled={!commentBody.trim() || addComment.isPending}
              onClick={() => {
                addComment.mutate(commentBody.trim(), {
                  onSuccess: () => setCommentBody(''),
                  onError: () => { /* toast handled by useAddTicketComment's onError */ },
                })
              }}
            >
              <Send className="h-3.5 w-3.5" />
              {addComment.isPending ? 'Sending...' : 'Send'}
            </Button>
          </div>
        </div>
      </div>

      {/* -- Footer -- */}
      <div className="flex flex-row gap-2 border-t border-border px-4 py-3">
        <Button
          size="sm"
          variant="outline"
          className="text-xs gap-1.5"
          disabled={syncStatus.isPending}
          onClick={() => syncStatus.mutate()}
        >
          <RefreshCw className={`h-3.5 w-3.5 ${syncStatus.isPending ? 'animate-spin' : ''}`} />
          {syncStatus.isPending ? 'Syncing...' : 'Sync Status'}
        </Button>

        {ticket?.url && (
          <Button size="sm" variant="outline" className="text-xs gap-1.5" asChild>
            <a href={ticket.url} target="_blank" rel="noreferrer">
              <ExternalLink className="h-3.5 w-3.5" />
              Open in {ticket.provider}
            </a>
          </Button>
        )}

        <Button
          size="sm"
          variant="default"
          className="text-xs gap-1.5 ml-auto"
          disabled
          title="Resolve via external provider — API endpoint pending"
        >
          <CheckCircle2 className="h-3.5 w-3.5" />
          Mark Resolved
        </Button>
      </div>
    </div>
  )
}
