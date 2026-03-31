import { useEffect, useMemo, useState } from 'react'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Button } from '@/components/ui/button'
import { TicketViewportContent } from './TicketViewportContent'
import { ExternalLink, CheckSquare, Headphones } from 'lucide-react'
import { useFindingTicket, useRemediateFinding, type Ticket } from '@/hooks/useIntegrations'

const KNOWN_PROVIDERS = ['asana', 'jira', 'servicenow'] as const
type ProviderKey = typeof KNOWN_PROVIDERS[number]

interface IntegrationViewportProps {
  findingId: string
  ticket?: Ticket
}

export function IntegrationViewport({ findingId, ticket }: IntegrationViewportProps) {
  const ticketQuery = useFindingTicket(findingId)
  const createTicket = useRemediateFinding()
  const resolvedTicket = ticket ?? ticketQuery.data ?? undefined
  const [requestedAssignee, setRequestedAssignee] = useState('')
  const [activeProvider, setActiveProvider] = useState<ProviderKey>(() => {
    const provider = ticket?.provider
    return (KNOWN_PROVIDERS as readonly string[]).includes(provider ?? '') ? provider as ProviderKey : 'asana'
  })

  useEffect(() => {
    const provider = resolvedTicket?.provider
    if ((KNOWN_PROVIDERS as readonly string[]).includes(provider ?? '')) {
      setActiveProvider(provider as ProviderKey)
    }
  }, [resolvedTicket?.provider])

  const providerAvailability = useMemo(() => ({
    asana: resolvedTicket ? resolvedTicket.provider === 'asana' : true,
    jira: resolvedTicket ? resolvedTicket.provider === 'jira' : true,
    servicenow: resolvedTicket ? resolvedTicket.provider === 'servicenow' : false,
  }), [resolvedTicket])

  return (
    <div className="space-y-2">
      <p className="text-xs font-medium text-muted-foreground uppercase tracking-wide">
        Integrations
      </p>
      <Tabs value={activeProvider} onValueChange={(value) => setActiveProvider(value as ProviderKey)}>
        <TabsList variant="line" className="h-8">
          <TabsTrigger
            value="asana"
            disabled={!providerAvailability.asana}
            className="text-xs gap-1.5"
            onClick={() => setActiveProvider('asana')}
          >
            <CheckSquare className="h-3.5 w-3.5" />
            Asana
          </TabsTrigger>
          <TabsTrigger
            value="jira"
            disabled={!providerAvailability.jira}
            className="text-xs gap-1.5"
            onClick={() => setActiveProvider('jira')}
          >
            <ExternalLink className="h-3.5 w-3.5" />
            Jira
          </TabsTrigger>
          <TabsTrigger
            value="servicenow"
            disabled={!providerAvailability.servicenow}
            className="text-xs gap-1.5"
            onClick={() => setActiveProvider('servicenow')}
          >
            <Headphones className="h-3.5 w-3.5" />
            ServiceNow
          </TabsTrigger>
        </TabsList>

        <TabsContent value="asana" className="mt-2">
          {resolvedTicket?.provider === 'asana'
            ? <TicketViewportContent findingId={findingId} />
            : (
              <ProviderPanel
                provider="asana"
                activeProvider={activeProvider}
                isLoading={ticketQuery.isLoading}
                isError={ticketQuery.isError}
                requestedAssignee={requestedAssignee}
                onRequestedAssigneeChange={setRequestedAssignee}
                onCreate={() => createTicket.mutate({
                  findingId,
                  provider: 'asana',
                  assignee: requestedAssignee.trim() || undefined,
                })}
                isCreating={createTicket.isPending}
              />
            )}
        </TabsContent>

        <TabsContent value="jira" className="mt-2">
          {resolvedTicket?.provider === 'jira'
            ? <TicketViewportContent findingId={findingId} />
            : (
              <ProviderPanel
                provider="jira"
                activeProvider={activeProvider}
                isLoading={ticketQuery.isLoading}
                isError={ticketQuery.isError}
                requestedAssignee={requestedAssignee}
                onRequestedAssigneeChange={setRequestedAssignee}
                onCreate={() => createTicket.mutate({
                  findingId,
                  provider: 'jira',
                  assignee: requestedAssignee.trim() || undefined,
                })}
                isCreating={createTicket.isPending}
              />
            )}
        </TabsContent>

        <TabsContent value="servicenow" className="mt-2">
          {resolvedTicket?.provider === 'servicenow'
            ? <TicketViewportContent findingId={findingId} />
            : (
              <ProviderPanel
                provider="servicenow"
                activeProvider={activeProvider}
                isLoading={ticketQuery.isLoading}
                isError={ticketQuery.isError}
                requestedAssignee={requestedAssignee}
                onRequestedAssigneeChange={setRequestedAssignee}
                onCreate={() => undefined}
                isCreating={false}
              />
            )}
        </TabsContent>
      </Tabs>
    </div>
  )
}

function ProviderPanel({
  provider,
  activeProvider,
  isLoading,
  isError,
  requestedAssignee,
  onRequestedAssigneeChange,
  onCreate,
  isCreating,
}: {
  provider: ProviderKey
  activeProvider: ProviderKey
  isLoading: boolean
  isError: boolean
  requestedAssignee: string
  onRequestedAssigneeChange: (value: string) => void
  onCreate: () => void
  isCreating: boolean
}) {
  const label = provider === 'servicenow' ? 'ServiceNow' : provider === 'jira' ? 'Jira' : 'Asana'
  const canCreate = provider === activeProvider && (provider === 'jira' || provider === 'asana')

  if (isLoading) {
    return (
      <div className="rounded-md border border-dashed border-border p-6 text-center">
        <p className="text-sm text-muted-foreground">
          Loading {label} ticket state…
        </p>
      </div>
    )
  }

  if (isError) {
    return (
      <div className="rounded-md border border-dashed border-border p-6 text-center">
        <p className="text-sm text-muted-foreground">
          Unable to load {label} ticket state right now.
        </p>
        <p className="text-xs text-muted-foreground/60 mt-1">
          Avoid creating a duplicate ticket until the provider check succeeds.
        </p>
      </div>
    )
  }

  return (
    <div className="rounded-md border border-dashed border-border bg-muted/20 p-4 space-y-3">
      <div>
        <p className="text-sm font-medium">
          {provider === 'servicenow' ? `${label} parity is still pending.` : `Create a ${label} ticket`}
        </p>
        <p className="text-xs text-muted-foreground mt-1">
          {provider === 'servicenow'
            ? 'Jira and Asana are wired for provider selection first. ServiceNow stays view-only until parity lands.'
            : 'Route this finding into the selected provider without leaving the remediation panel.'}
        </p>
      </div>

      {provider !== 'servicenow' && (
        <>
          <label className="block space-y-1">
            <span className="text-[11px] font-medium uppercase tracking-wide text-muted-foreground">
              Requested assignee
            </span>
            <input
              value={requestedAssignee}
              onChange={(event) => onRequestedAssigneeChange(event.target.value)}
              placeholder="alice@example.com or team alias"
              className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-ring"
            />
          </label>

          <div className="flex items-center justify-between gap-3">
            <p className="text-[11px] text-muted-foreground">
              {provider === 'jira'
                ? 'Creates a Jira issue and requests assignee routing when provided.'
                : 'Creates an Asana task and forwards the requested assignee if supported.'}
            </p>
            <Button
              size="sm"
              className="text-xs"
              disabled={!canCreate || isCreating}
              onClick={onCreate}
            >
              {isCreating ? 'Creating…' : `Create ${label} ticket`}
            </Button>
          </div>
        </>
      )}
    </div>
  )
}
