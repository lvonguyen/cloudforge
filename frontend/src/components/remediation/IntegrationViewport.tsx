import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { TicketViewportContent } from './TicketViewportContent'
import { ExternalLink, CheckSquare, Headphones } from 'lucide-react'

interface Ticket {
  id: string
  provider: string
  status: string
  [key: string]: unknown
}

interface IntegrationViewportProps {
  findingId: string
  ticket?: Ticket
}

export function IntegrationViewport({ findingId, ticket }: IntegrationViewportProps) {
  const hasAsana = ticket?.provider === 'asana'
  const hasJira = ticket?.provider === 'jira'
  const hasSNow = ticket?.provider === 'servicenow'
  const hasAnyTicket = hasAsana || hasJira || hasSNow
  const defaultTab = ticket?.provider ?? 'asana'

  return (
    <div className="space-y-2">
      <p className="text-xs font-medium text-muted-foreground uppercase tracking-wide">
        Integrations
      </p>
      <Tabs defaultValue={defaultTab}>
        <TabsList variant="line" className="h-8">
          <TabsTrigger value="asana" disabled={!hasAsana} className="text-xs gap-1.5">
            <CheckSquare className="h-3.5 w-3.5" />
            Asana
          </TabsTrigger>
          <TabsTrigger value="jira" disabled={!hasJira} className="text-xs gap-1.5">
            <ExternalLink className="h-3.5 w-3.5" />
            Jira
          </TabsTrigger>
          <TabsTrigger value="servicenow" disabled={!hasSNow} className="text-xs gap-1.5">
            <Headphones className="h-3.5 w-3.5" />
            ServiceNow
          </TabsTrigger>
        </TabsList>

        <TabsContent value="asana" className="mt-2">
          {hasAsana ? (
            <TicketViewportContent findingId={findingId} />
          ) : (
            <PlaceholderContent provider="Asana" />
          )}
        </TabsContent>

        <TabsContent value="jira" className="mt-2">
          {hasJira ? (
            <TicketViewportContent findingId={findingId} />
          ) : (
            <PlaceholderContent provider="Jira" />
          )}
        </TabsContent>

        <TabsContent value="servicenow" className="mt-2">
          {hasSNow ? (
            <TicketViewportContent findingId={findingId} />
          ) : (
            <PlaceholderContent provider="ServiceNow" />
          )}
        </TabsContent>
      </Tabs>
    </div>
  )
}

function PlaceholderContent({ provider }: { provider: string }) {
  return (
    <div className="rounded-md border border-dashed border-border p-6 text-center">
      <p className="text-sm text-muted-foreground">
        {provider} integration not configured for this finding.
      </p>
      <p className="text-xs text-muted-foreground/60 mt-1">
        Create a ticket via the Remediation tab to enable this viewport.
      </p>
    </div>
  )
}
