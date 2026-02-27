import { useState } from 'react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from '@/components/ui/table'
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from '@/components/ui/select'

interface AuditEvent {
  id: string
  timestamp: string
  actor: string
  actor_role: string
  action: string
  resource: string
  result: 'success' | 'denied' | 'error'
  ip: string
}

const EVENTS: AuditEvent[] = [
  { id: 'evt-001', timestamp: '2026-02-26 09:14:32', actor: 'liem@cloudforge.dev', actor_role: 'admin', action: 'exception.approve', resource: 'EXC-003', result: 'success', ip: '10.0.1.5' },
  { id: 'evt-002', timestamp: '2026-02-26 09:01:10', actor: 'priya@cloudforge.dev', actor_role: 'operator', action: 'finding.remediate', resource: 'FIND-0421', result: 'success', ip: '10.0.2.12' },
  { id: 'evt-003', timestamp: '2026-02-26 08:55:44', actor: 'jchen@cloudforge.dev', actor_role: 'operator', action: 'policy.evaluate', resource: 'payments-api EC2', result: 'denied', ip: '10.0.2.8' },
  { id: 'evt-004', timestamp: '2026-02-26 08:44:20', actor: 'falhassan@cloudforge.dev', actor_role: 'requester', action: 'exception.create', resource: 'EXC-004', result: 'success', ip: '10.0.3.44' },
  { id: 'evt-005', timestamp: '2026-02-26 08:30:01', actor: 'system@cloudforge.dev', actor_role: 'admin', action: 'agent.start', resource: 'agent-cloud-remediator', result: 'success', ip: '127.0.0.1' },
  { id: 'evt-006', timestamp: '2026-02-25 22:10:05', actor: 'system@cloudforge.dev', actor_role: 'admin', action: 'scan.complete', resource: 'aws-prod-account', result: 'success', ip: '127.0.0.1' },
  { id: 'evt-007', timestamp: '2026-02-25 17:30:15', actor: 'jchen@cloudforge.dev', actor_role: 'operator', action: 'finding.suppress', resource: 'FIND-0312', result: 'error', ip: '10.0.2.8' },
]

const RESULT_CONFIG: Record<string, string> = {
  success: 'bg-green-100 text-green-700',
  denied: 'bg-red-100 text-red-700',
  error: 'bg-orange-100 text-orange-700',
}

const ACTION_COLORS: Record<string, string> = {
  approve: 'text-green-600',
  remediate: 'text-blue-600',
  evaluate: 'text-indigo-600',
  create: 'text-purple-600',
  start: 'text-cyan-600',
  complete: 'text-green-600',
  suppress: 'text-yellow-600',
}

function actionColor(action: string): string {
  const verb = action.split('.')[1] ?? ''
  return ACTION_COLORS[verb] ?? 'text-foreground'
}

export default function AuditLog() {
  const [resultFilter, setResultFilter] = useState('all')
  const [actorFilter, setActorFilter] = useState('all')

  const actors = ['all', ...Array.from(new Set(EVENTS.map(e => e.actor)))]
  const filtered = EVENTS
    .filter(e => resultFilter === 'all' || e.result === resultFilter)
    .filter(e => actorFilter === 'all' || e.actor === actorFilter)

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold">Audit Log</h1>
        <p className="text-sm text-muted-foreground mt-0.5">Immutable event stream — last 7 days</p>
      </div>

      {/* Filters */}
      <div className="flex gap-3 flex-wrap">
        <Select value={resultFilter} onValueChange={setResultFilter}>
          <SelectTrigger className="h-8 w-32 text-xs">
            <SelectValue placeholder="Result" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Results</SelectItem>
            <SelectItem value="success">Success</SelectItem>
            <SelectItem value="denied">Denied</SelectItem>
            <SelectItem value="error">Error</SelectItem>
          </SelectContent>
        </Select>
        <Select value={actorFilter} onValueChange={setActorFilter}>
          <SelectTrigger className="h-8 w-52 text-xs">
            <SelectValue placeholder="Actor" />
          </SelectTrigger>
          <SelectContent>
            {actors.map(a => (
              <SelectItem key={a} value={a} className="text-xs">{a === 'all' ? 'All Actors' : a}</SelectItem>
            ))}
          </SelectContent>
        </Select>
        <div className="ml-auto flex items-center gap-2">
          {(['success', 'denied', 'error'] as const).map(r => (
            <Badge key={r} variant="outline" className={`text-[10px] ${RESULT_CONFIG[r]}`}>
              {EVENTS.filter(e => e.result === r).length} {r}
            </Badge>
          ))}
        </div>
      </div>

      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
            {filtered.length} events
          </CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="text-xs pl-4">Timestamp</TableHead>
                <TableHead className="text-xs">Actor</TableHead>
                <TableHead className="text-xs">Action</TableHead>
                <TableHead className="text-xs">Resource</TableHead>
                <TableHead className="text-xs">Result</TableHead>
                <TableHead className="text-xs">IP</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {filtered.map(evt => (
                <TableRow key={evt.id} className="hover:bg-muted/30">
                  <TableCell className="text-[10px] font-mono text-muted-foreground pl-4 whitespace-nowrap">{evt.timestamp}</TableCell>
                  <TableCell>
                    <p className="text-xs">{evt.actor}</p>
                    <p className="text-[10px] text-muted-foreground">{evt.actor_role}</p>
                  </TableCell>
                  <TableCell className={`text-xs font-mono font-medium ${actionColor(evt.action)}`}>{evt.action}</TableCell>
                  <TableCell className="text-xs font-mono">{evt.resource}</TableCell>
                  <TableCell>
                    <span className={`text-[10px] font-medium px-2 py-0.5 rounded-full ${RESULT_CONFIG[evt.result]}`}>
                      {evt.result}
                    </span>
                  </TableCell>
                  <TableCell className="text-[10px] font-mono text-muted-foreground">{evt.ip}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  )
}
