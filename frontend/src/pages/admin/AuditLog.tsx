import { useState } from 'react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from '@/components/ui/table'
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from '@/components/ui/select'
import { useAuditLog } from '@/hooks/useAuditLog'

const RESULT_CONFIG: Record<string, string> = {
  success: 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300',
  denied: 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300',
  error: 'bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-300',
}

const ACTION_COLORS: Record<string, string> = {
  approve: 'text-green-600 dark:text-green-400',
  remediate: 'text-blue-600 dark:text-blue-400',
  evaluate: 'text-indigo-600 dark:text-indigo-400',
  create: 'text-purple-600 dark:text-purple-400',
  start: 'text-cyan-600 dark:text-cyan-400',
  complete: 'text-green-600 dark:text-green-400',
  suppress: 'text-yellow-600 dark:text-yellow-400',
}

function actionColor(action: string): string {
  const verb = action.split('.')[1] ?? ''
  return ACTION_COLORS[verb] ?? 'text-foreground'
}

export default function AuditLog() {
  const [resultFilter, setResultFilter] = useState('all')
  const [actorFilter, setActorFilter] = useState('all')

  const { data: EVENTS = [] } = useAuditLog()
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
            <button
              key={r}
              onClick={() => setResultFilter(prev => prev === r ? 'all' : r)}
              className={`text-[10px] font-medium px-2 py-0.5 rounded-none cursor-pointer transition-colors ${
                resultFilter === r ? RESULT_CONFIG[r] + ' ring-1 ring-current' : RESULT_CONFIG[r] + ' opacity-60 hover:opacity-100'
              }`}
            >
              {EVENTS.filter(e => e.result === r).length} {r.toUpperCase()}
            </button>
          ))}
        </div>
      </div>

      <div className="flex items-center gap-3 text-[10px] text-muted-foreground">
        <span>Action colors:</span>
        <span className="text-green-600 dark:text-green-400">approve/complete</span>
        <span className="text-blue-600 dark:text-blue-400">remediate</span>
        <span className="text-indigo-600 dark:text-indigo-400">evaluate</span>
        <span className="text-purple-600 dark:text-purple-400">create</span>
        <span className="text-cyan-600 dark:text-cyan-400">start</span>
        <span className="text-yellow-600 dark:text-yellow-400">suppress</span>
      </div>

      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
            {filtered.length} events
          </CardTitle>
        </CardHeader>
        <CardContent className="p-0 overflow-x-auto">
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
