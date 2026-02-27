import { Badge } from '@/components/ui/badge'
import { cn } from '@/lib/utils'
import type { SignalType } from '@/types/ai-governance'

const SIGNAL_LABELS: Record<SignalType, string> = {
  injection_attempt: 'Injection',
  data_exfiltration: 'Exfiltration',
  tool_abuse: 'Tool Abuse',
  privilege_escalation: 'PrivEsc',
  anomalous_behavior: 'Anomaly',
  policy_violation: 'Policy Block',
  rate_limit_exceeded: 'Rate Limit',
}

const SEVERITY_CLASS: Record<string, string> = {
  critical: 'bg-red-100 text-red-800 border-red-300',
  high: 'bg-orange-100 text-orange-800 border-orange-300',
  medium: 'bg-yellow-100 text-yellow-800 border-yellow-300',
  low: 'bg-blue-100 text-blue-800 border-blue-300',
}

export function SecuritySignalBadge({ type, severity }: { type: SignalType; severity: string }) {
  return (
    <Badge
      variant="outline"
      className={cn('text-[10px] font-medium', SEVERITY_CLASS[severity] ?? SEVERITY_CLASS.medium)}
    >
      {SIGNAL_LABELS[type] ?? type}
    </Badge>
  )
}
