import type { Finding } from '@/types/compliance'

export interface FindingSlaState {
  label: string
  detail: string
  badgeClass: string
  textClass: string
  overdue: boolean
}

const DAY_MS = 24 * 60 * 60 * 1000

export function formatWorkflowStatus(status?: string): string {
  if (!status) return 'Unknown'
  return status.replace(/_/g, ' ').replace(/\b\w/g, char => char.toUpperCase())
}

export function formatDate(value?: string): string {
  if (!value) return 'N/A'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return 'N/A'
  return date.toLocaleDateString()
}

export function formatDateTime(value?: string): string {
  if (!value) return 'N/A'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return 'N/A'
  return date.toLocaleString()
}

export function getFindingSlaState(
  finding: Pick<Finding, 'due_date' | 'sla_breach_date' | 'resolved_at' | 'workflow_status'>,
  now = new Date(),
): FindingSlaState {
  if (finding.resolved_at || finding.workflow_status === 'closed' || finding.workflow_status === 'verified') {
    return {
      label: 'Resolved',
      detail: 'No active SLA clock',
      badgeClass: 'bg-emerald-100 text-emerald-700 border-emerald-200 dark:bg-emerald-900/30 dark:text-emerald-300 dark:border-emerald-800',
      textClass: 'text-emerald-600 dark:text-emerald-400',
      overdue: false,
    }
  }

  if (!finding.due_date) {
    return {
      label: 'No SLA',
      detail: 'No due date assigned',
      badgeClass: 'bg-slate-100 text-slate-700 border-slate-200 dark:bg-slate-900/30 dark:text-slate-300 dark:border-slate-800',
      textClass: 'text-muted-foreground',
      overdue: false,
    }
  }

  const dueDate = new Date(finding.due_date)
  if (Number.isNaN(dueDate.getTime())) {
    return {
      label: 'Unknown',
      detail: 'Due date unavailable',
      badgeClass: 'bg-slate-100 text-slate-700 border-slate-200 dark:bg-slate-900/30 dark:text-slate-300 dark:border-slate-800',
      textClass: 'text-muted-foreground',
      overdue: false,
    }
  }

  const daysRemaining = Math.ceil((dueDate.getTime() - now.getTime()) / DAY_MS)
  if (finding.sla_breach_date || daysRemaining < 0) {
    return {
      label: 'Overdue',
      detail: `${Math.abs(daysRemaining)}d overdue`,
      badgeClass: 'bg-red-100 text-red-700 border-red-200 dark:bg-red-900/30 dark:text-red-300 dark:border-red-800',
      textClass: 'text-red-600 dark:text-red-400',
      overdue: true,
    }
  }

  if (daysRemaining === 0) {
    return {
      label: 'Due today',
      detail: 'Remediation deadline is today',
      badgeClass: 'bg-amber-100 text-amber-700 border-amber-200 dark:bg-amber-900/30 dark:text-amber-300 dark:border-amber-800',
      textClass: 'text-amber-600 dark:text-amber-400',
      overdue: false,
    }
  }

  if (daysRemaining <= 3) {
    return {
      label: 'At risk',
      detail: `${daysRemaining}d remaining`,
      badgeClass: 'bg-amber-100 text-amber-700 border-amber-200 dark:bg-amber-900/30 dark:text-amber-300 dark:border-amber-800',
      textClass: 'text-amber-600 dark:text-amber-400',
      overdue: false,
    }
  }

  return {
    label: 'On track',
    detail: `${daysRemaining}d remaining`,
    badgeClass: 'bg-emerald-100 text-emerald-700 border-emerald-200 dark:bg-emerald-900/30 dark:text-emerald-300 dark:border-emerald-800',
    textClass: 'text-emerald-600 dark:text-emerald-400',
    overdue: false,
  }
}
