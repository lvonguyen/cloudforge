export type WidgetId =
  | 'kpi-cards'
  | 'sla-compliance'
  | 'trend-row'
  | 'choke-points'
  | 'exception-queue'

export interface WidgetPreset {
  id: string
  label: string
  description: string
  widgets: WidgetId[]
}

export const WIDGET_PRESETS: WidgetPreset[] = [
  {
    id: 'security',
    label: 'Security Focus',
    description: 'Prioritizes attack surface and choke points',
    widgets: ['kpi-cards', 'choke-points', 'sla-compliance', 'trend-row', 'exception-queue'],
  },
  {
    id: 'compliance',
    label: 'Compliance Focus',
    description: 'Prioritizes SLA compliance and exception management',
    widgets: ['kpi-cards', 'sla-compliance', 'exception-queue', 'trend-row', 'choke-points'],
  },
  {
    id: 'operations',
    label: 'Operations Focus',
    description: 'Prioritizes trends and remediation queue',
    widgets: ['kpi-cards', 'trend-row', 'exception-queue', 'sla-compliance', 'choke-points'],
  },
]

const STORAGE_KEY = 'cloudforge-dashboard-layout'

export function loadDashboardLayout(): WidgetId[] | null {
  try {
    const stored = localStorage.getItem(STORAGE_KEY)
    if (!stored) return null
    return JSON.parse(stored) as WidgetId[]
  } catch {
    return null
  }
}

export function saveDashboardLayout(widgets: WidgetId[]): void {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(widgets))
}
