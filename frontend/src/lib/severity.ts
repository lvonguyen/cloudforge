// Canonical severity and status color maps — single source of truth.
// Import these instead of defining inline color maps in individual components.

export const SEVERITY_HEX: Record<string, string> = {
  CRITICAL: '#ef4444',
  HIGH: '#f97316',
  MEDIUM: '#eab308',
  LOW: '#3b82f6',
}

export const SEVERITY_DOT_COLORS: Record<string, string> = {
  CRITICAL: 'bg-red-400',
  HIGH: 'bg-orange-400',
  MEDIUM: 'bg-yellow-500',
  LOW: 'bg-blue-400',
}

export const SEVERITY_NEUTRAL_HEX = '#6b7280'

export const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-300',
  HIGH: 'bg-orange-100 text-orange-800 dark:bg-orange-900/30 dark:text-orange-300',
  MEDIUM: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-300',
  LOW: 'bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-300',
}

// AttackPaths adds border classes for outlined badges — computed from SEVERITY_COLORS
const SEVERITY_BORDER_OVERRIDES: Record<string, string> = {
  CRITICAL: 'border-red-300 dark:border-red-700',
  HIGH: 'border-orange-300 dark:border-orange-700',
  MEDIUM: 'border-yellow-300 dark:border-yellow-700',
  LOW: 'border-blue-300 dark:border-blue-700',
}
export const SEVERITY_COLORS_BORDERED: Record<string, string> = Object.fromEntries(
  Object.entries(SEVERITY_COLORS).map(([k, v]) => [k, `${v} ${SEVERITY_BORDER_OVERRIDES[k] ?? ''}`]),
)

// Remediation workflow statuses (lowercase keys)
export const REMEDIATION_STATUS_COLORS: Record<string, string> = {
  pending: 'bg-gray-100 text-gray-700 dark:bg-gray-900/30 dark:text-gray-300',
  in_progress: 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-300',
  completed: 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300',
  failed: 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300',
  skipped: 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-300',
}

// Exception/approval workflow statuses (uppercase keys)
export const EXCEPTION_STATUS_COLORS: Record<string, string> = {
  PENDING: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-300',
  APPROVED: 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-300',
  REJECTED: 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-300',
  EXPIRED: 'bg-gray-100 text-gray-700 dark:bg-gray-900/30 dark:text-gray-300',
}
