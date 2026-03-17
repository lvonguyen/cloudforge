import type { Finding } from '@/types/compliance'

export function exportCSV(findings: Finding[]) {
  const headers = ['ID', 'Title', 'Severity', 'Category', 'Provider', 'Resource Type', 'Resource', 'Region', 'Status', 'SLA Due Date', 'First Found', 'Remediation']
  const rows = findings.map(f => [
    f.id,
    `"${f.title.replace(/"/g, '""')}"`,
    f.severity,
    f.category,
    f.cloud_provider.toUpperCase(),
    f.resource_type,
    f.resource_name,
    f.region,
    f.workflow_status,
    f.due_date ?? '',
    f.first_found_at,
    `"${f.remediation.replace(/"/g, '""')}"`,
  ])
  const csv = [headers.join(','), ...rows.map(r => r.join(','))].join('\n')
  const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  const now = new Date()
  const ts = `${now.getFullYear()}${String(now.getMonth() + 1).padStart(2, '0')}${String(now.getDate()).padStart(2, '0')}_${String(now.getHours()).padStart(2, '0')}${String(now.getMinutes()).padStart(2, '0')}${String(now.getSeconds()).padStart(2, '0')}`
  a.href = url
  a.download = `findings_export_${ts}.csv`
  document.body.appendChild(a)
  a.click()
  document.body.removeChild(a)
  URL.revokeObjectURL(url)
}
