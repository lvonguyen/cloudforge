import type { Finding } from '@/types/compliance'

export function exportCSV(findings: Finding[]) {
  const headers = ['ID', 'Title', 'Severity', 'Category', 'Provider', 'Resource Type', 'Resource', 'Region', 'Status', 'SLA Due Date', 'First Found', 'Remediation']
  const esc = (v: string) => `"${String(v).replace(/"/g, '""')}"`
  const rows = findings.map(f => [
    esc(f.id),
    esc(f.title),
    esc(f.severity),
    esc(f.category),
    esc(f.cloud_provider.toUpperCase()),
    esc(f.resource_type),
    esc(f.resource_name),
    esc(f.region),
    esc(f.workflow_status),
    esc(f.due_date ?? ''),
    esc(f.first_found_at),
    esc(f.remediation),
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
