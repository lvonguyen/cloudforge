import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import type { CostAllocation } from '@/types/finops'

export function ChargebackTable({ allocations }: { allocations: CostAllocation[] }) {
  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead className="text-xs">Cost Center</TableHead>
          <TableHead className="text-xs">Team</TableHead>
          <TableHead className="text-xs text-right">Total</TableHead>
          <TableHead className="text-xs text-right">AWS</TableHead>
          <TableHead className="text-xs text-right">Azure</TableHead>
          <TableHead className="text-xs text-right">GCP</TableHead>
          <TableHead className="text-xs text-right">%</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {allocations.map(a => (
          <TableRow key={a.cost_center}>
            <TableCell className="text-xs font-mono font-medium">{a.cost_center}</TableCell>
            <TableCell className="text-xs text-muted-foreground">{a.team}</TableCell>
            <TableCell className="text-xs text-right font-medium">${(a.total_cost / 1000).toFixed(0)}K</TableCell>
            <TableCell className="text-xs text-right text-[#f59e0b]">${((a.by_provider.aws ?? 0) / 1000).toFixed(0)}K</TableCell>
            <TableCell className="text-xs text-right text-[#3b82f6]">${((a.by_provider.azure ?? 0) / 1000).toFixed(0)}K</TableCell>
            <TableCell className="text-xs text-right text-[#22c55e]">${((a.by_provider.gcp ?? 0) / 1000).toFixed(0)}K</TableCell>
            <TableCell className="text-xs text-right">{a.percentage}%</TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  )
}
