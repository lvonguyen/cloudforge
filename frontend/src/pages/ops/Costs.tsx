// MVP page — shell with correct imports, to be implemented by finops agent
import { useCostSummary, useCostAnomalies } from '@/hooks/useCosts'
import { CostSummaryCard } from '@/components/finops/CostSummaryCard'
import { AnomalyAlertCard } from '@/components/finops/AnomalyAlertCard'
import { SpendChart } from '@/components/finops/SpendChart'
import { ChargebackTable } from '@/components/finops/ChargebackTable'

// Suppress unused import warnings during scaffold phase
void (useCostSummary as unknown)
void (useCostAnomalies as unknown)
void (CostSummaryCard as unknown)
void (AnomalyAlertCard as unknown)
void (SpendChart as unknown)
void (ChargebackTable as unknown)

export default function Costs() {
  return (
    <div className="space-y-4">
      <h1 className="text-xl font-semibold">Cost Management</h1>
      <p className="text-sm text-muted-foreground">
        Multi-cloud spend dashboard, anomaly alerts, chargeback table. Implementation pending.
      </p>
    </div>
  )
}
