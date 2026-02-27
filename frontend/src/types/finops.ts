export interface CostRecord {
  id: string
  provider: string
  account_id: string
  service_name: string
  resource_id: string
  region: string
  date: string
  cost: number
  currency: string
  tags: Record<string, string>
  cost_center: string
  team: string
  environment: string
}

export interface AnomalyAlert {
  id: string
  provider: string
  account_id: string
  service_name: string
  detected_at: string
  expected_cost: number
  actual_cost: number
  deviation_percent: number
  severity: string
}

export interface CostAllocation {
  cost_center: string
  team: string
  total_cost: number
  by_provider: Record<string, number>
  by_service: Record<string, number>
  percentage: number
}

export interface ChargebackReport {
  period: string
  generated_at: string
  total_cost: number
  allocations: CostAllocation[]
}

export interface DailyProviderCost {
  date: string
  aws: number
  azure: number
  gcp: number
  total: number
}

export interface CostSummary {
  period: string
  total: number
  by_provider: Record<string, number>
  daily: DailyProviderCost[]
  anomalies: AnomalyAlert[]
  chargeback: ChargebackReport
}
