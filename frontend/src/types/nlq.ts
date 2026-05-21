export type NLQFilterField = 'severity' | 'provider' | 'category' | 'status' | 'environment'

export type NLQFilterMap = Partial<Record<NLQFilterField, string[]>>

export type NLQExclusions = NLQFilterMap

export interface NLQFilters extends NLQFilterMap {
  text?: string
  exclude?: NLQFilterMap
}
