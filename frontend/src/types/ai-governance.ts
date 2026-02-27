export type AgentStatus = 'active' | 'inactive' | 'suspended' | 'deprecated'

export type SpanType = 'llm' | 'retrieval' | 'tool' | 'chain' | 'agent' | 'policy'

export type TraceStatus = 'running' | 'completed' | 'failed' | 'blocked'

export type SignalType =
  | 'injection_attempt' | 'data_exfiltration' | 'tool_abuse'
  | 'privilege_escalation' | 'anomalous_behavior' | 'policy_violation'
  | 'rate_limit_exceeded'

export type STRIDECategory =
  | 'spoofing' | 'tampering' | 'repudiation'
  | 'information_disclosure' | 'denial_of_service' | 'elevation_of_privilege'

export interface Capability {
  name: string
  description: string
  data_access: string[]
  risk_level: string
}

export interface ToolBinding {
  tool_id: string
  name: string
  category: string
  permissions: string[]
  parameters: Record<string, string>
}

export interface Agent {
  id: string
  name: string
  description: string
  framework: string
  version: string
  owner: string
  team: string
  environment: string
  capabilities: Capability[]
  tools: ToolBinding[]
  policies: string[]
  risk_level: string
  status: AgentStatus
  last_active_at?: string
  created_at: string
  updated_at: string
}

export interface PolicyDecision {
  policy_id: string
  decision: 'allow' | 'deny' | 'warn'
  reason: string
  eval_time_us: number
  timestamp: string
}

export interface LLMSpanData {
  model: string
  provider: string
  prompt_tokens: number
  completion_tokens: number
  total_tokens: number
  temperature: number
  max_tokens: number
  prompt_hash: string
  finish_reason: string
}

export interface RetrievalSpanData {
  vector_store: string
  query: string
  num_results: number
  top_scores: number[]
  filter_applied: boolean
}

export interface ToolSpanData {
  tool_name: string
  tool_category: string
  input_hash: string
  output_hash: string
  parameter_count: number
  external_call: boolean
  policy_decision?: PolicyDecision
}

export interface SpanData {
  llm?: LLMSpanData
  retrieval?: RetrievalSpanData
  tool?: ToolSpanData
}

export interface SpanEvent {
  timestamp: string
  name: string
  attributes: Record<string, unknown>
}

export interface Span {
  span_id: string
  parent_span_id?: string
  name: string
  type: SpanType
  start_time: string
  end_time?: string
  duration_ms: number
  status: string
  attributes: Record<string, unknown>
  events: SpanEvent[]
  data: SpanData
}

export interface SecuritySignal {
  id: string
  trace_id: string
  span_id: string
  type: SignalType
  severity: string
  title: string
  description: string
  evidence: Record<string, unknown>
  timestamp: string
  mitigated: boolean
}

export interface TraceMetrics {
  total_spans: number
  llm_calls: number
  tool_invocations: number
  total_tokens: number
  estimated_cost_usd: number
  policy_evaluations: number
  security_signals: number
}

export interface AgentTrace {
  trace_id: string
  agent_id: string
  session_id: string
  user_id: string
  start_time: string
  end_time?: string
  duration_ms: number
  status: TraceStatus
  spans: Span[]
  security_signals: SecuritySignal[]
  metrics: TraceMetrics
  metadata: Record<string, unknown>
}

export interface Threat {
  id: string
  title: string
  description: string
  category: STRIDECategory
  affected_components: string[]
  trust_boundary: string
  entry_point: string
  likelihood: string
  impact: string
  risk_level: string
  atlas_techniques: string[]
  mitigation_ids: string[]
}

export interface Mitigation {
  id: string
  title: string
  description: string
  control_type: string
  implementation: string
  mapped_controls: string[]
  status: string
}

export interface RiskSummary {
  total_threats: number
  threats_by_category: Record<string, number>
  threats_by_risk: Record<string, number>
  mitigation_coverage: number
  residual_risk_score: number
}

export interface TrustBoundary {
  id: string
  name: string
  description: string
  components: string[]
}

export interface ThreatModel {
  id: string
  name: string
  description: string
  target_agent_id?: string
  scope: string
  trust_boundaries: TrustBoundary[]
  threats: Threat[]
  mitigations: Mitigation[]
  risk_summary: RiskSummary
  created_at: string
  updated_at: string
}
