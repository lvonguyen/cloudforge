import { branding } from '@/lib/branding'
import { useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { useAgent, useAgentTraces } from '@/hooks/useAgents'
import { AgentStatusBadge } from '@/components/ai/AgentStatusBadge'
import { SecuritySignalBadge } from '@/components/ai/SecuritySignalBadge'
import { TraceTimeline } from '@/components/ai/TraceTimeline'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Separator } from '@/components/ui/separator'
import { Button } from '@/components/ui/button'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import {
  Bot, ChevronDown, ChevronRight, ArrowLeft,
  ShieldAlert, User, Clock, Cpu, Activity,
  CheckCircle2, AlertTriangle, XCircle, Filter
} from 'lucide-react'
import { cn } from '@/lib/utils'
import type {
  ThreatModel, STRIDECategory, AgentTrace, SignalType
} from '@/types/ai-governance'

// ── Per-framework threat model variants ──────────────────────────────────

const BASE_TRUST_BOUNDARIES: ThreatModel['trust_boundaries'] = [
  { id: 'tb-1', name: 'Agent Runtime', description: 'Sandboxed agent execution environment', components: ['AgentRunner', 'ToolExecutor'] },
  { id: 'tb-2', name: 'Cloud APIs', description: 'External cloud provider endpoints', components: ['AWS', 'Azure', 'GCP'] },
  { id: 'tb-3', name: 'Policy Engine', description: 'OPA evaluation service', components: ['PolicyEvaluator', 'PolicyStore'] },
]

const BASE_MITIGATIONS: ThreatModel['mitigations'] = [
  { id: 'mit-001', title: 'Prompt Injection Detection', control_type: 'preventive', description: 'Validate and sanitize all tool outputs before feeding into LLM context.', implementation: 'Regex + LLM-as-judge classifier on tool response payloads.', mapped_controls: ['NIST CSF DE.CM-7', 'SOC2 CC6.1'], status: 'implemented' },
  { id: 'mit-002', title: 'Output Monitoring & Rate Limiting', control_type: 'detective', description: 'Monitor LLM completions for extraction patterns; enforce per-agent token budgets.', implementation: 'Regex rules + sliding window token counter in AgentRunner.', mapped_controls: ['NIST CSF DE.AE-3'], status: 'implemented' },
  { id: 'mit-003', title: 'Immutable Audit Trail', control_type: 'detective', description: 'All spans written to append-only S3 + CloudWatch Logs; agent cannot modify.', implementation: 'S3 Object Lock + CloudWatch log group with no-delete retention.', mapped_controls: ['SOC2 CC7.2', 'ISO 27001 A.12.4.3'], status: 'implemented' },
  { id: 'mit-004', title: 'Policy Engine Hardening', control_type: 'preventive', description: 'OPA policy evaluation is mandatory for every tool call; cannot be bypassed by agent.', implementation: 'Policy sidecar enforced at ToolExecutor layer; deny-by-default.', mapped_controls: ['NIST CSF PR.AC-4', 'SOC2 CC6.3'], status: 'planned' },
]

interface FrameworkProfile {
  name: string
  description: string
  threats: ThreatModel['threats']
  risk_summary: ThreatModel['risk_summary']
}

const FRAMEWORK_PROFILES: Record<string, FrameworkProfile> = {
  langchain: {
    name: 'LangChain Agent Threat Model',
    description: `STRIDE analysis for LangChain-based autonomous agents within ${branding.productName}. Focus on chain composition, tool binding, and retrieval-augmented generation attack surface.`,
    threats: [
      { id: 'th-001', title: 'Prompt Injection via Retrieved Context', description: 'Adversarial content in vector store documents instructs agent to bypass safety guardrails during RAG retrieval.', category: 'spoofing', affected_components: ['Retriever', 'LLMChain'], trust_boundary: 'Agent Runtime', entry_point: 'Vector store document', likelihood: 'high', impact: 'high', risk_level: 'critical', atlas_techniques: ['AML.T0051', 'AML.T0054'], mitigation_ids: ['mit-001'] },
      { id: 'th-002', title: 'Chain-of-Thought Manipulation', description: 'Adversary crafts inputs that corrupt intermediate reasoning steps in multi-hop chains.', category: 'tampering', affected_components: ['SequentialChain', 'OutputParser'], trust_boundary: 'Agent Runtime', entry_point: 'Chain input', likelihood: 'medium', impact: 'high', risk_level: 'high', atlas_techniques: ['AML.T0020'], mitigation_ids: ['mit-001', 'mit-003'] },
      { id: 'th-003', title: 'Tool Abuse via Dynamic Routing', description: 'Agent dynamically selects and invokes tools based on LLM output, enabling unintended tool execution.', category: 'elevation_of_privilege', affected_components: ['AgentExecutor', 'ToolRouter'], trust_boundary: 'Policy Engine', entry_point: 'LLM tool selection', likelihood: 'medium', impact: 'critical', risk_level: 'critical', atlas_techniques: ['AML.T0054'], mitigation_ids: ['mit-004'] },
      { id: 'th-004', title: 'Callback Data Leakage', description: 'Sensitive intermediate outputs exposed through LangChain callback handlers to external logging.', category: 'information_disclosure', affected_components: ['CallbackManager', 'StdOutHandler'], trust_boundary: 'Agent Runtime', entry_point: 'Callback chain', likelihood: 'low', impact: 'medium', risk_level: 'medium', atlas_techniques: ['AML.T0025'], mitigation_ids: ['mit-002', 'mit-003'] },
      { id: 'th-005', title: 'Recursive Agent Loop', description: 'Agent enters infinite self-calling loop, exhausting token budget and compute.', category: 'denial_of_service', affected_components: ['AgentExecutor'], trust_boundary: 'Agent Runtime', entry_point: 'Max iterations config', likelihood: 'medium', impact: 'medium', risk_level: 'medium', atlas_techniques: ['AML.T0016'], mitigation_ids: ['mit-002'] },
      { id: 'th-006', title: 'Trace Omission in Custom Chains', description: 'Custom chain implementations skip span emission, breaking audit continuity.', category: 'repudiation', affected_components: ['CustomChain', 'SpanExporter'], trust_boundary: 'Agent Runtime', entry_point: 'Chain implementation', likelihood: 'low', impact: 'medium', risk_level: 'low', atlas_techniques: ['AML.T0048'], mitigation_ids: ['mit-003'] },
    ],
    risk_summary: { total_threats: 6, threats_by_category: { spoofing: 1, tampering: 1, repudiation: 1, information_disclosure: 1, denial_of_service: 1, elevation_of_privilege: 1 }, threats_by_risk: { critical: 2, high: 1, medium: 2, low: 1 }, mitigation_coverage: 83, residual_risk_score: 3.6 },
  },
  autogen: {
    name: 'AutoGen Multi-Agent Threat Model',
    description: `STRIDE analysis for AutoGen multi-agent orchestration within ${branding.productName}. Focus on inter-agent communication, group chat dynamics, and delegated execution trust.`,
    threats: [
      { id: 'th-001', title: 'Agent Impersonation in Group Chat', description: 'Malicious agent injects messages masquerading as trusted orchestrator, redirecting task delegation.', category: 'spoofing', affected_components: ['GroupChatManager', 'MessageRouter'], trust_boundary: 'Agent Runtime', entry_point: 'Group chat message', likelihood: 'medium', impact: 'high', risk_level: 'high', atlas_techniques: ['AML.T0051'], mitigation_ids: ['mit-001'] },
      { id: 'th-002', title: 'Delegated Code Execution Escape', description: 'Agent generates and executes code that escapes sandbox boundaries through subprocess or import manipulation.', category: 'elevation_of_privilege', affected_components: ['CodeExecutor', 'DockerSandbox'], trust_boundary: 'Agent Runtime', entry_point: 'Generated code block', likelihood: 'medium', impact: 'critical', risk_level: 'critical', atlas_techniques: ['AML.T0054'], mitigation_ids: ['mit-004'] },
      { id: 'th-003', title: 'Conversation History Poisoning', description: 'Early messages in multi-turn conversation bias later agent decisions toward attacker objectives.', category: 'tampering', affected_components: ['ConversationBuffer', 'AssistantAgent'], trust_boundary: 'Agent Runtime', entry_point: 'Chat history', likelihood: 'medium', impact: 'high', risk_level: 'high', atlas_techniques: ['AML.T0020'], mitigation_ids: ['mit-001', 'mit-002'] },
      { id: 'th-004', title: 'Cross-Agent Data Leakage', description: 'Sensitive data from one agent context leaks to another agent through shared memory or conversation.', category: 'information_disclosure', affected_components: ['GroupChatManager', 'SharedMemory'], trust_boundary: 'Agent Runtime', entry_point: 'Shared state', likelihood: 'low', impact: 'high', risk_level: 'medium', atlas_techniques: ['AML.T0025'], mitigation_ids: ['mit-003'] },
      { id: 'th-005', title: 'Consensus Deadlock', description: 'Agents in group chat fail to converge, creating infinite discussion loop that exhausts resources.', category: 'denial_of_service', affected_components: ['GroupChatManager'], trust_boundary: 'Agent Runtime', entry_point: 'Termination condition', likelihood: 'medium', impact: 'medium', risk_level: 'medium', atlas_techniques: ['AML.T0016'], mitigation_ids: ['mit-002'] },
      { id: 'th-006', title: 'Unattributed Agent Actions', description: 'Actions taken by sub-agents lack proper attribution, preventing forensic analysis.', category: 'repudiation', affected_components: ['AssistantAgent', 'TraceCollector'], trust_boundary: 'Agent Runtime', entry_point: 'Agent action dispatch', likelihood: 'low', impact: 'medium', risk_level: 'low', atlas_techniques: ['AML.T0048'], mitigation_ids: ['mit-003'] },
    ],
    risk_summary: { total_threats: 6, threats_by_category: { spoofing: 1, tampering: 1, repudiation: 1, information_disclosure: 1, denial_of_service: 1, elevation_of_privilege: 1 }, threats_by_risk: { critical: 1, high: 2, medium: 2, low: 1 }, mitigation_coverage: 75, residual_risk_score: 3.4 },
  },
  crewai: {
    name: 'CrewAI Role-Based Agent Threat Model',
    description: `STRIDE analysis for CrewAI role-based agent crews within ${branding.productName}. Focus on role assignment, task delegation chains, and inter-crew trust boundaries.`,
    threats: [
      { id: 'th-001', title: 'Role Hijacking via Backstory Injection', description: 'Adversarial content injected into agent backstory/role prompt alters agent behavior beyond intended scope.', category: 'spoofing', affected_components: ['CrewAgent', 'RolePrompt'], trust_boundary: 'Agent Runtime', entry_point: 'Agent backstory field', likelihood: 'medium', impact: 'high', risk_level: 'high', atlas_techniques: ['AML.T0051'], mitigation_ids: ['mit-001'] },
      { id: 'th-002', title: 'Task Output Corruption in Sequential Crew', description: 'Corrupted output from one task propagates through sequential task chain, compounding errors.', category: 'tampering', affected_components: ['TaskPipeline', 'OutputValidator'], trust_boundary: 'Agent Runtime', entry_point: 'Task output', likelihood: 'medium', impact: 'high', risk_level: 'high', atlas_techniques: ['AML.T0020'], mitigation_ids: ['mit-001', 'mit-003'] },
      { id: 'th-003', title: 'Cross-Crew Secret Leakage', description: 'Agents in different crews share tool context, exposing credentials across trust boundaries.', category: 'information_disclosure', affected_components: ['ToolContext', 'CrewManager'], trust_boundary: 'Cloud APIs', entry_point: 'Shared tool bindings', likelihood: 'low', impact: 'high', risk_level: 'medium', atlas_techniques: ['AML.T0025'], mitigation_ids: ['mit-003'] },
      { id: 'th-004', title: 'Delegation Privilege Escalation', description: 'Agent delegates task to sub-agent with higher tool permissions than the delegating agent holds.', category: 'elevation_of_privilege', affected_components: ['DelegationManager', 'ToolExecutor'], trust_boundary: 'Policy Engine', entry_point: 'Task delegation', likelihood: 'medium', impact: 'critical', risk_level: 'critical', atlas_techniques: ['AML.T0054'], mitigation_ids: ['mit-004'] },
      { id: 'th-005', title: 'Hierarchical Crew Cascade Failure', description: 'Manager agent failure cascades to all worker agents, causing total crew shutdown.', category: 'denial_of_service', affected_components: ['ManagerAgent', 'WorkerAgents'], trust_boundary: 'Agent Runtime', entry_point: 'Manager LLM call', likelihood: 'low', impact: 'high', risk_level: 'medium', atlas_techniques: ['AML.T0016'], mitigation_ids: ['mit-002'] },
      { id: 'th-006', title: 'Task Attribution Gap', description: 'Delegated sub-tasks lack trace linkage to parent task, breaking audit chain.', category: 'repudiation', affected_components: ['TaskTracker', 'SpanExporter'], trust_boundary: 'Agent Runtime', entry_point: 'Delegation event', likelihood: 'low', impact: 'medium', risk_level: 'low', atlas_techniques: ['AML.T0048'], mitigation_ids: ['mit-003'] },
    ],
    risk_summary: { total_threats: 6, threats_by_category: { spoofing: 1, tampering: 1, repudiation: 1, information_disclosure: 1, denial_of_service: 1, elevation_of_privilege: 1 }, threats_by_risk: { critical: 1, high: 2, medium: 2, low: 1 }, mitigation_coverage: 67, residual_risk_score: 3.5 },
  },
}

// Default threat model for frameworks not in FRAMEWORK_PROFILES
const DEFAULT_PROFILE: FrameworkProfile = {
  name: 'Cloud Agent Threat Model',
  description: `STRIDE analysis for autonomous cloud-acting agents within ${branding.productName}.`,
  threats: [
    { id: 'th-001', title: 'Prompt Injection — Admin Impersonation', description: 'Adversarial prompt in tool output instructs agent to act as admin, bypassing authorization checks.', category: 'spoofing', affected_components: ['LLMInvoker', 'ToolExecutor'], trust_boundary: 'Agent Runtime', entry_point: 'Tool response payload', likelihood: 'medium', impact: 'high', risk_level: 'high', atlas_techniques: ['AML.T0051', 'AML.T0054'], mitigation_ids: ['mit-001', 'mit-002'] },
    { id: 'th-002', title: 'Tool Output Manipulation', description: 'Malicious data in cloud API response alters agent decision-making mid-execution.', category: 'tampering', affected_components: ['ToolExecutor', 'CloudAPIClient'], trust_boundary: 'Cloud APIs', entry_point: 'Cloud API response', likelihood: 'low', impact: 'high', risk_level: 'medium', atlas_techniques: ['AML.T0020'], mitigation_ids: ['mit-003'] },
    { id: 'th-003', title: 'Training Data Extraction via Probing', description: 'Repeated crafted queries extract memorized training data from the underlying LLM.', category: 'information_disclosure', affected_components: ['LLMInvoker'], trust_boundary: 'Agent Runtime', entry_point: 'LLM prompt', likelihood: 'low', impact: 'medium', risk_level: 'low', atlas_techniques: ['AML.T0025', 'AML.T0035'], mitigation_ids: ['mit-002'] },
    { id: 'th-004', title: 'Policy Bypass via Prompt Engineering', description: 'Adversary crafts prompts to make agent call privileged tools without triggering policy deny rules.', category: 'elevation_of_privilege', affected_components: ['PolicyEvaluator', 'ToolExecutor'], trust_boundary: 'Policy Engine', entry_point: 'Agent instructions', likelihood: 'medium', impact: 'critical', risk_level: 'critical', atlas_techniques: ['AML.T0054', 'AML.T0051'], mitigation_ids: ['mit-001', 'mit-004'] },
    { id: 'th-005', title: 'Audit Log Suppression', description: 'Agent or compromised tool omits span data from trace, removing forensic evidence.', category: 'repudiation', affected_components: ['TraceCollector', 'SpanExporter'], trust_boundary: 'Agent Runtime', entry_point: 'Trace export pipeline', likelihood: 'low', impact: 'medium', risk_level: 'low', atlas_techniques: ['AML.T0048'], mitigation_ids: ['mit-003'] },
    { id: 'th-006', title: 'Token Budget Exhaustion', description: 'Recursive agent loop or adversarial prompt inflates token usage, triggering rate limits and degrading service.', category: 'denial_of_service', affected_components: ['LLMInvoker', 'AgentRunner'], trust_boundary: 'Agent Runtime', entry_point: 'LLM invocation loop', likelihood: 'medium', impact: 'medium', risk_level: 'medium', atlas_techniques: ['AML.T0016'], mitigation_ids: ['mit-004'] },
  ],
  risk_summary: { total_threats: 6, threats_by_category: { spoofing: 1, tampering: 1, repudiation: 1, information_disclosure: 1, denial_of_service: 1, elevation_of_privilege: 1 }, threats_by_risk: { critical: 1, high: 1, medium: 2, low: 2 }, mitigation_coverage: 75, residual_risk_score: 3.2 },
}

function getThreatModelForAgent(agentId: string, framework: string): ThreatModel {
  const profile = FRAMEWORK_PROFILES[framework] ?? DEFAULT_PROFILE
  return {
    id: `tm-${framework}-${agentId.slice(0, 8)}`,
    name: profile.name,
    description: profile.description,
    scope: 'All agent interactions with cloud APIs, LLM providers, and internal policy engine.',
    target_agent_id: agentId,
    trust_boundaries: BASE_TRUST_BOUNDARIES,
    threats: profile.threats,
    mitigations: BASE_MITIGATIONS,
    risk_summary: profile.risk_summary,
    created_at: '2026-01-15T00:00:00Z',
    updated_at: '2026-02-27T00:00:00Z',
  }
}

// ── Helpers ────────────────────────────────────────────────────────────────

const RISK_CONFIG: Record<string, { bg: string; text: string; label: string }> = {
  critical: { bg: 'bg-red-100 dark:bg-red-900/30', text: 'text-red-800 dark:text-red-300', label: 'Critical' },
  high:     { bg: 'bg-orange-100 dark:bg-orange-900/30', text: 'text-orange-800 dark:text-orange-300', label: 'High' },
  medium:   { bg: 'bg-yellow-100 dark:bg-yellow-900/30', text: 'text-yellow-800 dark:text-yellow-300', label: 'Medium' },
  low:      { bg: 'bg-green-100 dark:bg-green-900/30', text: 'text-green-800 dark:text-green-300', label: 'Low' },
}

const STRIDE_META: Record<STRIDECategory, { label: string; color: string; abbr: string }> = {
  spoofing:               { label: 'Spoofing',               color: 'border-purple-300 bg-purple-50 dark:border-purple-700 dark:bg-purple-950/20',  abbr: 'S' },
  tampering:              { label: 'Tampering',              color: 'border-orange-300 bg-orange-50 dark:border-orange-700 dark:bg-orange-950/20',  abbr: 'T' },
  repudiation:            { label: 'Repudiation',            color: 'border-gray-300 bg-gray-50 dark:border-gray-700 dark:bg-gray-950/20',      abbr: 'R' },
  information_disclosure: { label: 'Info Disclosure',        color: 'border-blue-300 bg-blue-50 dark:border-blue-700 dark:bg-blue-950/20',      abbr: 'I' },
  denial_of_service:      { label: 'Denial of Service',      color: 'border-red-300 bg-red-50 dark:border-red-700 dark:bg-red-950/20',        abbr: 'D' },
  elevation_of_privilege: { label: 'Elevation of Privilege', color: 'border-rose-300 bg-rose-50 dark:border-rose-700 dark:bg-rose-950/20',      abbr: 'E' },
}

const MITIGATION_STATUS_CONFIG: Record<string, { icon: typeof CheckCircle2; className: string }> = {
  implemented: { icon: CheckCircle2, className: 'text-green-600 dark:text-green-400' },
  planned:     { icon: AlertTriangle, className: 'text-yellow-600 dark:text-yellow-400' },
  'not started': { icon: XCircle, className: 'text-red-500 dark:text-red-400' },
}

const SIGNAL_TYPE_LABELS: Record<SignalType, string> = {
  injection_attempt: 'Injection',
  data_exfiltration: 'Exfiltration',
  tool_abuse: 'Tool Abuse',
  privilege_escalation: 'PrivEsc',
  anomalous_behavior: 'Anomaly',
  policy_violation: 'Policy Block',
  rate_limit_exceeded: 'Rate Limit',
}

function formatDuration(ms: number) {
  if (ms < 1000) return `${ms}ms`
  return `${(ms / 1000).toFixed(1)}s`
}

function formatTs(iso: string) {
  return new Date(iso).toLocaleString()
}

// ── Trace row with expand/collapse ────────────────────────────────────────

function TraceRow({ trace }: { trace: AgentTrace }) {
  const [expanded, setExpanded] = useState(false)
  const statusColors: Record<string, string> = {
    completed: 'text-green-700 bg-green-50 dark:text-green-300 dark:bg-green-950/20',
    blocked:   'text-red-700 bg-red-50 dark:text-red-300 dark:bg-red-950/20',
    failed:    'text-red-700 bg-red-50 dark:text-red-300 dark:bg-red-950/20',
    running:   'text-blue-700 bg-blue-50 dark:text-blue-300 dark:bg-blue-950/20',
  }

  return (
    <div className="border rounded-none overflow-hidden">
      <button
        className="w-full flex items-center gap-3 px-4 py-3 hover:bg-muted/50 transition-colors text-left"
        onClick={() => setExpanded(v => !v)}
      >
        {expanded ? <ChevronDown className="h-4 w-4 shrink-0 text-muted-foreground" /> : <ChevronRight className="h-4 w-4 shrink-0 text-muted-foreground" />}
        <div className="flex-1 min-w-0 grid grid-cols-4 gap-4 items-center">
          <div>
            <p className="text-xs font-mono font-medium truncate">{trace.trace_id}</p>
            <p className="text-[10px] text-muted-foreground">sess: {trace.session_id}</p>
          </div>
          <div className="text-xs text-muted-foreground">{formatTs(trace.start_time)}</div>
          <div className="text-xs">{formatDuration(trace.duration_ms)}</div>
          <span className={cn('text-[10px] font-medium px-2 py-0.5 rounded-full w-fit', statusColors[trace.status] ?? 'text-gray-600 bg-gray-50 dark:text-gray-300 dark:bg-gray-950/20')}>
            {trace.status}
          </span>
        </div>
        {trace.metrics && (
          <div className="flex items-center gap-3 text-[10px] text-muted-foreground shrink-0">
            <span>{trace.metrics.total_spans} spans</span>
            <span>{trace.metrics.llm_calls} LLM</span>
            <span>{trace.metrics.total_tokens.toLocaleString()} tokens</span>
            <span>${trace.metrics.estimated_cost_usd.toFixed(4)}</span>
            {trace.metrics.security_signals > 0 && (
              <span className="text-red-600 dark:text-red-400 font-medium">{trace.metrics.security_signals} signal{trace.metrics.security_signals !== 1 ? 's' : ''}</span>
            )}
          </div>
        )}
      </button>
      {expanded && (
        <div className="px-4 pb-4 pt-2 bg-muted/20 border-t">
          <TraceTimeline spans={trace.spans} />
        </div>
      )}
    </div>
  )
}

// ── Main page ─────────────────────────────────────────────────────────────

export default function AIAgentDetail() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const { data: agent, isLoading: agentLoading } = useAgent(id ?? '')
  const { data: traces = [], isLoading: tracesLoading } = useAgentTraces(id ?? '')

  const [signalFilter, setSignalFilter] = useState<string>('all')

  if (agentLoading || tracesLoading) {
    return <div className="text-sm text-muted-foreground p-6">Loading agent data…</div>
  }
  if (!agent) {
    return <div className="text-sm text-muted-foreground p-6">Agent not found.</div>
  }

  const threatModel = getThreatModelForAgent(agent.id, agent.framework)
  const riskCfg = RISK_CONFIG[agent.risk_level] ?? RISK_CONFIG.low
  const allSignals = traces.flatMap(t => t.security_signals ?? [])
  const filteredSignals = signalFilter === 'all'
    ? allSignals
    : allSignals.filter(s => s.type === signalFilter)
  const signalTypeCounts = allSignals.reduce<Record<string, number>>((acc, s) => {
    acc[s.type] = (acc[s.type] ?? 0) + 1
    return acc
  }, {})

  return (
    <div className="space-y-6 max-w-6xl mx-auto pb-10">

      {/* Back button */}
      <Button variant="ghost" size="sm" className="gap-1.5 -ml-2" onClick={() => navigate('/admin/ai-agents')}>
        <ArrowLeft className="h-4 w-4" />
        All Agents
      </Button>

      {/* Agent header */}
      <div className="flex items-start justify-between gap-4">
        <div className="flex items-start gap-4">
          <div className="h-12 w-12 rounded-none bg-indigo-100 dark:bg-indigo-900/30 flex items-center justify-center shrink-0">
            <Bot className="h-6 w-6 text-indigo-700 dark:text-indigo-300" />
          </div>
          <div>
            <div className="flex items-center gap-3 flex-wrap">
              <h1 className="text-2xl font-bold">{agent.name}</h1>
              <AgentStatusBadge status={agent.status} />
              <span className={cn('text-xs font-semibold px-2.5 py-1 rounded-full', riskCfg.bg, riskCfg.text)}>
                {riskCfg.label} Risk
              </span>
            </div>
            <p className="mt-1 text-sm text-muted-foreground max-w-2xl">{agent.description}</p>
            <div className="flex items-center gap-4 mt-2 flex-wrap">
              <Badge variant="secondary" className="gap-1 text-xs">
                <Cpu className="h-3 w-3" />{agent.framework} v{agent.version}
              </Badge>
              <span className="text-xs text-muted-foreground flex items-center gap-1">
                <User className="h-3 w-3" />{agent.owner}
              </span>
              <span className="text-xs text-muted-foreground">Team: {agent.team}</span>
              <span className="text-xs text-muted-foreground">Env: {agent.environment}</span>
              {agent.last_active_at && (
                <span className="text-xs text-muted-foreground flex items-center gap-1">
                  <Clock className="h-3 w-3" />Last active: {formatTs(agent.last_active_at)}
                </span>
              )}
            </div>
          </div>
        </div>

        {/* Quick stats */}
        <div className="flex gap-3 shrink-0">
          {[
            { label: 'Traces', value: traces.length, color: 'text-indigo-700 dark:text-indigo-300' },
            { label: 'Signals', value: allSignals.length, color: allSignals.length > 0 ? 'text-red-600 dark:text-red-400' : 'text-green-600 dark:text-green-400' },
            { label: 'Tools', value: agent.tools.length, color: 'text-orange-600 dark:text-orange-400' },
            { label: 'Policies', value: agent.policies.length, color: 'text-blue-600 dark:text-blue-400' },
          ].map(({ label, value, color }) => (
            <div key={label} className="text-center px-4 py-2 bg-muted/50 rounded-none min-w-[64px]">
              <p className={cn('text-xl font-bold', color)}>{value}</p>
              <p className="text-[10px] text-muted-foreground">{label}</p>
            </div>
          ))}
        </div>
      </div>

      <Separator />

      {/* Tabs */}
      <Tabs defaultValue="traces">
        <TabsList className="mb-4">
          <TabsTrigger value="traces" className="gap-1.5">
            <Activity className="h-3.5 w-3.5" />Trace Timeline
          </TabsTrigger>
          <TabsTrigger value="stride" className="gap-1.5">
            <ShieldAlert className="h-3.5 w-3.5" />STRIDE Threats
          </TabsTrigger>
          <TabsTrigger value="signals" className="gap-1.5">
            <AlertTriangle className="h-3.5 w-3.5" />
            Security Signals
            {allSignals.length > 0 && (
              <span className="ml-1 h-4 w-4 rounded-full bg-red-500 text-white text-[9px] flex items-center justify-center">{allSignals.length}</span>
            )}
          </TabsTrigger>
          <TabsTrigger value="capabilities">Capabilities &amp; Tools</TabsTrigger>
        </TabsList>

        {/* ── Tab 1: Trace Timeline ──────────────────────────────────────── */}
        <TabsContent value="traces" className="space-y-3">
          {traces.length === 0 ? (
            <p className="text-sm text-muted-foreground">No traces recorded for this agent.</p>
          ) : traces.map(trace => (
            <TraceRow key={trace.trace_id} trace={trace} />
          ))}
        </TabsContent>

        {/* ── Tab 2: STRIDE Threat Model ─────────────────────────────────── */}
        <TabsContent value="stride" className="space-y-6">

          {/* Risk summary banner */}
          <div className="grid grid-cols-4 gap-4">
            {[
              { label: 'Total Threats', value: threatModel.risk_summary.total_threats, color: 'text-foreground' },
              { label: 'Critical', value: threatModel.risk_summary.threats_by_risk.critical ?? 0, color: 'text-red-700 dark:text-red-400' },
              { label: 'Coverage', value: `${threatModel.risk_summary.mitigation_coverage}%`, color: 'text-green-700 dark:text-green-400' },
              { label: 'Residual Risk', value: `${threatModel.risk_summary.residual_risk_score}/5`, color: 'text-orange-700 dark:text-orange-400' },
            ].map(({ label, value, color }) => (
              <Card key={label}>
                <CardContent className="p-4">
                  <p className={cn('text-2xl font-bold', color)}>{value}</p>
                  <p className="text-xs text-muted-foreground mt-0.5">{label}</p>
                </CardContent>
              </Card>
            ))}
          </div>

          {/* STRIDE grid */}
          <div>
            <h3 className="text-sm font-semibold mb-3">Threat Categories</h3>
            <div className="grid grid-cols-3 gap-3">
              {(Object.keys(STRIDE_META) as STRIDECategory[]).map(cat => {
                const meta = STRIDE_META[cat]
                const threats = threatModel.threats.filter(t => t.category === cat)
                const maxRisk = threats.reduce<string>((prev, t) => {
                  const order = ['critical', 'high', 'medium', 'low']
                  return order.indexOf(t.risk_level) < order.indexOf(prev) ? t.risk_level : prev
                }, 'low')
                const riskC = RISK_CONFIG[maxRisk]
                return (
                  <Card key={cat} className={cn('border', meta.color)}>
                    <CardHeader className="pb-1 pt-3 px-4">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <span className="text-[10px] font-bold bg-foreground/10 rounded px-1.5 py-0.5">{meta.abbr}</span>
                          <CardTitle className="text-xs">{meta.label}</CardTitle>
                        </div>
                        {threats.length > 0 && (
                          <span className={cn('text-[10px] font-semibold px-2 py-0.5 rounded-full', riskC?.bg, riskC?.text)}>
                            {maxRisk}
                          </span>
                        )}
                      </div>
                    </CardHeader>
                    <CardContent className="px-4 pb-3 pt-1">
                      {threats.length === 0 ? (
                        <p className="text-[10px] text-muted-foreground">No threats identified</p>
                      ) : (
                        <ul className="space-y-1">
                          {threats.map(t => (
                            <li key={t.id} className="text-[10px] flex items-start gap-1.5">
                              <span className={cn('mt-0.5 h-1.5 w-1.5 rounded-full shrink-0 inline-block', RISK_CONFIG[t.risk_level]?.bg?.replace('bg-', 'bg-').replace('-100', '-500') ?? 'bg-gray-400')} />
                              <span className="leading-tight">{t.title}</span>
                            </li>
                          ))}
                        </ul>
                      )}
                      {threats.length > 0 && threats[0].atlas_techniques.length > 0 && (
                        <div className="flex flex-wrap gap-1 mt-2">
                          {threats.flatMap(t => t.atlas_techniques).slice(0, 3).map(atl => (
                            <span key={atl} className="text-[9px] font-mono bg-background border rounded px-1">{atl}</span>
                          ))}
                        </div>
                      )}
                    </CardContent>
                  </Card>
                )
              })}
            </div>
          </div>

          {/* Mitigations list */}
          <div>
            <h3 className="text-sm font-semibold mb-3">Mitigations</h3>
            <div className="space-y-2">
              {threatModel.mitigations.map(m => {
                const cfg = MITIGATION_STATUS_CONFIG[m.status] ?? MITIGATION_STATUS_CONFIG['not started']
                const Icon = cfg.icon
                return (
                  <Card key={m.id}>
                    <CardContent className="p-4">
                      <div className="flex items-start gap-3">
                        <Icon className={cn('h-4 w-4 mt-0.5 shrink-0', cfg.className)} />
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 flex-wrap">
                            <p className="text-sm font-medium">{m.title}</p>
                            <Badge variant="outline" className="text-[10px]">{m.control_type}</Badge>
                            <span className={cn('text-[10px] font-medium capitalize', cfg.className)}>{m.status}</span>
                          </div>
                          <p className="text-xs text-muted-foreground mt-0.5">{m.description}</p>
                          <p className="text-xs text-muted-foreground mt-0.5 italic">{m.implementation}</p>
                          <div className="flex flex-wrap gap-1 mt-1.5">
                            {m.mapped_controls.map(ctrl => (
                              <span key={ctrl} className="text-[9px] font-mono bg-muted rounded px-1.5 py-0.5">{ctrl}</span>
                            ))}
                          </div>
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                )
              })}
            </div>
          </div>
        </TabsContent>

        {/* ── Tab 3: Security Signals ────────────────────────────────────── */}
        <TabsContent value="signals" className="space-y-4">

          {/* Signal type summary */}
          {allSignals.length > 0 && (
            <div className="flex flex-wrap gap-2">
              <Button
                variant={signalFilter === 'all' ? 'secondary' : 'outline'}
                size="sm"
                className="text-xs h-7 gap-1"
                onClick={() => setSignalFilter('all')}
              >
                <Filter className="h-3 w-3" />All ({allSignals.length})
              </Button>
              {Object.entries(signalTypeCounts).map(([type, count]) => (
                <Button
                  key={type}
                  variant={signalFilter === type ? 'secondary' : 'outline'}
                  size="sm"
                  className="text-xs h-7"
                  onClick={() => setSignalFilter(type)}
                >
                  {SIGNAL_TYPE_LABELS[type as SignalType] ?? type} ({count})
                </Button>
              ))}
            </div>
          )}

          {allSignals.length === 0 ? (
            <div className="flex items-center gap-2 text-sm text-green-700 dark:text-green-300 bg-green-50 dark:bg-green-950/20 border border-green-200 dark:border-green-800 rounded-none px-4 py-3">
              <CheckCircle2 className="h-4 w-4 shrink-0" />
              No security signals detected for this agent.
            </div>
          ) : filteredSignals.length === 0 ? (
            <p className="text-sm text-muted-foreground">No signals match the selected filter.</p>
          ) : (
            <div className="space-y-3">
              {filteredSignals.map(sig => (
                <Card key={sig.id} className={cn(sig.mitigated ? '' : 'border-red-200 dark:border-red-800')}>
                  <CardContent className="p-4">
                    <div className="flex items-start justify-between gap-3">
                      <div className="flex items-start gap-3 flex-1 min-w-0">
                        <SecuritySignalBadge type={sig.type as SignalType} severity={sig.severity} />
                        <div className="min-w-0">
                          <p className="text-sm font-medium leading-snug">{sig.title}</p>
                          <p className="text-xs text-muted-foreground mt-0.5">{sig.description}</p>
                          <p className="text-[10px] text-muted-foreground mt-1">{formatTs(sig.timestamp)}</p>
                        </div>
                      </div>
                      <div className="shrink-0 flex flex-col items-end gap-1">
                        <span className={cn(
                          'text-[10px] font-medium px-2 py-0.5 rounded-full',
                          sig.mitigated ? 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300' : 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300'
                        )}>
                          {sig.mitigated ? 'Mitigated' : 'Open'}
                        </span>
                        <span className="text-[9px] font-mono text-muted-foreground">{sig.span_id}</span>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          )}
        </TabsContent>

        {/* ── Tab 4: Capabilities & Tools ───────────────────────────────── */}
        <TabsContent value="capabilities" className="space-y-6">

          {/* Capabilities */}
          <div>
            <h3 className="text-sm font-semibold mb-3">Capabilities</h3>
            <div className="space-y-2">
              {agent.capabilities.map(cap => {
                const cfg = RISK_CONFIG[cap.risk_level] ?? RISK_CONFIG.low
                return (
                  <Card key={cap.name}>
                    <CardContent className="p-4">
                      <div className="flex items-start justify-between gap-3">
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 mb-1">
                            <p className="text-sm font-medium font-mono">{cap.name}</p>
                            <span className={cn('text-[10px] font-semibold px-2 py-0.5 rounded-full', cfg.bg, cfg.text)}>
                              {cfg.label}
                            </span>
                          </div>
                          <p className="text-xs text-muted-foreground">{cap.description}</p>
                          <div className="flex flex-wrap gap-1 mt-2">
                            {cap.data_access.map(da => (
                              <code key={da} className="text-[9px] font-mono bg-muted border rounded px-1.5 py-0.5">{da}</code>
                            ))}
                          </div>
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                )
              })}
            </div>
          </div>

          {/* Tools table */}
          <div>
            <h3 className="text-sm font-semibold mb-3">Tool Bindings</h3>
            <Card>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="text-xs">Tool</TableHead>
                    <TableHead className="text-xs">Category</TableHead>
                    <TableHead className="text-xs">Permissions</TableHead>
                    <TableHead className="text-xs">Parameters</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {agent.tools.map(tool => (
                    <TableRow key={tool.tool_id}>
                      <TableCell>
                        <p className="text-xs font-medium font-mono">{tool.name}</p>
                        <p className="text-[10px] text-muted-foreground">{tool.tool_id}</p>
                      </TableCell>
                      <TableCell>
                        <Badge variant="secondary" className="text-[10px]">{tool.category}</Badge>
                      </TableCell>
                      <TableCell>
                        <div className="flex flex-col gap-0.5">
                          {tool.permissions.map(p => (
                            <code key={p} className="text-[9px] font-mono">{p}</code>
                          ))}
                        </div>
                      </TableCell>
                      <TableCell>
                        {Object.keys(tool.parameters).length === 0 ? (
                          <span className="text-[10px] text-muted-foreground">—</span>
                        ) : (
                          <div className="flex flex-col gap-0.5">
                            {Object.entries(tool.parameters).map(([k, v]) => (
                              <code key={k} className="text-[9px] font-mono">{k}: {String(v)}</code>
                            ))}
                          </div>
                        )}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </Card>
          </div>

          {/* Bound policies */}
          <div>
            <h3 className="text-sm font-semibold mb-3">Bound Policies</h3>
            <div className="flex flex-wrap gap-2">
              {agent.policies.map(polId => (
                <Badge key={polId} variant="outline" className="font-mono text-xs">{polId}</Badge>
              ))}
            </div>
          </div>
        </TabsContent>
      </Tabs>
    </div>
  )
}
