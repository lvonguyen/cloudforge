import {
  AlertTriangle,
  Boxes,
  Bug,
  Cloud,
  Crown,
  Cpu,
  Database,
  FileKey2,
  Globe,
  HardDrive,
  KeyRound,
  Network,
  Server,
  ShieldAlert,
  type LucideIcon,
} from 'lucide-react'
import type { AttackPathEdge, AttackPathNode } from '@/types/attack-path'

type NodeVisualInput = Pick<AttackPathNode, 'resource_type' | 'category' | 'resource_name' | 'label'>
type EdgeVisualInput = Pick<AttackPathEdge, 'edge_type' | 'label'>

function includesAny(value: string, terms: string[]) {
  return terms.some(term => value.includes(term))
}

function normalizeNodeTokens(node: NodeVisualInput) {
  return [
    node.resource_type ?? '',
    node.category ?? '',
    node.resource_name ?? '',
    node.label ?? '',
  ]
    .join(' ')
    .toLowerCase()
}

function normalizeEdgeTokens(edge: EdgeVisualInput) {
  return [edge.edge_type ?? '', edge.label ?? ''].join(' ').toLowerCase()
}

export function getAttackPathResourceIcon(node: NodeVisualInput): LucideIcon {
  const tokens = normalizeNodeTokens(node)

  if (includesAny(tokens, ['iam', 'role', 'identity', 'principal', 'serviceaccount', 'policy'])) return KeyRound
  if (includesAny(tokens, ['secret', 'kms', 'keyvault', 'vault', 'certificate', 'token'])) return FileKey2
  if (includesAny(tokens, ['database', 'rds', 'sql', 'postgres', 'mysql', 'dynamo', 'bigquery', 'redshift', 'spanner', 'cosmos', 'alloydb', 'warehouse'])) return Database
  if (includesAny(tokens, ['s3', 'bucket', 'blob', 'storage', 'object', 'filestore', 'efs', 'fsx'])) return HardDrive
  if (includesAny(tokens, ['kubernetes', 'container', 'cluster', 'eks', 'ecs', 'gke', 'aks', 'pod', 'ecr', 'acr', 'artifact'])) return Boxes
  if (includesAny(tokens, ['lambda', 'function', 'cloudrun', 'serverless', 'appservice', 'runner'])) return Cpu
  if (includesAny(tokens, ['network', 'vpc', 'subnet', 'gateway', 'cdn', 'apigateway', 'ingress', 'loadbalancer', 'frontdoor', 'firewall', 'security_group', 'nsg'])) return Globe
  if (includesAny(tokens, ['vulnerability', 'cve', 'exploit'])) return Bug
  if (includesAny(tokens, ['misconfiguration', 'exposure', 'public'])) return ShieldAlert
  if (includesAny(tokens, ['compute', 'instance', 'ec2', 'vm', 'server', 'node'])) return Server
  if (includesAny(tokens, ['route', 'path', 'hop'])) return Network
  if (tokens.includes('cloud')) return Cloud
  return AlertTriangle
}

export function isCrownJewelNode(node: NodeVisualInput) {
  const tokens = normalizeNodeTokens(node)
  return includesAny(tokens, [
    'database',
    'warehouse',
    'bucket',
    'blob',
    'storage',
    'secret',
    'kms',
    'keyvault',
    'vault',
    'token',
    'pii',
    'patient',
    'payroll',
    'customer',
    'finance',
    'orders-db',
    'prod',
  ])
}

export function isPrivilegeEscalationEdge(edge: EdgeVisualInput) {
  const tokens = normalizeEdgeTokens(edge)
  return includesAny(tokens, [
    'assume_role',
    'assume-role',
    'privilege',
    'escalat',
    'impersonat',
    'trust',
    'sts',
    'role chaining',
  ])
}

export function isExposureEdge(edge: EdgeVisualInput) {
  const tokens = normalizeEdgeTokens(edge)
  return includesAny(tokens, ['internet', 'public', 'ingress', 'exposed', 'external'])
}

export function isImpactEdge(edge: EdgeVisualInput) {
  const tokens = normalizeEdgeTokens(edge)
  return includesAny(tokens, ['can_access', 'db-access', 'data', 's3', 'bucket', 'impact', 'write', 'read'])
}

export function formatEdgeLabel(edge: EdgeVisualInput) {
  const base = edge.label || edge.edge_type || 'connected'
  if (isPrivilegeEscalationEdge(edge)) return 'Privilege escalation'
  if (isExposureEdge(edge)) return 'Network reachability'
  if (isImpactEdge(edge)) return 'Data access'
  return base
}

export function getEdgeAccent(edge: EdgeVisualInput) {
  if (isPrivilegeEscalationEdge(edge)) return { stroke: '#f59e0b', label: 'privilege' as const, tone: 'amber' as const, emphasize: true }
  if (isImpactEdge(edge)) return { stroke: '#8b5cf6', label: 'impact' as const, tone: 'violet' as const, emphasize: true }
  if (isExposureEdge(edge)) return { stroke: '#0ea5e9', label: 'exposure' as const, tone: 'sky' as const, emphasize: false }
  return { stroke: null, label: 'default' as const, tone: 'slate' as const, emphasize: false }
}

export function formatResourceTypeLabel(resourceType: string) {
  const normalized = resourceType.replaceAll('_', ' ').trim()
  if (!normalized) return 'resource'
  return normalized.replace(/\b\w/g, (char) => char.toUpperCase())
}

export function formatAttackPathResourceType(resourceType?: string) {
  return formatResourceTypeLabel(resourceType ?? '')
}

export function getAttackPathEdgeMeta(edge: EdgeVisualInput) {
  const accent = getEdgeAccent(edge)
  return {
    label: formatEdgeLabel(edge),
    tone: accent.tone,
    emphasize: accent.emphasize,
  }
}

export function getAttackPathEdgeSemantic(edge: EdgeVisualInput) {
  const meta = getAttackPathEdgeMeta(edge)
  return {
    badge: meta.label,
    detail: meta.label,
    tone: meta.tone,
    emphasize: meta.emphasize,
    color:
      meta.tone === 'amber'
        ? '#f59e0b'
        : meta.tone === 'violet'
          ? '#8b5cf6'
          : meta.tone === 'sky'
            ? '#0ea5e9'
            : '#64748b',
    icon: meta.tone === 'amber' ? ShieldAlert : meta.tone === 'violet' ? Crown : meta.tone === 'sky' ? Globe : Network,
  }
}

export function getCrownJewelIcon() {
  return Crown
}

export function getCrownJewelLabel(node: NodeVisualInput) {
  const tokens = normalizeNodeTokens(node)
  if (includesAny(tokens, ['secret', 'kms', 'keyvault', 'vault', 'token'])) return 'Secrets / key material'
  if (includesAny(tokens, ['iam', 'identity', 'principal'])) return 'Identity control plane'
  if (includesAny(tokens, ['database', 'warehouse', 'bucket', 'blob', 'storage'])) return 'Sensitive data store'
  return 'High-value asset'
}

export { Crown }
