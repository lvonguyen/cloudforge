import type { AttackPath } from '@/types/attack-path'
import type { Finding } from '@/types/compliance'

export type ThreatContextCueKind = 'public_internet' | 'network_boundary'

export interface ThreatContextCue {
  kind: ThreatContextCueKind
  label: string
  detail: string
  evidence: string[]
}

export interface ThreatContextSignals {
  exposureSurface?: ThreatContextCue
  networkBoundary?: ThreatContextCue
}

interface ThreatContextExplicitSource {
  internet_facing?: boolean
  entry_point_type?: string
  network_boundary?: string
  subnet?: string
  tags?: Record<string, string>
}

const PUBLIC_SIGNAL_PATTERNS: Array<{ pattern: RegExp; evidence: string }> = [
  { pattern: /0\.0\.0\.0\/0/i, evidence: '0.0.0.0/0 rule' },
  { pattern: /\bpublic(?:ly)?\b/i, evidence: 'public-facing language' },
  { pattern: /\binternet(?:-facing)?\b/i, evidence: 'internet-facing language' },
  { pattern: /\bexternal\b/i, evidence: 'external access language' },
  { pattern: /\bingress\b/i, evidence: 'ingress language' },
  { pattern: /\bapi gateway\b/i, evidence: 'API gateway' },
  { pattern: /\balb\b|\bapplication load balancer\b/i, evidence: 'load balancer' },
  { pattern: /\belb\b|\bload balancer\b/i, evidence: 'load balancer' },
  { pattern: /\bpublic subnet\b/i, evidence: 'public subnet' },
  { pattern: /\bopen to the world\b/i, evidence: 'open-to-world wording' },
]

const BOUNDARY_SIGNAL_PATTERNS: Array<{ pattern: RegExp; evidence: string }> = [
  { pattern: /\bnsg\b|\bnetwork security group\b/i, evidence: 'NSG' },
  { pattern: /\bsecurity group\b|\bsg-[a-z0-9-]+\b/i, evidence: 'security group' },
  { pattern: /\bfirewall\b|\bvpc firewall\b/i, evidence: 'firewall' },
  { pattern: /\bdmz\b/i, evidence: 'DMZ' },
  { pattern: /\bsubnet\b/i, evidence: 'subnet' },
  { pattern: /\bvnet\b|\bvpc\b/i, evidence: 'virtual network boundary' },
  { pattern: /\bprivate link\b|\bservice endpoint\b/i, evidence: 'private link / service endpoint' },
  { pattern: /\binternet gateway\b|\begress gateway\b|\bgateway\b/i, evidence: 'gateway boundary' },
]

function joinSignals(parts: Array<string | string[] | undefined>): string {
  return parts
    .flatMap(part => Array.isArray(part) ? part : [part])
    .filter((part): part is string => Boolean(part))
    .join(' ')
    .toLowerCase()
}

function collectEvidence(
  haystack: string,
  patterns: Array<{ pattern: RegExp; evidence: string }>,
): string[] {
  return [...new Set(
    patterns
      .filter(({ pattern }) => pattern.test(haystack))
      .map(({ evidence }) => evidence),
  )]
}

function readTag(tags: Record<string, string> | undefined, keys: string[]): string | undefined {
  if (!tags) return undefined
  const normalizedKeys = new Set(keys.map(key => key.toLowerCase()))
  for (const [key, value] of Object.entries(tags)) {
    if (normalizedKeys.has(key.toLowerCase()) && value.trim()) return value.trim()
  }
  return undefined
}

function isTruthyTag(value?: string): boolean {
  if (!value) return false
  return ['1', 'true', 'yes', 'y', 'public', 'internet', 'external'].includes(value.trim().toLowerCase())
}

function boundaryLabelForProvider(provider?: string, haystack = ''): string {
  if (/\bdmz\b|\bpublic subnet\b/i.test(haystack)) return 'DMZ / subnet'
  if (/\bnsg\b|\bnetwork security group\b/i.test(haystack)) return 'NSG / VNet'
  if (/\bsecurity group\b|\bsg-[a-z0-9-]+\b/i.test(haystack)) return 'Security group / subnet'
  if (/\bfirewall\b/i.test(haystack)) return 'Firewall / network boundary'

  switch (provider) {
    case 'azure':
      return 'NSG / VNet'
    case 'gcp':
      return 'Firewall / VPC boundary'
    case 'aws':
      return 'Security group / subnet'
    default:
      return 'Network boundary'
  }
}

function collectFindingHaystack(finding: Finding): string {
  return joinSignals([
    finding.title,
    finding.description,
    finding.ai_risk_rationale,
    finding.remediation,
    finding.resource_name,
    finding.resource_type,
    finding.category,
    finding.type,
    finding.ai_contextual_factors,
    finding.toxic_combo_details?.description,
    finding.toxic_combo_details?.attack_vector,
    finding.toxic_combo_details?.attack_path,
    Object.entries(finding.tags ?? {}).flatMap(([key, value]) => [key, value]),
  ])
}

function collectAttackPathHaystack(path: AttackPath, relatedFindings: Finding[]): string {
  return joinSignals([
    path.title,
    path.description,
    path.ai_description,
    path.ai_remediation,
    path.ai_risk_narrative,
    path.entry_point.resource_name,
    path.entry_point.resource_type,
    path.entry_point.category,
    path.target.resource_name,
    path.target.resource_type,
    path.nodes.flatMap(node => [node.resource_name, node.resource_type, node.category]),
    relatedFindings.map(collectFindingHaystack),
  ])
}

function buildExplicitSignals(
  explicitSource: ThreatContextExplicitSource | undefined,
): ThreatContextSignals {
  if (!explicitSource) return {}

  const explicitInternetFacing =
    explicitSource.internet_facing === true ||
    explicitSource.entry_point_type?.trim().toLowerCase() === 'internet' ||
    isTruthyTag(readTag(explicitSource.tags, ['internet_facing', 'public_exposure', 'exposure_surface']))

  const explicitBoundary =
    explicitSource.network_boundary ||
    readTag(explicitSource.tags, ['network_boundary', 'network-zone', 'network_zone']) ||
    explicitSource.subnet ||
    readTag(explicitSource.tags, ['subnet', 'security_group', 'security-group', 'nsg', 'firewall', 'dmz'])

  return {
    exposureSurface: explicitInternetFacing
      ? {
          kind: 'public_internet',
          label: 'Public internet',
          detail: 'Reported directly by path or finding metadata instead of heuristic inference.',
          evidence: ['explicit network exposure metadata'],
        }
      : undefined,
    networkBoundary: explicitBoundary
      ? {
          kind: 'network_boundary',
          label: explicitBoundary,
          detail: 'Reported directly by path or finding metadata instead of heuristic inference.',
          evidence: ['explicit network boundary metadata'],
        }
      : undefined,
  }
}

function buildSignals(
  haystack: string,
  provider?: string,
  explicitSource?: ThreatContextExplicitSource,
): ThreatContextSignals {
  const explicitSignals = buildExplicitSignals(explicitSource)
  const exposureEvidence = collectEvidence(haystack, PUBLIC_SIGNAL_PATTERNS)
  const boundaryEvidence = collectEvidence(haystack, BOUNDARY_SIGNAL_PATTERNS)

  const hasExposureSignal =
    exposureEvidence.length > 0 ||
    /\bnetwork[_ ]exposure\b/i.test(haystack)

  const hasBoundarySignal = boundaryEvidence.length > 0 || hasExposureSignal

  const exposureSurface = explicitSignals.exposureSurface ?? (hasExposureSignal
    ? {
        kind: 'public_internet' as const,
        label: 'Public internet',
        detail: 'Inferred internet-reachable ingress based on finding, remediation, or path context.',
        evidence: exposureEvidence.length > 0 ? exposureEvidence : ['network exposure context'],
      }
    : undefined)

  const networkBoundary = explicitSignals.networkBoundary ?? (hasBoundarySignal
    ? {
        kind: 'network_boundary' as const,
        label: boundaryLabelForProvider(provider, haystack),
        detail: 'Inferred network control boundary analysts should validate before treating the path as externally reachable.',
        evidence: boundaryEvidence.length > 0
          ? boundaryEvidence
          : ['provider network controls'],
      }
    : undefined)

  return { exposureSurface, networkBoundary }
}

export function inferFindingThreatContextSignals(finding: Finding): ThreatContextSignals {
  return buildSignals(collectFindingHaystack(finding), finding.cloud_provider, finding)
}

export function inferAttackPathThreatContextSignals(
  path: AttackPath,
  relatedFindings: Finding[] = [],
): ThreatContextSignals {
  const firstExplicitFinding = relatedFindings.find(finding =>
    finding.internet_facing === true ||
    Boolean(finding.network_boundary) ||
    Boolean(finding.subnet) ||
    Boolean(readTag(finding.tags, ['internet_facing', 'public_exposure', 'exposure_surface', 'network_boundary', 'network-zone', 'network_zone', 'subnet', 'security_group', 'security-group', 'nsg', 'firewall', 'dmz'])),
  )

  return buildSignals(
    collectAttackPathHaystack(path, relatedFindings),
    path.entry_point.provider,
    {
      internet_facing:
        path.entry_point.internet_facing ??
        (path.entry_point_type?.trim().toLowerCase() === 'internet' ? true : undefined) ??
        firstExplicitFinding?.internet_facing,
      entry_point_type: path.entry_point_type,
      network_boundary:
        path.entry_point.network_boundary ??
        firstExplicitFinding?.network_boundary,
      subnet:
        path.entry_point.subnet ??
        firstExplicitFinding?.subnet,
      tags: firstExplicitFinding?.tags,
    },
  )
}
