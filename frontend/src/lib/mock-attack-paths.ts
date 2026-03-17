/**
 * Client-side mock attack path generator.
 * Mirrors the Go server's computeAttackPaths heuristic so attack paths
 * render when the backend isn't running (dev mode, Cloudflare Pages).
 */
import type { Finding } from '@/types/compliance'
import type { AttackPath, AttackPathNode, AttackPathEdge, AttackPathStats } from '@/types/attack-path'

const SEVERITY_RANK: Record<string, number> = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 }

function isEntryPoint(f: Finding): boolean {
  if (f.category === 'NETWORK') return true
  if (f.category === 'VULNERABILITY' && f.exploit_available) return true
  const rt = f.resource_type?.toLowerCase() ?? ''
  if (['compute', 'container', 'serverless'].some(t => rt.includes(t))) {
    return (SEVERITY_RANK[f.severity] ?? 0) >= 3
  }
  return false
}

function isTarget(f: Finding): boolean {
  const rt = f.resource_type?.toLowerCase() ?? ''
  return rt === 'storage' || rt === 'database' || rt === 'secret' || rt === 'encryption'
}

function canConnect(a: Finding, b: Finding): boolean {
  if (a.account_id !== b.account_id) return false
  if (a.resource_id === b.resource_id) return false
  return a.region === b.region || a.resource_type === b.resource_type
}

function findingToNode(f: Finding): AttackPathNode {
  return {
    id: `node-${f.id}`,
    finding_id: f.id,
    resource_id: f.resource_id,
    resource_name: f.resource_name,
    resource_type: f.resource_type,
    provider: f.cloud_provider,
    account_id: f.account_id,
    region: f.region,
    severity: f.severity,
    category: f.category,
    label: `${f.resource_name} (${f.resource_type})`,
  }
}

function inferEdgeType(from: Finding, to: Finding): string {
  const toType = to.resource_type?.toLowerCase() ?? ''
  if (['storage', 'database', 'secret'].some(t => toType.includes(t))) return 'data_access'
  if (from.category === 'IDENTITY' || to.category === 'IDENTITY') return 'iam_trust'
  if (from.category === 'NETWORK' || to.category === 'NETWORK') return 'network_reachable'
  return 'lateral_movement'
}

function buildEdge(from: Finding, to: Finding, index: number): AttackPathEdge {
  const edgeType = inferEdgeType(from, to)
  const labels: Record<string, string> = {
    data_access: 'Can access data',
    iam_trust: 'IAM trust relationship',
    network_reachable: 'Network reachable',
    lateral_movement: 'Lateral movement',
  }
  return {
    id: `edge-${index}`,
    source: `node-${from.id}`,
    target: `node-${to.id}`,
    label: labels[edgeType] ?? edgeType,
    edge_type: edgeType,
  }
}

/** Generate mock attack paths from findings data, mirroring Go computeAttackPaths. */
export function computeMockAttackPaths(findings: Finding[]): { paths: AttackPath[]; stats: AttackPathStats } {
  // Group by account
  const byAccount = new Map<string, Finding[]>()
  for (const f of findings) {
    const acc = f.account_id
    if (!byAccount.has(acc)) byAccount.set(acc, [])
    byAccount.get(acc)!.push(f)
  }

  const paths: AttackPath[] = []
  const usedFindings = new Set<string>()
  let pathIndex = 0

  for (const [, accountFindings] of byAccount) {
    if (accountFindings.length < 2) continue

    const entries = accountFindings.filter(isEntryPoint)
    const targets = accountFindings.filter(isTarget)
    const intermediates = accountFindings.filter(f => !isEntryPoint(f) && !isTarget(f))

    // Build chains: entry -> target (direct or via intermediate)
    for (const entry of entries) {
      for (const target of targets) {
        if (!canConnect(entry, target) && intermediates.length === 0) continue

        // Try direct connection
        if (canConnect(entry, target)) {
          const nodes = [findingToNode(entry), findingToNode(target)]
          const edges = [buildEdge(entry, target, 0)]
          const score = Math.min(
            (SEVERITY_RANK[entry.severity] ?? 1) * 25 + (SEVERITY_RANK[target.severity] ?? 1) * 25,
            100,
          )

          paths.push({
            id: `ap-${String(++pathIndex).padStart(4, '0')}`,
            title: `${entry.resource_name} → ${target.resource_name}`,
            description: `Attack path from ${entry.category.toLowerCase()} finding on ${entry.resource_name} to ${target.resource_type} ${target.resource_name}`,
            severity: (SEVERITY_RANK[entry.severity] ?? 0) >= 4 ? 'CRITICAL' : 'HIGH',
            score,
            hop_count: nodes.length - 1,
            entry_point: nodes[0],
            target: nodes[1],
            nodes,
            edges,
            mitre_tactics: entry.mitre_tactics ?? [],
            finding_ids: [entry.id, target.id],
            ai_enriched: false,
          })

          usedFindings.add(entry.id)
          usedFindings.add(target.id)

          // Cap per-account to avoid explosion
          if (paths.length > 200) break
          continue
        }

        // Try via intermediate
        for (const mid of intermediates) {
          if (canConnect(entry, mid) && canConnect(mid, target)) {
            const nodes = [findingToNode(entry), findingToNode(mid), findingToNode(target)]
            const edges = [buildEdge(entry, mid, 0), buildEdge(mid, target, 1)]
            const score = Math.min(
              (SEVERITY_RANK[entry.severity] ?? 1) * 25 +
                (SEVERITY_RANK[mid.severity] ?? 1) * 25 +
                (SEVERITY_RANK[target.severity] ?? 1) * 25,
              100,
            )

            paths.push({
              id: `ap-${String(++pathIndex).padStart(4, '0')}`,
              title: `${entry.resource_name} → ${mid.resource_name} → ${target.resource_name}`,
              description: `Multi-hop attack from ${entry.resource_name} through ${mid.resource_name} to ${target.resource_name}`,
              severity: (SEVERITY_RANK[entry.severity] ?? 0) >= 4 ? 'CRITICAL' : 'HIGH',
              score,
              hop_count: nodes.length - 1,
              entry_point: nodes[0],
              target: nodes[2],
              nodes,
              edges,
              mitre_tactics: [...new Set([...(entry.mitre_tactics ?? []), ...(mid.mitre_tactics ?? [])])],
              finding_ids: [entry.id, mid.id, target.id],
              ai_enriched: false,
            })

            usedFindings.add(entry.id)
            usedFindings.add(mid.id)
            usedFindings.add(target.id)
            break // one intermediate per entry-target pair
          }
        }

        if (paths.length > 200) break
      }
      if (paths.length > 200) break
    }
  }

  // Sort by severity rank desc, then score desc
  paths.sort((a, b) => {
    const ra = SEVERITY_RANK[a.severity] ?? 0
    const rb = SEVERITY_RANK[b.severity] ?? 0
    if (rb !== ra) return rb - ra
    return b.score - a.score
  })

  // Compute stats
  const stats: AttackPathStats = {
    total_findings: findings.length,
    findings_in_paths: usedFindings.size,
    isolated_findings: findings.length - usedFindings.size,
    coverage_percent: findings.length > 0 ? Math.round((usedFindings.size / findings.length) * 100) : 0,
    total_paths: paths.length,
    critical_paths: paths.filter(p => p.severity === 'CRITICAL').length,
    high_paths: paths.filter(p => p.severity === 'HIGH').length,
    medium_paths: paths.filter(p => p.severity === 'MEDIUM').length,
    by_provider: {},
  }

  for (const p of paths) {
    const prov = p.entry_point.provider
    stats.by_provider[prov] = (stats.by_provider[prov] ?? 0) + 1
  }

  return { paths, stats }
}
