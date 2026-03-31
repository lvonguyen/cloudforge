import { useQuery } from '@tanstack/react-query'
import { apiClient } from '@/lib/api'
import type { GraphQueryResult, GraphStats } from '@/types/security-graph'

/**
 * Fetch the typed subgraph within N hops of a node from the backend.
 * Uses GET /api/v1/graph/neighborhood/{nodeType}/{nodeId}?hops=N&limit=N
 */
export function useGraphNeighborhood(
  nodeType: string | null,
  nodeId: string | null,
  hops = 1,
  limit = 100,
) {
  return useQuery({
    queryKey: ['graph', 'neighborhood', nodeType, nodeId, hops, limit],
    queryFn: () =>
      apiClient.get<GraphQueryResult>(
        `/graph/neighborhood/${encodeURIComponent(nodeType!)}/${encodeURIComponent(nodeId!)}?hops=${hops}&limit=${limit}`,
      ),
    enabled: !!nodeType && !!nodeId,
    staleTime: 60_000,
  })
}

/**
 * Fetch graph vertex/edge counts grouped by type.
 * Uses GET /api/v1/graph/stats
 */
export function useGraphStats() {
  return useQuery({
    queryKey: ['graph', 'stats'],
    queryFn: () => apiClient.get<GraphStats>('/graph/stats'),
    staleTime: 60_000,
  })
}
