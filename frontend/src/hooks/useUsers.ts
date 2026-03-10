import { useQuery } from '@tanstack/react-query'
import { apiClient, ApiError } from '@/lib/api'

interface UserRow {
  id: string
  name: string
  email: string
  role: 'admin' | 'operator' | 'requester'
  team: string
  last_login: string
  status: 'active' | 'inactive'
}

export function useUsers(roleFilter?: string) {
  const role = roleFilter && roleFilter !== 'all' ? roleFilter : undefined
  return useQuery({
    queryKey: ['users', roleFilter],
    queryFn: async () => {
      try {
        return await apiClient.get<UserRow[]>(`/users${role ? `?role=${role}` : ''}`)
      } catch (err) {
        if (err instanceof ApiError && err.status < 500) throw err
        console.warn('[useUsers] API unavailable, using mock data')
        const mod = await import('@/lib/mock/users.json')
        return mod.default as UserRow[]
      }
    },
  })
}
