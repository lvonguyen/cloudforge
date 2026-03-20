import { useQuery } from '@tanstack/react-query'
import { fetchWithMockFallback } from '@/lib/api'

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
    queryFn: () => fetchWithMockFallback<UserRow[]>(
      `/users${role ? `?role=${role}` : ''}`,
      () => import('@/lib/mock/users.json') as Promise<{ default: UserRow[] }>,
      'useUsers',
    ),
  })
}
