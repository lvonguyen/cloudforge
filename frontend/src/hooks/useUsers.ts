import { useQuery } from '@tanstack/react-query'
import usersData from '@/lib/mock/users.json'

interface UserRow {
  id: string
  name: string
  email: string
  role: 'admin' | 'operator' | 'requester'
  team: string
  last_login: string
  status: 'active' | 'inactive'
}

const users = usersData as UserRow[]

export function useUsers(roleFilter?: string) {
  return useQuery({
    queryKey: ['users', roleFilter],
    queryFn: async () => {
      if (!roleFilter || roleFilter === 'all') return users
      return users.filter(u => u.role === roleFilter)
    },
  })
}
