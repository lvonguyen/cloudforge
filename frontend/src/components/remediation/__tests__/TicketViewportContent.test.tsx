import { beforeEach, describe, expect, it, vi } from 'vitest'
import { screen } from '@testing-library/react'

import { renderWithProviders } from '@/test/utils'
import { TicketViewportContent } from '../TicketViewportContent'

const useFindingTicketMock = vi.fn()
const useTicketCommentsMock = vi.fn()
const useAddTicketCommentMock = vi.fn()
const useSyncTicketStatusMock = vi.fn()

vi.mock('@/hooks/useIntegrations', () => ({
  useFindingTicket: (...args: unknown[]) => useFindingTicketMock(...args),
  useTicketComments: (...args: unknown[]) => useTicketCommentsMock(...args),
  useAddTicketComment: (...args: unknown[]) => useAddTicketCommentMock(...args),
  useSyncTicketStatus: (...args: unknown[]) => useSyncTicketStatusMock(...args),
}))

describe('TicketViewportContent', () => {
  beforeEach(() => {
    useFindingTicketMock.mockReset()
    useTicketCommentsMock.mockReset()
    useAddTicketCommentMock.mockReset()
    useSyncTicketStatusMock.mockReset()

    useTicketCommentsMock.mockReturnValue({ data: [] })
    useAddTicketCommentMock.mockReturnValue({ mutate: vi.fn(), isPending: false })
    useSyncTicketStatusMock.mockReturnValue({ mutate: vi.fn(), isPending: false })
  })

  it('falls back to requested_assignee metadata when the provider has not assigned the ticket yet', () => {
    useFindingTicketMock.mockReturnValue({
      data: {
        id: 'ticket-1',
        external_id: 'JIRA-123',
        provider: 'jira',
        finding_id: 'finding-123',
        title: 'Remediate finding-123',
        status: 'open',
        priority: 'high',
        assignee: undefined,
        created_at: '2026-03-18T10:00:00Z',
        updated_at: '2026-03-18T10:00:00Z',
        metadata: {
          requested_assignee: 'alice@example.com',
        },
      },
      isLoading: false,
      isError: false,
    })

    renderWithProviders(<TicketViewportContent findingId="finding-123" />)

    expect(screen.getByText('alice@example.com')).toBeInTheDocument()
    expect(screen.getByText(/requested during ticket creation/i)).toBeInTheDocument()
  })
})
