import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, screen, waitFor } from '@testing-library/react'

import { renderWithProviders } from '@/test/utils'
import { IntegrationViewport } from '../IntegrationViewport'

const useFindingTicketMock = vi.fn()
const useRemediateFindingMock = vi.fn()
const mutateMock = vi.fn()

vi.mock('@/hooks/useIntegrations', () => ({
  useFindingTicket: (...args: unknown[]) => useFindingTicketMock(...args),
  useRemediateFinding: (...args: unknown[]) => useRemediateFindingMock(...args),
}))

vi.mock('../TicketViewportContent', () => ({
  TicketViewportContent: () => <div>Ticket content</div>,
}))

describe('IntegrationViewport', () => {
  beforeEach(() => {
    useFindingTicketMock.mockReset()
    useRemediateFindingMock.mockReset()
    mutateMock.mockReset()

    useFindingTicketMock.mockReturnValue({
      data: null,
      isLoading: false,
      isError: false,
    })
    useRemediateFindingMock.mockReturnValue({
      mutate: mutateMock,
      isPending: false,
    })
  })

  it('forwards the selected provider and requested assignee when creating a Jira ticket', async () => {
    renderWithProviders(<IntegrationViewport findingId="finding-123" />)

    fireEvent.click(screen.getByRole('tab', { name: /jira/i }))
    await waitFor(() => {
      expect(screen.getByRole('button', { name: /create jira ticket/i })).toBeInTheDocument()
    })
    fireEvent.change(screen.getByPlaceholderText(/alice@example.com or team alias/i), {
      target: { value: 'alice@example.com' },
    })
    fireEvent.click(screen.getByRole('button', { name: /create jira ticket/i }))

    expect(mutateMock).toHaveBeenCalledWith({
      findingId: 'finding-123',
      provider: 'jira',
      assignee: 'alice@example.com',
    })
  })

  it('keeps ServiceNow disabled while parity is pending', () => {
    renderWithProviders(<IntegrationViewport findingId="finding-123" />)

    expect(screen.getByRole('tab', { name: /servicenow/i })).toBeDisabled()
  })

  it('shows a loading placeholder while ticket state is resolving', () => {
    useFindingTicketMock.mockReturnValue({
      data: null,
      isLoading: true,
      isError: false,
    })

    renderWithProviders(<IntegrationViewport findingId="finding-123" />)

    expect(screen.getByText(/loading asana ticket state/i)).toBeInTheDocument()
  })
})
