import { beforeEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, screen } from '@testing-library/react'
import { renderWithAuth } from '@/test/utils'
import { setPreviewRoleOverride } from '@/lib/auth'
import { TopNav } from '../TopNav'

describe('TopNav terminal access', () => {
  beforeEach(() => {
    vi.stubEnv('DEV', true)
    sessionStorage.clear()
    setPreviewRoleOverride(null)
  })

  it('renders the terminal button for operator sessions and toggles active state', () => {
    setPreviewRoleOverride('operator')
    renderWithAuth(<TopNav onMenuClick={() => {}} />)

    const button = screen.getByRole('button', { name: 'Show terminal panel' })
    expect(button).toBeInTheDocument()

    fireEvent.click(button)
    expect(screen.getByRole('button', { name: 'Hide terminal panel' })).toBeInTheDocument()
  })

  it('hides the terminal button for viewer sessions', () => {
    setPreviewRoleOverride('viewer')
    renderWithAuth(<TopNav onMenuClick={() => {}} />)

    expect(screen.queryByRole('button', { name: /terminal panel/i })).not.toBeInTheDocument()
  })
})
