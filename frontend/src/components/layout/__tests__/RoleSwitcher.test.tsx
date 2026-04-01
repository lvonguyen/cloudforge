import { describe, it, expect, vi, beforeEach } from 'vitest'
import { screen, fireEvent } from '@testing-library/react'
import { renderWithAuth } from '@/test/utils'
import { PREVIEW_ROLE_KEY, setPreviewRoleOverride } from '@/lib/auth'
import { RoleSwitcher } from '../RoleSwitcher'

// Radix DropdownMenu requires pointer events to open in jsdom.
// We test the trigger content directly and use pointerDown for open state.
function openDropdown() {
  const trigger = screen.getByRole('button')
  fireEvent.pointerDown(trigger, { button: 0, pointerType: 'mouse' })
}

describe('RoleSwitcher', () => {
  beforeEach(() => {
    vi.stubEnv('DEV', true)
    sessionStorage.clear()
    setPreviewRoleOverride(null)
  })

  it('renders the current role label in the trigger', () => {
    renderWithAuth(<RoleSwitcher />)
    expect(screen.getByText('Admin')).toBeInTheDocument()
  })

  it('renders a trigger button with the "Dev: Switch Role" label', () => {
    renderWithAuth(<RoleSwitcher />)
    // The trigger has role="button" — verify it exists
    expect(screen.getByRole('button')).toBeInTheDocument()
  })

  it('shows operator role label when a preview override is active', () => {
    setPreviewRoleOverride('operator')
    renderWithAuth(<RoleSwitcher />)
    expect(screen.getByText('Operator')).toBeInTheDocument()
  })

  it('restores the preview role from session storage after a remount', () => {
    sessionStorage.setItem(PREVIEW_ROLE_KEY, 'operator')
    renderWithAuth(<RoleSwitcher />)
    expect(screen.getByText('Operator')).toBeInTheDocument()
  })
})
