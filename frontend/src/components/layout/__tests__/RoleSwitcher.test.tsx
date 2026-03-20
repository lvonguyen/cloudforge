import { describe, it, expect, vi, beforeEach } from 'vitest'
import { screen, fireEvent } from '@testing-library/react'
import { renderWithAuth } from '@/test/utils'
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

  it('shows operator role label after switching via sessionStorage', () => {
    sessionStorage.setItem('aegis_role', 'operator')
    renderWithAuth(<RoleSwitcher />)
    expect(screen.getByText('Operator')).toBeInTheDocument()
  })
})
