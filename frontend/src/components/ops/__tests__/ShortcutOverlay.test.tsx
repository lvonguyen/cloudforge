import { describe, it, expect, vi } from 'vitest'
import { screen, fireEvent } from '@testing-library/react'
import { render } from '@testing-library/react'
import { ShortcutOverlay } from '../ShortcutOverlay'
import { CommandCenterProvider } from '@/contexts/CommandCenterContext'

function renderOverlay() {
  return render(
    <CommandCenterProvider>
      <ShortcutOverlay />
    </CommandCenterProvider>,
  )
}

describe('ShortcutOverlay', () => {
  it('renders all 6 shortcut entries', () => {
    renderOverlay()
    expect(screen.getByText('Esc')).toBeInTheDocument()
    expect(screen.getByText('L')).toBeInTheDocument()
    expect(screen.getByText('D')).toBeInTheDocument()
    expect(screen.getByText('1')).toBeInTheDocument()
    expect(screen.getByText('2')).toBeInTheDocument()
    expect(screen.getByText('?')).toBeInTheDocument()
  })

  it('renders shortcut descriptions', () => {
    renderOverlay()
    expect(screen.getByText('Close overlay / deselect entity')).toBeInTheDocument()
    expect(screen.getByText('Toggle left panel')).toBeInTheDocument()
    expect(screen.getByText('Close detail panel')).toBeInTheDocument()
    expect(screen.getByText('Charts view')).toBeInTheDocument()
    expect(screen.getByText('Heatmap view')).toBeInTheDocument()
    expect(screen.getByText('Toggle this overlay')).toBeInTheDocument()
  })

  it('has close button', () => {
    renderOverlay()
    expect(screen.getByLabelText('Close shortcuts')).toBeInTheDocument()
  })

  it('has backdrop element', () => {
    renderOverlay()
    expect(screen.getByTestId('shortcut-overlay')).toBeInTheDocument()
  })

  it('renders header text', () => {
    renderOverlay()
    expect(screen.getByText('Keyboard Shortcuts')).toBeInTheDocument()
  })
})
