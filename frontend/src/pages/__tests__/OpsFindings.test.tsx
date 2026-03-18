import { describe, it, expect } from 'vitest'
import { screen } from '@testing-library/react'
import { renderWithProviders } from '@/test/utils'
import Findings from '@/pages/ops/Findings'

describe('OpsFindings', () => {
  it('renders without crashing', () => {
    renderWithProviders(<Findings />)
    expect(screen.getByRole('heading', { level: 1 })).toBeInTheDocument()
  })

  it('shows the Findings heading', () => {
    renderWithProviders(<Findings />)
    expect(screen.getByText('Findings')).toBeInTheDocument()
  })

  it('renders the search input', () => {
    renderWithProviders(<Findings />)
    expect(screen.getByRole('textbox')).toBeInTheDocument()
  })
})
