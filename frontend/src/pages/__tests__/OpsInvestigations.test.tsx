import { describe, it, expect } from 'vitest'
import { screen } from '@testing-library/react'
import { renderWithProviders } from '@/test/utils'
import Investigations from '@/pages/ops/Investigations'

describe('OpsInvestigations', () => {
  it('renders without crashing', () => {
    renderWithProviders(<Investigations />)
    // Page shows loading state while findings query resolves
    expect(screen.getByText(/loading investigations/i)).toBeInTheDocument()
  })
})
