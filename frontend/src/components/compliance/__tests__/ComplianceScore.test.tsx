import { describe, it, expect } from 'vitest'
import { screen } from '@testing-library/react'
import { renderWithProviders } from '@/test/utils'
import { ComplianceScore } from '../ComplianceScore'

describe('ComplianceScore', () => {
  it('renders score with one decimal place', () => {
    renderWithProviders(<ComplianceScore score={85} />)
    expect(screen.getByText('85.0%')).toBeInTheDocument()
  })

  it('applies green color for score >= 90', () => {
    renderWithProviders(<ComplianceScore score={92} />)
    const el = screen.getByText('92.0%')
    expect(el.className).toMatch(/green/)
  })

  it('applies yellow color for score >= 75 and < 90', () => {
    renderWithProviders(<ComplianceScore score={80} />)
    const el = screen.getByText('80.0%')
    expect(el.className).toMatch(/yellow/)
  })

  it('applies orange color for score >= 60 and < 75', () => {
    renderWithProviders(<ComplianceScore score={65} />)
    const el = screen.getByText('65.0%')
    expect(el.className).toMatch(/orange/)
  })

  it('applies red color for score < 60', () => {
    renderWithProviders(<ComplianceScore score={45} />)
    const el = screen.getByText('45.0%')
    expect(el.className).toMatch(/red/)
  })

  it('renders boundary score 90 as green', () => {
    renderWithProviders(<ComplianceScore score={90} />)
    const el = screen.getByText('90.0%')
    expect(el.className).toMatch(/green/)
  })

  it('renders boundary score 75 as yellow', () => {
    renderWithProviders(<ComplianceScore score={75} />)
    const el = screen.getByText('75.0%')
    expect(el.className).toMatch(/yellow/)
  })

  it('renders boundary score 60 as orange', () => {
    renderWithProviders(<ComplianceScore score={60} />)
    const el = screen.getByText('60.0%')
    expect(el.className).toMatch(/orange/)
  })

  it('formats decimal scores correctly', () => {
    renderWithProviders(<ComplianceScore score={87.456} />)
    expect(screen.getByText('87.5%')).toBeInTheDocument()
  })
})
