import { describe, it, expect } from 'vitest'
import { screen } from '@testing-library/react'
import { renderWithProviders } from '@/test/utils'
import { CostSummaryCard } from '../CostSummaryCard'

describe('CostSummaryCard', () => {
  it('renders label in uppercase', () => {
    renderWithProviders(<CostSummaryCard label="Total Cost" amount={125000} />)
    const title = screen.getByText(/Total Cost/i)
    expect(title).toBeInTheDocument()
    expect(title.className).toMatch(/uppercase/)
  })

  it('formats amount as thousands with K suffix', () => {
    renderWithProviders(<CostSummaryCard label="Monthly" amount={45000} />)
    expect(screen.getByText('$45K')).toBeInTheDocument()
  })

  it('rounds amount to nearest whole number', () => {
    renderWithProviders(<CostSummaryCard label="Projected" amount={148750} />)
    expect(screen.getByText('$149K')).toBeInTheDocument()
  })

  it('displays breakdown text when provided', () => {
    renderWithProviders(
      <CostSummaryCard label="Total" amount={100000} breakdown="Compute $60K, Storage $40K" />
    )
    expect(screen.getByText('Compute $60K, Storage $40K')).toBeInTheDocument()
  })

  it('does not display breakdown when not provided', () => {
    renderWithProviders(<CostSummaryCard label="Total" amount={100000} />)
    expect(screen.queryByText(/Compute/)).not.toBeInTheDocument()
  })

  it('displays positive trend with TrendingUp icon and red color', () => {
    const { container } = renderWithProviders(
      <CostSummaryCard label="Monthly" amount={50000} trend={15.5} />
    )
    expect(screen.getByText('15.5% MoM')).toBeInTheDocument()
    expect(container.querySelector('.text-red-600')).toBeInTheDocument()
  })

  it('displays negative trend with TrendingDown icon and green color', () => {
    const { container } = renderWithProviders(
      <CostSummaryCard label="Monthly" amount={50000} trend={-8.2} />
    )
    expect(screen.getByText('8.2% MoM')).toBeInTheDocument()
    expect(container.querySelector('.text-green-600')).toBeInTheDocument()
  })

  it('displays zero trend with TrendingUp icon and red color', () => {
    const { container } = renderWithProviders(
      <CostSummaryCard label="Monthly" amount={50000} trend={0} />
    )
    expect(screen.getByText('0.0% MoM')).toBeInTheDocument()
    expect(container.querySelector('.text-red-600')).toBeInTheDocument()
  })

  it('does not display trend when undefined', () => {
    renderWithProviders(<CostSummaryCard label="Monthly" amount={50000} />)
    expect(screen.queryByText(/MoM/)).not.toBeInTheDocument()
  })

  it('formats large amounts correctly', () => {
    renderWithProviders(<CostSummaryCard label="Annual" amount={2500000} />)
    expect(screen.getByText('$2.5M')).toBeInTheDocument()
  })

  it('formats small amounts correctly', () => {
    renderWithProviders(<CostSummaryCard label="Dev" amount={1500} />)
    expect(screen.getByText('$2K')).toBeInTheDocument()
  })
})
