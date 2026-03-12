import { describe, it, expect } from 'vitest'
import { screen } from '@testing-library/react'
import { renderWithProviders } from '@/test/utils'
import { StatusBadge } from '../StatusBadge'
import type { ApprovalStatus } from '@/types/grc'

describe('StatusBadge', () => {
  it('renders Pending for PENDING status', () => {
    renderWithProviders(<StatusBadge status="PENDING" />)
    expect(screen.getByText('Pending')).toBeInTheDocument()
  })

  it('renders Approved for APPROVED status', () => {
    renderWithProviders(<StatusBadge status="APPROVED" />)
    expect(screen.getByText('Approved')).toBeInTheDocument()
  })

  it('renders Rejected for REJECTED status', () => {
    renderWithProviders(<StatusBadge status="REJECTED" />)
    expect(screen.getByText('Rejected')).toBeInTheDocument()
  })

  it('renders Expired for EXPIRED status', () => {
    renderWithProviders(<StatusBadge status="EXPIRED" />)
    expect(screen.getByText('Expired')).toBeInTheDocument()
  })

  it('renders Revoked for REVOKED status', () => {
    renderWithProviders(<StatusBadge status="REVOKED" />)
    expect(screen.getByText('Revoked')).toBeInTheDocument()
  })

  it('applies yellow styling for PENDING', () => {
    renderWithProviders(<StatusBadge status="PENDING" />)
    const el = screen.getByText('Pending')
    expect(el.className).toMatch(/yellow/)
  })

  it('applies green styling for APPROVED', () => {
    renderWithProviders(<StatusBadge status="APPROVED" />)
    const el = screen.getByText('Approved')
    expect(el.className).toMatch(/green/)
  })

  it('applies red styling for REJECTED', () => {
    renderWithProviders(<StatusBadge status="REJECTED" />)
    const el = screen.getByText('Rejected')
    expect(el.className).toMatch(/red/)
  })

  it('falls back to PENDING config for unknown status', () => {
    renderWithProviders(<StatusBadge status={'UNKNOWN' as ApprovalStatus} />)
    expect(screen.getByText('Pending')).toBeInTheDocument()
  })
})
