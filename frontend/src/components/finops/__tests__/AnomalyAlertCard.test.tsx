import { describe, it, expect } from 'vitest'
import { screen } from '@testing-library/react'
import { renderWithProviders } from '@/test/utils'
import { AnomalyAlertCard } from '../AnomalyAlertCard'
import type { AnomalyAlert } from '@/types/finops'

describe('AnomalyAlertCard', () => {
  it('displays service name with deviation percent', () => {
    const anomaly: AnomalyAlert = {
      id: 'a-001',
      provider: 'aws',
      service_name: 'EC2',
      expected_cost: 1000,
      actual_cost: 1500,
      deviation_percent: 50,
      severity: 'high',
    }

    renderWithProviders(<AnomalyAlertCard anomaly={anomaly} />)
    expect(screen.getByText('EC2 +50%')).toBeInTheDocument()
  })

  it('displays provider in uppercase', () => {
    const anomaly: AnomalyAlert = {
      id: 'a-002',
      provider: 'azure',
      service_name: 'VirtualMachines',
      expected_cost: 2000,
      actual_cost: 2800,
      deviation_percent: 40,
      severity: 'medium',
    }

    renderWithProviders(<AnomalyAlertCard anomaly={anomaly} />)
    expect(screen.getByText(/AZURE/)).toBeInTheDocument()
  })

  it('displays actual cost with locale formatting', () => {
    const anomaly: AnomalyAlert = {
      id: 'a-003',
      provider: 'gcp',
      service_name: 'ComputeEngine',
      expected_cost: 5000,
      actual_cost: 12500,
      deviation_percent: 150,
      severity: 'critical',
    }

    renderWithProviders(<AnomalyAlertCard anomaly={anomaly} />)
    expect(screen.getByText(/\$12,500 actual/)).toBeInTheDocument()
  })

  it('displays expected cost with locale formatting', () => {
    const anomaly: AnomalyAlert = {
      id: 'a-004',
      provider: 'aws',
      service_name: 'S3',
      expected_cost: 8000,
      actual_cost: 9600,
      deviation_percent: 20,
      severity: 'low',
    }

    renderWithProviders(<AnomalyAlertCard anomaly={anomaly} />)
    expect(screen.getByText(/\$8,000 expected/)).toBeInTheDocument()
  })

  it('applies critical severity border class', () => {
    const anomaly: AnomalyAlert = {
      id: 'a-005',
      provider: 'aws',
      service_name: 'RDS',
      expected_cost: 3000,
      actual_cost: 9000,
      deviation_percent: 200,
      severity: 'critical',
    }

    const { container } = renderWithProviders(<AnomalyAlertCard anomaly={anomaly} />)
    const card = container.querySelector('.border-red-300')
    expect(card).toBeInTheDocument()
  })

  it('applies high severity border class', () => {
    const anomaly: AnomalyAlert = {
      id: 'a-006',
      provider: 'aws',
      service_name: 'Lambda',
      expected_cost: 500,
      actual_cost: 1000,
      deviation_percent: 100,
      severity: 'high',
    }

    const { container } = renderWithProviders(<AnomalyAlertCard anomaly={anomaly} />)
    const card = container.querySelector('.border-orange-300')
    expect(card).toBeInTheDocument()
  })

  it('applies medium severity border class', () => {
    const anomaly: AnomalyAlert = {
      id: 'a-007',
      provider: 'azure',
      service_name: 'Storage',
      expected_cost: 1000,
      actual_cost: 1300,
      deviation_percent: 30,
      severity: 'medium',
    }

    const { container } = renderWithProviders(<AnomalyAlertCard anomaly={anomaly} />)
    const card = container.querySelector('.border-yellow-300')
    expect(card).toBeInTheDocument()
  })

  it('applies low severity border class', () => {
    const anomaly: AnomalyAlert = {
      id: 'a-008',
      provider: 'gcp',
      service_name: 'CloudStorage',
      expected_cost: 2000,
      actual_cost: 2200,
      deviation_percent: 10,
      severity: 'low',
    }

    const { container } = renderWithProviders(<AnomalyAlertCard anomaly={anomaly} />)
    const card = container.querySelector('.border-blue-300')
    expect(card).toBeInTheDocument()
  })

  it('rounds deviation_percent to whole number', () => {
    const anomaly: AnomalyAlert = {
      id: 'a-009',
      provider: 'aws',
      service_name: 'DynamoDB',
      expected_cost: 1000,
      actual_cost: 1425,
      deviation_percent: 42.5,
      severity: 'medium',
    }

    renderWithProviders(<AnomalyAlertCard anomaly={anomaly} />)
    expect(screen.getByText(/DynamoDB \+43%/)).toBeInTheDocument()
  })

  it('displays AlertTriangle icon', () => {
    const anomaly: AnomalyAlert = {
      id: 'a-010',
      provider: 'aws',
      service_name: 'EC2',
      expected_cost: 1000,
      actual_cost: 1500,
      deviation_percent: 50,
      severity: 'high',
    }

    const { container } = renderWithProviders(<AnomalyAlertCard anomaly={anomaly} />)
    const icon = container.querySelector('.text-orange-500')
    expect(icon).toBeInTheDocument()
  })
})
