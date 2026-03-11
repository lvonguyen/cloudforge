import { describe, it, expect } from 'vitest'
import {
  SEVERITY_COLORS,
  SEVERITY_COLORS_BORDERED,
  REMEDIATION_STATUS_COLORS,
  EXCEPTION_STATUS_COLORS,
} from '@/lib/severity'

describe('SEVERITY_COLORS', () => {
  it('defines all four canonical severity levels', () => {
    expect(SEVERITY_COLORS).toHaveProperty('CRITICAL')
    expect(SEVERITY_COLORS).toHaveProperty('HIGH')
    expect(SEVERITY_COLORS).toHaveProperty('MEDIUM')
    expect(SEVERITY_COLORS).toHaveProperty('LOW')
  })

  it('CRITICAL color contains red classes', () => {
    expect(SEVERITY_COLORS.CRITICAL).toContain('red')
  })

  it('HIGH color contains orange classes', () => {
    expect(SEVERITY_COLORS.HIGH).toContain('orange')
  })

  it('MEDIUM color contains yellow classes', () => {
    expect(SEVERITY_COLORS.MEDIUM).toContain('yellow')
  })

  it('LOW color contains blue classes', () => {
    expect(SEVERITY_COLORS.LOW).toContain('blue')
  })

  it('all values are non-empty strings', () => {
    for (const [, value] of Object.entries(SEVERITY_COLORS)) {
      expect(typeof value).toBe('string')
      expect(value.length).toBeGreaterThan(0)
    }
  })
})

describe('SEVERITY_COLORS_BORDERED', () => {
  it('includes all base keys from SEVERITY_COLORS', () => {
    for (const key of Object.keys(SEVERITY_COLORS)) {
      expect(SEVERITY_COLORS_BORDERED).toHaveProperty(key)
    }
  })

  it('bordered values extend base values with border classes', () => {
    for (const key of Object.keys(SEVERITY_COLORS)) {
      const base = SEVERITY_COLORS[key]
      const bordered = SEVERITY_COLORS_BORDERED[key]
      expect(bordered).toContain(base)
      expect(bordered).toContain('border-')
    }
  })

  it('CRITICAL bordered value includes red border', () => {
    expect(SEVERITY_COLORS_BORDERED.CRITICAL).toContain('border-red')
  })
})

describe('REMEDIATION_STATUS_COLORS', () => {
  it('defines pending, in_progress, completed, failed, skipped', () => {
    expect(REMEDIATION_STATUS_COLORS).toHaveProperty('pending')
    expect(REMEDIATION_STATUS_COLORS).toHaveProperty('in_progress')
    expect(REMEDIATION_STATUS_COLORS).toHaveProperty('completed')
    expect(REMEDIATION_STATUS_COLORS).toHaveProperty('failed')
    expect(REMEDIATION_STATUS_COLORS).toHaveProperty('skipped')
  })

  it('completed status uses green class', () => {
    expect(REMEDIATION_STATUS_COLORS.completed).toContain('green')
  })

  it('failed status uses red class', () => {
    expect(REMEDIATION_STATUS_COLORS.failed).toContain('red')
  })

  it('in_progress status uses blue class', () => {
    expect(REMEDIATION_STATUS_COLORS.in_progress).toContain('blue')
  })
})

describe('EXCEPTION_STATUS_COLORS', () => {
  it('defines PENDING, APPROVED, REJECTED, EXPIRED', () => {
    expect(EXCEPTION_STATUS_COLORS).toHaveProperty('PENDING')
    expect(EXCEPTION_STATUS_COLORS).toHaveProperty('APPROVED')
    expect(EXCEPTION_STATUS_COLORS).toHaveProperty('REJECTED')
    expect(EXCEPTION_STATUS_COLORS).toHaveProperty('EXPIRED')
  })

  it('APPROVED uses green class', () => {
    expect(EXCEPTION_STATUS_COLORS.APPROVED).toContain('green')
  })

  it('REJECTED uses red class', () => {
    expect(EXCEPTION_STATUS_COLORS.REJECTED).toContain('red')
  })

  it('PENDING uses yellow class', () => {
    expect(EXCEPTION_STATUS_COLORS.PENDING).toContain('yellow')
  })
})
