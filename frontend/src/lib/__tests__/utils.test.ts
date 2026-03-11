import { describe, it, expect } from 'vitest'
import { cn } from '@/lib/utils'

describe('cn (classname merge utility)', () => {
  it('returns a single class unchanged', () => {
    expect(cn('foo')).toBe('foo')
  })

  it('merges multiple classes', () => {
    expect(cn('foo', 'bar')).toBe('foo bar')
  })

  it('deduplicates conflicting Tailwind classes (last wins)', () => {
    // tailwind-merge resolves conflicts: p-4 overrides p-2
    const result = cn('p-2', 'p-4')
    expect(result).toBe('p-4')
    expect(result).not.toContain('p-2')
  })

  it('handles conditional classes with objects', () => {
    const result = cn('base', { 'text-red-500': true, 'text-blue-500': false })
    expect(result).toContain('base')
    expect(result).toContain('text-red-500')
    expect(result).not.toContain('text-blue-500')
  })

  it('handles undefined and null values gracefully', () => {
    expect(() => cn('foo', undefined, null as unknown as string)).not.toThrow()
  })

  it('returns empty string for no arguments', () => {
    expect(cn()).toBe('')
  })

  it('handles array inputs', () => {
    const result = cn(['foo', 'bar'])
    expect(result).toContain('foo')
    expect(result).toContain('bar')
  })

  it('merges text-color conflicts — last wins', () => {
    const result = cn('text-sm text-red-500', 'text-blue-500')
    expect(result).toContain('text-blue-500')
    expect(result).not.toContain('text-red-500')
  })
})
