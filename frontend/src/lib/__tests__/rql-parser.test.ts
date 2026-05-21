import { describe, it, expect } from 'vitest'
import { parseRQL, rqlToFilters } from '@/lib/rql-parser'

describe('rql-parser', () => {
  it('maps equality conditions to positive NLQ filters', () => {
    expect(rqlToFilters(parseRQL('severity=CRITICAL AND provider=aws'))).toEqual({
      severity: ['CRITICAL'],
      provider: ['aws'],
    })
  })

  it('maps inequality conditions to exclusion filters', () => {
    expect(rqlToFilters(parseRQL('provider=aws AND status!=resolved'))).toEqual({
      provider: ['aws'],
      exclude: { status: ['resolved'] },
    })
  })
})
