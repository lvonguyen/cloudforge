import { describe, it, expect } from 'vitest'
import { parseJWTPayload, isTokenExpired } from '../auth'

// Build a minimal JWT string with a given payload (unsigned — fine for unit tests)
function makeJWT(payload: Record<string, unknown>): string {
  const header = btoa(JSON.stringify({ alg: 'HS256', typ: 'JWT' }))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
  const body = btoa(JSON.stringify(payload))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
  return `${header}.${body}.fakesig`
}

describe('parseJWTPayload', () => {
  it('returns payload from a valid 3-segment JWT', () => {
    const payload = { sub: 'user-123', email: 'test@example.com', exp: 9999999999 }
    const token = makeJWT(payload)
    const result = parseJWTPayload(token)
    expect(result).not.toBeNull()
    expect(result?.sub).toBe('user-123')
    expect(result?.email).toBe('test@example.com')
  })

  it('returns null for a malformed token (no dots)', () => {
    const result = parseJWTPayload('notavalidtoken')
    expect(result).toBeNull()
  })

  it('returns null for a token with invalid base64 in the payload segment', () => {
    const result = parseJWTPayload('header.!!!invalid!!!.sig')
    expect(result).toBeNull()
  })

  it('returns null for an empty string', () => {
    const result = parseJWTPayload('')
    expect(result).toBeNull()
  })
})

describe('isTokenExpired', () => {
  it('returns false when exp is in the future', () => {
    const futureExp = Math.floor(Date.now() / 1000) + 3600 // 1 hour from now
    const token = makeJWT({ sub: 'user-123', exp: futureExp })
    expect(isTokenExpired(token)).toBe(false)
  })

  it('returns true when exp is in the past', () => {
    const pastExp = Math.floor(Date.now() / 1000) - 3600 // 1 hour ago
    const token = makeJWT({ sub: 'user-123', exp: pastExp })
    expect(isTokenExpired(token)).toBe(true)
  })

  it('returns true when token has no exp claim', () => {
    const token = makeJWT({ sub: 'user-123' })
    expect(isTokenExpired(token)).toBe(true)
  })

  it('returns true for a malformed token', () => {
    expect(isTokenExpired('not.a.valid.jwt')).toBe(true)
  })
})
