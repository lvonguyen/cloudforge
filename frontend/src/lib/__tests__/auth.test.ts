import { describe, it, expect } from 'vitest'
import { parseJWTPayload, isTokenExpired, userFromToken, deriveRoleFromGroups } from '../auth'

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

describe('userFromToken', () => {
  it('derives admin role from aegis-admin group', () => {
    const token = makeJWT({ email: 'admin@test.com', name: 'Admin One', groups: ['aegis-admin'] })
    const user = userFromToken(token)
    expect(user.role).toBe('admin')
    expect(user.email).toBe('admin@test.com')
    expect(user.name).toBe('Admin One')
  })

  it('derives operator role from aegis-operator group', () => {
    const token = makeJWT({ email: 'op@test.com', name: 'Operator', groups: ['aegis-operator'] })
    const user = userFromToken(token)
    expect(user.role).toBe('operator')
  })

  it('always uses JWT-derived role instead of any client-stored override', () => {
    const token = makeJWT({ email: 'admin@test.com', name: 'Admin', groups: ['aegis-admin'] })
    const user = userFromToken(token)
    expect(user.role).toBe('admin')
  })

  it('falls back to viewer when no group match and no savedRole', () => {
    const token = makeJWT({ email: 'user@test.com', name: 'User', groups: ['some-other-group'] })
    const user = userFromToken(token)
    expect(user.role).toBe('viewer')
  })

  it('falls back to viewer when groups claim is absent', () => {
    const token = makeJWT({ email: 'user@test.com', name: 'User' })
    const user = userFromToken(token)
    expect(user.role).toBe('viewer')
  })

  it('uses email as name fallback when name claim is missing', () => {
    const token = makeJWT({ email: 'fallback@test.com' })
    const user = userFromToken(token)
    expect(user.name).toBe('fallback@test.com')
  })

  it('prefers admin over operator when both groups present', () => {
    const token = makeJWT({ email: 'a@b.com', name: 'X', groups: ['aegis-admin', 'aegis-operator'] })
    const user = userFromToken(token)
    expect(user.role).toBe('admin')
  })
})

describe('deriveRoleFromGroups', () => {
  it('returns admin for aegis-admin group', () => {
    expect(deriveRoleFromGroups(['aegis-admin'])).toBe('admin')
  })

  it('returns operator for aegis-operator group', () => {
    expect(deriveRoleFromGroups(['aegis-operator'])).toBe('operator')
  })

  it('returns viewer for unknown groups', () => {
    expect(deriveRoleFromGroups(['some-other-group'])).toBe('viewer')
  })

  it('returns viewer for empty groups', () => {
    expect(deriveRoleFromGroups([])).toBe('viewer')
  })

  it('prefers admin when both admin and operator present', () => {
    expect(deriveRoleFromGroups(['aegis-operator', 'aegis-admin'])).toBe('admin')
  })
})
