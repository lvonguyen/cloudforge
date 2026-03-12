import { createContext, useContext, useState, useCallback, type ReactNode, createElement } from 'react'
import { branding } from '@/lib/branding'

export type Role = 'admin' | 'operator' | 'requester' | 'viewer'

export interface User {
  name: string
  email: string
  role: Role
  groups?: string[]
}

const DEFAULT_USER: User = {
  name: 'Admin One',
  email: `admin1@${branding.emailDomain}`,
  role: 'admin',
  groups: [`${branding.storagePrefix}-admin`],
}

const ANONYMOUS_USER: User = {
  name: 'Anonymous',
  email: '',
  role: 'viewer',
  groups: [],
}

// Storage keys use the tenant's storagePrefix to avoid collisions
const ROLE_KEY = `${branding.storagePrefix}_role`
export const TOKEN_KEY = `${branding.storagePrefix}_access_token`
const ID_TOKEN_KEY = `${branding.storagePrefix}_id_token`
const VERIFIER_KEY = `${branding.storagePrefix}_pkce_verifier`
export const STATE_KEY = `${branding.storagePrefix}_oauth_state`
const NONCE_KEY = `${branding.storagePrefix}_oauth_nonce`
export const LOGIN_RETURN_KEY = `${branding.storagePrefix}_login_return`

const OKTA_ISSUER = import.meta.env.VITE_OKTA_ISSUER as string | undefined
const OKTA_CLIENT_ID = import.meta.env.VITE_OKTA_CLIENT_ID as string | undefined

// Group name prefix for RBAC group matching
const GROUP_PREFIX = branding.storagePrefix

// --- PKCE helpers ---

function generateRandomString(length: number): string {
  const array = new Uint8Array(length)
  crypto.getRandomValues(array)
  return Array.from(array, (b) => b.toString(16).padStart(2, '0')).join('').slice(0, length)
}

async function sha256(plain: string): Promise<ArrayBuffer> {
  return crypto.subtle.digest('SHA-256', new TextEncoder().encode(plain))
}

function base64UrlEncode(buffer: ArrayBuffer): string {
  return btoa(String.fromCharCode(...new Uint8Array(buffer)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '')
}

async function createPKCEChallenge(): Promise<{ verifier: string; challenge: string }> {
  const verifier = generateRandomString(64)
  const hashed = await sha256(verifier)
  return { verifier, challenge: base64UrlEncode(hashed) }
}

// --- Token helpers ---

function getStoredToken(): string | null {
  return sessionStorage.getItem(TOKEN_KEY)
}

export function parseJWTPayload(token: string): Record<string, unknown> | null {
  try {
    const base64 = token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/')
    return JSON.parse(atob(base64))
  } catch {
    return null
  }
}

export function isTokenExpired(token: string): boolean {
  const payload = parseJWTPayload(token)
  if (!payload || typeof payload.exp !== 'number') return true
  return payload.exp * 1000 < Date.now()
}

function userFromToken(token: string, savedRole: Role | null): User {
  const payload = parseJWTPayload(token)
  const email = (payload?.email as string) ?? ''
  const name = (payload?.name as string) || email
  const groups = (payload?.groups as string[]) ?? []

  let role: Role = savedRole ?? 'requester'
  if (!savedRole) {
    if (groups.includes(`${GROUP_PREFIX}-admin`)) role = 'admin'
    else if (groups.includes(`${GROUP_PREFIX}-operator`)) role = 'operator'
  }

  return { name, email, role }
}

// --- Auth context ---

interface AuthContextValue {
  user: User
  role: Role
  setRole: (role: Role) => void
  login: () => Promise<void>
  logout: () => void
  isAuthenticated: boolean
  exchangeCode: (code: string) => Promise<void>
}

const AuthContext = createContext<AuthContextValue | null>(null)

export function AuthProvider({ children }: { children: ReactNode }) {
  const savedRole = localStorage.getItem(ROLE_KEY) as Role | null
  const isDev = import.meta.env.DEV

  const [user, setUser] = useState<User>(() => {
    if (isDev) return { ...DEFAULT_USER, role: savedRole ?? DEFAULT_USER.role }

    const token = getStoredToken()
    if (token && !isTokenExpired(token)) {
      return userFromToken(token, savedRole)
    }
    return ANONYMOUS_USER
  })

  const [isAuthenticated, setIsAuthenticated] = useState(() => {
    if (isDev) return true
    const token = getStoredToken()
    return !!token && !isTokenExpired(token)
  })

  const login = useCallback(async () => {
    if (!OKTA_ISSUER || !OKTA_CLIENT_ID) {
      console.warn('[auth] Okta not configured, skipping login')
      return
    }
    const { verifier, challenge } = await createPKCEChallenge()
    sessionStorage.setItem(VERIFIER_KEY, verifier)

    const state = crypto.randomUUID()
    sessionStorage.setItem(STATE_KEY, state)

    const nonce = generateRandomString(32)
    sessionStorage.setItem(NONCE_KEY, nonce)

    const params = new URLSearchParams({
      response_type: 'code',
      client_id: OKTA_CLIENT_ID,
      redirect_uri: `${window.location.origin}/callback`,
      scope: 'openid profile email groups',
      code_challenge: challenge,
      code_challenge_method: 'S256',
      state,
      nonce,
    })
    window.location.href = `${OKTA_ISSUER}/v1/authorize?${params}`
  }, [])

  const logout = useCallback(() => {
    const idToken = sessionStorage.getItem(ID_TOKEN_KEY)
    sessionStorage.removeItem(TOKEN_KEY)
    sessionStorage.removeItem(ID_TOKEN_KEY)
    sessionStorage.removeItem(VERIFIER_KEY)
    sessionStorage.removeItem(STATE_KEY)
    sessionStorage.removeItem(NONCE_KEY)
    localStorage.removeItem(ROLE_KEY)

    if (!isDev && OKTA_ISSUER && OKTA_CLIENT_ID) {
      const params = new URLSearchParams({
        post_logout_redirect_uri: window.location.origin,
      })
      if (idToken) params.set('id_token_hint', idToken)
      window.location.href = `${OKTA_ISSUER}/v1/logout?${params}`
    } else {
      setUser(DEFAULT_USER)
      setIsAuthenticated(false)
    }
  }, [isDev])

  const setRole = useCallback((role: Role) => {
    localStorage.setItem(ROLE_KEY, role)
    setUser((prev) => ({ ...prev, role }))
  }, [])

  // Exchange authorization code for tokens (called from Callback page)
  const exchangeCode = useCallback(async (code: string) => {
    if (!OKTA_ISSUER || !OKTA_CLIENT_ID) return
    const verifier = sessionStorage.getItem(VERIFIER_KEY)
    if (!verifier) throw new Error('Missing PKCE verifier')

    const res = await fetch(`${OKTA_ISSUER}/v1/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        client_id: OKTA_CLIENT_ID,
        redirect_uri: `${window.location.origin}/callback`,
        code,
        code_verifier: verifier,
      }),
    })

    if (!res.ok) {
      const text = await res.text()
      throw new Error(`Token exchange failed: ${text}`)
    }

    const data = await res.json()
    if (!data.access_token || typeof data.access_token !== 'string') {
      throw new Error('Invalid token response from IdP')
    }
    // Always verify nonce in id_token to prevent replay attacks.
    // Absence of id_token or stored nonce is itself an error condition.
    const storedNonce = sessionStorage.getItem(NONCE_KEY)
    if (!storedNonce) {
      throw new Error('OIDC nonce missing from session — possible replay attack')
    }
    if (!data.id_token) {
      throw new Error('id_token missing from token response — cannot verify nonce')
    }
    const idPayload = parseJWTPayload(data.id_token)
    if (!idPayload || idPayload.nonce !== storedNonce) {
      throw new Error('OIDC nonce mismatch — possible token replay')
    }

    sessionStorage.setItem(TOKEN_KEY, data.access_token)
    sessionStorage.setItem(ID_TOKEN_KEY, data.id_token)
    sessionStorage.removeItem(VERIFIER_KEY)
    sessionStorage.removeItem(STATE_KEY)
    sessionStorage.removeItem(NONCE_KEY)

    const currentRole = localStorage.getItem(ROLE_KEY) as Role | null
    const u = userFromToken(data.access_token, currentRole)
    setUser(u)
    setIsAuthenticated(true)
  }, [])

  // Auto-login is handled by ProtectedRoute — no global redirect needed.
  // The landing page (/) is public; protected routes trigger login on access.

  const value: AuthContextValue = {
    user,
    role: user.role,
    setRole,
    login,
    logout,
    isAuthenticated,
    exchangeCode,
  }

  return createElement(AuthContext.Provider, { value }, children)
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth must be used within AuthProvider')
  return ctx
}
