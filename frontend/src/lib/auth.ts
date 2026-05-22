import { createContext, useContext, useState, useCallback, useMemo, useEffect, type ReactNode, createElement } from 'react'
import { branding } from '@/lib/branding'
import { isDemoMode } from '@/lib/runtime'

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

const ROLE_DISPLAY_NAMES: Record<Role, string> = {
  admin: 'Demo Admin',
  operator: 'Demo Operator',
  requester: 'Demo Requester',
  viewer: 'Demo Viewer',
}

const DEMO_USER: User = {
  name: 'Demo Viewer',
  email: `demo@${branding.emailDomain}`,
  role: 'viewer',
  groups: [`${branding.storagePrefix}-viewer`],
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
export const DEMO_SESSION_KEY = `${branding.storagePrefix}_demo_session`
export const PREVIEW_ROLE_KEY = `${branding.storagePrefix}_preview_role`

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

function hasDemoSession(): boolean {
  if (typeof window === 'undefined') return false
  return sessionStorage.getItem(DEMO_SESSION_KEY) === 'true'
}

function getPreferredAuthToken(staticToken?: string): string | null {
  const storedToken = getStoredToken()
  if (storedToken && !isTokenExpired(storedToken)) {
    return storedToken
  }
  if (staticToken && !isTokenExpired(staticToken)) {
    return staticToken
  }
  return null
}

function usesStaticPortfolioToken(staticToken?: string): boolean {
  const storedToken = getStoredToken()
  if (storedToken && !isTokenExpired(storedToken)) return false
  return Boolean(staticToken && !isTokenExpired(staticToken))
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

// Role rank: higher number = more privilege. Used to cap preview-only
// role switching in dev/demo contexts.
const ROLE_RANK: Record<Role, number> = { viewer: 0, requester: 1, operator: 2, admin: 3 }

// Demo role switching should survive reloads during walkthroughs, but only
// within dev/demo sessions. Real authenticated flows still derive role from JWT.
let previewRoleOverride: Role | null = null

export function getPreviewRoleOverride(): Role | null {
  return previewRoleOverride
}

export function setPreviewRoleOverride(role: Role | null): void {
  previewRoleOverride = role
}

function getStoredPreviewRole(): Role | null {
  if (typeof window === 'undefined') return null
  const raw = sessionStorage.getItem(PREVIEW_ROLE_KEY)
  if (raw === 'admin' || raw === 'operator' || raw === 'requester' || raw === 'viewer') {
    return raw
  }
  return null
}

export function deriveRoleFromGroups(groups: string[]): Role {
  if (groups.includes(`${GROUP_PREFIX}-admin`)) return 'admin'
  if (groups.includes(`${GROUP_PREFIX}-operator`)) return 'operator'
  if (groups.includes(`${GROUP_PREFIX}-requester`)) return 'requester'
  return 'viewer'
}

export function userFromToken(token: string): User {
  const payload = parseJWTPayload(token)
  const email = (payload?.email as string) ?? ''
  const name = (payload?.name as string) || email
  const groups = (payload?.groups as string[]) ?? []

  const jwtRole = deriveRoleFromGroups(groups)
  return { name, email, role: jwtRole, groups }
}

// --- Auth context ---

interface AuthContextValue {
  user: User
  role: Role
  isDemoSession: boolean
  canSwitchRoles: boolean
  setRole: (role: Role) => void
  login: () => Promise<void>
  loginAsDemo: () => Promise<void>
  logout: () => void
  isAuthenticated: boolean
  exchangeCode: (code: string) => Promise<void>
}

const AuthContext = createContext<AuthContextValue | null>(null)

export function AuthProvider({ children }: { children: ReactNode }) {
  const isDev = import.meta.env.DEV
  const isDemoBuild = isDemoMode()

  const staticToken = import.meta.env.VITE_STATIC_TOKEN as string | undefined
  const isStaticPortfolioSession = usesStaticPortfolioToken(staticToken)
  const [isDemoSession, setIsDemoSession] = useState(() => hasDemoSession())
  const canSwitchRoles = isDev || isDemoBuild || isDemoSession || isStaticPortfolioSession

  const [user, setUser] = useState<User>(() => {
    const canUsePreviewRole = isDev || isDemoBuild || hasDemoSession() || isStaticPortfolioSession
    const previewRole = canUsePreviewRole ? (getPreviewRoleOverride() ?? getStoredPreviewRole()) : null
    if (previewRole) {
      setPreviewRoleOverride(previewRole)
    }
    if (isDev) {
      return previewRole
        ? { ...DEFAULT_USER, role: previewRole, name: ROLE_DISPLAY_NAMES[previewRole] }
        : DEFAULT_USER
    }
    if (isDemoBuild) {
      return previewRole
        ? { ...DEMO_USER, role: previewRole, name: ROLE_DISPLAY_NAMES[previewRole] }
        : DEMO_USER
    }

    const token = getPreferredAuthToken(staticToken)
    if (token) {
      const nextUser = userFromToken(token)
      return previewRole
        ? { ...nextUser, role: previewRole, name: ROLE_DISPLAY_NAMES[previewRole] }
        : hasDemoSession() ? { ...nextUser, role: 'viewer' } : nextUser
    }
    return ANONYMOUS_USER
  })

  const [isAuthenticated, setIsAuthenticated] = useState(() => {
    if (isDev || isDemoBuild) return true
    return !!getPreferredAuthToken(staticToken)
  })

  useEffect(() => {
    // Clear any legacy persisted role override so old preview data cannot
    // leak across reloads or into authenticated flows.
    sessionStorage.removeItem(ROLE_KEY)
    if (!isDev && !isDemoBuild && !isDemoSession && !isStaticPortfolioSession) {
      sessionStorage.removeItem(PREVIEW_ROLE_KEY)
      setPreviewRoleOverride(null)
    }
  }, [isDemoBuild, isDemoSession, isDev, isStaticPortfolioSession])

  const login = useCallback(async () => {
    if (!OKTA_ISSUER || !OKTA_CLIENT_ID) {
      console.warn('[auth] Okta not configured, skipping login')
      return
    }
    sessionStorage.removeItem(DEMO_SESSION_KEY)
    sessionStorage.removeItem(PREVIEW_ROLE_KEY)
    setPreviewRoleOverride(null)
    setIsDemoSession(false)
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

  const loginAsDemo = useCallback(async () => {
    if (!OKTA_ISSUER || !OKTA_CLIENT_ID) {
      console.warn('[auth] Okta not configured, skipping demo login')
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

    // Pre-fill the Okta login form with the demo email
    if (branding.demoAccess.email) {
      params.set('login_hint', branding.demoAccess.email)
    }

    // Flag this as a demo session for viewer-scoped access via Okta SSO
    sessionStorage.setItem(DEMO_SESSION_KEY, 'true')
    setIsDemoSession(true)

    window.location.href = `${OKTA_ISSUER}/v1/authorize?${params}`
  }, [])

  const logout = useCallback(() => {
    const idToken = sessionStorage.getItem(ID_TOKEN_KEY)
    const isDemo = hasDemoSession()

    sessionStorage.removeItem(TOKEN_KEY)
    sessionStorage.removeItem(ID_TOKEN_KEY)
    sessionStorage.removeItem(VERIFIER_KEY)
    sessionStorage.removeItem(STATE_KEY)
    sessionStorage.removeItem(NONCE_KEY)
    sessionStorage.removeItem(ROLE_KEY)
    sessionStorage.removeItem(DEMO_SESSION_KEY)
    sessionStorage.removeItem(PREVIEW_ROLE_KEY)
    setPreviewRoleOverride(null)
    setIsDemoSession(false)

    // Always clear React state so UI reflects logged-out immediately,
    // even if the Okta redirect is slow or fails.
    setUser(ANONYMOUS_USER)
    setIsAuthenticated(false)

    // Demo sessions may lack a valid id_token_hint for RP-initiated logout
    // (Okta shows an error page when hint is missing/invalid). Skip Okta
    // logout for demo — local session clear + redirect to landing suffices.
    if (!isDev && OKTA_ISSUER && OKTA_CLIENT_ID && !isDemo) {
      const params = new URLSearchParams({
        post_logout_redirect_uri: window.location.origin,
      })
      if (idToken) params.set('id_token_hint', idToken)
      window.location.href = `${OKTA_ISSUER}/v1/logout?${params}`
    } else {
      window.location.href = window.location.origin
    }
  }, [isDev])

  const setRole = useCallback((role: Role) => {
    if (!canSwitchRoles) return
    const maxRole = isDev ? DEFAULT_USER.role : 'admin' as Role
    const effective = ROLE_RANK[role] <= ROLE_RANK[maxRole] ? role : maxRole
    setPreviewRoleOverride(effective)
    sessionStorage.setItem(PREVIEW_ROLE_KEY, effective)
    setUser((prev) => ({
      ...prev,
      role: effective,
      name: ROLE_DISPLAY_NAMES[effective],
    }))
  }, [canSwitchRoles, isDev])

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

    // Demo sessions default to viewer (read-only). Regular users derive
    // their role from group claims in the access token.
    const isDemo = hasDemoSession()
    const nextUser = userFromToken(data.access_token)
    setUser(isDemo ? { ...nextUser, role: 'viewer' } : nextUser)
    setIsDemoSession(isDemo)
    setIsAuthenticated(true)
  }, [])

  // Auto-login is handled by ProtectedRoute — no global redirect needed.
  // The landing page (/) is public; protected routes trigger login on access.

  const value = useMemo<AuthContextValue>(
    () => ({ user, role: user.role, isDemoSession, canSwitchRoles, setRole, login, loginAsDemo, logout, isAuthenticated, exchangeCode }),
    [user, isDemoSession, canSwitchRoles, setRole, login, loginAsDemo, logout, isAuthenticated, exchangeCode],
  )

  return createElement(AuthContext.Provider, { value }, children)
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth must be used within AuthProvider')
  return ctx
}
