import { useEffect, useRef, useState } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { useAuth, STATE_KEY, LOGIN_RETURN_KEY } from '@/lib/auth'

export default function Callback() {
  const [searchParams] = useSearchParams()
  const navigate = useNavigate()
  const { exchangeCode, login } = useAuth()
  const [error, setError] = useState<string | null>(null)
  const called = useRef(false)

  useEffect(() => {
    if (called.current) return
    called.current = true

    const code = searchParams.get('code')
    const errorParam = searchParams.get('error')
    const returnedState = searchParams.get('state')
    const savedState = sessionStorage.getItem(STATE_KEY)

    if (errorParam) {
      setError(searchParams.get('error_description') ?? errorParam)
      return
    }

    if (!returnedState || returnedState !== savedState) {
      setError('OAuth state mismatch — possible CSRF. Please try logging in again.')
      return
    }

    if (!code) {
      setError('Missing authorization code')
      return
    }

    exchangeCode(code)
      .then(() => {
        const isDemo = sessionStorage.getItem(`${import.meta.env.VITE_STORAGE_PREFIX || 'aegis'}_demo_session`) === 'true'
        const defaultPath = isDemo ? '/ops/findings' : '/ops'
        const raw = sessionStorage.getItem(LOGIN_RETURN_KEY) ?? defaultPath
        sessionStorage.removeItem(LOGIN_RETURN_KEY)
        const returnPath = (raw.startsWith('/') && !raw.startsWith('//')) ? raw : defaultPath
        navigate(returnPath, { replace: true })
      })
      .catch((err) => setError(err instanceof Error ? err.message : 'Token exchange failed'))
  }, [searchParams, exchangeCode, navigate])

  if (error) {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <div className="max-w-md space-y-4 text-center">
          <h1 className="text-xl font-mono font-bold text-destructive">Authentication Error</h1>
          <p className="text-sm text-muted-foreground">{error}</p>
          <div className="flex items-center justify-center gap-4">
            <button
              onClick={() => login()}
              className="text-sm font-medium underline hover:no-underline"
            >
              Try again
            </button>
            <a href="/" className="text-sm underline">Return to home</a>
          </div>
        </div>
      </div>
    )
  }

  return (
    <div className="flex min-h-screen items-center justify-center">
      <p className="text-sm text-muted-foreground font-mono">Completing authentication...</p>
    </div>
  )
}
