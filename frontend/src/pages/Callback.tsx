import { useEffect, useState } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { useAuth } from '@/lib/auth'

export default function Callback() {
  const [searchParams] = useSearchParams()
  const navigate = useNavigate()
  const { exchangeCode } = useAuth()
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    const code = searchParams.get('code')
    const errorParam = searchParams.get('error')
    const returnedState = searchParams.get('state')
    const savedState = sessionStorage.getItem('cloudforge_oauth_state')

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
      .then(() => navigate('/ops', { replace: true }))
      .catch((err) => setError(err instanceof Error ? err.message : 'Token exchange failed'))
  }, [searchParams, exchangeCode, navigate])

  if (error) {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <div className="max-w-md space-y-4 text-center">
          <h1 className="text-xl font-mono font-bold text-destructive">Authentication Error</h1>
          <p className="text-sm text-muted-foreground">{error}</p>
          <a href="/" className="text-sm underline">Return to home</a>
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
