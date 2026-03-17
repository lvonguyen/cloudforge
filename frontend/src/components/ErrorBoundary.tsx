import { Component, type ReactNode } from 'react'
import { useLocation } from 'react-router-dom'

interface Props { children: ReactNode; fallbackLabel?: string }
interface State { hasError: boolean; error: Error | null }

export class ErrorBoundary extends Component<Props, State> {
  state: State = { hasError: false, error: null }

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error }
  }

  componentDidCatch(error: Error, errorInfo: React.ErrorInfo) {
    console.error('[ErrorBoundary]', error, errorInfo.componentStack)
    // Stale deployment chunks: Cloudflare Pages deploys new hashes but cached
    // index.js still references old chunk paths. Auto-reload to fetch fresh assets.
    if (error.message?.includes('dynamically imported module') || error.message?.includes('Failed to fetch')) {
      window.location.reload()
      return
    }
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="flex flex-col items-center justify-center h-full gap-4 p-8 text-center">
          <h2 className="text-lg font-semibold">
            Something went wrong{this.props.fallbackLabel ? ` in ${this.props.fallbackLabel}` : ''}
          </h2>
          <p className="text-sm text-muted-foreground max-w-md">{this.state.error?.message}</p>
          <button
            type="button"
            className="px-4 py-2 text-sm bg-primary text-primary-foreground rounded-md"
            onClick={() => this.setState({ hasError: false, error: null })}
          >
            Try again
          </button>
        </div>
      )
    }
    return this.props.children
  }
}

export function RoutingErrorBoundary(props: Props) {
  const { pathname } = useLocation()
  return <ErrorBoundary key={pathname} {...props} />
}
