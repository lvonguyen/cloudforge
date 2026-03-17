import { useState, useEffect, useCallback, useRef } from 'react'
import { Search, X, Sparkles } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { apiClient } from '@/lib/api'

interface NLQFilters {
  severity?: string[]
  provider?: string[]
  category?: string[]
  status?: string[]
  environment?: string[]
  text?: string
}

interface NLQueryBarProps {
  onApplyFilters: (filters: NLQFilters) => void
}

export function NLQueryBar({ onApplyFilters }: NLQueryBarProps) {
  const [open, setOpen] = useState(false)
  const [query, setQuery] = useState('')
  const [loading, setLoading] = useState(false)
  const [appliedFilters, setAppliedFilters] = useState<NLQFilters | null>(null)
  const inputRef = useRef<HTMLInputElement>(null)

  // Cmd+K / Ctrl+K shortcut
  useEffect(() => {
    function handleKeyDown(e: KeyboardEvent) {
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault()
        setOpen(prev => !prev)
      }
      if (e.key === '/' && !open && document.activeElement?.tagName !== 'INPUT' && document.activeElement?.tagName !== 'TEXTAREA') {
        e.preventDefault()
        setOpen(true)
      }
      if (e.key === 'Escape' && open) {
        setOpen(false)
      }
    }
    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [open])

  // Auto-focus input when opened
  useEffect(() => {
    if (open) inputRef.current?.focus()
  }, [open])

  const handleSubmit = useCallback(async () => {
    const q = query.trim()
    if (!q) return
    setLoading(true)

    try {
      const filters = await apiClient.post<NLQFilters>('/ai/nlq', { query: q })
      setAppliedFilters(filters)
      onApplyFilters(filters)
      setOpen(false)
    } catch {
      // Fallback: treat as text search
      const fallback: NLQFilters = { text: q }
      setAppliedFilters(fallback)
      onApplyFilters(fallback)
      setOpen(false)
    } finally {
      setLoading(false)
    }
  }, [query, onApplyFilters])

  const clearFilters = useCallback(() => {
    setAppliedFilters(null)
    setQuery('')
    onApplyFilters({})
  }, [onApplyFilters])

  return (
    <>
      {/* Trigger bar */}
      <button
        onClick={() => setOpen(true)}
        className="flex items-center gap-2 px-3 py-1.5 text-xs text-muted-foreground border border-border hover:bg-muted/30 transition-colors w-full max-w-md"
      >
        <Sparkles className="h-3.5 w-3.5 text-violet-500" />
        <span className="flex-1 text-left">Ask a question about findings...</span>
        <kbd className="text-[10px] font-mono bg-muted px-1.5 py-0.5 border border-border">⌘K</kbd>
      </button>

      {/* Applied filters pills */}
      {appliedFilters && Object.keys(appliedFilters).length > 0 && (
        <div className="flex items-center gap-1.5 flex-wrap mt-1.5">
          <span className="text-[10px] text-muted-foreground uppercase tracking-wide">Interpreted as:</span>
          {appliedFilters.severity?.map(s => (
            <Badge key={s} variant="outline" className="text-[10px] px-1.5 py-0 rounded-none">{s}</Badge>
          ))}
          {appliedFilters.provider?.map(p => (
            <Badge key={p} variant="outline" className="text-[10px] px-1.5 py-0 rounded-none">{p.toUpperCase()}</Badge>
          ))}
          {appliedFilters.category?.map(c => (
            <Badge key={c} variant="outline" className="text-[10px] px-1.5 py-0 rounded-none">{c}</Badge>
          ))}
          {appliedFilters.status?.map(st => (
            <Badge key={st} variant="outline" className="text-[10px] px-1.5 py-0 rounded-none">{st}</Badge>
          ))}
          {appliedFilters.environment?.map(e => (
            <Badge key={e} variant="outline" className="text-[10px] px-1.5 py-0 rounded-none">{e}</Badge>
          ))}
          {appliedFilters.text && (
            <Badge variant="outline" className="text-[10px] px-1.5 py-0 rounded-none">"{appliedFilters.text}"</Badge>
          )}
          <button onClick={clearFilters} className="text-[10px] text-blue-600 dark:text-blue-400 hover:underline ml-1">
            Clear
          </button>
        </div>
      )}

      {/* Overlay input */}
      {open && (
        <div className="fixed inset-0 z-50 flex items-start justify-center pt-[20vh]" onClick={() => setOpen(false)}>
          <div className="absolute inset-0 bg-background/80 backdrop-blur-sm" />
          <div className="relative w-full max-w-lg mx-4" onClick={e => e.stopPropagation()}>
            <div className="border border-border bg-background shadow-2xl">
              <div className="flex items-center gap-2 px-4 py-3 border-b border-border">
                <Search className="h-4 w-4 text-muted-foreground shrink-0" />
                <input
                  ref={inputRef}
                  type="text"
                  value={query}
                  onChange={e => setQuery(e.target.value)}
                  onKeyDown={e => { if (e.key === 'Enter') handleSubmit() }}
                  placeholder="e.g. critical AWS misconfigs in production"
                  className="flex-1 text-sm bg-transparent border-none outline-none"
                  disabled={loading}
                />
                {loading && <span className="text-[10px] text-muted-foreground animate-pulse">Analyzing...</span>}
                <button onClick={() => setOpen(false)} className="p-1 hover:bg-muted" aria-label="Close">
                  <X className="h-4 w-4" />
                </button>
              </div>
              <div className="px-4 py-2 text-[10px] text-muted-foreground">
                <span className="font-medium">Examples:</span>{' '}
                <span className="text-violet-500">critical AWS misconfigs</span> · <span className="text-violet-500">open vulnerabilities in prod</span> · <span className="text-violet-500">S3 bucket findings</span>
              </div>
            </div>
          </div>
        </div>
      )}
    </>
  )
}
