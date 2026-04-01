import { useState, useEffect, useCallback, useRef, useId } from 'react'
import { Search, X, Sparkles, Code2 } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { apiClient } from '@/lib/api'
import { parseRQL, rqlToFilters, isValidRQL, RQL_SYNTAX_HINT } from '@/lib/rql-parser'

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

type QueryMode = 'nlq' | 'rql'

export function NLQueryBar({ onApplyFilters }: NLQueryBarProps) {
  const [open, setOpen] = useState(false)
  const [query, setQuery] = useState('')
  const [loading, setLoading] = useState(false)
  const [appliedFilters, setAppliedFilters] = useState<NLQFilters | null>(null)
  const [mode, setMode] = useState<QueryMode>('nlq')
  const inputRef = useRef<HTMLInputElement>(null)
  const previouslyFocusedRef = useRef<HTMLElement | null>(null)
  const dialogId = useId()
  const dialogTitleId = useId()
  const dialogDescriptionId = useId()
  const nlqTabId = useId()
  const rqlTabId = useId()
  const nlqPanelId = useId()
  const rqlPanelId = useId()
  const inputId = useId()

  const closeOverlay = useCallback(() => setOpen(false), [])

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
    if (open) {
      previouslyFocusedRef.current =
        document.activeElement instanceof HTMLElement ? document.activeElement : null
      inputRef.current?.focus()
      return
    }

    if (previouslyFocusedRef.current) {
      previouslyFocusedRef.current.focus()
      previouslyFocusedRef.current = null
    }
  }, [open])

  const handleSubmit = useCallback(async () => {
    const q = query.trim()
    if (!q) return

    // RQL mode: parse client-side, no AI call needed
    if (mode === 'rql') {
      if (!isValidRQL(q)) {
        // Invalid RQL — fall back to text search
        const fallback: NLQFilters = { text: q }
        setAppliedFilters(fallback)
        onApplyFilters(fallback)
        setOpen(false)
        return
      }
      const parsed = parseRQL(q)
      const raw = rqlToFilters(parsed)
      const filters: NLQFilters = {}
      if (raw.severity) filters.severity = raw.severity
      if (raw.provider) filters.provider = raw.provider
      if (raw.category) filters.category = raw.category
      if (raw.status) filters.status = raw.status
      if (raw.environment) filters.environment = raw.environment
      setAppliedFilters(filters)
      onApplyFilters(filters)
      setOpen(false)
      return
    }

    // NLQ mode: try client-side keyword extraction first, then AI endpoint
    const lower = q.toLowerCase()
    const severityTerms = ['critical', 'high', 'medium', 'low']
    const providerTerms = ['aws', 'azure', 'gcp']
    const categoryTerms: Record<string, string> = {
      vuln: 'VULNERABILITY', vulnerability: 'VULNERABILITY', vulnerabilities: 'VULNERABILITY',
      misconfig: 'MISCONFIGURATION', misconfiguration: 'MISCONFIGURATION',
      identity: 'IDENTITY', iam: 'IDENTITY',
      network: 'NETWORK', data: 'DATA_PROTECTION', pii: 'DATA_PROTECTION', phi: 'DATA_PROTECTION',
      sensitive: 'DATA_PROTECTION', pci: 'DATA_PROTECTION',
    }
    const statusTerms: Record<string, string> = {
      open: 'open', 'in progress': 'in_progress', resolved: 'resolved', suppressed: 'suppressed',
    }

    const matchedSev = severityTerms.filter(s => lower.includes(s)).map(s => s.toUpperCase())
    const matchedProv = providerTerms.filter(p => lower.includes(p))
    const matchedCat = Object.entries(categoryTerms).filter(([k]) => lower.includes(k)).map(([, v]) => v)
    const matchedStatus = Object.entries(statusTerms).filter(([k]) => lower.includes(k)).map(([, v]) => v)

    if (matchedSev.length > 0 || matchedProv.length > 0 || matchedCat.length > 0 || matchedStatus.length > 0) {
      const filters: NLQFilters = {}
      if (matchedSev.length > 0) filters.severity = matchedSev
      if (matchedProv.length > 0) filters.provider = matchedProv
      if (matchedCat.length > 0) filters.category = [...new Set(matchedCat)]
      if (matchedStatus.length > 0) filters.status = [...new Set(matchedStatus)]
      setAppliedFilters(filters)
      onApplyFilters(filters)
      setOpen(false)
      return
    }

    // No keywords matched — call AI endpoint
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
  }, [query, onApplyFilters, mode])

  const clearFilters = useCallback(() => {
    setAppliedFilters(null)
    setQuery('')
    onApplyFilters({})
  }, [onApplyFilters])

  return (
    <>
      {/* Trigger bar */}
      <button
        type="button"
        onClick={() => setOpen(true)}
        className="flex items-center gap-2 px-3 py-1.5 text-xs text-muted-foreground border border-border hover:bg-muted/30 transition-colors w-full max-w-md"
        aria-haspopup="dialog"
        aria-expanded={open}
        aria-controls={dialogId}
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
          <button
            type="button"
            onClick={clearFilters}
            className="text-[10px] text-blue-600 dark:text-blue-400 hover:underline ml-1"
          >
            Clear
          </button>
        </div>
      )}

      {/* Overlay input */}
      {open && (
        <div className="fixed inset-0 z-50 flex items-start justify-center pt-[20vh]" onClick={closeOverlay}>
          <div className="absolute inset-0 bg-background/80 backdrop-blur-sm" aria-hidden="true" />
          <div
            id={dialogId}
            role="dialog"
            aria-modal="true"
            aria-labelledby={dialogTitleId}
            aria-describedby={dialogDescriptionId}
            className="relative w-full max-w-lg mx-4 border border-border bg-background shadow-2xl"
            onClick={e => e.stopPropagation()}
          >
            <h2 id={dialogTitleId} className="sr-only">Findings query assistant</h2>
            <p id={dialogDescriptionId} className="sr-only">
              Search findings with natural language or structured RQL filters.
            </p>

            {/* Mode toggle */}
            <div className="flex items-center gap-1 px-4 pt-3 pb-1" role="tablist" aria-label="Query mode">
              {/* Mode toggle */}
              <button
                type="button"
                id={nlqTabId}
                role="tab"
                aria-selected={mode === 'nlq'}
                aria-controls={nlqPanelId}
                tabIndex={mode === 'nlq' ? 0 : -1}
                className={`text-[10px] font-medium px-2 py-0.5 transition-colors ${mode === 'nlq' ? 'bg-violet-100 text-violet-700 dark:bg-violet-900/30 dark:text-violet-300' : 'text-muted-foreground hover:text-foreground'}`}
                onClick={() => setMode('nlq')}
              >
                <Sparkles className="h-3 w-3 inline mr-1" aria-hidden="true" />
                NLQ
              </button>
              <button
                type="button"
                id={rqlTabId}
                role="tab"
                aria-selected={mode === 'rql'}
                aria-controls={rqlPanelId}
                tabIndex={mode === 'rql' ? 0 : -1}
                className={`text-[10px] font-medium px-2 py-0.5 transition-colors ${mode === 'rql' ? 'bg-emerald-100 text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-300' : 'text-muted-foreground hover:text-foreground'}`}
                onClick={() => setMode('rql')}
              >
                <Code2 className="h-3 w-3 inline mr-1" aria-hidden="true" />
                RQL
              </button>
            </div>

            <div
              id={mode === 'nlq' ? nlqPanelId : rqlPanelId}
              role="tabpanel"
              aria-labelledby={mode === 'nlq' ? nlqTabId : rqlTabId}
            >
              <div className="flex items-center gap-2 px-4 py-2 border-b border-border">
                <Search className="h-4 w-4 text-muted-foreground shrink-0" />
                <label htmlFor={inputId} className="sr-only">Findings query</label>
                <input
                  id={inputId}
                  ref={inputRef}
                  type="text"
                  value={query}
                  onChange={e => setQuery(e.target.value)}
                  onKeyDown={e => { if (e.key === 'Enter') handleSubmit() }}
                  placeholder={mode === 'rql' ? 'severity=CRITICAL AND provider=aws' : 'e.g. critical AWS misconfigs in production'}
                  className="flex-1 text-sm bg-transparent border-none outline-none font-mono text-foreground placeholder:text-muted-foreground"
                  disabled={loading}
                  aria-label="Findings query"
                />
                {loading && (
                  <span className="text-[10px] text-muted-foreground animate-pulse" role="status" aria-live="polite">
                    Analyzing...
                  </span>
                )}
                <button type="button" onClick={closeOverlay} className="p-1 hover:bg-muted" aria-label="Close">
                  <X className="h-4 w-4" />
                </button>
              </div>
              <div className="px-4 py-2 text-[10px] text-muted-foreground">
                {mode === 'rql' ? (
                  <>
                    <span className="font-medium">Syntax:</span>{' '}
                    <span className="text-emerald-500 font-mono">{RQL_SYNTAX_HINT}</span>
                  </>
                ) : (
                  <>
                    <span className="font-medium">Examples:</span>{' '}
                    <span className="text-violet-500">critical AWS misconfigs</span> · <span className="text-violet-500">open vulnerabilities in prod</span> · <span className="text-violet-500">S3 bucket findings</span>
                  </>
                )}
              </div>
            </div>
          </div>
        </div>
      )}
    </>
  )
}
