import { useState, useEffect, useRef, useCallback, useMemo } from 'react'
import { useNavigate } from 'react-router-dom'
import { Dialog, DialogContent, DialogTitle } from '@/components/ui/dialog'
import {
  Search,
  ArrowRight,
  FileText,
  Shield,
  Bot,
  Home,
  Settings,
  AlertTriangle,
  Wrench,
  DollarSign,
  Box,
} from 'lucide-react'

interface CommandItem {
  id: string
  label: string
  section: 'Navigate' | 'Actions'
  icon: typeof Search
  action: () => void
}

interface CommandPaletteProps {
  open: boolean
  onOpenChange: (open: boolean) => void
}

export function CommandPalette({ open, onOpenChange }: CommandPaletteProps) {
  const navigate = useNavigate()
  const [query, setQuery] = useState('')
  const [selectedIndex, setSelectedIndex] = useState(0)
  const inputRef = useRef<HTMLInputElement>(null)

  const items: CommandItem[] = [
    // Navigate section
    { id: 'nav-dashboard', label: 'Command Center', section: 'Navigate', icon: Home, action: () => navigate('/ops') },
    { id: 'nav-findings', label: 'Findings', section: 'Navigate', icon: AlertTriangle, action: () => navigate('/ops/findings') },
    { id: 'nav-remediation', label: 'Remediation', section: 'Navigate', icon: Wrench, action: () => navigate('/ops/remediation') },
    { id: 'nav-compliance', label: 'Compliance', section: 'Navigate', icon: Shield, action: () => navigate('/ops/compliance') },
    { id: 'nav-containers', label: 'Containers', section: 'Navigate', icon: Box, action: () => navigate('/ops/containers') },
    { id: 'nav-spend', label: 'Spend', section: 'Navigate', icon: DollarSign, action: () => navigate('/ops/costs') },
    { id: 'nav-policies', label: 'Policies', section: 'Navigate', icon: FileText, action: () => navigate('/admin/policies') },
    { id: 'nav-agents', label: 'AI Agents', section: 'Navigate', icon: Bot, action: () => navigate('/admin/ai-agents') },
    { id: 'nav-system', label: 'System Health', section: 'Navigate', icon: Settings, action: () => navigate('/admin/system') },
    // Actions section
    { id: 'act-export', label: 'Export Findings CSV', section: 'Actions', icon: ArrowRight, action: () => navigate('/ops/findings') },
  ]

  const filtered = query
    ? items.filter(i => i.label.toLowerCase().includes(query.toLowerCase()))
    : items

  useEffect(() => { setSelectedIndex(0) }, [query])

  useEffect(() => {
    if (open) {
      setQuery('')
      setTimeout(() => inputRef.current?.focus(), 0)
    }
  }, [open])

  const execute = useCallback((item: CommandItem) => {
    onOpenChange(false)
    item.action()
  }, [onOpenChange])

  function handleKeyDown(e: React.KeyboardEvent) {
    if (e.key === 'ArrowDown') {
      e.preventDefault()
      setSelectedIndex(i => Math.min(i + 1, filtered.length - 1))
    } else if (e.key === 'ArrowUp') {
      e.preventDefault()
      setSelectedIndex(i => Math.max(i - 1, 0))
    } else if (e.key === 'Enter' && filtered[selectedIndex]) {
      e.preventDefault()
      execute(filtered[selectedIndex])
    }
  }

  const sections = ['Navigate', 'Actions'] as const

  const groupedItems = useMemo(() => {
    const groups: { section: string; items: { item: CommandItem; globalIndex: number }[] }[] = []
    let idx = 0
    for (const section of sections) {
      const sItems = filtered.filter(i => i.section === section)
      if (sItems.length > 0) {
        groups.push({ section, items: sItems.map(item => ({ item, globalIndex: idx++ })) })
      }
    }
    return groups
  }, [filtered])

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-lg p-0 gap-0 overflow-hidden" showCloseButton={false} aria-describedby={undefined}>
        <DialogTitle className="sr-only">Command palette</DialogTitle>
        <div className="flex items-center gap-2 px-3 border-b border-border">
          <Search className="h-4 w-4 shrink-0 text-muted-foreground" />
          <input
            ref={inputRef}
            type="text"
            value={query}
            onChange={e => setQuery(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder="Type a command or search..."
            className="flex-1 h-11 bg-transparent text-sm outline-none placeholder:text-muted-foreground"
          />
          <kbd className="hidden sm:inline-flex h-5 items-center rounded border border-border bg-muted px-1.5 font-mono text-[10px] text-muted-foreground">ESC</kbd>
        </div>

        <div className="max-h-72 overflow-y-auto py-1">
          {filtered.length === 0 && (
            <p className="py-6 text-center text-sm text-muted-foreground">No results found.</p>
          )}
          {groupedItems.map(({ section, items: groupItems }) => (
            <div key={section}>
              <p className="px-3 py-1.5 text-[10px] font-medium uppercase tracking-wide text-muted-foreground">{section}</p>
              {groupItems.map(({ item, globalIndex }) => {
                const Icon = item.icon
                return (
                  <button
                    key={item.id}
                    type="button"
                    onClick={() => execute(item)}
                    className={`flex w-full items-center gap-3 px-3 py-2 text-sm ${
                      globalIndex === selectedIndex ? 'bg-accent text-accent-foreground' : 'text-foreground hover:bg-accent/50'
                    }`}
                  >
                    <Icon className="h-4 w-4 shrink-0 text-muted-foreground" />
                    <span>{item.label}</span>
                  </button>
                )
              })}
            </div>
          ))}
        </div>
      </DialogContent>
    </Dialog>
  )
}
