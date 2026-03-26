import { useCallback, useEffect, useRef } from 'react'
import { useAuth } from '@/lib/auth'
import { useTerminalPanel } from '@/lib/terminal-context'
import { useTerminalWS, type ServerMessage } from '@/hooks/useTerminalWS'
import { XTermView } from '@/components/layout/XTermView'
import { X, TerminalSquare, GripHorizontal, Wifi, WifiOff } from 'lucide-react'
import { Terminal as XTerminal } from '@xterm/xterm'

const PROMPT = '\x1b[38;5;39m❯\x1b[0m '

export function TerminalPanel() {
  const { role } = useAuth()
  const { state, toggle, close, setHeight, setConnected, setExecuting } = useTerminalPanel()
  const dragRef = useRef<{ startY: number; startHeight: number } | null>(null)
  const termRef = useRef<XTerminal | null>(null)
  const cmdIdRef = useRef(0)

  // RBAC: only operator and admin can see the terminal.
  if (role !== 'operator' && role !== 'admin') return null

  const onMessage = useCallback((msg: ServerMessage) => {
    const term = termRef.current
    if (!term) return

    switch (msg.type) {
      case 'output': {
        const text = msg.data ?? ''
        if (msg.stream === 'stderr') {
          term.write(`\x1b[31m${text.replace(/\n/g, '\r\n')}\x1b[0m`)
        } else {
          term.write(text.replace(/\n/g, '\r\n'))
        }
        break
      }
      case 'exit':
        if (msg.elapsed_ms !== undefined) {
          term.write(`\r\n\x1b[90m[exit ${msg.code ?? 0} in ${msg.elapsed_ms}ms]\x1b[0m`)
        }
        term.write('\r\n' + PROMPT)
        setExecuting(false)
        break
      case 'error':
        term.write(`\r\n\x1b[31m✗ ${msg.message ?? 'unknown error'}\x1b[0m\r\n` + PROMPT)
        setExecuting(false)
        break
    }
  }, [setExecuting])

  const { send, isConnected } = useTerminalWS({
    enabled: state.isOpen,
    onMessage,
    onConnected: () => setConnected(true),
    onDisconnected: () => setConnected(false),
  })

  // Sync connection state.
  useEffect(() => {
    setConnected(isConnected)
  }, [isConnected, setConnected])

  const onCommand = useCallback((command: string) => {
    cmdIdRef.current++
    const id = `cmd-${cmdIdRef.current}`
    setExecuting(true)
    send({ type: 'execute', id, command })
  }, [send, setExecuting])

  // Keyboard shortcut: Ctrl+` to toggle.
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (e.ctrlKey && e.key === '`') {
        e.preventDefault()
        toggle()
      }
    }
    document.addEventListener('keydown', handler)
    return () => document.removeEventListener('keydown', handler)
  }, [toggle])

  // Drag-to-resize handler.
  const onDragStart = useCallback((e: React.MouseEvent) => {
    e.preventDefault()
    e.stopPropagation()
    dragRef.current = { startY: e.clientY, startHeight: state.panelHeight }

    const onMouseMove = (ev: MouseEvent) => {
      if (!dragRef.current) return
      const diff = dragRef.current.startY - ev.clientY
      setHeight(dragRef.current.startHeight + diff)
    }
    const onMouseUp = () => {
      dragRef.current = null
      document.removeEventListener('mousemove', onMouseMove)
      document.removeEventListener('mouseup', onMouseUp)
      document.body.style.cursor = ''
      document.body.style.userSelect = ''
    }
    document.body.style.cursor = 'row-resize'
    document.body.style.userSelect = 'none'
    document.addEventListener('mousemove', onMouseMove)
    document.addEventListener('mouseup', onMouseUp)
  }, [state.panelHeight, setHeight])


  if (!state.isOpen) return null

  return (
    <div
      className="fixed bottom-0 left-0 right-0 z-50 border-t border-border bg-[#0a0a0f] shadow-lg transition-[height] duration-200"
      style={{ height: `${state.panelHeight}px` }}
    >
      {/* Drag handle */}
      <div
        role="separator"
        aria-orientation="horizontal"
        aria-label="Resize terminal panel"
        onMouseDown={onDragStart}
        className="absolute -top-1 left-0 right-0 h-2 cursor-row-resize flex items-center justify-center group z-10"
      >
        <GripHorizontal className="h-3 w-5 text-muted-foreground/40 group-hover:text-muted-foreground transition-colors" />
      </div>

      {/* Header bar */}
      <div className="flex h-9 items-center gap-2 border-b border-[#1e2330] bg-[#0d0d14] px-3 text-xs select-none">
        <TerminalSquare className="h-3.5 w-3.5 text-muted-foreground" />
        <span className="font-medium text-gray-200">Cloud Terminal</span>

        {/* Connection status */}
        <span className="flex items-center gap-1 ml-2">
          {isConnected ? (
            <>
              <Wifi className="h-3 w-3 text-green-400" />
              <span className="text-green-400 text-[10px]">Connected</span>
            </>
          ) : (
            <>
              <WifiOff className="h-3 w-3 text-gray-500" />
              <span className="text-gray-500 text-[10px]">Disconnected</span>
            </>
          )}
        </span>

        {state.isExecuting && (
          <span className="ml-1 text-blue-400 animate-pulse text-[10px] font-medium">RUNNING</span>
        )}

        <div className="ml-auto flex items-center gap-1">
          <span className="text-gray-600 text-[10px] mr-2">Ctrl+`</span>
          <button
            onClick={(e) => { e.stopPropagation(); close() }}
            className="rounded-sm p-0.5 text-muted-foreground hover:bg-[#1e2330] hover:text-foreground transition-colors"
            aria-label="Close terminal panel"
          >
            <X className="h-3.5 w-3.5" />
          </button>
        </div>
      </div>

      {/* Terminal content */}
      <div className="h-[calc(100%-36px)]">
        <XTermView
          onCommand={onCommand}
          panelHeight={state.panelHeight}
          isConnected={isConnected}
          isExecuting={state.isExecuting}
        />
      </div>
    </div>
  )
}
