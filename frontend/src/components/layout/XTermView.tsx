import { useEffect, useRef, useCallback } from 'react'
import { Terminal } from '@xterm/xterm'
import { FitAddon } from '@xterm/addon-fit'
import { WebLinksAddon } from '@xterm/addon-web-links'
import '@xterm/xterm/css/xterm.css'

interface XTermViewProps {
  onCommand: (command: string) => void
  panelHeight: number
  isConnected: boolean
  isExecuting: boolean
}

const THEME = {
  background: '#0a0a0f',
  foreground: '#e5e7eb',
  cursor: '#3b82f6',
  cursorAccent: '#0a0a0f',
  selectionBackground: '#3b82f640',
  black: '#0a0a0f',
  red: '#ef4444',
  green: '#22c55e',
  yellow: '#f59e0b',
  blue: '#3b82f6',
  magenta: '#a855f7',
  cyan: '#06b6d4',
  white: '#e5e7eb',
  brightBlack: '#6b7280',
  brightRed: '#f87171',
  brightGreen: '#4ade80',
  brightYellow: '#fbbf24',
  brightBlue: '#60a5fa',
  brightMagenta: '#c084fc',
  brightCyan: '#22d3ee',
  brightWhite: '#f9fafb',
}

const PROMPT = '\x1b[38;5;39m❯\x1b[0m '

export function XTermView({ onCommand, panelHeight, isConnected, isExecuting }: XTermViewProps) {
  const containerRef = useRef<HTMLDivElement>(null)
  const termRef = useRef<Terminal | null>(null)
  const fitRef = useRef<FitAddon | null>(null)
  const lineRef = useRef('')

  const writePrompt = useCallback(() => {
    termRef.current?.write(PROMPT)
  }, [])

  // Initialize terminal once.
  useEffect(() => {
    if (!containerRef.current || termRef.current) return

    const term = new Terminal({
      theme: THEME,
      fontFamily: '"JetBrains Mono", "Fira Code", "Cascadia Code", monospace',
      fontSize: 13,
      lineHeight: 1.4,
      cursorBlink: true,
      cursorStyle: 'bar',
      allowProposedApi: true,
      scrollback: 5000,
    })

    const fit = new FitAddon()
    const links = new WebLinksAddon()

    term.loadAddon(fit)
    term.loadAddon(links)
    term.open(containerRef.current)

    fit.fit()
    termRef.current = term
    fitRef.current = fit

    // Welcome banner.
    term.writeln('\x1b[1;36m  Cloud Aegis Terminal\x1b[0m')
    term.writeln('\x1b[90m  Type a command (e.g., aws s3 ls, kubectl get pods)\x1b[0m')
    term.writeln('\x1b[90m  Only read-only cloud CLI commands are allowed.\x1b[0m')
    term.writeln('')
    writePrompt()

    // Handle key input.
    term.onData((data) => {
      // Ignore input while executing.
      if (isExecuting) return

      const code = data.charCodeAt(0)

      if (code === 13) {
        // Enter — submit command.
        term.write('\r\n')
        const cmd = lineRef.current.trim()
        lineRef.current = ''
        if (cmd) {
          onCommand(cmd)
        } else {
          writePrompt()
        }
      } else if (code === 127 || code === 8) {
        // Backspace.
        if (lineRef.current.length > 0) {
          lineRef.current = lineRef.current.slice(0, -1)
          term.write('\b \b')
        }
      } else if (code === 3) {
        // Ctrl+C — cancel current line.
        lineRef.current = ''
        term.write('^C\r\n')
        writePrompt()
      } else if (code === 12) {
        // Ctrl+L — clear.
        term.clear()
        writePrompt()
      } else if (data >= ' ') {
        // Printable character.
        lineRef.current += data
        term.write(data)
      }
    })

    return () => {
      term.dispose()
      termRef.current = null
      fitRef.current = null
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  // Re-fit on panel resize.
  useEffect(() => {
    const timer = setTimeout(() => fitRef.current?.fit(), 50)
    return () => clearTimeout(timer)
  }, [panelHeight])

  // Also refit on window resize.
  useEffect(() => {
    const handler = () => fitRef.current?.fit()
    window.addEventListener('resize', handler)
    return () => window.removeEventListener('resize', handler)
  }, [])

  return (
    <div
      ref={containerRef}
      className="h-full w-full"
      style={{ backgroundColor: THEME.background }}
    />
  )
}

/** Write output to the terminal from outside. */
export function useXTermWriter() {
  const termRef = useRef<Terminal | null>(null)

  const setTerminal = useCallback((term: Terminal | null) => {
    termRef.current = term
  }, [])

  const writeOutput = useCallback((text: string, stream: 'stdout' | 'stderr' = 'stdout') => {
    if (!termRef.current) return
    const colored = stream === 'stderr'
      ? `\x1b[31m${text}\x1b[0m`
      : text
    // Replace newlines with \r\n for terminal.
    termRef.current.write(colored.replace(/\n/g, '\r\n'))
  }, [])

  const writePrompt = useCallback(() => {
    termRef.current?.write('\r\n' + PROMPT)
  }, [])

  return { setTerminal, writeOutput, writePrompt }
}
