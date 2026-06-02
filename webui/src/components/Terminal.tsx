import { useEffect, useRef, useCallback } from 'react'
import { Terminal as XTerm } from '@xterm/xterm'
import { FitAddon } from '@xterm/addon-fit'
import { WebLinksAddon } from '@xterm/addon-web-links'
import '@xterm/xterm/css/xterm.css'
import type { TermMsg } from '../types'
import { X } from 'lucide-react'

interface Props {
  sessionID: string
  sessionName: string
  onClose: () => void
}

export default function Terminal({ sessionID, sessionName, onClose }: Props) {
  const containerRef = useRef<HTMLDivElement>(null)
  const termRef      = useRef<XTerm | null>(null)
  const fitRef       = useRef<FitAddon | null>(null)
  const wsRef        = useRef<WebSocket | null>(null)
  const inputBuf     = useRef<string>('')

  // ── Write to xterm ─────────────────────────────────────────────────────────
  const write = useCallback((data: string) => {
    termRef.current?.write(data)
  }, [])

  // ── Initialise xterm ───────────────────────────────────────────────────────
  useEffect(() => {
    if (!containerRef.current) return

    const term = new XTerm({
      theme: {
        background:  '#0a0a0f',
        foreground:  '#e0e0e0',
        cursor:      '#00ff88',
        black:       '#0a0a0f',
        brightBlack: '#555577',
        red:         '#ff4444',
        green:       '#00ff88',
        yellow:      '#ffaa00',
        blue:        '#00d4ff',
        magenta:     '#aa88ff',
        cyan:        '#00d4ff',
        white:       '#e0e0e0',
      },
      fontFamily:  '"JetBrains Mono", "Fira Code", monospace',
      fontSize:    13,
      lineHeight:  1.4,
      cursorBlink: true,
      cursorStyle: 'block',
      scrollback:  5000,
      allowProposedApi: true,
    })

    const fit   = new FitAddon()
    const links = new WebLinksAddon()
    term.loadAddon(fit)
    term.loadAddon(links)
    term.open(containerRef.current)
    fit.fit()

    termRef.current = term
    fitRef.current  = fit

    // Resize observer keeps xterm sized to its container.
    const ro = new ResizeObserver(() => fit.fit())
    ro.observe(containerRef.current)

    // ── Keyboard input handling ──────────────────────────────────────────
    term.onData((data) => {
      if (data === '\r' || data === '\n') {
        // Enter — send buffered input to server.
        const cmd = inputBuf.current
        inputBuf.current = ''
        term.write('\r\n')
        wsRef.current?.send(JSON.stringify({ type: 'input', data: cmd } as TermMsg))
      } else if (data === '\x7f' || data === '\x08') {
        // Backspace
        if (inputBuf.current.length > 0) {
          inputBuf.current = inputBuf.current.slice(0, -1)
          term.write('\b \b')
        }
      } else if (data === '\x03') {
        // Ctrl+C — send interrupt
        inputBuf.current = ''
        term.write('^C\r\n')
        wsRef.current?.send(JSON.stringify({ type: 'input', data: '' } as TermMsg))
      } else if (!data.startsWith('\x1b')) {
        // Printable character — echo locally and buffer.
        inputBuf.current += data
        term.write(data)
      }
    })

    return () => {
      ro.disconnect()
      term.dispose()
      termRef.current = null
    }
  }, [])

  // ── WebSocket connection ────────────────────────────────────────────────────
  useEffect(() => {
    const proto = window.location.protocol === 'https:' ? 'wss' : 'ws'
    const url   = `${proto}://${window.location.host}/ws/terminal/${sessionID}`
    const ws    = new WebSocket(url)
    wsRef.current = ws

    ws.onopen = () => {
      write('\r\n\x1b[1;32m[+] WebSocket connected\x1b[0m\r\n')
    }

    ws.onclose = () => {
      write('\r\n\x1b[1;31m[!] Connection closed.\x1b[0m\r\n')
    }

    ws.onerror = () => {
      write('\r\n\x1b[1;31m[!] WebSocket error — check server logs.\x1b[0m\r\n')
    }

    ws.onmessage = (e) => {
      try {
        const msg = JSON.parse(e.data) as TermMsg
        switch (msg.type) {
          case 'output':
          case 'error':
            write(msg.data)
            break
          case 'prompt':
            // Render the ANSI prompt but reset the input buffer.
            write(msg.data)
            inputBuf.current = ''
            break
        }
      } catch { /* ignore */ }
    }

    return () => { ws.close(); wsRef.current = null }
  }, [sessionID, write])

  return (
    <div className="flex flex-col h-full bg-bg rounded-lg border border-border overflow-hidden">

      {/* ── Title bar ────────────────────────────────────────────────────── */}
      <div className="flex items-center justify-between px-4 py-2 bg-surface border-b border-border shrink-0">
        <div className="flex items-center gap-2">
          {/* Traffic-light dots */}
          <span className="w-3 h-3 rounded-full bg-danger"  />
          <span className="w-3 h-3 rounded-full bg-warn"    />
          <span className="w-3 h-3 rounded-full bg-primary" />
          <span className="text-muted text-xs ml-2 font-mono">
            phantom:<span className="text-primary">{sessionName}</span>
            &nbsp;—&nbsp;
            <span className="text-accent">{sessionID.slice(0, 8)}</span>
          </span>
        </div>
        <button
          onClick={onClose}
          className="text-muted hover:text-danger transition-colors p-1 rounded"
          title="Close terminal"
        >
          <X size={14} />
        </button>
      </div>

      {/* ── xterm.js container ───────────────────────────────────────────── */}
      <div ref={containerRef} className="flex-1 min-h-0 p-2" />
    </div>
  )
}
