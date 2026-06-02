import { useState, useEffect, useRef, useCallback } from 'react'
import type { WSEvent } from '../types'

type WSStatus = 'connecting' | 'connected' | 'disconnected'

export function useEventStream(onEvent: (e: WSEvent) => void) {
  const [status, setStatus] = useState<WSStatus>('connecting')
  const ws = useRef<WebSocket | null>(null)

  useEffect(() => {
    const proto  = window.location.protocol === 'https:' ? 'wss' : 'ws'
    const host   = window.location.host
    const url    = `${proto}://${host}/ws/events`

    function connect() {
      setStatus('connecting')
      const sock = new WebSocket(url)

      sock.onopen  = () => setStatus('connected')
      sock.onclose = () => {
        setStatus('disconnected')
        // Auto-reconnect after 3 s
        setTimeout(connect, 3000)
      }
      sock.onerror = () => sock.close()
      sock.onmessage = (e) => {
        try {
          const ev = JSON.parse(e.data) as WSEvent
          onEvent(ev)
        } catch { /* ignore */ }
      }

      ws.current = sock
    }

    connect()
    return () => ws.current?.close()
  }, [onEvent])

  return status
}

// ─── Terminal WebSocket ───────────────────────────────────────────────────────

export function useTerminalWS(sessionID: string | null) {
  const [ready, setReady] = useState(false)
  const ws = useRef<WebSocket | null>(null)

  const send = useCallback((data: string) => {
    ws.current?.send(JSON.stringify({ type: 'input', data }))
  }, [])

  useEffect(() => {
    if (!sessionID) return

    const proto = window.location.protocol === 'https:' ? 'wss' : 'ws'
    const url   = `${proto}://${window.location.host}/ws/terminal/${sessionID}`
    const sock  = new WebSocket(url)

    sock.onopen  = () => setReady(true)
    sock.onclose = () => setReady(false)
    sock.onerror = () => sock.close()

    ws.current = sock
    return () => { sock.close(); ws.current = null; setReady(false) }
  }, [sessionID])

  return { ws: ws.current, ready, send }
}
