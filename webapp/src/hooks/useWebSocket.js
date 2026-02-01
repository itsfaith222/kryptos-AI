/**
 * WebSocket hook for real-time scan alerts (Person D - Hour 6-12).
 * Connects to backend /ws; on new_scan messages calls onScan(payload).
 */
import { useEffect, useRef } from 'react'

const WS_BASE = import.meta.env.DEV
  ? `${window.location.protocol === 'https:' ? 'wss:' : 'ws:'}//${window.location.host}`
  : 'ws://localhost:8000'

export function useWebSocket(onScan) {
  const wsRef = useRef(null)
  const onScanRef = useRef(onScan)
  onScanRef.current = onScan

  useEffect(() => {
    const url = `${WS_BASE}/ws`
    const ws = new WebSocket(url)
    wsRef.current = ws

    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data)
        if (data.type === 'new_scan' && data.payload) {
          onScanRef.current?.(data.payload)
        }
      } catch (_) {}
    }

    const pingInterval = setInterval(() => {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send('ping')
      }
    }, 25000)

    return () => {
      clearInterval(pingInterval)
      ws.close()
      wsRef.current = null
    }
  }, [])

  return wsRef
}
