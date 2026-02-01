import { useState, useEffect, useRef, useCallback } from 'react'
import { APP_NAME } from './config'
import { ToastProvider, useToast } from './components/Toasts'
import { useWebSocket } from './hooks/useWebSocket'
import TrendChart from './components/TrendChart'

const API_BASE = import.meta.env.DEV ? '' : 'http://localhost:8000'

function RiskBadge({ score }) {
  const s = score ?? 0
  if (s >= 70) return <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-red-500/20 text-red-400 border border-red-500/50">High</span>
  if (s >= 40) return <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-amber-500/20 text-amber-400 border border-amber-500/50">Medium</span>
  return <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-emerald-500/20 text-emerald-400 border border-emerald-500/50">Low</span>
}

const DISMISSED_STORAGE_KEY = 'kryptos-dismissed-alerts'

function loadDismissedIds() {
  try {
    const raw = sessionStorage.getItem(DISMISSED_STORAGE_KEY)
    if (!raw) return new Set()
    const arr = JSON.parse(raw)
    return new Set(Array.isArray(arr) ? arr : [])
  } catch {
    return new Set()
  }
}

function saveDismissedIds(ids) {
  try {
    sessionStorage.setItem(DISMISSED_STORAGE_KEY, JSON.stringify([...ids]))
  } catch (_) {}
}

function HistoryPanel({ history, onNewScan, onDismissAlert }) {
  useWebSocket((payload) => {
    onNewScan(payload)
  })

  if (!history?.length) {
    return (
      <div className="flex flex-col items-center justify-center h-full text-slate-500 text-sm p-6 text-center">
        <svg className="w-12 h-12 mb-3 opacity-50" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
        </svg>
        <p>No alerts yet</p>
        <p className="text-xs mt-1">Scans from the extension will appear here</p>
      </div>
    )
  }

  return (
    <div className="flex flex-col gap-3 overflow-y-auto p-4">
      {history.map((alert) => (
        <AlertCard key={alert.scanId || alert.timestamp + alert.url} alert={alert} onDismiss={onDismissAlert} />
      ))}
    </div>
  )
}

function formatAlertTime(isoString) {
  if (!isoString) return '—'
  try {
    const s = String(isoString).trim()
    const hasZone = /Z$/.test(s) || /[+-]\d{2}:?\d{2}$/.test(s)
    const utc = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}/.test(s) && !hasZone
      ? s.replace(/\.\d+$/, '') + 'Z'
      : isoString
    const d = new Date(utc)
    if (Number.isNaN(d.getTime())) return isoString
    const now = new Date()
    const diffMs = now - d
    const diffMins = Math.floor(diffMs / 60000)
    const diffHours = Math.floor(diffMs / 3600000)
    const diffDays = Math.floor(diffMs / 86400000)
    if (diffMs < 0) return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })
    if (diffMins < 1) return 'Just now'
    if (diffMins < 60) return `${diffMins} min ago`
    if (diffHours < 24) return `${diffHours}h ago`
    if (diffDays < 7) return `${diffDays}d ago`
    return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: d.getFullYear() !== now.getFullYear() ? 'numeric' : undefined, hour: '2-digit', minute: '2-digit' })
  } catch (_) {
    return isoString
  }
}

function AlertCard({ alert, onDismiss }) {
  const risk = alert.riskScore ?? 0
  const voiceAlert = alert.voiceAlert
  const hasVoice = Boolean(voiceAlert)
  const audioSrc = hasVoice
    ? voiceAlert.startsWith('audio/mpeg;base64,')
      ? voiceAlert
      : `${API_BASE}/audio/${voiceAlert}`
    : null

  let hostname = alert.scanType || '—'
  try {
    if (alert.url) hostname = new URL(alert.url).hostname
  } catch (_) {}

  const detailUrl = alert.scanId ? `/scan/${alert.scanId}` : null
  const imageSrc = alert.image_data
    ? (String(alert.image_data).startsWith('data:') ? alert.image_data : `data:image/png;base64,${alert.image_data}`)
    : null

  return (
    <div className="rounded-xl border border-slate-700/80 bg-slate-800/50 p-4 hover:border-slate-600 transition relative group animate-fade-up">
      {onDismiss && (
        <button
          type="button"
          onClick={() => onDismiss(alert)}
          className={`absolute top-3 right-3 p-1 rounded-md text-slate-400 hover:text-slate-200 hover:bg-slate-700/80 transition focus:outline-none ${risk >= 70 ? 'opacity-100' : 'opacity-0 group-hover:opacity-100 focus:opacity-100'}`}
          title="Dismiss alert"
          aria-label="Dismiss alert"
        >
          <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
          </svg>
        </button>
      )}
      <div className={`flex items-start justify-between gap-2 mb-2 ${onDismiss ? 'pr-8' : ''}`}>
        <div>
          <p className="text-slate-200 text-sm font-medium truncate max-w-[180px]" title={alert.url || '—'}>
            {hostname}
          </p>
          <p className="text-slate-500 text-xs">{alert.threatType || 'unknown'}</p>
          <p className="text-slate-500 text-xs mt-0.5" title={alert.timestamp || ''}>
            {formatAlertTime(alert.timestamp)}
          </p>
        </div>
        <RiskBadge score={risk} />
      </div>
      {alert.explanation && (
        <p className="text-slate-400 text-xs line-clamp-2 mb-2">{alert.explanation}</p>
      )}
      {imageSrc && (
        <div className="mt-2 rounded-lg overflow-hidden border border-slate-600/80 bg-slate-800/80 max-h-24 w-full">
          {detailUrl ? (
            <a href={detailUrl}>
              <img src={imageSrc} alt="Scanned content" className="w-full h-24 object-cover object-top" />
            </a>
          ) : (
            <img src={imageSrc} alt="Scanned content" className="w-full h-24 object-cover object-top" />
          )}
        </div>
      )}
      {hasVoice && audioSrc && (
        <audio
          controls
          src={audioSrc}
          className="w-full h-8 mt-2"
          preload="metadata"
        />
      )}
      {detailUrl && (
        <a
          href={detailUrl}
          className="inline-block mt-2 text-xs text-indigo-400 hover:text-indigo-300 transition-colors"
        >
          View full analysis →
        </a>
      )}
    </div>
  )
}

const INITIAL_EDUCATOR_MESSAGE = "Hi! Ask me anything about security or privacy—type your question or use the mic to speak."

/** Try to parse an age (1–120) from the first user message when we don't have age yet. */
function parseAgeFromMessage(text) {
  if (!text || typeof text !== 'string') return null
  const match = text.trim().match(/\b(1?\d?\d|1[01]\d|120)\b/)
  if (!match) return null
  const n = parseInt(match[1], 10)
  return n >= 1 && n <= 120 ? n : null
}

function EducatorChat({ addToast }) {
  const [messages, setMessages] = useState([
    { role: 'assistant', content: INITIAL_EDUCATOR_MESSAGE },
  ])
  const [userAge, setUserAge] = useState(null)
  const [input, setInput] = useState('')
  const [loading, setLoading] = useState(false)
  const [isRecording, setIsRecording] = useState(false)
  const [playingId, setPlayingId] = useState(null)
  const bottomRef = useRef(null)
  const mediaRecorderRef = useRef(null)
  const streamRef = useRef(null)

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages])

  async function startRecording() {
    try {
      const stream = await navigator.mediaDevices.getUserMedia({ audio: true })
      streamRef.current = stream
      const recorder = new MediaRecorder(stream)
      const chunks = []
      recorder.ondataavailable = (e) => { if (e.data.size) chunks.push(e.data) }
      recorder.onstop = async () => {
        streamRef.current?.getTracks().forEach((t) => t.stop())
        streamRef.current = null
        if (chunks.length === 0) return
        const blob = new Blob(chunks, { type: recorder.mimeType || 'audio/webm' })
        setLoading(true)
        try {
          const form = new FormData()
          form.append('file', blob, 'recording.webm')
          const res = await fetch(`${API_BASE}/educator/speech-to-text`, { method: 'POST', body: form })
          const data = await res.json().catch(() => ({}))
          if (res.ok && data.text) setInput((prev) => (prev ? `${prev} ${data.text}` : data.text))
          else addToast(data.detail || 'Could not transcribe', 'error')
        } catch (err) {
          addToast(err.message || 'Speech-to-text failed', 'error')
        } finally {
          setLoading(false)
        }
      }
      recorder.start()
      mediaRecorderRef.current = recorder
      setIsRecording(true)
    } catch (err) {
      addToast(err.message || 'Microphone access denied', 'error')
    }
  }

  function stopRecording() {
    if (mediaRecorderRef.current?.state === 'recording') {
      mediaRecorderRef.current.stop()
      mediaRecorderRef.current = null
    }
    setIsRecording(false)
  }

  async function playReplyTts(content, msgIndex) {
    if (!content || playingId !== null) return
    setPlayingId(msgIndex)
    try {
      const res = await fetch(`${API_BASE}/educator/tts`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text: content }),
      })
      if (!res.ok) {
        addToast('Could not play voice', 'error')
        setPlayingId(null)
        return
      }
      const blob = await res.blob()
      const url = URL.createObjectURL(blob)
      const audio = new Audio(url)
      audio.onended = () => {
        URL.revokeObjectURL(url)
        setPlayingId(null)
      }
      audio.onerror = () => {
        URL.revokeObjectURL(url)
        setPlayingId(null)
      }
      await audio.play()
    } catch (err) {
      addToast(err.message || 'Playback failed', 'error')
      setPlayingId(null)
    }
  }

  async function sendMessage(e) {
    e?.preventDefault()
    const text = input.trim()
    if (!text || loading) return

    let ageToSend = userAge
    if (userAge == null) {
      const parsed = parseAgeFromMessage(text)
      if (parsed != null) {
        setUserAge(parsed)
        ageToSend = parsed
      }
    }

    const userMsg = { role: 'user', content: text }
    setMessages((m) => [...m, userMsg])
    setInput('')
    setLoading(true)

    const controller = new AbortController()
    const timeoutId = setTimeout(() => controller.abort(), 35000)
    try {
      const res = await fetch(`${API_BASE}/educator/chat`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: text, age: ageToSend ?? undefined }),
        signal: controller.signal,
      })
      clearTimeout(timeoutId)
      const data = await res.json().catch(() => ({}))
      if (!res.ok) {
        addToast(data.detail || 'Educator unavailable', 'error')
        setMessages((m) => [...m, { role: 'assistant', content: 'Sorry, I could not respond. Please try again.' }])
        return
      }
      setMessages((m) => [...m, { role: 'assistant', content: data.reply || '' }])
    } catch (err) {
      clearTimeout(timeoutId)
      const isTimeout = err?.name === 'AbortError'
      addToast(isTimeout ? 'Request timed out. Is the backend running?' : (err.message || 'Request failed'), 'error')
      setMessages((m) => [...m, { role: 'assistant', content: 'Sorry, something went wrong. Please try again.' }])
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="flex flex-col h-full">
      <div className="flex-1 overflow-y-auto p-4 space-y-4">
        {messages.map((msg, i) => (
          <div
            key={i}
            className={`flex ${msg.role === 'user' ? 'justify-end' : 'justify-start'} items-end gap-2`}
          >
            <div
              className={`max-w-[85%] rounded-xl px-4 py-2.5 text-sm ${
                msg.role === 'user'
                  ? 'bg-emerald-600/30 text-emerald-100 border border-emerald-500/30'
                  : 'bg-slate-700/60 text-slate-200 border border-slate-600/50'
              }`}
            >
              {msg.content}
            </div>
            {msg.role === 'assistant' && msg.content && (
              <button
                type="button"
                onClick={() => playReplyTts(msg.content, i)}
                disabled={loading || playingId !== null}
                title="Play reply"
                className={`shrink-0 p-2 rounded-lg border transition ${
                  playingId === i
                    ? 'bg-emerald-600/50 border-emerald-500/50 text-emerald-200'
                    : 'bg-slate-700/60 border-slate-600/50 text-slate-400 hover:text-slate-200 hover:border-slate-500'
                } disabled:opacity-50 disabled:cursor-not-allowed`}
                aria-label="Play reply"
              >
                {playingId === i ? (
                  <svg className="w-4 h-4 animate-pulse" fill="currentColor" viewBox="0 0 24 24">
                    <rect x="6" y="4" width="4" height="16" rx="1" />
                    <rect x="14" y="4" width="4" height="16" rx="1" />
                  </svg>
                ) : (
                  <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 24 24">
                    <path d="M8 5v14l11-7z" />
                  </svg>
                )}
              </button>
            )}
          </div>
        ))}
        {loading && (
          <div className="flex justify-start">
            <div className="rounded-xl px-4 py-2.5 bg-slate-700/60 text-slate-400 text-sm animate-pulse">
              Thinking...
            </div>
          </div>
        )}
        <div ref={bottomRef} />
      </div>
      <form onSubmit={sendMessage} className="p-4 border-t border-slate-700/80">
        <div className="flex gap-2 items-center">
          <button
            type="button"
            onClick={isRecording ? stopRecording : startRecording}
            disabled={loading}
            title={isRecording ? 'Stop recording' : 'Record voice'}
            className={`shrink-0 p-2.5 rounded-lg border transition ${
              isRecording
                ? 'bg-red-600/30 border-red-500/50 text-red-300 hover:bg-red-600/50'
                : 'bg-slate-700/60 border-slate-600/50 text-slate-400 hover:text-slate-200 hover:border-slate-500'
            } disabled:opacity-50 disabled:cursor-not-allowed`}
            aria-label={isRecording ? 'Stop recording' : 'Record voice'}
          >
            {isRecording ? (
              <svg className="w-5 h-5" fill="currentColor" viewBox="0 0 24 24">
                <rect x="6" y="6" width="12" height="12" rx="2" />
              </svg>
            ) : (
              <svg className="w-5 h-5" fill="currentColor" viewBox="0 0 24 24">
                <path d="M12 14c1.66 0 3-1.34 3-3V5c0-1.66-1.34-3-3-3S9 3.34 9 5v6c0 1.66 1.34 3 3 3z" />
                <path d="M17 11c0 2.76-2.24 5-5 5s-5-2.24-5-5H5c0 3.53 2.61 6.43 6 6.92V21h2v-3.08c3.39-.49 6-3.39 6-6.92h-2z" />
              </svg>
            )}
          </button>
          <input
            type="text"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="Ask about security or privacy..."
            className="flex-1 px-4 py-2.5 rounded-lg bg-slate-800/80 border border-slate-600/80 text-slate-200 placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-indigo-500/50 focus:border-indigo-500/50 transition-colors"
            disabled={loading}
          />
          <button
            type="submit"
            disabled={loading || !input.trim()}
            className="btn-primary-open disabled:bg-slate-700 disabled:opacity-60 disabled:cursor-not-allowed disabled:hover:opacity-60 px-5"
          >
            Send
          </button>
        </div>
      </form>
    </div>
  )
}

function ScanDetailPage({ scanId }) {
  const [scan, setScan] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  useEffect(() => {
    let cancelled = false
    async function fetchScan() {
      try {
        const res = await fetch(`${API_BASE}/api/scan/${scanId}`)
        if (!res.ok) {
          if (res.status === 404) setError('Scan not found')
          else setError('Failed to load scan')
          return
        }
        const data = await res.json()
        if (!cancelled) setScan(data)
      } catch (err) {
        if (!cancelled) setError(err.message || 'Request failed')
      } finally {
        if (!cancelled) setLoading(false)
      }
    }
    fetchScan()
    return () => { cancelled = true }
  }, [scanId])

  if (loading) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950 text-slate-100 flex items-center justify-center">
        <div className="flex flex-col items-center gap-3">
          <svg className="animate-spin h-10 w-10 text-emerald-500" fill="none" viewBox="0 0 24 24">
            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
            <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
          </svg>
          <p className="text-slate-400">Loading analysis…</p>
        </div>
      </div>
    )
  }

  if (error || !scan) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950 text-slate-100 flex items-center justify-center">
        <div className="text-center">
          <p className="text-red-400 mb-4">{error || 'Scan not found'}</p>
          <a href="/" className="text-indigo-400 hover:text-indigo-300 transition-colors">← Back to dashboard</a>
        </div>
      </div>
    )
  }

  const risk = scan.riskScore ?? 0
  const voiceAlert = scan.voiceAlert
  const hasVoice = Boolean(voiceAlert)
  const audioSrc = hasVoice
    ? voiceAlert.startsWith('audio/mpeg;base64,')
      ? voiceAlert
      : `${API_BASE}/audio/${voiceAlert}`
    : null

  let urlHost = scan.url
  try {
    if (scan.url) urlHost = new URL(scan.url).hostname
  } catch (_) {}

  const scanImageSrc = scan.image_data
    ? (String(scan.image_data).startsWith('data:') ? scan.image_data : `data:image/png;base64,${scan.image_data}`)
    : null

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950 text-slate-100">
      <nav className="border-b border-slate-800/80 bg-slate-900/50 backdrop-blur-sm sticky top-0 z-40">
        <div className="max-w-3xl mx-auto px-4 sm:px-6 lg:px-8 h-14 flex items-center justify-between">
          <a href="/" className="flex items-center gap-2 text-indigo-400 hover:text-indigo-300 text-sm transition-colors">
            <img src="/logo.png" alt="" className="h-11 w-11 rounded object-contain" />
            ← Back to dashboard
          </a>
          <span className="text-slate-500 text-xs truncate max-w-[200px]" title={scan.scanId}>{scan.scanId?.slice(0, 8)}…</span>
        </div>
      </nav>
      <main className="max-w-3xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="flex items-center gap-3 mb-6">
          <RiskBadge score={risk} />
          <span className="text-slate-500 text-sm">{scan.threatType || 'unknown'}</span>
          {scan.url && (
            <a href={scan.url} target="_blank" rel="noopener noreferrer" className="text-indigo-400 hover:text-indigo-300 hover:underline text-sm truncate max-w-[240px] transition-colors">
              {urlHost}
            </a>
          )}
        </div>
        {scanImageSrc && (
          <section className="mb-6">
            <h2 className="text-sm font-semibold text-slate-400 mb-2">Scanned image</h2>
            <div className="rounded-xl overflow-hidden border border-slate-700/80 bg-slate-800/50 max-w-2xl">
              <img src={scanImageSrc} alt="Scanned content" className="w-full max-h-[70vh] object-contain" />
            </div>
          </section>
        )}
        {scan.explanation && (
          <section className="mb-6">
            <h2 className="text-sm font-semibold text-slate-400 mb-2">Explanation</h2>
            <p className="text-slate-200 leading-relaxed">{scan.explanation}</p>
          </section>
        )}
        {scan.nextSteps?.length > 0 && (
          <section className="mb-6">
            <h2 className="text-sm font-semibold text-slate-400 mb-2">Next steps</h2>
            <ul className="list-disc list-inside text-slate-200 space-y-1">
              {scan.nextSteps.map((step, i) => (
                <li key={i}>{step}</li>
              ))}
            </ul>
          </section>
        )}
        {scan.evidence?.length > 0 && (
          <section className="mb-6">
            <h2 className="text-sm font-semibold text-slate-400 mb-2">Evidence</h2>
            <ul className="space-y-2">
              {scan.evidence.map((e, i) => (
                <li key={i} className="text-slate-300 text-sm border-l-2 border-slate-600 pl-3">
                  {e.finding || JSON.stringify(e)}
                </li>
              ))}
            </ul>
          </section>
        )}
        {scan.mitreAttackTechniques?.length > 0 && (
          <section className="mb-6">
            <h2 className="text-sm font-semibold text-slate-400 mb-2">MITRE ATT&amp;CK</h2>
            <p className="text-slate-300 text-sm">{scan.mitreAttackTechniques.join(', ')}</p>
          </section>
        )}
        {hasVoice && audioSrc && (
          <section className="mb-6">
            <h2 className="text-sm font-semibold text-slate-400 mb-2">Voice alert</h2>
            <audio controls src={audioSrc} className="w-full h-10" preload="metadata" />
          </section>
        )}
      </main>
    </div>
  )
}

function sortAlertHistory(rows) {
  if (!Array.isArray(rows) || rows.length <= 1) return rows || []
  return [...rows].sort((a, b) => {
    const riskA = a.riskScore ?? 0
    const riskB = b.riskScore ?? 0
    const voiceA = Boolean(a.voiceAlert)
    const voiceB = Boolean(b.voiceAlert)
    // High risk (70+) first, then items with voice, then by timestamp (newest first)
    if (riskA >= 70 && riskB < 70) return -1
    if (riskA < 70 && riskB >= 70) return 1
    if (voiceA && !voiceB) return -1
    if (!voiceA && voiceB) return 1
    const tsA = new Date(a.timestamp || 0).getTime()
    const tsB = new Date(b.timestamp || 0).getTime()
    return tsB - tsA
  })
}

function Dashboard() {
  useEffect(() => {
    document.title = APP_NAME ? `${APP_NAME} Dashboard` : 'Kryptos-AI Dashboard'
  }, [])
  const [history, setHistory] = useState([])
  const [loading, setLoading] = useState(true)
  const [dismissedIds, setDismissedIds] = useState(loadDismissedIds)
  const { addToast } = useToast()

  const fetchHistory = useCallback(async () => {
    const controller = new AbortController()
    const timeoutId = setTimeout(() => controller.abort(), 12000)
    try {
      const res = await fetch(`${API_BASE}/history`, { signal: controller.signal })
      clearTimeout(timeoutId)
      const data = await res.json().catch(() => [])
      if (!res.ok) {
        addToast((data && data.detail) || 'Could not load alerts', 'error')
        setHistory([])
        return
      }
      const list = Array.isArray(data) ? data : []
      const filtered = list.filter((p) => !dismissedIds.has(p.scanId))
      setHistory(sortAlertHistory(filtered))
    } catch (err) {
      clearTimeout(timeoutId)
      setHistory([])
      if (err?.name === 'AbortError') {
        addToast('Alert history timed out. Is the backend running at http://localhost:8000?', 'error')
      } else {
        addToast('Could not load alerts. Is the backend running?', 'error')
      }
    } finally {
      setLoading(false)
    }
  }, [dismissedIds, addToast])

  useEffect(() => {
    fetchHistory()
  }, [fetchHistory])

  // Refetch alert history when window gains focus so we always see latest (including voice alerts)
  useEffect(() => {
    const onFocus = () => {
      setLoading(true)
      fetchHistory()
    }
    window.addEventListener('focus', onFocus)
    return () => window.removeEventListener('focus', onFocus)
  }, [fetchHistory])

  function onNewScan(payload) {
    if (!payload?.scanId) return
    if (dismissedIds.has(payload.scanId)) return
    setHistory((prev) => sortAlertHistory([payload, ...prev.filter((p) => p.scanId !== payload.scanId)].slice(0, 100)))
    const risk = payload?.riskScore ?? 0
    const hasVoice = Boolean(payload?.voiceAlert)
    addToast(
      risk >= 70
        ? `High risk alert: ${payload?.threatType || 'unknown'}${hasVoice ? ' · voice available' : ''}`
        : `New scan: risk ${risk}/100 · ${payload?.threatType || 'unknown'}`,
      risk >= 70 ? 'error' : 'success'
    )
  }

  function onDismissAlert(alert) {
    const id = alert?.scanId
    if (id) {
      setDismissedIds((prev) => {
        const next = new Set(prev)
        next.add(id)
        saveDismissedIds(next)
        return next
      })
    }
    setHistory((prev) => prev.filter((p) => (id != null ? p.scanId !== id : p !== alert)))
  }

  const [educatorOpen, setEducatorOpen] = useState(false)

  return (
    <div className="relative min-h-screen overflow-hidden text-slate-100 font-sans antialiased">
      {/* Photo-inspired gradient: dark edges, subtle indigo/violet glow at center */}
      <div className="dashboard-bg absolute inset-0 z-0" aria-hidden />
      {/* Curved arc pattern overlay */}
      <div className="dashboard-arcs z-0" aria-hidden>
        <svg viewBox="0 0 1600 1600" fill="none" xmlns="http://www.w3.org/2000/svg">
          <defs>
            {/* Stronger gradient along stroke – indigo to slate, more visible */}
            <linearGradient id="arc-stroke" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stopColor="rgb(129, 140, 248)" stopOpacity="0.42" />
              <stop offset="50%" stopColor="rgb(99, 102, 241)" stopOpacity="0.38" />
              <stop offset="100%" stopColor="rgb(148, 163, 184)" stopOpacity="0.28" />
            </linearGradient>
            {/* Alternate gradient for variety – brighter center feel */}
            <linearGradient id="arc-stroke-alt" x1="100%" y1="0%" x2="0%" y2="100%">
              <stop offset="0%" stopColor="rgb(165, 180, 252)" stopOpacity="0.35" />
              <stop offset="100%" stopColor="rgb(99, 102, 241)" stopOpacity="0.32" />
            </linearGradient>
          </defs>
          {/* Concentric / radiating arcs – thicker strokes, more visible */}
          <path d="M 200 800 A 600 900 0 0 1 800 200" stroke="url(#arc-stroke)" strokeWidth="1.4" fill="none" />
          <path d="M 800 200 A 600 900 0 0 1 1400 800" stroke="url(#arc-stroke)" strokeWidth="1.2" fill="none" />
          <path d="M 1400 800 A 600 900 0 0 1 800 1400" stroke="url(#arc-stroke)" strokeWidth="1.4" fill="none" />
          <path d="M 800 1400 A 600 900 0 0 1 200 800" stroke="url(#arc-stroke)" strokeWidth="1.2" fill="none" />
          <path d="M 100 800 A 800 600 0 0 0 800 100" stroke="url(#arc-stroke-alt)" strokeWidth="1.1" fill="none" />
          <path d="M 800 100 A 800 600 0 0 0 1500 800" stroke="url(#arc-stroke-alt)" strokeWidth="1.1" fill="none" />
          <path d="M 1500 800 A 800 600 0 0 0 800 1500" stroke="url(#arc-stroke-alt)" strokeWidth="1.1" fill="none" />
          <path d="M 800 1500 A 800 600 0 0 0 100 800" stroke="url(#arc-stroke-alt)" strokeWidth="1.1" fill="none" />
          <path d="M 400 800 A 400 700 0 0 1 800 400" stroke="url(#arc-stroke)" strokeWidth="1.2" fill="none" />
          <path d="M 800 400 A 400 700 0 0 1 1200 800" stroke="url(#arc-stroke)" strokeWidth="1.2" fill="none" />
          <path d="M 1200 800 A 400 700 0 0 1 800 1200" stroke="url(#arc-stroke)" strokeWidth="1.2" fill="none" />
          <path d="M 800 1200 A 400 700 0 0 1 400 800" stroke="url(#arc-stroke)" strokeWidth="1.2" fill="none" />
          <path d="M 300 800 A 500 500 0 0 0 800 300" stroke="url(#arc-stroke-alt)" strokeWidth="1" fill="none" />
          <path d="M 800 300 A 500 500 0 0 0 1300 800" stroke="url(#arc-stroke-alt)" strokeWidth="1" fill="none" />
          <path d="M 1300 800 A 500 500 0 0 0 800 1300" stroke="url(#arc-stroke-alt)" strokeWidth="1" fill="none" />
          <path d="M 800 1300 A 500 500 0 0 0 300 800" stroke="url(#arc-stroke-alt)" strokeWidth="1" fill="none" />
        </svg>
      </div>
      <nav className="relative z-10 border-b border-slate-800/80 bg-slate-900/50 backdrop-blur-sm sticky top-0">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between h-14">
            <div className="flex items-center gap-3">
              <a href="/" className="flex items-center gap-3">
                <img src="/logo.png" alt="Scout" className="h-14 w-14 rounded-lg object-contain" />
                <div>
                  <h1 className="text-lg font-semibold text-white">{APP_NAME || 'Kryptos-AI'}</h1>
                  <p className="text-xs text-slate-500">Dashboard</p>
                </div>
              </a>
            </div>
            <div className="flex items-center gap-2 text-xs text-slate-500">
              <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
              Live
            </div>
          </div>
        </div>
      </nav>

      <main className="relative z-10 max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6 h-[calc(100vh-3.5rem)]">
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 h-full min-h-0">
          {/* Alert history — left */}
          <div className="rounded-2xl border border-slate-700/80 bg-slate-800/30 flex flex-col overflow-hidden">
            <div className="px-5 py-4 border-b border-slate-700/80">
              <h2 className="text-base font-semibold text-white">Alert history</h2>
              <p className="text-slate-500 text-xs mt-0.5">Scans from extension · educator voice when available</p>
            </div>
            <div className="flex-1 min-h-0 overflow-y-auto">
              {loading ? (
                <div className="flex items-center justify-center h-32">
                  <svg className="animate-spin h-8 w-8 text-emerald-500" fill="none" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                  </svg>
                </div>
              ) : (
                <HistoryPanel history={history} onNewScan={onNewScan} onDismissAlert={onDismissAlert} />
              )}
            </div>
          </div>

          {/* Trend analysis — right */}
          <div className="rounded-2xl border border-slate-700/80 bg-slate-800/30 flex flex-col overflow-hidden min-h-0">
            <div className="px-5 py-4 border-b border-slate-700/80">
              <h2 className="text-base font-semibold text-white">Trend analysis</h2>
              <p className="text-slate-500 text-xs mt-0.5">Alerts per hour · last 12 hours</p>
            </div>
            <div className="flex-1 min-h-0">
              <TrendChart history={history} />
            </div>
          </div>
        </div>
      </main>

      {/* Floating educator bubble — bottom-right */}
      {!educatorOpen ? (
        <button
          type="button"
          onClick={() => setEducatorOpen(true)}
          className="fixed bottom-6 right-6 z-50 flex h-14 w-14 items-center justify-center rounded-full bg-indigo-600 text-white shadow-lg transition hover:bg-indigo-500 hover:scale-105 focus:outline-none focus:ring-2 focus:ring-indigo-400 focus:ring-offset-2 focus:ring-offset-slate-900"
          title="Open Educator chat"
          aria-label="Open Educator chat"
        >
          <svg className="h-6 w-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 12h.01M12 12h.01M16 12h.01M21 12c0 4.418-4.03 8-9 8a9.863 9.863 0 01-4.255-.949L3 20l1.395-3.72C3.512 15.042 3 13.574 3 12c0-4.418 4.03-8 9-8s9 3.582 9 8z" />
          </svg>
        </button>
      ) : (
        <div
          className="fixed bottom-6 right-6 z-50 flex w-[420px] max-w-[calc(100vw-3rem)] flex-col rounded-2xl border border-slate-700 bg-slate-900 shadow-2xl"
          style={{ height: 'min(70vh, 560px)' }}
        >
          <div className="flex items-center justify-between border-b border-slate-700/80 px-4 py-3">
            <h3 className="text-sm font-semibold text-white">Educator chat</h3>
            <button
              type="button"
              onClick={() => setEducatorOpen(false)}
              className="rounded-lg p-2 text-slate-400 hover:bg-slate-700/80 hover:text-white transition"
              title="Close"
              aria-label="Close Educator chat"
            >
              <svg className="h-5 w-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
          </div>
          <div className="flex-1 min-h-0 overflow-hidden">
            <EducatorChat addToast={addToast} />
          </div>
        </div>
      )}
    </div>
  )
}

function AppRouter() {
  const pathname = typeof window !== 'undefined' ? window.location.pathname : ''
  const scanMatch = pathname.match(/^\/scan\/([^/]+)$/)
  const scanId = scanMatch ? scanMatch[1] : null

  if (scanId) {
    return <ScanDetailPage scanId={scanId} />
  }
  return (
    <ToastProvider>
      <Dashboard />
    </ToastProvider>
  )
}

export default function App() {
  return <AppRouter />
}
