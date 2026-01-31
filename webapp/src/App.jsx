import { useState, useEffect } from 'react'
import { APP_NAME } from './config'

const API_BASE = import.meta.env.DEV ? '' : 'http://localhost:8000'

export default function App() {
  useEffect(() => {
    document.title = APP_NAME ? `${APP_NAME} Dashboard` : 'Dashboard'
  }, [])
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)

  async function runTestScan() {
    setLoading(true)
    setError(null)
    setResult(null)
    try {
      const res = await fetch(`${API_BASE}/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          url: 'https://example.com',
          scanType: 'email',
          content: 'Urgent: Verify your account now!',
        }),
      })
      if (!res.ok) throw new Error(res.statusText)
      const data = await res.json()
      setResult(data)
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen bg-slate-900 text-slate-100 p-8">
      <header className="mb-8">
        <h1 className="text-2xl font-bold text-emerald-400">{APP_NAME} Dashboard</h1>
        <p className="text-slate-400">Mock scan results – Hour 2 milestone</p>
      </header>

      <button
        onClick={runTestScan}
        disabled={loading}
        className="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 disabled:bg-slate-600 rounded font-medium"
      >
        {loading ? 'Scanning...' : 'Run Test Scan'}
      </button>

      {error && (
        <div className="mt-4 p-4 bg-red-900/50 border border-red-500 rounded text-red-200">
          Error: {error}. Is the backend running on port 8000?
        </div>
      )}

      {result && (
        <div className="mt-6 p-4 bg-slate-800 rounded border border-slate-600 max-w-2xl">
          <h2 className="text-lg font-semibold text-emerald-400 mb-2">Scan Result</h2>
          <dl className="grid gap-2 text-sm">
            <div><dt className="text-slate-500">scanId</dt><dd>{result.scanId}</dd></div>
            <div><dt className="text-slate-500">url</dt><dd>{result.url}</dd></div>
            <div><dt className="text-slate-500">scanType</dt><dd>{result.scanType}</dd></div>
            <div><dt className="text-slate-500">riskScore</dt><dd className="text-amber-400">{result.riskScore}%</dd></div>
            <div><dt className="text-slate-500">threatType</dt><dd>{result.threatType}</dd></div>
            <div><dt className="text-slate-500">confidence</dt><dd>{(result.confidence * 100).toFixed(0)}%</dd></div>
            <div><dt className="text-slate-500">explanation</dt><dd className="text-slate-300">{result.explanation}</dd></div>
            <div>
              <dt className="text-slate-500">nextSteps</dt>
              <dd><ul className="list-disc list-inside text-slate-300">{result.nextSteps?.map((s, i) => <li key={i}>{s}</li>)}</ul></dd>
            </div>
            <div>
              <dt className="text-slate-500">mitreAttackTechniques</dt>
              <dd className="text-rose-400">{result.mitreAttackTechniques?.join(', ')}</dd>
            </div>
          </dl>
        </div>
      )}
    </div>
  )
}
