import { useMemo } from 'react'
import {
  ResponsiveContainer,
  LineChart,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
} from 'recharts'

/** Bucket alerts by hour. Returns { hourKey, hourLabel, total }[] for last 12 hours. */
function bucketAlertsByHour(history, hours = 12) {
  const now = new Date()
  const buckets = new Map()

  for (let i = hours - 1; i >= 0; i--) {
    const d = new Date(now)
    d.setHours(d.getHours() - i, 0, 0, 0)
    const hourKey = d.toISOString().slice(0, 13) // YYYY-MM-DDTHH
    const hourLabel = d.toLocaleTimeString(undefined, { hour: 'numeric', minute: '2-digit' })
    buckets.set(hourKey, {
      hourKey,
      hourLabel,
      total: 0,
    })
  }

  if (Array.isArray(history) && history.length > 0) {
    const cutoff = new Date(now)
    cutoff.setHours(cutoff.getHours() - hours, 0, 0, 0)

    for (const alert of history) {
      const ts = alert.timestamp
      if (!ts) continue
      let d
      try {
        const s = String(ts).trim()
        const hasZone = /Z$/.test(s) || /[+-]\d{2}:?\d{2}$/.test(s)
        const utc = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}/.test(s) && !hasZone
          ? s.replace(/\.\d+$/, '') + 'Z'
          : ts
        d = new Date(utc)
        if (Number.isNaN(d.getTime()) || d < cutoff) continue
      } catch (_) {
        continue
      }
      const hourKey = d.toISOString().slice(0, 13)
      if (!buckets.has(hourKey)) continue
      const bucket = buckets.get(hourKey)
      bucket.total += 1
    }
  }

  return Array.from(buckets.values()).sort((a, b) => a.hourKey.localeCompare(b.hourKey))
}

export default function TrendChart({ history }) {
  const data = useMemo(() => bucketAlertsByHour(history || [], 24), [history])

  return (
    <div className="flex flex-col h-full min-h-0 p-4">
      <div className="flex-shrink-0 mb-2">
        <h3 className="text-sm font-semibold text-slate-400">Alerts over time</h3>
        <p className="text-xs text-slate-500 mt-0.5">By hour · last 12 hours</p>
      </div>
      <div className="flex-1 min-h-[240px] w-full">
        <ResponsiveContainer width="100%" height="100%">
          <LineChart
            data={data}
            margin={{ top: 8, right: 8, left: 0, bottom: 0 }}
          >
            <CartesianGrid strokeDasharray="3 3" stroke="#334155" vertical={false} />
            <XAxis
              dataKey="hourLabel"
              tick={{ fill: '#94a3b8', fontSize: 10 }}
              axisLine={{ stroke: '#334155' }}
              tickLine={{ stroke: '#334155' }}
              interval="preserveStartEnd"
              minTickGap={32}
            />
            <YAxis
              allowDecimals={false}
              tick={{ fill: '#94a3b8', fontSize: 11 }}
              axisLine={{ stroke: '#334155' }}
              tickLine={{ stroke: '#334155' }}
            />
            <Tooltip
              contentStyle={{
                backgroundColor: '#1e293b',
                border: '1px solid #334155',
                borderRadius: '8px',
                fontSize: '12px',
              }}
              labelStyle={{ color: '#e2e8f0' }}
              formatter={(value) => [value, 'Alerts']}
              labelFormatter={(label) => label}
            />
            <Line
              type="monotone"
              dataKey="total"
              name="Alerts"
              stroke="#64748b"
              strokeWidth={2}
              dot={{ fill: '#64748b', strokeWidth: 0, r: 3 }}
              activeDot={{ r: 4, fill: '#94a3b8' }}
              connectNulls
            />
          </LineChart>
        </ResponsiveContainer>
      </div>
    </div>
  )
}
