/**
 * Toast notifications for new scans and errors (Person D - Hour 6-12).
 */
import { createContext, useContext, useState, useCallback } from 'react'

const ToastContext = createContext(null)

const TOAST_TTL_MS = 4500

export function ToastProvider({ children }) {
  const [toasts, setToasts] = useState([])

  const addToast = useCallback((message, type = 'info') => {
    const id = Date.now()
    setToasts((prev) => [...prev, { id, message, type }])
    setTimeout(() => {
      setToasts((prev) => prev.filter((t) => t.id !== id))
    }, TOAST_TTL_MS)
  }, [])

  return (
    <ToastContext.Provider value={{ toasts, addToast }}>
      {children}
      <div
        className="fixed bottom-4 right-4 z-50 flex flex-col gap-2 max-w-sm"
        aria-live="polite"
      >
        {toasts.map((t) => (
          <div
            key={t.id}
            className={`px-4 py-3 rounded-lg shadow-lg border text-sm ${
              t.type === 'error'
                ? 'bg-red-900/90 border-red-600 text-red-100'
                : t.type === 'success'
                ? 'bg-emerald-900/90 border-emerald-600 text-emerald-100'
                : 'bg-slate-800/95 border-slate-600 text-slate-200'
            }`}
          >
            {t.message}
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  )
}

export function useToast() {
  const ctx = useContext(ToastContext)
  if (!ctx) return { addToast: () => {} }
  return ctx
}
