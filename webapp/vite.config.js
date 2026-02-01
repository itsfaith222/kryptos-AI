import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/scan': {
        target: 'http://localhost:8000',
        changeOrigin: true,
        bypass(req) {
          // GET /scan/:id is the webapp scan-detail page; serve SPA so React can route
          if (req.method === 'GET' && req.url && req.url.startsWith('/scan/')) return '/index.html'
        },
      },
      '/api': 'http://localhost:8000',
      '/health': 'http://localhost:8000',
      '/history': 'http://localhost:8000',
      '/audio': 'http://localhost:8000',
      '/educator': 'http://localhost:8000',
      '/ws': { target: 'ws://localhost:8000', ws: true },
    },
  },
})
