import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    host: 'localhost',
    port: 5173,
    strictPort: true,
    proxy: {
      '/api/ask': {
        target: 'http://127.0.0.1:3000',
        changeOrigin: true,
      },
      '/api': {
        target: 'http://127.0.0.1:3001',
        changeOrigin: true,
        configure(proxy) { proxy.on('proxyReq', (request) => request.setHeader('Origin', 'http://localhost:5173')) },
      },
      '/mcp': {
        target: 'http://127.0.0.1:3001',
        changeOrigin: true,
      },
      '/oauth/interaction': {
        target: 'http://127.0.0.1:3001',
        changeOrigin: false,
        bypass(request) {
          if (request.method === 'GET' && request.headers.accept?.includes('text/html')) return request.url
        },
      },
      '/oauth': { target: 'http://127.0.0.1:3001', changeOrigin: false },
      '/.well-known': { target: 'http://127.0.0.1:3001', changeOrigin: false },
    },
  },
})
