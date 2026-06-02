import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  build: {
    // Outputs into server/web/ui/ which is tracked by git (placeholder index.html
    // always present so go:embed compiles on a fresh clone without running npm).
    // The built assets (assets/*.js, assets/*.css) are gitignored — only
    // index.html is committed so the Go embed always has at least one file.
    outDir:      '../server/web/ui',
    emptyOutDir: false, // keep existing placeholder; vite overwrites index.html
  },
  server: {
    port: 5173,
    proxy: {
      '/api':       'http://localhost:8080',
      '/ws':        { target: 'ws://localhost:8080', ws: true },
    },
  },
})
