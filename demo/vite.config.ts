import { defineConfig, type Plugin } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

function ddgSearchPlugin(): Plugin {
  return {
    name: 'ddg-search-proxy',
    configureServer(server) {
      server.middlewares.use('/api/search', async (req, res) => {
        try {
          const url = new URL(req.url ?? '', 'http://localhost')
          const q = url.searchParams.get('q') ?? ''
          const api = `https://api.duckduckgo.com/?q=${encodeURIComponent(q)}&format=json&no_html=1&skip_disambig=1`
          const r = await fetch(api)
          const data = (await r.json()) as { AbstractText?: string; RelatedTopics?: { Text?: string }[] }
          res.setHeader('Content-Type', 'application/json')
          res.end(
            JSON.stringify({
              abstract: data.AbstractText || '',
              snippet: (data.RelatedTopics?.[0] as { Text?: string })?.Text || '',
            }),
          )
        } catch {
          res.statusCode = 502
          res.end(JSON.stringify({ abstract: '', snippet: '' }))
        }
      })
    },
  }
}

export default defineConfig({
  plugins: [react(), tailwindcss(), ddgSearchPlugin()],
  server: {
    host: '0.0.0.0',
    port: 43123,
    strictPort: true,
  },
  preview: {
    host: '0.0.0.0',
    port: 43123,
  },
})
