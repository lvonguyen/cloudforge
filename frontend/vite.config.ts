import path from 'path'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import { defineConfig, type Plugin } from 'vite'

/**
 * Vite plugin that interpolates %VITE_*% placeholders in index.html.
 * This allows the <title> tag and meta description to be parameterized
 * per-tenant at build time via .env files.
 */
function htmlBrandingPlugin(): Plugin {
  return {
    name: 'html-branding',
    transformIndexHtml: {
      order: 'pre',
      handler(html, ctx) {
        // Replace %VITE_FOO% patterns with their env var values
        return html.replace(/%([A-Z_]+)%/g, (match, key) => {
          const value = ctx.server
            ? process.env[key] // dev server: read from process.env
            : process.env[key] // build: env vars are loaded by Vite
          return value ?? match // leave unchanged if not defined
        })
      },
    },
  }
}

export default defineConfig(({ mode }) => {
  // Load env vars so they're available to the HTML plugin at build time
  const env = { ...process.env }
  // Vite loads .env files into process.env before config resolution,
  // but we also manually load them for the HTML transform
  try {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const { loadEnv } = require('vite') as typeof import('vite')
    const loaded = loadEnv(mode, process.cwd(), '')
    Object.assign(env, loaded)
    Object.assign(process.env, loaded)
  } catch {
    // loadEnv not available in some contexts — env vars from .env are still loaded by Vite
  }

  return {
    plugins: [htmlBrandingPlugin(), react(), tailwindcss()],
    resolve: {
      alias: {
        '@': path.resolve(__dirname, './src'),
      },
    },
    build: {
      rollupOptions: {
        output: {
          manualChunks: {
            'vendor-xyflow': ['@xyflow/react', '@xyflow/system'],
            'vendor-recharts': ['recharts'],
            'vendor-tanstack': ['@tanstack/react-query', '@tanstack/react-virtual'],
          },
        },
      },
    },
    server: {
      proxy: {
        '/api': {
          target: 'http://localhost:8080',
          changeOrigin: true,
        },
        '/health': {
          target: 'http://localhost:8080',
          changeOrigin: true,
        },
        '/healthz': {
          target: 'http://localhost:8080',
          changeOrigin: true,
        },
        '/ready': {
          target: 'http://localhost:8080',
          changeOrigin: true,
        },
      },
    },
  }
})
