import path from "node:path"
import { defineConfig, type Plugin } from "vite"
import react from "@vitejs/plugin-react"
import tailwindcss from "@tailwindcss/vite"

const backend = "https://localhost:8443"

/*
 * The production CSP (style-src 'self') blocks <style> elements created at
 * runtime. Two dependencies inject one; their CSS is shipped in the bundled
 * stylesheet instead (see src/index.css), so we turn the injection off to
 * avoid CSP violation reports.
 */
function noRuntimeStyleTags(): Plugin {
  return {
    name: "leazone-no-runtime-style-tags",
    enforce: "pre",
    apply: "build",
    transform(code, id) {
      if (/node_modules[\\/]sonner[\\/]dist[\\/]index\.m?js$/.test(id)) {
        return code.replace(/^__insertCSS\("(?:[^"\\]|\\.)*"\);?$/m, "")
      }
      if (/node_modules[\\/]react-style-singleton[\\/]dist[\\/].*singleton\.js$/.test(id)) {
        return code.replace("if (!document)\n        return null;", "return null;")
      }
      return null
    },
  }
}

export default defineConfig({
  base: "/",
  plugins: [react(), tailwindcss(), noRuntimeStyleTags()],
  resolve: {
    alias: { "@": path.resolve(__dirname, "./src") },
  },
  server: {
    proxy: {
      "/api": { target: backend, changeOrigin: true, secure: false },
      "/health": { target: backend, changeOrigin: true, secure: false },
    },
  },
  build: {
    outDir: "dist",
    emptyOutDir: true,
    // No inline assets for scripts: CSP forbids inline script; data: images are allowed.
    assetsInlineLimit: 4096,
    chunkSizeWarningLimit: 600,
    rollupOptions: {
      output: {
        // Long-lived vendor chunks; table code stays with the pages that use it.
        manualChunks(id) {
          if (!id.includes("node_modules")) return undefined
          if (/node_modules[\\/](react|react-dom|scheduler|react-router|cookie|set-cookie-parser)[\\/]/.test(id)) return "react"
          if (/node_modules[\\/]@tanstack[\\/](react-query|query-core)[\\/]/.test(id)) return "query"
          if (/node_modules[\\/]@tanstack[\\/](react-table|table-core)[\\/]/.test(id)) return undefined
          return "ui"
        },
      },
    },
  },
})
