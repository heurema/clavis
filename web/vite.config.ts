import { defineConfig } from "vite"
import react from "@vitejs/plugin-react"
import tailwindcss from "@tailwindcss/vite"
import { tanstackRouter } from "@tanstack/router-plugin/vite"

const proxy = {
  "/api": {
    target: process.env.CLAVIS_API_PROXY ?? "http://127.0.0.1:8080",
    rewrite: (path: string) => path.replace(/^\/api/, ""),
  },
}

export default defineConfig({
  plugins: [tanstackRouter({ target: "react" }), react(), tailwindcss()],
  server: {
    host: "127.0.0.1",
    proxy,
  },
  preview: { host: "127.0.0.1", proxy },
})
