import { build } from "vite"

// Run the Vite router plugin before TypeScript checks, including on a clean
// checkout. This build resolves routes in memory and writes no web assets.
await build({ logLevel: "error", build: { write: false, emptyOutDir: false } })
