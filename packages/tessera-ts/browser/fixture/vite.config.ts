import { defineConfig } from 'vite';
import { resolve } from 'path';
import { fileURLToPath } from 'url';
import { dirname } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

export default defineConfig({
  root: __dirname,
  server: {
    port: 5173,
    // SharedArrayBuffer requires COOP/COEP headers (needed for Argon2 multi-threading in WASM)
    headers: {
      'Cross-Origin-Opener-Policy': 'same-origin',
      'Cross-Origin-Embedder-Policy': 'require-corp',
    },
    fs: {
      // Allow serving files from the package root (wasm/ directory is above fixture/)
      allow: [resolve(__dirname, '../..')],
    },
  },
  build: {
    target: 'es2022',
  },
  // Vite transforms `new URL('tessera_bg.wasm', import.meta.url)` patterns automatically.
  // assetsInclude ensures raw .wasm requests get the application/wasm MIME type.
  assetsInclude: ['**/*.wasm'],
  optimizeDeps: {
    // The wasm/web package uses import.meta.url — do NOT pre-bundle it (pre-bundling rewrites
    // import.meta.url to a node-context value, breaking the wasm fetch at runtime).
    exclude: ['../../wasm/web/tessera.js'],
  },
});
