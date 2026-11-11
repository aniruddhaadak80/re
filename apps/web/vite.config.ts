import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const coreSrc = fileURLToPath(new URL('../../packages/core/src/', import.meta.url));
const pkgSrc = (name: string) => fileURLToPath(new URL(`../../packages/${name}/src/`, import.meta.url));
const icedStub = fileURLToPath(new URL('./src/lib/iced-stub.ts', import.meta.url));
const base = process.env.BASE ?? '/re/';

// vite preview serves the same security headers as production (vercel.json), so the browser
// tests run under the real Content-Security-Policy. HSTS and upgrade-insecure-requests are left
// out because preview runs on plain http://127.0.0.1.
function productionHeaders(): Record<string, string> {
  const vercel = JSON.parse(readFileSync(new URL('../../vercel.json', import.meta.url), 'utf8')) as { headers?: { source: string; headers: { key: string; value: string }[] }[] };
  const all = vercel.headers?.find((h) => h.source === '/(.*)')?.headers ?? [];
  const out: Record<string, string> = {};
  for (const { key, value } of all) {
    if (key === 'Strict-Transport-Security') continue;
    out[key] = key === 'Content-Security-Policy' ? value.split(';').map((d) => d.trim()).filter((d) => d && d !== 'upgrade-insecure-requests').join('; ') : value;
  }
  return out;
}

export default defineConfig({
  base,
  plugins: [react()],
  resolve: {
    alias: [
      { find: /^@revlens\/core$/, replacement: `${coreSrc}index.ts` },
      { find: /^@revlens\/core\/internal\/(.*)$/, replacement: `${coreSrc}$1` },
      // the browser builds of the packages, from source (Node-only entries are never imported here)
      { find: /^@revlens\/(engine|managed|webrt|mobile|disasm|extras|desktop)$/, replacement: `${pkgSrc('$1')}index.ts` },
      // iced-x86 ships a Node build that reads its .wasm with fs; in the browser Capstone decodes x86 too
      { find: /^iced-x86$/, replacement: icedStub },
    ],
  },
  worker: { format: 'es' },
  server: { fs: { allow: ['../..'] } },
  preview: { headers: productionHeaders() },
  build: {
    target: 'es2022',
    chunkSizeWarningLimit: 1800,
    rolldownOptions: {
      output: {
        codeSplitting: {
          groups: [
            { name: 'react', test: /node_modules[\\/](react|react-dom|scheduler)[\\/]/ },
            { name: 'motion', test: /node_modules[\\/](framer-motion|motion|motion-dom|motion-utils)[\\/]/ },
          ],
        },
      },
    },
  },
});
