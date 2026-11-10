import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { fileURLToPath } from 'node:url';

const coreSrc = fileURLToPath(new URL('../../packages/core/src/', import.meta.url));
const base = process.env.BASE ?? '/re/';

export default defineConfig({
  base,
  plugins: [react()],
  resolve: {
    alias: [
      { find: /^@revlens\/core$/, replacement: `${coreSrc}index.ts` },
      { find: /^@revlens\/core\/internal\/(.*)$/, replacement: `${coreSrc}$1` },
    ],
  },
  worker: { format: 'es' },
  server: { fs: { allow: ['../..'] } },
  build: {
    target: 'es2022',
    chunkSizeWarningLimit: 1800,
    rollupOptions: {
      output: {
        manualChunks: (id) => {
          if (id.includes('node_modules/react') || id.includes('node_modules/scheduler')) return 'react';
          if (id.includes('node_modules/framer-motion') || id.includes('node_modules/motion')) return 'motion';
          return undefined;
        },
      },
    },
  },
});
