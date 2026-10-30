import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';
import { resolve } from 'path';

export default defineConfig({
  plugins: [
    react(),
    tailwindcss(),
  ],
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    rollupOptions: {
      input: {
        popup: resolve(__dirname, 'popup.html'),
        interstitial: resolve(__dirname, 'interstitial.html'),
        background: resolve(__dirname, 'src/background/service-worker.ts'),
        'navigation-guard': resolve(__dirname, 'src/content/navigation-guard.ts'),
        'search-guard': resolve(__dirname, 'src/content/search-guard.ts'),
      },
      output: {
        entryFileNames: (chunkInfo) => {
          if (
            chunkInfo.name === 'background' ||
            chunkInfo.name === 'navigation-guard' ||
            chunkInfo.name === 'search-guard'
          ) {
            return '[name].js';
          }
          return 'assets/[name]-[hash].js';
        },
        chunkFileNames: 'assets/[name]-[hash].js',
        assetFileNames: 'assets/[name]-[hash].[ext]',
      },
    },
  },
});
