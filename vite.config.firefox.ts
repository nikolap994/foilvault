import { defineConfig } from 'vite'
import { crx } from '@crxjs/vite-plugin'
import { resolve } from 'path'
import manifest from './manifest.firefox.json'

export default defineConfig({
  plugins: [crx({ manifest, browser: 'firefox' })],
  build: {
    outDir: 'dist-firefox',
    minify: false,
    sourcemap: true,
    rollupOptions: {
      input: {
        popup: resolve(__dirname, 'src/popup/popup.html'),
        options: resolve(__dirname, 'src/options/options.html'),
        onboarding: resolve(__dirname, 'src/onboarding/onboarding.html'),
      },
    },
  },
})
