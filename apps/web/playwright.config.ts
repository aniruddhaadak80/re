import { defineConfig, devices } from '@playwright/test';

// Set PW_LIBS to a folder of extra shared libraries when the host lacks some Chromium deps.
// Set PW_CHROMIUM to a local Chromium or Chrome binary on hosts where Playwright cannot
// download its own build (for example Linux arm64). CI uses the bundled browser.
const libs = process.env.PW_LIBS;
const executablePath = process.env.PW_CHROMIUM || undefined;
const env = libs ? { ...process.env, LD_LIBRARY_PATH: [libs, process.env.LD_LIBRARY_PATH].filter(Boolean).join(':') } as Record<string, string> : undefined;

export default defineConfig({
  testDir: './e2e',
  outputDir: './e2e/test-results',
  timeout: 60_000,
  expect: { timeout: 15_000 },
  fullyParallel: true,
  workers: process.env.CI ? 2 : 3,
  retries: 0,
  reporter: [['list']],
  use: {
    baseURL: 'http://127.0.0.1:4173/re/',
    serviceWorkers: 'block',
    acceptDownloads: true,
    trace: 'off',
    launchOptions: { ...(env ? { env } : {}), ...(executablePath ? { executablePath } : {}) },
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'], viewport: { width: 1280, height: 800 } } }],
  webServer: {
    command: 'npx vite preview --base /re/ --port 4173 --strictPort --host 127.0.0.1',
    url: 'http://127.0.0.1:4173/re/',
    reuseExistingServer: !process.env.CI,
    timeout: 60_000,
  },
});
