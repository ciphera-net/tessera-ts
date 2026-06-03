import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
  // Only look for browser specs, not the vitest node tests
  testDir: 'browser',
  testMatch: '**/*.spec.ts',

  // Argon2id in a real browser can be slow (64 MiB memory, parallelism)
  timeout: 90_000,
  expect: { timeout: 10_000 },

  // No parallel workers — Vite server is shared and wasm-init is heavyweight
  workers: 1,

  reporter: [['list'], ['html', { open: 'never', outputFolder: 'playwright-report' }]],

  use: {
    baseURL: 'http://localhost:5173',
    trace: 'retain-on-failure',
  },

  webServer: {
    // Serve the fixture via Vite — config is in browser/fixture/vite.config.ts
    command: 'npx vite browser/fixture --config browser/fixture/vite.config.ts --port 5173',
    port: 5173,
    reuseExistingServer: !process.env.CI,
    // Give Vite time to compile the TS + wasm imports on first start
    timeout: 60_000,
  },

  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'], channel: undefined },
    },
    {
      name: 'webkit',
      use: { ...devices['Desktop Safari'] },
    },
  ],
});
