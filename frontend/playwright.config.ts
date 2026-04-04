import { defineConfig, devices } from '@playwright/test'

const defaultBaseURL = 'http://localhost:5175'
const baseURL = process.env.PLAYWRIGHT_BASE_URL || defaultBaseURL
const isLocalTarget = /^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/i.test(baseURL)

export default defineConfig({
  testDir: './e2e',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: 1,
  workers: process.env.CI ? 1 : undefined,
  reporter: 'html',
  timeout: 30_000,

  use: {
    baseURL,
    screenshot: 'only-on-failure',
    trace: 'on-first-retry',
  },

  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],

  webServer: isLocalTarget
    ? {
        command: 'npx vite --port 5175 --mode e2e',
        url: defaultBaseURL,
        reuseExistingServer: false,
        timeout: 60_000,
      }
    : undefined,
})
