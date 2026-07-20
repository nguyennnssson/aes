// @ts-check
const { defineConfig, devices } = require('@playwright/test');

/**
 * Playwright config for the AES dashboard E2E test.
 * Runs HEADED (headless:false) so the browser window is visible.
 */
module.exports = defineConfig({
  testDir: '.',
  // Generous default per-test timeout (the dashboard polls every 3s).
  timeout: 60 * 1000,
  fullyParallel: false,
  reporter: 'list',
  use: {
    baseURL: 'http://localhost:8000',
    headless: false,
    actionTimeout: 15 * 1000,
    navigationTimeout: 30 * 1000,
    screenshot: 'only-on-failure',
    trace: 'retain-on-failure',
  },
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],
});
