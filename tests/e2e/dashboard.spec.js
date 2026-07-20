// @ts-check
const path = require('path');
const { test, expect } = require('@playwright/test');

const SCREENSHOT_PATH = path.join(__dirname, 'artifacts', 'dashboard-live.png');

test('AES dashboard shows live esp32-cam-02 fleet tile', async ({ page }) => {
  // 1. Navigate to the dashboard root.
  await page.goto('/');

  // 2. Title contains "AES" (full title: "AES — Live Security Console").
  await expect(page).toHaveTitle(/AES/);

  // 3. Wait up to 45s for the esp32-cam-02 fleet tile to appear inside #fleet.
  //    The dashboard re-renders #fleet every 3s from /api/state, so this is a
  //    poll/retry: locate the .tile inside #fleet whose name contains the id.
  const tile = page
    .locator('#fleet .tile')
    .filter({ hasText: 'esp32-cam-02' })
    .first();

  await expect(tile).toBeVisible({ timeout: 45 * 1000 });

  // 4. That tile's metrics line matches /cpu .*conn/ (case-insensitive),
  //    e.g. "cpu 12% · 0/s · 1 conn".
  const metrics = tile.locator('.metrics');
  await expect(metrics).toHaveText(/cpu .*conn/i, { timeout: 45 * 1000 });

  // 5. The #updated live indicator must NOT read "offline".
  const updated = page.locator('#updated');
  await expect(updated).not.toHaveText(/offline/i);

  // 6. Full-page screenshot of the live dashboard.
  await page.screenshot({ path: SCREENSHOT_PATH, fullPage: true });
});
