const { chromium } = require('@playwright/test');
const fs = require('fs');
(async () => {
  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1440, height: 1000 }, deviceScaleFactor: 2 });
  const base = 'file:///C:/Users/ADMIN/Downloads/aes/web/preview.html';
  const views = ['command', 'device', 'pipeline', 'patch', 'learning'];
  fs.mkdirSync('C:/Users/ADMIN/Downloads/aes/web/shots', { recursive: true });
  for (const v of views) {
    await page.goto(base + '#' + v);
    await page.waitForTimeout(800);
    await page.screenshot({ path: `C:/Users/ADMIN/Downloads/aes/web/shots/${v}.png`, fullPage: true });
    console.log('shot', v);
  }
  await browser.close();
})();
