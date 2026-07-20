const { chromium } = require("playwright");
const fs = require("fs");

(async () => {
  const out = "C:/Users/ADMIN/Downloads/aes/web/_verify";
  fs.mkdirSync(out, { recursive: true });
  const browser = await chromium.launch();
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 1000 } });
  const page = await ctx.newPage();
  const errors = [];
  page.on("pageerror", (e) => errors.push("PAGEERROR " + e.message));
  page.on("console", (m) => {
    if (m.type() === "error") errors.push("CONSOLE " + m.text());
  });

  const shots = [
    ["/", "home"],
    ["/device/esp32-cam-02", "device-cam-attack"],
    ["/device/tapo-c200-01", "device-tapo"],
    ["/learning", "learning"],
  ];

  for (const [path, name] of shots) {
    errors.length = 0;
    await page
      .goto("http://localhost:3000" + path, { waitUntil: "networkidle", timeout: 60000 })
      .catch((e) => errors.push("NAV " + e.message));
    await page.waitForTimeout(2000);
    await page.screenshot({ path: out + "/" + name + ".png", fullPage: true });
    const real = errors.filter((e) => !/favicon|the width\(0\)|height\(0\)|ResizeObserver/.test(e));
    console.log("=== " + path + " ===");
    console.log(real.length ? real.join("\n") : "OK — no console/page errors");
  }
  await browser.close();
})().catch((e) => {
  console.error("CAPTURE FAILED:", e.message);
  process.exit(1);
});
