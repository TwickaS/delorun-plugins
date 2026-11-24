import { chromium } from 'file:///home/vadim/delorun/code/node_modules/.pnpm/playwright@1.61.1/node_modules/playwright/index.mjs'
const browser = await chromium.launch()
const page = await browser.newPage({ viewport: { width: 390, height: 844 } })
await page.goto('http://127.0.0.1:18311/pane.html?mode=live')
await page.waitForSelector('.sa-pane')
await page.waitForTimeout(400)
const out = await page.evaluate(() => [...document.querySelectorAll('.sa-pane *')]
  .filter(el => el.scrollWidth > el.clientWidth + 1)
  .map(el => ({ cls: String(el.className), tag: el.tagName, scroll: el.scrollWidth, client: el.clientWidth, text: (el.textContent ?? '').slice(0, 40) }))
  .slice(0, 10))
console.log(JSON.stringify(out, null, 1))
await browser.close()
