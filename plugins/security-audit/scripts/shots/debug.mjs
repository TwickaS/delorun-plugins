import { chromium } from 'file:///home/vadim/delorun/code/node_modules/.pnpm/playwright@1.61.1/node_modules/playwright/index.mjs'
const HERE = new URL('./', import.meta.url).pathname
const browser = await chromium.launch()
const page = await browser.newPage({ viewport: { width: 900, height: 800 } })
page.on('console', m => console.log('CONSOLE', m.type(), m.text()))
page.on('pageerror', e => console.log('PAGEERROR', e.message))
await page.goto('file://' + HERE + 'pane.html')
await page.waitForTimeout(1200)
console.log((await page.content()).slice(0, 800))
await browser.close()
