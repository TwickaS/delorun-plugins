/**
 * Take the pane pictures: Live and Report, at 390 and 1440 px, from the harness
 * page over a local static server. Writes into release/shots/security-audit-reader/.
 */
import { chromium } from 'file:///home/vadim/delorun/code/node_modules/.pnpm/playwright@1.61.1/node_modules/playwright/index.mjs'

const OUT = '/home/vadim/delorun/release/shots/security-audit-reader'
const BASE = 'http://127.0.0.1:18311/pane.html'

const browser = await chromium.launch()
for (const width of [390, 1440]) {
  for (const mode of ['live', 'report']) {
    const page = await browser.newPage({ viewport: { width, height: width === 390 ? 844 : 900 }, deviceScaleFactor: 2 })
    page.on('pageerror', error => console.log('PAGEERROR', error.message))
    await page.goto(BASE + '?mode=' + mode)
    await page.waitForSelector('.sa-pane')
    await page.waitForTimeout(350)
    await page.screenshot({ path: OUT + '/' + mode + '-' + width + '.png', fullPage: false })
    await page.close()
    console.log(mode + '-' + width + '.png')
  }
}
await browser.close()
