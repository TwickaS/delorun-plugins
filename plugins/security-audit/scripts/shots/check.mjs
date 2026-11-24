import { chromium } from 'file:///home/vadim/delorun/code/node_modules/.pnpm/playwright@1.61.1/node_modules/playwright/index.mjs'
const BASE = 'http://127.0.0.1:18311/pane.html'
const browser = await chromium.launch()
for (const width of [390, 1440]) {
  for (const mode of ['live', 'report']) {
    const page = await browser.newPage({ viewport: { width, height: width === 390 ? 844 : 900 } })
    page.on('pageerror', e => console.log('PAGEERROR', e.message))
    await page.goto(BASE + '?mode=' + mode)
    await page.waitForSelector('.sa-pane')
    await page.waitForTimeout(300)
    const report = await page.evaluate(() => {
      const body = document.querySelector('.sa-pane-body')
      const pane = document.querySelector('.sa-pane')
      const widest = [...document.querySelectorAll('.sa-pane-body *')].reduce((max, el) => Math.max(max, el.getBoundingClientRect().right), 0)
      return {
        mode: pane?.getAttribute('data-audit-mode'),
        scrollX: document.documentElement.scrollWidth - document.documentElement.clientWidth,
        bodyScrollX: body === null ? -1 : body.scrollWidth - body.clientWidth,
        widestRight: Math.round(widest),
        paneRight: Math.round(pane?.getBoundingClientRect().right ?? 0),
        contentHeight: Math.round(body?.scrollHeight ?? 0),
        findings: document.querySelectorAll('.sa-finding-card').length,
        rows: document.querySelectorAll('.sa-table-row').length,
        traces: document.querySelectorAll('.sa-trace').length,
        denial: document.querySelectorAll('.sa-denial').length,
        badges: document.querySelectorAll('.sa-badge').length,
        map: document.querySelectorAll('.sa-map').length,
        barWidth: Math.round(document.querySelector('.sa-bar')?.getBoundingClientRect().width ?? 0),
        text: (document.querySelector('.sa-pane')?.innerText ?? '').slice(0, 1400),
      }
    })
    console.log('=====', mode, width, JSON.stringify(report, null, 1))
    await page.close()
  }
}
await browser.close()
