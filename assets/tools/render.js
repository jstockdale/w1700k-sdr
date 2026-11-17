// Render the SVGs to PNG at the sizes GitHub, Discord and browsers want.
const { chromium } = require('playwright');
const fs = require('fs');
const path = require('path');

const A = path.resolve(process.argv[2] || 'assets');
const PNG = path.join(A, 'png');
fs.mkdirSync(PNG, { recursive: true });

const jobs = [
  // [svg, out, width, height]  (square marks at the sizes platforms ask for)
  ['mark.svg', 'mark-1024.png', 1024, 1024],
  ['mark.svg', 'mark-512.png', 512, 512],
  ['mark.svg', 'mark-256.png', 256, 256],
  ['mark.svg', 'mark-128.png', 128, 128],
  ['mark-transparent.svg', 'mark-transparent-1024.png', 1024, 1024],
  ['mark-on-light.svg', 'mark-on-light-1024.png', 1024, 1024],
  ['favicon.svg', 'favicon-64.png', 64, 64],
  ['favicon.svg', 'favicon-32.png', 32, 32],
  ['favicon.svg', 'favicon-16.png', 16, 16],
  ['lockup-dark.svg', 'lockup-dark.png', 1552, 560],
  ['lockup-dark.svg', 'lockup-dark@2x.png', 3104, 1120],
  ['lockup-light.svg', 'lockup-light.png', 1552, 560],
  ['lockup-light.svg', 'lockup-light@2x.png', 3104, 1120],
  ['social-preview.svg', 'social-preview-1280x640.png', 1280, 640],
];

(async () => {
  const browser = await chromium.launch();
  for (const [svg, out, w, h] of jobs) {
    const page = await browser.newPage({ viewport: { width: w, height: h }, deviceScaleFactor: 1 });
    const data = fs.readFileSync(path.join(A, svg), 'utf8');
    const transparent = /transparent|mono/.test(svg);
    await page.setContent(
      `<html><body style="margin:0;background:${transparent ? 'transparent' : 'none'}">` +
      `<img src="data:image/svg+xml;base64,${Buffer.from(data).toString('base64')}" style="display:block;width:${w}px;height:${h}px"></body></html>`
    );
    await page.screenshot({ path: path.join(PNG, out), omitBackground: true, clip: { x: 0, y: 0, width: w, height: h } });
    await page.close();
    console.log(`  png/${out}  ${w}x${h}`);
  }
  await browser.close();
})();
