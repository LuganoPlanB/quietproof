import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdir, readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { createHash } from 'node:crypto';
import { chromium, webkit } from 'playwright';
import { fixtures, outputFixture } from '../../web/features/provider/fixtures.mjs';

const origin = process.env.QUIETPROOF_SITE_ORIGIN;
const root = process.env.QUIETPROOF_ARTIFACT_DIR;
assert(origin && root, 'Static artifact directory and preview origin required');
const manifest = JSON.parse(await readFile(resolve(root, 'asset-manifest.json')));
const wasmName = Object.keys(manifest).find(name => /^assets\/quietproof\.[a-f0-9]{64}\.wasm$/.test(name));
assert(wasmName, 'SHA256-named reactor required');
const wasm = await readFile(resolve(root, wasmName));
assert.equal(createHash('sha256').update(wasm).digest('hex'), manifest[wasmName]);

async function openDocumentation(page, url) {
  // Layout needs rendered content and fonts, not completion of every image.
  await page.goto(url, { waitUntil: 'domcontentloaded' });
  await page.locator('.vp-doc h1').waitFor();
  // WebKit can defer fonts.ready until window.load even when status is loaded.
  await page.waitForFunction(() => document.fonts.status === 'loaded');
}

async function withHostingPage(name, engine, artifact, check) {
  const browser = await engine.launch({ headless: true,
    ...(name === 'webkit' && process.env.QUIETPROOF_WEBKIT_EXECUTABLE ? { executablePath: process.env.QUIETPROOF_WEBKIT_EXECUTABLE } : {}) });
  let page;
  const pending = new Set();
  try {
    page = await browser.newPage();
    page.on('request', request => pending.add(request));
    page.on('requestfinished', request => pending.delete(request));
    page.on('requestfailed', request => pending.delete(request));
    if (process.env.QUIETPROOF_HOSTING_ARTIFACTS)
      await page.context().tracing.start({ screenshots: true, snapshots: true, sources: true });
    await check(page);
  } catch (error) {
    console.error(JSON.stringify({ engine: name, url: page?.url(), pendingRequests: [...pending].map(request => request.url()) }));
    if (page && process.env.QUIETPROOF_HOSTING_ARTIFACTS) {
      await mkdir(process.env.QUIETPROOF_HOSTING_ARTIFACTS, { recursive: true });
      await page.context().tracing.stop({ path: resolve(process.env.QUIETPROOF_HOSTING_ARTIFACTS, `${name}-${artifact}.zip`) });
    }
    throw error;
  } finally { await browser.close(); }
}

for (const [name, engine] of [['chromium', chromium], ['webkit', webkit]]) {
  test(`${name}: documentation readiness does not depend on an unfinished image`, { timeout: 120000 }, async () => {
    const browser = await engine.launch({ headless: true,
      ...(name === 'webkit' && process.env.QUIETPROOF_WEBKIT_EXECUTABLE ? { executablePath: process.env.QUIETPROOF_WEBKIT_EXECUTABLE } : {}) });
    let releaseImage;
    const imageReleased = new Promise(resolve => { releaseImage = resolve; });
    try {
      const page = await browser.newPage();
      page.setDefaultNavigationTimeout(10000);
      let loaded = false;
      page.on('load', () => { loaded = true; });
      await page.route(origin + '/readiness-probe.svg', async route => {
        await imageReleased;
        await route.fulfill({ contentType: 'image/svg+xml',
          body: '<svg xmlns="http://www.w3.org/2000/svg" width="1" height="1"/>' });
      });
      await page.route(origin + '/wasm-build', async route => {
        const response = await route.fetch();
        const body = (await response.text()).replace('</body>',
          `<img src="${origin}/readiness-probe.svg" alt="" width="1" height="1"></body>`);
        await route.fulfill({ response, body });
      });
      await openDocumentation(page, origin + '/wasm-build');
      assert.equal(await page.locator('.vp-doc h1').isVisible(), true);
      assert.equal(await page.evaluate(() => document.fonts.status), 'loaded');
      assert.equal(loaded, false, 'readiness must be reached while the image still blocks load');
      releaseImage();
      await page.waitForLoadState('load');
      assert.equal(loaded, true);
    } finally {
      releaseImage();
      await browser.close();
    }
  });

  test(`${name}: packaged base, local search, MIME fallback and stale reactor refusal`, { timeout: 120000 }, async () => {
    await withHostingPage(name, engine, 'tool', async page => {
      const errors = []; page.on('pageerror', error => errors.push(error.message));
      let mode = 'generic';
      await page.route('**/' + wasmName, route => route.fulfill({ contentType: 'application/octet-stream',
        body: mode === 'stale' ? Buffer.from([0, 97, 115, 109, 1, 0, 0, 0]) : wasm }));
      await page.route('https://blockstream.info/**', route => {
        const fixture = outputFixture(), url = route.request().url();
        return url.endsWith('/block-height/0') ? route.fulfill({ body: fixtures.mainnet.genesis })
          : route.fulfill({ json: url.endsWith('/utxo') ? fixture.utxos : fixture.tx });
      });
      await page.goto(origin + '/tool', { waitUntil: 'domcontentloaded' });
      await page.getByRole('button', { name: 'Look up outputs', exact: true }).waitFor();
      await page.getByLabel('Bitcoin addresses').fill(fixtures.mainnet.p2wpkh);
      await page.getByRole('button', { name: 'Look up outputs', exact: true }).click();
      await page.locator('.quietproof-claims').getByRole('checkbox').check();
      await page.getByLabel('Intended verifier').fill('Static artifact qualification');
      await page.getByRole('button', { name: 'Create request', exact: true }).click();
      await page.getByRole('region', { name: 'Canonical request preview' }).waitFor();
      mode = 'stale';
      await page.getByRole('button', { name: 'Regenerate request', exact: true }).click();
      await page.getByRole('alert').waitFor();
      assert.match(await page.getByRole('alert').innerText(), /version mismatch/);
      assert.equal(await page.getByRole('link', { name: 'Download .qpr request', exact: true }).count(), 0);
      const response = await page.request.get(origin + '/' + wasmName);
      assert.equal(response.status(), 200);
      assert.match(response.headers()['content-type'], /application\/wasm/);
      for (const path of ['SOURCE-NOTICE.txt', 'build-provenance.json', 'sources/quietproof.tar.gz',
                          'sources/longfellow-zk.tar.gz', 'licenses/quietproof-GPL-3.0.txt']) {
        assert.equal((await page.request.get(origin + '/' + path)).status(), 200, path);
      }
      const search = page.getByRole('button', { name: /Search/ }).first();
      await search.click();
      await page.locator('#localsearch-input').fill('verifier');
      await page.locator('.VPLocalSearchBox a[href]').first().waitFor();
      assert.deepEqual(errors, []);
    });
  });

  for (const path of ['/guide/browser-tool', '/wasm-build']) {
    test(`${name}: ${path} layout at mobile/desktop and 100%/200% text`, { timeout: 120000 }, async () => {
      await withHostingPage(name, engine, path.replaceAll('/', '_'), async page => {
        const errors = []; page.on('pageerror', error => errors.push(error.message));
        await openDocumentation(page, origin + path);
        const textSize = await page.addStyleTag({ content: '/* text-size probe */' });
        // Reuse the loaded document: changing viewport or text size requires no
        // navigation, and layout checks need no WASM/provider request mocks.
        for (const width of [390, 1440]) for (const scale of [1, 2]) {
          await page.setViewportSize({ width, height: width === 390 ? 844 : 900 });
          await textSize.evaluate((style, pixels) => {
            style.textContent = `html, .vp-doc { font-size: ${pixels}px !important; }`;
          }, 16 * scale);
          const layout = await page.locator('.vp-doc').evaluate(doc => {
            const selectors = 'p, li, th, td, h2, h3, pre code';
            return {
              fontSize: getComputedStyle(doc).fontSize,
              overflow: document.documentElement.scrollWidth > innerWidth,
              cramped: [...doc.querySelectorAll(selectors)].filter(element => {
                const style = getComputedStyle(element);
                return parseFloat(style.lineHeight) < parseFloat(style.fontSize) * 1.2;
              }).map(element => ({ tag: element.tagName, text: element.textContent.slice(0, 80) })),
            };
          });
          assert.equal(layout.fontSize, `${16 * scale}px`, `${path} text scaling applied`);
          assert.equal(layout.overflow, false, `${path} at ${width}px/${scale * 100}%`);
          assert.deepEqual(layout.cramped, [], `${path} line spacing at ${width}px/${scale * 100}%`);
        }
        assert.deepEqual(errors, []);
      });
    });
  }
}
