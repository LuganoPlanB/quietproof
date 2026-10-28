import { test } from 'node:test';
import assert from 'node:assert/strict';
import { chromium, webkit } from 'playwright';
import { mkdir } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fixtures, outputFixture } from './features/provider/fixtures.mjs';

const origin = process.env.QUIETPROOF_SITE_ORIGIN || 'http://127.0.0.1:4176';
const base = process.env.QUIETPROOF_SECURITY_BASE || '';
const evidence = process.env.QUIETPROOF_SECURITY_SCREENSHOTS;
const attack = '<img src="https://evil.invalid/x" onerror="window.__xss=1">';

for (const [name, engine] of [['chromium', chromium], ['webkit', webkit]]) {
  test(`${name}: static CSP, text rendering, bounded corrupt assets and outbound policy`, { timeout: 120000 }, async () => {
    const browser = await engine.launch({ headless: true,
      ...(name === 'webkit' && process.env.QUIETPROOF_WEBKIT_EXECUTABLE ? { executablePath: process.env.QUIETPROOF_WEBKIT_EXECUTABLE } : {}) });
    console.log(`${name} ${browser.version()}; base=${base || '/'}`);
    try {
      const page = await browser.newPage();
      const requests = [], violations = [], errors = [], blocked = new Set();
      let forbiddenDispatches = 0;
      await page.exposeFunction('recordCsp', value => violations.push(value));
      await page.addInitScript(() => {
        window.__xss = 0;
        document.addEventListener('securitypolicyviolation', event =>
          window.recordCsp({ directive: event.effectiveDirective, blocked: event.blockedURI }));
      });
      page.on('request', request => requests.push({ url: request.url(), method: request.method(), body: request.postData() }));
      page.on('requestfailed', request => {
        if (/CSP|Content Security Policy/i.test(request.failure()?.errorText ?? '')) blocked.add(request.url());
      });
      page.on('pageerror', error => errors.push(error.message));
      await page.route('https://evil.invalid/**', route => { forbiddenDispatches++; return route.abort(); });
      let providerMode = 'valid', assetMode = 'valid';
      await page.route('https://blockstream.info/**', route => {
        assert.equal(route.request().method(), 'GET'); assert.equal(route.request().postData(), null);
        if (providerMode === 'error') return route.fulfill({ status: 429, body: attack, contentType: 'text/html' });
        if (providerMode === 'malformed') return route.fulfill({ json: [{ txid: attack, vout: 0, value: 1, status: { confirmed: false } }] });
        const fixture = outputFixture(), url = route.request().url();
        return url.endsWith('/block-height/0') ? route.fulfill({ body: fixtures.mainnet.genesis })
          : route.fulfill({ json: url.endsWith('/utxo') ? fixture.utxos : fixture.tx });
      });
      await page.route(/\/(?:wasm\/quietproof|assets\/quietproof\.[a-f0-9]{64})\.wasm$/, route => assetMode === 'missing'
        ? route.fulfill({ status: 404, body: 'missing' }) : assetMode === 'corrupt'
          ? route.fulfill({ body: Buffer.from([0, 1, 2, 3]), contentType: 'application/wasm' }) : route.continue());
      await page.goto(origin + base + '/tool');
      const lookup = page.getByRole('button', { name: 'Look up outputs', exact: true });
      await lookup.waitFor();
      assert.equal(requests.filter(r => r.url.startsWith('https://')).length, 0, 'no remote access before action');
      assert.equal(requests.filter(r => r.url.endsWith('.wasm')).length, 0);
      const csp = await page.locator('meta[http-equiv="Content-Security-Policy"]').getAttribute('content');
      assert.match(csp, /script-src 'self' 'wasm-unsafe-eval' 'sha256-/);
      assert(!csp.includes("'unsafe-eval'"));
      assert.match(csp, /worker-src 'self'/);
      const manifest = await (await page.request.get(origin + base + '/asset-manifest.json')).json();
      const wasmPath = Object.keys(manifest).find(path => /^assets\/quietproof\.[a-f0-9]{64}\.wasm$/.test(path));
      assert(wasmPath, 'one SHA256-named reactor is packaged');
      const wasmResponse = await page.request.get(origin + base + '/' + wasmPath);
      assert.equal(wasmResponse.status(), 200); assert.match(wasmResponse.headers()['content-type'], /application\/wasm/);
      await page.getByLabel('Bitcoin addresses').fill(fixtures.mainnet.p2wpkh);
      await lookup.click(); await page.locator('.quietproof-claims').getByRole('checkbox').check();
      await page.getByLabel('Intended verifier').fill(attack);
      await page.getByLabel('Message (optional').fill(attack);
      const create = page.getByRole('button', { name: 'Create request', exact: true });
      await create.click();
      const preview = page.getByRole('region', { name: 'Canonical request preview' });
      await preview.waitFor();
      assert((await preview.innerText()).includes(attack));
      assert.equal(await preview.locator('img,script,iframe').count(), 0);
      assert.equal(await page.evaluate(() => window.__xss), 0);
      assert.deepEqual(violations, [], 'legitimate request/worker path runs under CSP');
      assert.deepEqual(errors, []);
      if (evidence) {
        await mkdir(evidence, { recursive: true });
        await page.screenshot({ path: resolve(evidence, `${name}-${base ? 'subpath' : 'root'}-escaped.png`), fullPage: true });
      }
      // Actual DOM-inserted executable content is blocked by CSP, independently
      // of Vue's escaping. Playwright evaluation itself is a trusted test seam.
      await page.evaluate(() => {
        const script = document.createElement('script'); script.textContent = 'window.__xss=2'; document.head.append(script);
        const remote = document.createElement('script'); remote.src = 'https://evil.invalid/x.js'; document.head.append(remote);
      });
      await page.waitForFunction(() => window.__xss === 0);
      await new Promise(r => setTimeout(r, 100));
      assert(violations.some(v => v.directive === 'script-src-elem' || v.directive === 'script-src'));
      assert.equal(await page.evaluate(() => window.__xss), 0);
      for (const mode of ['missing', 'corrupt']) {
        assetMode = mode;
        await page.getByRole('button', { name: 'Regenerate request', exact: true }).click();
        await page.getByRole('alert').waitFor();
        assert.equal(await page.getByRole('link', { name: 'Download .qpr request', exact: true }).count(), 0);
        // Preview has been invalidated; the retry action has its initial label.
        if (mode === 'missing') { assetMode = 'valid'; await create.click(); await preview.waitFor(); }
      }
      assetMode = 'valid';
      for (const mode of ['error', 'malformed']) {
        providerMode = mode; await lookup.click(); await page.getByRole('alert').waitFor();
        assert(!(await page.getByRole('alert').innerText()).includes(attack));
        assert.equal(await page.locator('.quietproof-claims input').count(), 0);
      }
      await page.goto(origin + base + '/verify');
      const before = requests.filter(r => r.url.startsWith('https://blockstream.info/')).length;
      await page.getByLabel('Proof file (.qpf)', { exact: true }).setInputFiles({ name: `${attack}.qpf`, mimeType: 'application/octet-stream', buffer: Buffer.from([1, 2, 3]) });
      await page.getByRole('button', { name: 'Inspect proof and policy', exact: true }).click();
      await page.getByRole('alert').filter({ hasText: 'Cannot decode' }).waitFor();
      assert.equal(requests.filter(r => r.url.startsWith('https://blockstream.info/')).length, before, 'invalid proof causes no explorer access');
      assert.equal(await page.evaluate(() => window.__xss), 0);
      for (const request of requests) {
        if (blocked.has(request.url)) continue; // Chromium emits request events for CSP-blocked attempts.
        assert.equal(request.method, 'GET'); assert.equal(request.body, null);
        assert(request.url.startsWith(origin + '/') || /^https:\/\/blockstream\.info\/(api|signet\/api)\//.test(request.url), request.url);
        assert(!request.url.includes('evil.invalid'));
      }
      assert.equal(forbiddenDispatches, 0, 'CSP prevents the injected external script from reaching transport');
      await page.close();
    } finally { await browser.close(); }
  });
}
