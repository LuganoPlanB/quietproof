import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile, mkdir, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { resolve } from 'node:path';
import { chromium, webkit } from 'playwright';
import { decodeInspection } from '../../wasm/codec.mjs';

const origin = process.env.QUIETPROOF_SITE_ORIGIN || 'http://127.0.0.1:4175';
const fixtures = process.env.QUIETPROOF_VERIFY_FIXTURES;
assert(fixtures, 'Set QUIETPROOF_VERIFY_FIXTURES to current native public feasibility fixtures.');
const proof = await readFile(resolve(fixtures, 'one-key.qpf'));
const request = await readFile(resolve(fixtures, 'one-key.qpr'));
const provenance = JSON.parse(await readFile(resolve(fixtures, 'one-key.json')));
assert.equal(provenance.nativeVerified, true);
assert(provenance.expiresAt > Math.floor(Date.now() / 1000) + 1800, 'Real fixture needs at least 30 minutes validity.');
const encoded = new Uint8Array(61 + request.length); encoded.set(new TextEncoder().encode('QWI1')); encoded.set(request, 61);
const metadata = decodeInspection(encoded.buffer), claim = metadata.claims[0];
assert.equal(metadata.network, 'mainnet'); assert.equal(metadata.claims.length, 1);
const invalid = Buffer.from(proof); invalid[invalid.length - 1] ^= 1;
const wrongRequest = await readFile(new URL('../../../tests/wasm/fixtures/0.qpr', import.meta.url));
const upload = (name, buffer) => ({ name, buffer, mimeType: 'application/octet-stream' });
const hash = bytes => createHash('sha256').update(bytes).digest('hex');

for (const [name, engine] of [['chromium', chromium], ['webkit', webkit]]) {
  test(`${name}: real proof results, offline/provider boundaries, expiry and operation invalidation`, { timeout: 900000 }, async () => {
    const browser = await engine.launch({ headless: true,
      ...(name === 'webkit' && process.env.QUIETPROOF_WEBKIT_EXECUTABLE ? { executablePath: process.env.QUIETPROOF_WEBKIT_EXECUTABLE } : {}) });
    console.log(JSON.stringify({ engine: name, version: browser.version(), proofSha256: hash(proof), requestSha256: hash(request), expiresAt: provenance.expiresAt }));
    let page, releaseFetch;
    try {
      page = await browser.newPage({ viewport: { width: 1440, height: 900 } });
      await page.emulateMedia({ reducedMotion: 'reduce' });
      const pageErrors = [];
      page.on('pageerror', error => { pageErrors.push(error.message); console.log('page-error: ' + error.message); });
      const requests = []; let providerMode = 'unspent', holdFetch = false, expireWorker = false;
      await page.addInitScript(() => {
        const NativeWorker = window.Worker;
        window.__qpWorkers = { created: 0, terminated: 0, sent: [], holdVerify: false, held: [] };
        window.Worker = class extends NativeWorker {
          constructor(...args) {
            super(...args); window.__qpWorkers.created++;
            const send = super.postMessage.bind(this);
            this.postMessage = (data, transfer) => {
              window.__qpWorkers.sent.push(data.type);
              if (data.type === 'verify' && window.__qpWorkers.holdVerify) {
                window.__qpWorkers.held.push({ worker: this, send: () => send(data, transfer) });
              } else send(data, transfer);
            };
          }
          terminate() {
            if (!this.closed) { this.closed = true; window.__qpWorkers.terminated++; }
            window.__qpWorkers.held = window.__qpWorkers.held.filter(entry => entry.worker !== this);
            super.terminate();
          }
        };
      });
      // Test-only worker clock injection. The actual verifier runs between its
      // two wall-clock checks; expiry on the second check must prevent fetching.
      await page.route(/\/assets\/worker-[^/]+\.js$/, async route => {
        if (!expireWorker) return route.continue();
        const response = await route.fetch();
        const prefix = `self.addEventListener('message', ({data}) => {
          if (data.type === 'prepare') Date.now = () => ${(provenance.expiresAt - 1) * 1000};
          if (data.type === 'verify') { let calls = 0; Date.now = () => (++calls === 1 ? ${(provenance.expiresAt - 1) * 1000} : ${provenance.expiresAt * 1000}); }
        });\n`;
        await route.fulfill({ response, body: prefix + await response.text() });
      });
      const tip = '56'.repeat(32), funding = '34'.repeat(32);
      const fundingStatus = { confirmed: true, block_height: 100, block_hash: funding, block_time: 1600000000 };
      const outputs = Array.from({ length: claim.vout + 1 }, () => ({ value: 1, scriptpubkey: '51' }));
      outputs[claim.vout] = { value: Number(claim.amountSats), scriptpubkey: '0014' + claim.program };
      await page.route('https://blockstream.info/**', async route => {
        const request = route.request();
        requests.push({ url: request.url(), method: request.method(), body: request.postData() });
        if (holdFetch) { holdFetch = false; await new Promise(r => { releaseFetch = r; }); }
        if (providerMode === 'outage') return route.abort('failed');
        const url = request.url(); let body;
        if (url.endsWith('/block-height/0')) body = '000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f';
        else if (url.endsWith('/blocks/tip/hash')) body = tip;
        else if (url.endsWith('/block-height/100')) body = funding;
        else if (url.endsWith(`/tx/${claim.txid}`)) body = JSON.stringify({ txid: claim.txid, vout: outputs, status: fundingStatus });
        else if (url.endsWith(`/tx/${claim.txid}/status`)) body = JSON.stringify(fundingStatus);
        else if (url.includes('/outspend/')) body = JSON.stringify(providerMode === 'spent' ? { spent: true, txid: '78'.repeat(32), vin: 0, status: { confirmed: false } } : { spent: false });
        else if (url.endsWith('/status')) body = JSON.stringify({ in_best_chain: providerMode !== 'reorg' });
        else body = JSON.stringify({ id: tip, height: 110 });
        await route.fulfill({ body, headers: { 'access-control-allow-origin': '*', 'content-type': 'application/json' } });
      });
      await page.goto(origin + '/verify');
      await page.getByRole('button', { name: 'Verify offline', exact: true }).waitFor();
      await page.waitForFunction(() => !document.querySelector('.quietproof-verify button[type=submit]').disabled);
      const proofInput = page.getByLabel('Proof file (.qpf)', { exact: true });
      const policyInput = page.getByLabel('Expected policy source');
      const selectedNetwork = page.getByLabel('Verification network (chosen independently)');
      const online = page.getByRole('checkbox', { name: 'After valid cryptography', exact: false });
      const crypto = page.locator('[data-result=crypto]'), policy = page.locator('[data-result=policy]'), explorer = page.locator('[data-result=explorer]');
      async function capture(state) {
        for (const [width, height] of [[390, 844], [1440, 900]]) for (const scale of [100, 200]) {
          await page.setViewportSize({ width, height });
          await page.evaluate(scale => {
            let style = document.querySelector('#qp-test-scale');
            if (!style) { style = document.createElement('style'); style.id = 'qp-test-scale'; document.head.append(style); }
            style.textContent = `html, .quietproof-verify { font-size: ${16 * scale / 100}px !important; line-height: 1.6; }`;
            scrollTo(0, 0);
          }, scale);
          await page.waitForTimeout(350);
          assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false, `${state}: no horizontal overflow`);
          if (process.env.QUIETPROOF_VERIFY_SCREENSHOTS) {
            await mkdir(process.env.QUIETPROOF_VERIFY_SCREENSHOTS, { recursive: true });
            await page.screenshot({ path: resolve(process.env.QUIETPROOF_VERIFY_SCREENSHOTS, `${name}-${width}-${scale}-results-${state}.png`), fullPage: true, animations: 'disabled' });
          }
        }
        await page.setViewportSize({ width: 1440, height: 900 });
        await page.evaluate(() => document.querySelector('#qp-test-scale')?.remove());
      }
      async function awaitText(locator, text) { await locator.filter({ hasText: text }).waitFor({ timeout: 180000 }); }
      async function begin() {
        await page.getByRole('button', { name: await online.isChecked() ? 'Verify and check explorer' : 'Verify offline', exact: true }).click();
      }
      async function computationStarted() {
        await page.getByText(/Checking proof cryptography…/).waitFor({ timeout: 30000 });
        await page.waitForTimeout(100);
      }
      await proofInput.setInputFiles(upload('native-public.qpf', proof));
      await selectedNetwork.selectOption('mainnet'); await begin();
      await page.getByRole('region', { name: 'Verification results' }).waitFor();
      console.log('initial-verification-result: ' + (await page.getByRole('region', { name: 'Verification results' }).innerText()).slice(0, 1800));
      await page.getByText('Select an independent expected policy before verification.', { exact: true }).waitFor();
      assert.equal(requests.length, 0);
      await policyInput.selectOption('request');
      const expected = page.getByLabel('Expected request file (.qpr)', { exact: true });
      await expected.setInputFiles(upload('expected.qpr', request));
      await page.evaluate(() => { window.__qpWorkers.holdVerify = true; });
      await begin(); await page.waitForFunction(() => window.__qpWorkers.held.length === 1);
      await capture('verifying');
      await page.evaluate(() => {
        window.__qpWorkers.holdVerify = false;
        for (const entry of window.__qpWorkers.held.splice(0)) entry.send();
      });
      await awaitText(crypto, /^Valid$/); await awaitText(policy, 'Matched at check time'); await awaitText(explorer, 'Unavailable');
      assert.equal(requests.length, 0); await capture('offline');
      await online.check();
      await proofInput.setInputFiles(upload('corrupted.qpf', invalid)); await begin();
      await awaitText(crypto, 'Invalid — do not accept'); assert.equal(requests.length, 0); await capture('invalid');
      await proofInput.setInputFiles(upload('native-public.qpf', proof));
      await expected.setInputFiles(upload('wrong.qpr', wrongRequest)); await begin();
      await awaitText(policy, 'Rejected — do not accept'); assert.equal(requests.length, 0); await capture('policy-rejected');
      await expected.setInputFiles(upload('expected.qpr', request)); await online.check();
      assert.equal(requests.length, 0, 'choosing online access does not fetch');
      holdFetch = true; releaseFetch = undefined; await begin();
      await page.getByText(/Fetching fresh explorer observations…/).waitFor({ timeout: 180000 });
      for (let attempt = 0; !releaseFetch && attempt < 500; attempt++) await new Promise(r => setTimeout(r, 10));
      assert(releaseFetch, 'provider request reached the owned loading gate');
      await capture('fetching'); releaseFetch(); releaseFetch = undefined;
      await awaitText(explorer, 'Reported unspent under selected limits'); await capture('unspent');
      assert.match(await page.getByRole('region', { name: 'Verification results' }).innerText(), /50000 sats/);
      for (const [mode, status, state] of [['spent','Reported spent','spent'],['reorg','Inconclusive','inconclusive'],['outage','Unavailable','unavailable']]) {
        providerMode = mode; await page.getByRole('button', { name: 'Retry verification', exact: true }).click();
        await awaitText(explorer, status); await awaitText(crypto, /^Valid$/); await capture(state);
      }
      const beforeExpiry = requests.length; expireWorker = true;
      await page.getByRole('button', { name: 'Retry verification', exact: true }).click();
      await awaitText(policy, 'Rejected — do not accept'); assert.equal(requests.length, beforeExpiry, 'expiry after real crypto prevents explorer fetch');
      await capture('expired'); expireWorker = false;
      providerMode = 'unspent';
      await begin(); await computationStarted();
      await page.getByRole('button', { name: 'Cancel verification', exact: true }).focus(); await page.keyboard.press('Enter');
      await page.getByText('Import cancelled. No result retained.', { exact: true }).waitFor();
      assert.equal(await page.getByRole('region', { name: 'Verification results' }).count(), 0); await capture('cancelled');
      await begin(); await computationStarted(); await selectedNetwork.selectOption('signet');
      assert.equal(await page.getByRole('region', { name: 'Verification results' }).count(), 0);
      assert.equal(requests.length, beforeExpiry, 'network change disposes old worker before explorer access');
      await selectedNetwork.selectOption('mainnet'); await begin(); await computationStarted(); await online.uncheck();
      assert.equal(requests.length, beforeExpiry, 'provider selection change invalidates the operation');
      await begin(); await awaitText(crypto, /^Valid$/); await awaitText(explorer, 'Unavailable');
      assert.equal(requests.length, beforeExpiry, 'offline recovery stays disconnected');
      assert(requests.every(r => r.method === 'GET' && r.body === null && r.url.startsWith('https://blockstream.info/api/')));
      const workers = await page.evaluate(() => ({ created: window.__qpWorkers.created, terminated: window.__qpWorkers.terminated, held: window.__qpWorkers.held.length }));
      assert.equal(workers.created, workers.terminated); assert.equal(workers.held, 0);
      assert.deepEqual(pageErrors, []);
      console.log(JSON.stringify({ engine: name, fixtureRequests: requests.length, workers, screenshotStates: 11, combinationsPerState: 4, cleanup: 'all gates released; all owned workers terminated' }));
    } catch (error) {
      if (page && process.env.QUIETPROOF_VERIFY_SCREENSHOTS) {
        await mkdir(process.env.QUIETPROOF_VERIFY_SCREENSHOTS, { recursive: true });
        await writeFile(resolve(process.env.QUIETPROOF_VERIFY_SCREENSHOTS, `${name}-results-failure.txt`), await page.locator('body').innerText().catch(() => 'Page unavailable'));
        await page.screenshot({ path: resolve(process.env.QUIETPROOF_VERIFY_SCREENSHOTS, `${name}-results-failure.png`), fullPage: true }).catch(() => {});
      }
      throw error;
    } finally {
      releaseFetch?.();
      await page?.evaluate(() => { window.__qpWorkers.holdVerify = false; for (const entry of window.__qpWorkers.held.splice(0)) entry.send(); }).catch(() => {});
      await page?.close().catch(() => {}); await browser.close();
    }
  });
}
