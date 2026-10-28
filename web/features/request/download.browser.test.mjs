import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { execFileSync } from 'node:child_process';
import { chromium, webkit } from 'playwright';
import { fixtures, outputFixture } from '../provider/fixtures.mjs';

const origin = process.env.QUIETPROOF_SITE_ORIGIN || 'http://127.0.0.1:4174';
const evidence = process.env.QUIETPROOF_REQUEST_SCREENSHOTS;
const cli = process.env.QUIETPROOF_NATIVE_CLI;

for (const [name, engine] of [['chromium', chromium], ['webkit', webkit]]) {
  test(`${name}: real WASM preview/download/native inspection, invalidation, failure and cancellation`, { timeout: 180000 }, async () => {
    assert(cli, 'Set QUIETPROOF_NATIVE_CLI to the current native parser.');
    const browser = await engine.launch({ headless: true,
      ...(name === 'webkit' && process.env.QUIETPROOF_WEBKIT_EXECUTABLE ? { executablePath: process.env.QUIETPROOF_WEBKIT_EXECUTABLE } : {}) });
    console.log(`${name} ${browser.version()}`);
    try {
      for (const [width, height] of [[390, 844], [1440, 900]]) for (const scale of [100, 200]) {
        const page = await browser.newPage({ viewport: { width, height }, acceptDownloads: true });
        let workerMode = 'real', holdAsset = false, releaseAsset, wasmFetches = 0;
        await page.addInitScript(() => {
          window.__requestBytes = []; window.__urls = []; window.__revoked = [];
          const OriginalWorker = Worker;
          window.Worker = class extends OriginalWorker {
            constructor(...args) {
              super(...args);
              this.addEventListener('message', ({ data }) => {
                if (data.bytes instanceof ArrayBuffer) window.__requestBytes.push(Array.from(new Uint8Array(data.bytes)));
              });
            }
          };
          const create = URL.createObjectURL.bind(URL), revoke = URL.revokeObjectURL.bind(URL);
          URL.createObjectURL = blob => { const url = create(blob); window.__urls.push(url); return url; };
          URL.revokeObjectURL = url => { window.__revoked.push(url); revoke(url); };
        });
        await page.route('https://blockstream.info/**', route => {
          const url = route.request().url(), fixture = outputFixture();
          return url.endsWith('/block-height/0') ? route.fulfill({ body: fixtures.mainnet.genesis })
            : route.fulfill({ json: url.endsWith('/utxo') ? fixture.utxos : fixture.tx });
        });
        await page.route(/\/(?:wasm\/quietproof|assets\/quietproof\.[a-f0-9]{64})\.wasm$/, async route => {
          wasmFetches++;
          if (holdAsset) await new Promise(r => { releaseAsset = r; });
          await route.continue().catch(() => {});
        });
        await page.route(/(?:\/web\/wasm\/worker\.mjs|\/assets\/worker-[^/]+\.js)/, route => workerMode === 'error'
          ? route.fulfill({ contentType: 'text/javascript', body: "self.onmessage=({data})=>self.postMessage({id:data.id,type:data.type==='initialize'?'ready':'error',message:'Injected worker error'});" })
          : route.continue());
        await page.goto(origin + '/tool');
        const create = page.getByRole('button', { name: 'Create request', exact: true });
        await create.waitFor(); assert.equal(await create.isDisabled(), true);
        assert.equal(wasmFetches, 0);
        await page.getByLabel('Bitcoin addresses').fill(fixtures.mainnet.p2wpkh);
        await page.getByRole('button', { name: 'Look up outputs', exact: true }).click();
        await page.locator('.quietproof-claims').getByRole('checkbox').check();
        await page.getByLabel('Intended verifier').fill('Example auditor');
        await page.getByLabel('Message (optional').fill('Public fixture control');
        await page.addStyleTag({ content: `html { font-size: ${16 * scale / 100}px !important; } .quietproof-request { font-size: ${16 * scale / 100}px !important; line-height: 1.6; }` });
        assert.equal(wasmFetches, 0, 'valid editing never loads WASM');
        await create.click();
        const preview = page.getByRole('region', { name: 'Canonical request preview' });
        await preview.waitFor();
        assert.match(await preview.innerText(), /12345 sats/);
        assert.match(await preview.innerText(), /Example auditor/);
        const link = page.getByRole('link', { name: 'Download .qpr request', exact: true });
        async function download() {
          const promise = page.waitForEvent('download'); await link.focus(); await page.keyboard.press('Enter'); const result = await promise;
          assert.match(result.suggestedFilename(), /^quietproof-mainnet-[a-f0-9]{16}\.qpr$/);
          const bytes = await readFile(await result.path());
          assert.deepEqual([...bytes], await page.evaluate(() => window.__requestBytes.at(-1)), 'download equals exact worker result');
          const inspected = JSON.parse(execFileSync(cli, ['inspect', await result.path()], { encoding: 'utf8' }));
          assert.equal(inspected.network, 'mainnet'); assert.equal(inspected.verifier, 'Example auditor');
          assert.equal(inspected.purpose, 'proof-of-control'); assert.equal(inspected.claims, 1);
          assert.equal(inspected.statement_version, 1); assert.deepEqual(inspected.script_kinds, ['p2wpkh']);
          assert.equal(inspected.expires_at - inspected.not_before, 300);
          return { bytes, inspected };
        }
        const first = await download(), repeated = await download();
        assert.deepEqual(first.bytes, repeated.bytes);
        assert.equal(await page.evaluate(() => window.__urls.length), 1);
        if (evidence) {
          await mkdir(evidence, { recursive: true });
          await writeFile(resolve(evidence, `${name}-${width}-${scale}.qpr`), first.bytes);
          await writeFile(resolve(evidence, `${name}-${width}-${scale}-native.json`), JSON.stringify(first.inspected, null, 2));
        }
        async function capture(state) {
          assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false);
          if (evidence) {
            await page.evaluate(() => scrollTo(0, 0)); await page.waitForTimeout(100);
            await page.screenshot({ path: resolve(evidence, `${name}-${width}-${scale}-${state}.png`), fullPage: true });
            await (state === 'success' ? preview : page.getByRole('alert')).scrollIntoViewIfNeeded();
            await page.screenshot({ path: resolve(evidence, `${name}-${width}-${scale}-${state}-detail.png`) });
          }
        }
        await capture('success');
        await page.getByRole('button', { name: 'Regenerate request', exact: true }).click();
        await preview.waitFor();
        assert.notDeepEqual(await page.evaluate(() => window.__requestBytes.at(-1)), [...first.bytes]);
        assert.equal(await page.evaluate(() => window.__revoked.length), 1);
        await page.getByLabel('Intended verifier').fill('Changed verifier');
        assert.equal(await preview.count(), 0); assert.equal(await link.count(), 0);
        assert.equal(await page.evaluate(() => window.__revoked.length), 2);
        await page.getByLabel('Request lifetime').fill('0'); assert.equal(await create.isDisabled(), true);
        await page.getByLabel('Request lifetime').fill('300');
        // A real worker is used above; this fixture exercises the same worker-error channel.
        workerMode = 'error'; await create.click(); await page.getByRole('alert').waitFor();
        assert.match(await page.getByRole('alert').innerText(), /Request creation failed/);
        assert.equal(await link.count(), 0); await capture('error');
        workerMode = 'real'; holdAsset = true; releaseAsset = undefined; await create.click();
        await page.getByText('Creating the canonical request…', { exact: true }).waitFor();
        while (!releaseAsset) await new Promise(r => setTimeout(r, 10));
        await page.getByRole('button', { name: 'Cancel creation', exact: true }).click();
        holdAsset = false; releaseAsset();
        await page.getByText('Request creation cancelled. You can retry.', { exact: true }).waitFor();
        assert.equal(await link.count(), 0);
        // Editing context during creation also invalidates the held response.
        holdAsset = true; releaseAsset = undefined; await create.click();
        while (!releaseAsset) await new Promise(r => setTimeout(r, 10));
        await page.getByLabel('Message (optional').fill('Changed during creation');
        holdAsset = false; releaseAsset(); await page.waitForTimeout(50);
        assert.equal(await link.count(), 0); assert.equal(await create.isEnabled(), true);
        // Recovery uses fresh real workers, not a fake successful response.
        await create.click(); await preview.waitFor(); assert.equal(await link.count(), 1);
        await page.getByLabel('Bitcoin network', { exact: true }).selectOption('signet');
        assert.equal(await link.count(), 0);
        assert.equal(await page.evaluate(() => window.__urls.length === window.__revoked.length), true);
        await page.close();
      }
    } finally { await browser.close(); }
  });
}
