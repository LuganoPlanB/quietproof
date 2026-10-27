import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile, mkdir } from 'node:fs/promises';
import { resolve } from 'node:path';
import { chromium, webkit } from 'playwright';
const origin = process.env.QUIETPROOF_SITE_ORIGIN || 'http://127.0.0.1:4175';
const evidence = process.env.QUIETPROOF_VERIFY_SCREENSHOTS;
// Synthetic metadata-only native codec fixtures; never used to claim crypto.
// Refresh their public timestamps in test bytes to exercise policy preparation.
const fixtureTime = BigInt(Math.floor(Date.now() / 1000) - 2);
function fresh(bytes) {
  const out = Buffer.from(bytes), now = fixtureTime;
  for (const [old, value] of [[1700000000n, now], [1700000001n, now + 1n], [1700000300n, now + 300n]]) {
    const needle = Buffer.alloc(8); needle.writeBigUInt64BE(old);
    let offset = out.indexOf(needle);
    while (offset >= 0) { out.writeBigUInt64BE(value, offset); offset = out.indexOf(needle, offset + 8); }
  }
  return out;
}
const proof = fresh(await readFile(new URL('../../../tests/wasm/fixtures/0.qpf', import.meta.url)));
const request = fresh(await readFile(new URL('../../../tests/wasm/fixtures/0.qpr', import.meta.url)));
const upload = (name, buffer) => ({ name, buffer, mimeType: 'application/octet-stream' });
for (const [name, engine] of [['chromium', chromium], ['webkit', webkit]]) {
  test(`${name}: bounded real-worker import, independent policies, failures, keyboard and cancellation`, { timeout: 180000 }, async () => {
    const browser = await engine.launch({ headless: true,
      ...(name === 'webkit' && process.env.QUIETPROOF_WEBKIT_EXECUTABLE ? { executablePath: process.env.QUIETPROOF_WEBKIT_EXECUTABLE } : {}) });
    console.log(`${name}: ${browser.version()}`);
    try {
      for (const [width, height] of [[390, 844], [1440, 900]]) for (const scale of [100, 200]) {
        const page = await browser.newPage({ viewport: { width, height } });
        let explorers = 0, stalled = false, release;
        try {
        await page.route('https://blockstream.info/**', route => { explorers++; return route.abort(); });
        await page.route('**/wasm/quietproof.wasm', async route => {
          if (stalled) await new Promise(r => { release = r; });
          await route.continue().catch(() => {});
        });
        await page.goto(origin + '/verify');
        const inspect = page.getByRole('button', { name: 'Inspect proof and policy', exact: true });
        await inspect.waitFor(); await page.waitForFunction(() => !document.querySelector('.quietproof-verify button[type=submit]').disabled);
        await page.addStyleTag({ content: `html, .quietproof-verify { font-size: ${16 * scale / 100}px !important; line-height: 1.6; }` });
        async function capture(state) {
          const overflow = await page.evaluate(() => [...document.querySelectorAll('.quietproof-verify, .quietproof-verify *')].filter(e => e.getBoundingClientRect().right > innerWidth || e.scrollWidth > e.clientWidth + 2).map(e => ({ tag: e.tagName, id: e.id, width: e.getBoundingClientRect().width, right: e.getBoundingClientRect().right, scroll: e.scrollWidth, client: e.clientWidth })).slice(-15));
          if (overflow.length) console.log(JSON.stringify({ name, width, scale, state, overflow }));
          if (evidence) {
            await mkdir(evidence, { recursive: true }); await page.evaluate(() => scrollTo(0, 0));
            await page.screenshot({ path: resolve(evidence, `${name}-${width}-${scale}-${state}.png`), fullPage: true });
          }
          assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false, 'no horizontal overflow');
        }
        await capture('empty');
        const file = page.getByLabel('Proof file (.qpf)', { exact: true });
        // Native file input is keyboard operable; choosing happens through the browser chooser.
        await file.scrollIntoViewIfNeeded(); await file.focus();
        assert.equal(await page.evaluate(() => document.activeElement?.id), 'qp-proof');
        const chooser = page.waitForEvent('filechooser'); await page.keyboard.press('Space');
        await (await chooser).setFiles(upload('proof.qpf', proof));
        await inspect.focus(); await page.keyboard.press('Enter');
        await page.getByRole('heading', { name: 'Inspection only · cryptography not checked' }).waitFor();
        await page.getByText('No expected policy selected.', { exact: false }).waitFor();
        await capture('inspection');
        await page.getByLabel('Expected policy source').selectOption('request');
        assert.equal(await page.getByRole('region', { name: 'Unverified inspection' }).count(), 0);
        await inspect.click(); await page.getByRole('alert').filter({ hasText: '.qpr' }).waitFor();
        await page.getByLabel('Expected request file (.qpr)', { exact: true }).setInputFiles(upload('expected.qpr', request));
        await inspect.click(); await page.getByText('Expected policy matched at inspection time.', { exact: false }).waitFor();
        await capture('matched');
        const wrong = Buffer.from(request); wrong[wrong.length - 1] ^= 1;
        await page.getByLabel('Expected request file (.qpr)', { exact: true }).setInputFiles(upload('wrong.qpr', wrong));
        await inspect.click(); await page.getByRole('alert').filter({ hasText: 'Expected policy rejected' }).waitFor();
        await capture('mismatch');
        for (const invalid of [Buffer.from([1, 2, 3]), request.subarray(0, request.length - 1)]) {
          await page.getByLabel('Expected request file (.qpr)', { exact: true }).setInputFiles(upload('invalid.qpr', invalid));
          await inspect.click(); await page.getByRole('alert').filter({ hasText: 'Expected policy rejected' }).waitFor();
        }
        await page.getByLabel('Expected policy source').selectOption('explicit');
        assert.equal(await page.getByLabel('Expected verifier', { exact: true }).inputValue(), '');
        assert.equal(await page.getByLabel('Expected Bitcoin network').inputValue(), '');
        await page.getByLabel('Expected verifier', { exact: true }).fill('golden.example');
        await page.getByLabel('Expected purpose', { exact: true }).selectOption('proof-of-funds');
        await page.getByLabel('Expected Bitcoin network').selectOption('mainnet');
        await page.getByLabel('Expected message (empty is allowed)').fill('public test message');
        await page.getByRole('checkbox', { name: 'I independently chose this context', exact: false }).check(); await inspect.click();
        await page.getByRole('alert').filter({ hasText: 'Expected policy rejected' }).waitFor();
        await page.getByLabel('Expected Bitcoin network').selectOption('signet');
        assert.equal(await page.getByRole('checkbox', { name: 'I independently chose this context', exact: false }).isChecked(), false);
        await page.getByRole('checkbox', { name: 'I independently chose this context', exact: false }).check(); await inspect.click();
        await page.getByText('Expected policy matched at inspection time.', { exact: false }).waitFor();
        await page.getByLabel('Expected policy source').selectOption('none');
        for (const bad of [Buffer.from([1, 2, 3]), proof.subarray(0, proof.length - 1), Buffer.from(proof)]) {
          if (bad.length === proof.length) bad[4] = 255;
          await file.setInputFiles(upload('bad.qpf', bad)); await inspect.click();
          await page.getByRole('alert').filter({ hasText: 'Cannot decode' }).waitFor();
        }
        await capture('failure');
        // Size preflight runs before arrayBuffer and WASM loading (unit gate checks read counters).
        await page.evaluate(() => {
          const input = document.querySelector('#qp-proof'), transfer = new DataTransfer();
          const file = new File([new Blob([new Uint8Array(134221890)])], 'oversized.qpf');
          transfer.items.add(file); input.files = transfer.files; input.dispatchEvent(new Event('change', { bubbles: true }));
        });
        await inspect.click(); await page.getByRole('alert').filter({ hasText: 'Proof size' }).waitFor();
        await file.setInputFiles(upload('proof.qpf', proof));
        stalled = true; await inspect.click();
        await page.getByText('Reading and inspecting in a worker…', { exact: true }).waitFor();
        for (let attempt = 0; !release && attempt < 500; attempt++) await new Promise(r => setTimeout(r, 10));
        assert(release, 'asset route reached the injected loading gate');
        await capture('loading');
        await page.getByRole('button', { name: 'Cancel import' }).focus(); await page.keyboard.press('Enter');
        await page.getByText('Import cancelled. No result retained.', { exact: true }).waitFor();
        stalled = false; release(); await page.waitForTimeout(50);
        assert.equal(await page.getByRole('region', { name: 'Unverified inspection' }).count(), 0);
        await capture('cancelled');
        await inspect.click(); await page.getByRole('heading', { name: 'Inspection only · cryptography not checked' }).waitFor();
        assert.equal(explorers, 0, 'no explorer fetch during import or policy inspection');
        } finally { release?.(); await page.close(); }
      }
    } finally { await browser.close(); }
  });
}
