import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdir, readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { execFileSync } from 'node:child_process';
import { chromium, webkit } from 'playwright';
import { workflows, providerResponse } from './workflow-fixtures.mjs';

const origin = process.env.QUIETPROOF_SITE_ORIGIN || 'http://127.0.0.1:4174';
const cli = process.env.QUIETPROOF_NATIVE_CLI;
const output = resolve(process.env.QUIETPROOF_SIGNING_ARTIFACTS || tmpdir(), `signing-${Date.now()}-${process.pid}`);
const engines = [['chromium', chromium], ['webkit', webkit]].filter(([name]) => !process.env.QUIETPROOF_UI_ENGINE || process.env.QUIETPROOF_UI_ENGINE === name);
const layouts = [[390, 844, 100], [390, 844, 200], [1440, 900, 100], [1440, 900, 200]];

for (const [engine, browserType] of engines) {
  for (const network of ['mainnet', 'signet']) for (const [kind, profile] of [['p2wpkh', '1'], ['p2pkh', '2'], ['p2pkh', '1']]) {
    test(`${engine}: ${network} ${kind} profile ${profile} exact message, wallet instructions and copy`, { timeout: 180000 }, async () => {
      assert(cli, 'A current native QuietProof CLI is required for independent message parity.');
      const executablePath = engine === 'chromium' ? process.env.QUIETPROOF_CHROMIUM_EXECUTABLE : process.env.QUIETPROOF_WEBKIT_EXECUTABLE;
      const browser = await browserType.launch({ headless: true, ...(executablePath ? { executablePath } : {}) });
      const dir = resolve(output, `${engine}-${network}-${kind}-${profile}`);
      await mkdir(dir, { recursive: true });
      try {
        for (const [width, height, scale] of layouts) {
          const page = await browser.newPage({ viewport: { width, height }, acceptDownloads: true });
          const errors = []; page.on('pageerror', e => errors.push(e.message));
          await page.addInitScript(() => {
            window.__copied = [];
            Object.defineProperty(navigator, 'clipboard', { configurable: true, value: {
              async writeText(value) { if (window.__denyClipboard) throw new Error('Clipboard denied'); window.__copied.push(value); },
            } });
          });
          const workflow = workflows.find(w => w.network === network && w.claims.length === 1 && w.claims[0].scriptKind === kind);
          const calls = [];
          await page.route('https://blockstream.info/**', route => {
            calls.push(route.request().url()); return route.fulfill(providerResponse(workflow, route.request().url()));
          });
          // Old bookmarks still resolve to the renamed tool, including site subpaths.
          await page.goto(origin + '/tool');
          await page.waitForURL(origin + '/request');
          const mode = page.getByLabel('Proof mode', { exact: true });
          assert.equal(await mode.inputValue(), 'signature-possession');
          assert.equal(await mode.locator('option[value="key-knowledge"]').isDisabled(), true);
          assert.equal(calls.length, 0);
          await page.getByLabel('Bitcoin network', { exact: true }).selectOption(network);
          await page.getByLabel('Bitcoin addresses').fill(workflow.claims[0].address);
          await page.getByRole('button', { name: 'Look up outputs', exact: true }).click();
          await page.locator('.quietproof-claims input').check();
          await page.getByLabel('Intended verifier').fill('signing.example');
          if (process.env.QUIETPROOF_SIGNATURE_MODE === '0') {
            await page.getByText('Signature possession is unavailable in this verifier build.', { exact: false }).first().waitFor();
            assert.equal(await page.getByRole('button', { name: 'Create request', exact: true }).isDisabled(), true);
            assert.equal(await page.getByRole('region', { name: 'Wallet signing instructions', exact: true }).count(), 0);
            await page.close(); continue;
          }
          await page.waitForFunction(() => !document.querySelector('#qp-signing-profile').disabled);
          await page.getByLabel('Signing procedure', { exact: true }).selectOption(profile);
          await page.getByRole('button', { name: 'Create request', exact: true }).click();
          const signing = page.getByRole('region', { name: 'Wallet signing instructions', exact: true });
          await signing.waitFor();
          const message = await page.getByLabel('Exact message to sign', { exact: true }).inputValue();
          assert.match(message, /^quietproof:signature:v4:[0-9a-f]{64}$/);
          const download = page.waitForEvent('download');
          await page.getByRole('link', { name: 'Download .qpr request', exact: true }).click();
          const request = resolve(dir, `${width}-${scale}.qpr`), material = resolve(dir, `${width}-${scale}.txt`);
          await (await download).saveAs(request);
          execFileSync(cli, ['signing-material', '--request', request, '--output', material], { timeout: 15000 });
          assert.equal(await readFile(material, 'utf8'), message, 'website message exactly equals native export for downloaded bytes');
          await page.getByRole('button', { name: 'Copy signing message', exact: true }).click();
          assert.equal(await page.evaluate(() => window.__copied.at(-1)), message);
          const full = kind === 'p2pkh' && profile === '1';
          if (full) {
            assert.equal(await page.getByLabel('RPC command', { exact: true }).count(), 0);
            assert.match(await signing.innerText(), /not BIP322 Full/);
          } else {
            const command = await page.getByLabel('RPC command', { exact: true }).inputValue();
            assert.equal(command, `bitcoin-cli${network === 'signet' ? ' -signet' : ''} -rpcconnect=127.0.0.1 signmessage '${workflow.claims[0].address}' '${message}'`);
            assert.match(await signing.innerText(), new RegExp(network === 'signet' ? '38332' : '8332'));
            assert.match(await signing.innerText(), /-rpcwallet="WALLET_NAME"/);
            assert.match(await signing.innerText(), profile === '2' ? /Standard \(Electrum\)/ : /BIP322 Simple/);
            assert.match(await signing.innerText(), /Sparrow has no equivalent public signing RPC/);
            await page.getByRole('button', { name: 'Copy RPC command', exact: true }).click();
            assert.equal(await page.evaluate(() => window.__copied.at(-1)), command);
          }
          await page.evaluate(() => { window.__denyClipboard = true; });
          await page.getByRole('button', { name: 'Copy signing message', exact: true }).click();
          await signing.getByRole('status').filter({ hasText: 'Clipboard unavailable' }).waitFor();
          assert.equal(await page.getByLabel('Exact message to sign').inputValue(), message, 'manual copy remains available');
          await page.addStyleTag({ content: `html,.quietproof-request{font-size:${16 * scale / 100}px!important;line-height:1.6}` });
          assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false);
          await signing.scrollIntoViewIfNeeded();
          await page.screenshot({ path: resolve(dir, `${width}-${scale}.png`), fullPage: true });
          await page.screenshot({ path: resolve(dir, `${width}-${scale}-detail.png`) });
          await page.getByLabel('Message (optional').fill('Changed context');
          assert.equal(await signing.count(), 0, 'edits discard the old message and command');
          await page.getByLabel('Request lifetime').fill('1');
          await page.getByRole('button', { name: 'Create request', exact: true }).click();
          await page.getByRole('region', { name: 'Canonical request preview' }).waitFor();
          await page.getByText('This request has expired according to your device clock.', { exact: false }).waitFor({ timeout: 5000 });
          assert.equal(await signing.count(), 0, 'expired requests cannot offer stale signing instructions');
          assert.deepEqual(errors, []);
          await page.close();
        }
      } finally { await browser.close(); }
    });
  }
}
