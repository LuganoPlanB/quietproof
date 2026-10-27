import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdir } from 'node:fs/promises';
import { resolve } from 'node:path';
import { chromium, webkit } from 'playwright';
import { fixtures, outputFixture } from '../provider/fixtures.mjs';

const origin = process.env.QUIETPROOF_SITE_ORIGIN || 'http://127.0.0.1:4174';
const evidence = process.env.QUIETPROOF_REQUEST_SCREENSHOTS;
for (const [name, engine] of [['chromium', chromium], ['webkit', webkit]]) {
  test(`${name}: explicit lookup, labels, states, selection bounds and network invalidation`, { timeout: 180000 }, async () => {
    const browser = await engine.launch({ headless: true,
      ...(name === 'webkit' && process.env.QUIETPROOF_WEBKIT_EXECUTABLE ? { executablePath: process.env.QUIETPROOF_WEBKIT_EXECUTABLE } : {}) });
    console.log(`${name} ${browser.version()}`);
    try {
      for (const [width, height] of [[390, 844], [1440, 900]]) for (const scale of [100, 200]) {
        const page = await browser.newPage({ viewport: { width, height } });
        let mode = 'success', calls = 0, release;
        await page.route('https://blockstream.info/**', async route => {
          calls++;
          if (mode === 'loading') await new Promise(r => { release = r; });
          if (mode === 'error') return route.abort('failed');
          const url = route.request().url();
          if (url.endsWith('/block-height/0')) return route.fulfill({ body: fixtures.mainnet.genesis });
          const fixture = outputFixture();
          fixture.utxos = Array.from({ length: 17 }, (_, i) => ({ ...fixture.utxos[0], vout: i }));
          fixture.tx.vout = Array.from({ length: 17 }, () => ({ ...fixture.tx.vout[0] }));
          return route.fulfill({ json: url.endsWith('/utxo') ? (mode === 'empty' ? [] : fixture.utxos) : fixture.tx });
        });
        await page.goto(origin + '/tool');
        const lookup = page.getByRole('button', { name: 'Look up outputs', exact: true });
        await lookup.waitFor(); await page.waitForFunction(() => !document.querySelector('button[type=submit]').disabled);
        await page.addStyleTag({ content: `html { font-size: ${16 * scale / 100}px !important; } .quietproof-request { font-size: ${16 * scale / 100}px !important; line-height: 1.6; }` });
        assert.equal(calls, 0);
        await page.getByLabel('Bitcoin addresses').fill(fixtures.mainnet.p2wpkh);
        await page.getByLabel('Intended verifier').fill('Example auditor');
        await page.getByLabel('Request lifetime').fill('301');
        await page.getByLabel('Message (optional').fill('Review control');
        async function capture(state) {
          assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false, 'no horizontal page overflow');
          if (evidence) {
            await mkdir(evidence, { recursive: true }); await page.evaluate(() => scrollTo(0, 0));
            await page.waitForTimeout(100);
            await page.screenshot({ path: resolve(evidence, `${name}-${width}-${scale}-${state}.png`), fullPage: true });
          }
        }
        mode = 'loading'; await lookup.focus(); await page.keyboard.press('Enter');
        await page.getByText('Looking up outputs…', { exact: true }).waitFor(); await capture('loading');
        await page.waitForFunction(() => !!document.querySelector('button[type=submit]:disabled'));
        while (!release) await new Promise(r => setTimeout(r, 10));
        mode = 'empty'; release(); await page.getByText('No unspent outputs reported for these addresses.', { exact: true }).waitFor(); await capture('empty');
        mode = 'error'; await lookup.click(); await page.getByRole('alert').waitFor(); await capture('error');
        mode = 'success'; await lookup.click(); await page.getByText('17 outputs reported. Select the outputs to disclose.', { exact: true }).waitFor();
        const boxes = page.locator('.quietproof-claims').getByRole('checkbox'); assert.equal(await boxes.count(), 17);
        await boxes.nth(0).focus(); await page.keyboard.press('Space');
        for (let i = 1; i < 16; i++) await boxes.nth(i).check();
        assert.equal(await boxes.nth(16).isDisabled(), true);
        assert.match(await page.locator('.quietproof-total').innerText(), /197520 sats/);
        await page.getByLabel('Request lifetime').fill('86401');
        await page.getByText('Lifetime must be a whole number from 1 to 86400 seconds.', { exact: true }).waitFor();
        await page.getByLabel('Request lifetime').fill('300');
        await page.getByText('Selection and context are ready for request creation.', { exact: true }).waitFor();
        await capture('limits');
        await boxes.nth(0).uncheck(); assert.equal(await boxes.nth(16).isEnabled(), true);
        await page.getByLabel('Bitcoin network', { exact: true }).selectOption('signet');
        assert.equal(await boxes.count(), 0); assert.match(await page.locator('.quietproof-total').innerText(), /0 sats/);
        assert.match(await page.locator('.quietproof-provider').innerText(), /signet\/api/);
        await capture('network-switch');
        // In-flight response cannot repopulate outputs after a network change.
        await page.getByLabel('Bitcoin network', { exact: true }).selectOption('mainnet');
        mode = 'loading'; release = undefined; await lookup.click();
        while (!release) await new Promise(r => setTimeout(r, 10));
        await page.getByLabel('Bitcoin network', { exact: true }).selectOption('signet');
        mode = 'success'; release(); await page.waitForTimeout(50); assert.equal(await boxes.count(), 0);
        const previousCalls = calls;
        await page.getByLabel('Bitcoin addresses').fill('3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy');
        await lookup.click(); await page.getByRole('alert').filter({ hasText: 'Unsupported address' }).waitFor();
        assert.equal(calls, previousCalls, 'unsupported script rejected before fetch');
        await page.getByLabel('Bitcoin addresses').fill('one\ntwo\nthree');
        await lookup.click(); await page.getByRole('alert').filter({ hasText: 'Enter one or two addresses' }).waitFor();
        assert.equal(calls, previousCalls, 'address limit rejected before fetch');
        await page.close();
      }
    } finally { await browser.close(); }
  });
}
