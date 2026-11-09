import { test } from 'node:test';
import assert from 'node:assert/strict';
import { chromium, webkit } from 'playwright';
import { mkdir, readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fixtures, outputFixture } from '../provider/fixtures.mjs';

const origin = process.env.QUIETPROOF_SITE_ORIGIN || 'http://127.0.0.1:4174';
const screenshots = process.env.QUIETPROOF_DEFAULT_SCREENSHOTS;
for (const [name,engine] of [['chromium',chromium],['webkit',webkit]].filter(([name]) => !process.env.QUIETPROOF_UI_ENGINE || process.env.QUIETPROOF_UI_ENGINE === name)) {
  test(`${name}: PoSC-only website defaults, disabled PoKC and private-input errors`, { timeout:180000 }, async () => {
    const browser = await engine.launch({ headless:true,
      ...(name === 'chromium' && process.env.QUIETPROOF_CHROMIUM_EXECUTABLE ? { executablePath: process.env.QUIETPROOF_CHROMIUM_EXECUTABLE } : {}),
      ...(name === 'webkit' && process.env.QUIETPROOF_WEBKIT_EXECUTABLE ? {executablePath:process.env.QUIETPROOF_WEBKIT_EXECUTABLE}: {}) });
    console.log(`${name}: ${browser.version()}`);
    try {
      for (const [width,height] of [[375,812],[1440,900]]) for (const scale of [100,200]) {
        const page = await browser.newPage({viewport:{width,height}});
        let explorerCalls = 0;
        await page.route('https://blockstream.info/**', route => {
          explorerCalls++;
          const url=route.request().url(), fixture=outputFixture();
          return url.endsWith('/block-height/0') ? route.fulfill({body:fixtures.mainnet.genesis}) :
            route.fulfill({json:url.endsWith('/utxo')?fixture.utxos:fixture.tx});
        });
        async function capture(state) {
          await page.addStyleTag({content:`html,.quietproof-request,.quietproof-verify {font-size:${16*scale/100}px!important;line-height:1.6}`});
          assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false,'no horizontal page overflow');
          if (screenshots) { await mkdir(screenshots,{recursive:true}); await page.screenshot({path:resolve(screenshots,`${name}-${width}x${height}-${scale}-${state}.png`),fullPage:true}); }
        }
        await page.goto(origin+'/request');
        const requestMode=page.getByLabel('Proof mode',{exact:true});
        await requestMode.waitFor(); assert.equal(await requestMode.inputValue(),'signature-possession');
        assert.equal(explorerCalls,0,'capability probing makes no explorer request');
        await page.getByLabel('Bitcoin addresses').fill(fixtures.mainnet.p2wpkh);
        await page.getByRole('button',{name:'Look up outputs',exact:true}).click();
        await page.locator('.quietproof-claims').getByRole('checkbox').check();
        await page.getByLabel('Intended verifier').fill('default-custody.example');
        if (process.env.QUIETPROOF_SIGNATURE_MODE === '0') {
          await page.getByText('Signature possession is unavailable in this verifier build.',{exact:false}).first().waitFor();
          assert.equal(await page.getByRole('button',{name:'Create request',exact:true}).isDisabled(),true);
          assert.equal(await requestMode.inputValue(),'signature-possession','unsupported capability never changes the default relation');
          assert.equal(await page.locator('.quietproof-preview').count(),0);
        }
        if (process.env.QUIETPROOF_SIGNATURE_MODE !== '0') {
          await page.getByRole('button',{name:'Create request',exact:true}).click();
          await page.getByRole('region',{name:'Canonical request preview'}).waitFor();
          assert.match(await page.locator('.quietproof-preview').innerText(),/Signature possession/);
          await capture('default-request');
        }
        assert.equal(await requestMode.locator('option[value="key-knowledge"]').isDisabled(),true);
        await page.goto(origin+'/verify');
        const proofMode=page.getByLabel('Proof mode (chosen independently)',{exact:true});
        await proofMode.waitFor(); assert.equal(await proofMode.inputValue(),'signature-possession');
        assert.equal(await page.getByLabel('Expected policy source').inputValue(),'request');
        const proof=page.getByLabel('Proof file (.qpf)',{exact:true});
        await proof.setInputFiles({name:'private.qpa',mimeType:'application/octet-stream',buffer:Buffer.from('QPA1private test marker')});
        await page.getByRole('button',{name:'Inspect proof and policy',exact:true}).click();
        await page.getByRole('alert').filter({hasText:'Private .qpa'}).waitFor();
        await capture('private-input-error');
        await proof.setInputFiles({name:'public.qpf',mimeType:'application/octet-stream',buffer:Buffer.from('QPE1')});
        await page.getByRole('button',{name:'Inspect proof and policy',exact:true}).click();
        await page.getByRole('alert').filter({hasText:'.qpr'}).waitFor();
        await capture('missing-request');
        assert.equal(await proofMode.locator('option[value="key-knowledge"]').isDisabled(),true);
        await proofMode.focus(); await page.keyboard.press('ArrowDown'); await page.keyboard.press('Enter');
        assert.equal(await proofMode.inputValue(),'signature-possession');
        assert.equal(await page.getByLabel('Expected policy source').locator('option').count(),1);
        const legacy=await readFile(new URL('../../../tests/wasm/fixtures/0.qpf',import.meta.url));
        const expected=await readFile(new URL('../../../tests/wasm/fixtures/signature-p2wpkh.qpr',import.meta.url));
        await proof.setInputFiles({name:'legacy.qpf',mimeType:'application/octet-stream',buffer:legacy});
        await page.getByLabel('Expected request file (.qpr)',{exact:true}).setInputFiles({name:'expected.qpr',mimeType:'application/octet-stream',buffer:expected});
        await page.getByRole('button',{name:'Inspect proof and policy',exact:true}).click();
        await page.getByRole('alert').filter({hasText:process.env.QUIETPROOF_SIGNATURE_MODE === '0' ? /unavailable|unsupported/i : 'Proof mode does not match'}).waitFor();
        assert.equal(await proofMode.inputValue(),'signature-possession','legacy input cannot enable PoKC');
        await capture('legacy-disabled'); await page.close();
      }
    } finally { await browser.close(); }
  });
}
