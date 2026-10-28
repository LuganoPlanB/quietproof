import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile, mkdir, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { chromium, webkit } from 'playwright';
import { cappedMemoryArtifact } from '../tests/wasm/resources.mjs';
import { fixtures, outputFixture } from './features/provider/fixtures.mjs';

const origin = process.env.QUIETPROOF_SITE_ORIGIN || 'http://127.0.0.1:4177';
const evidence = process.env.QUIETPROOF_ACCESSIBILITY_EVIDENCE;
const fixtureRoot = process.env.QUIETPROOF_VERIFY_FIXTURES;
assert(fixtureRoot, 'Current public native fixtures required.');
const proof = await readFile(resolve(fixtureRoot, 'one-key.qpf'));
const request = await readFile(resolve(fixtureRoot, 'one-key.qpr'));
const provenance = JSON.parse(await readFile(resolve(fixtureRoot, 'one-key.json')));
assert(provenance.nativeVerified && provenance.expiresAt > Date.now()/1000 + 1800);
const capped = cappedMemoryArtifact(await readFile(process.env.QUIETPROOF_WASM));
const upload = (name, buffer) => ({ name, buffer, mimeType: 'application/octet-stream' });

for (const [name, engine] of [['chromium', chromium], ['webkit', webkit]]) {
  test(`${name}: keyboard, ARIA states, reflow, controlled memory failure and real-proof recovery`, { timeout: 600000 }, async () => {
    const browser = await engine.launch({ headless: true,
      ...(name === 'webkit' && process.env.QUIETPROOF_WEBKIT_EXECUTABLE ? { executablePath: process.env.QUIETPROOF_WEBKIT_EXECUTABLE } : {}) });
    console.log(`${name} ${browser.version()}; automated DOM/ARIA checks; no actual screen reader`);
    let page, releaseProvider;
    try {
      page = await browser.newPage({ viewport: { width: 1440, height: 900 } });
      await page.emulateMedia({ reducedMotion: 'reduce' });
      await page.addInitScript(() => {
        const NativeWorker = Worker;
        const nativeTimeout = window.setTimeout.bind(window);
        window.setTimeout = (fn, delay, ...args) => nativeTimeout(fn,
          window.__shortDeadline && delay === 300000 ? 50 : delay, ...args);
        window.__resourceWorkers = { created: 0, terminated: 0, hold: true, held: [] };
        window.Worker = class extends NativeWorker {
          constructor(...args) {
            super(...args); window.__resourceWorkers.created++;
            const send = super.postMessage.bind(this);
            this.postMessage = (data, transfer) => {
              if (data.type === 'verify' && window.__resourceWorkers.hold)
                window.__resourceWorkers.held.push({ worker: this, send: () => send(data, transfer) });
              else send(data, transfer);
            };
          }
          terminate() {
            if (!this.closed) { this.closed = true; window.__resourceWorkers.terminated++; }
            window.__resourceWorkers.held = window.__resourceWorkers.held.filter(x => x.worker !== this);
            super.terminate();
          }
        };
      });
      let providerMode = 'hold', lowMemory = false, providerCalls = 0;
      await page.route('https://blockstream.info/**', async route => {
        providerCalls++;
        if (providerMode === 'hold') await new Promise(r => { releaseProvider = r; });
        if (providerMode === 'error') return route.fulfill({ status: 429, body: 'unavailable' });
        const fixture = outputFixture(), url = route.request().url();
        return url.endsWith('/block-height/0') ? route.fulfill({ body: fixtures.mainnet.genesis })
          : route.fulfill({ json: url.endsWith('/utxo') ? fixture.utxos : fixture.tx });
      });
      // Inject the allocation ceiling at the worker's initialization boundary.
      // Production asset integrity remains enabled and checks the original bytes.
      await page.route(/\/assets\/worker-[^/]+\.js$/, async route => {
        if (!lowMemory) return route.continue();
        const response = await route.fetch();
        const prefix = `const ceiling = Uint8Array.from(atob('${Buffer.from(capped).toString('base64')}'), c => c.charCodeAt(0));\n`;
        const suffix = `\nconst original = self.onmessage; self.onmessage = event => {
          if (event.data.type === 'initialize') event.data.bytes = ceiling.buffer.slice(0);
          return original(event);
        };`;
        return route.fulfill({ response, body: prefix + await response.text() + suffix });
      });
      async function capture(state, feature, detail) {
        for (const [width,height] of [[390,844],[1440,900]]) for (const scale of [100,200]) {
          await page.setViewportSize({ width,height });
          await page.evaluate(scale => {
            let style=document.querySelector('#qp-a11y-scale');
            if (!style) { style=document.createElement('style'); style.id='qp-a11y-scale'; document.head.append(style); }
            style.textContent=`html, .quietproof-request, .quietproof-verify {font-size:${16*scale/100}px!important;line-height:1.6}`;
          },scale);
          await detail.scrollIntoViewIfNeeded(); await page.waitForTimeout(350);
          assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth),false,`${state}/${width}/${scale} reflow`);
          const unnamed = await feature.locator('input,select,textarea').evaluateAll(nodes => nodes.filter(n=>!n.labels?.length && !n.getAttribute('aria-label')).map(n=>n.id));
          assert.deepEqual(unnamed,[],`${state} controls have labels`);
          const snapshot=await feature.ariaSnapshot();
          assert.match(snapshot,/region|group|heading/);
          if (evidence) {
            await mkdir(evidence,{recursive:true});
            const stem=resolve(evidence,`${name}-${width}-${scale}-${state}`);
            await writeFile(stem+'.aria.txt',snapshot);
            // Viewport is the primary layout evidence. Full-page stitching can
            // place a fixed header in the middle of a long captured image.
            await page.screenshot({path:stem+'-viewport.png',animations:'disabled'});
            await page.screenshot({path:stem+'-full.png',fullPage:true,animations:'disabled'});
          }
        }
        await page.setViewportSize({width:1440,height:900});
        await page.evaluate(()=>document.querySelector('#qp-a11y-scale')?.remove());
      }
      await page.goto(origin+'/tool');
      const requestFeature=page.getByRole('region',{name:'Create a request',exact:true});
      const lookup=page.getByRole('button',{name:'Look up outputs',exact:true}); await lookup.waitFor();
      await capture('request-empty',requestFeature,lookup);
      await page.getByLabel('Bitcoin addresses').fill(fixtures.mainnet.p2wpkh);
      await lookup.focus(); await page.keyboard.press('Enter');
      await page.getByText('Looking up outputs…',{exact:true}).waitFor();
      await page.waitForFunction(()=>document.querySelector('.quietproof-request button[type=submit]').disabled);
      await capture('request-loading',requestFeature,page.getByRole('button',{name:'Cancel lookup'}));
      assert(releaseProvider,'provider reached the owned loading gate');
      providerMode='error'; releaseProvider(); releaseProvider=undefined;
      await page.getByRole('alert').waitFor(); await capture('request-error',requestFeature,page.getByRole('alert'));
      providerMode='valid'; await lookup.click(); await page.locator('.quietproof-claims').getByRole('checkbox').check();
      await page.getByLabel('Intended verifier').fill('Accessible auditor');
      await page.getByRole('button',{name:'Create request',exact:true}).click();
      const preview=page.getByRole('region',{name:'Canonical request preview'}); await preview.waitFor();
      await capture('request-success',requestFeature,preview.getByRole('heading',{name:'Review the request'}));
      const download=page.getByRole('link',{name:'Download .qpr request',exact:true}); await download.focus();
      assert.equal(await download.evaluate(el=>el===document.activeElement),true);
      await page.goto(origin+'/verify');
      const feature=page.getByRole('region',{name:'Import a proof',exact:true});
      const verify=page.getByRole('button',{name:'Verify offline',exact:true}); await verify.waitFor();
      await capture('verify-empty',feature,verify);
      await page.getByLabel('Proof file (.qpf)',{exact:true}).focus(); await page.keyboard.press('Tab');
      assert.equal(await page.evaluate(()=>document.activeElement.id),'qp-policy');
      await page.getByLabel('Expected policy source').selectOption('request');
      await page.getByLabel('Expected request file (.qpr)',{exact:true}).setInputFiles(upload('expected.qpr',request));
      await page.getByLabel('Proof file (.qpf)',{exact:true}).setInputFiles(upload('public.qpf',proof));
      await page.getByLabel('Verification network (chosen independently)').selectOption('mainnet');
      const before=providerCalls;
      await verify.focus(); await page.keyboard.press('Enter');
      await page.waitForFunction(()=>window.__resourceWorkers.held.length===1,{},{timeout:30000});
      const progress=page.getByRole('status').filter({hasText:/Checking proof cryptography/});
      await progress.waitFor(); assert.equal(await progress.getAttribute('aria-live'),'polite');
      await capture('verify-progress',feature,progress);
      const cancel=page.getByRole('button',{name:'Cancel verification',exact:true}); await cancel.focus(); await page.keyboard.press('Enter');
      await page.getByText('Import cancelled. No result retained.',{exact:true}).waitFor();
      assert.equal(await verify.evaluate(el=>el===document.activeElement),true,'cancel restores actionable keyboard focus');
      await capture('verify-cancelled',feature,verify);
      await page.evaluate(()=>{window.__resourceWorkers.hold=false;});
      lowMemory=true; await verify.click();
      const heading=page.getByRole('heading',{name:'Separate verification results'});
      await heading.waitFor({timeout:180000});
      assert.equal(await heading.evaluate(el=>el===document.activeElement),true,'failure announces its results heading');
      assert.match(await page.getByRole('region',{name:'Verification results',exact:true}).innerText(),/resources|memory|worker|stopped/i);
      assert.equal(await page.locator('[data-result=crypto]').innerText(),'Not checked to completion');
      await capture('verify-resource-failure',feature,heading);
      lowMemory=false; await page.evaluate(()=>{window.__shortDeadline=true;});
      await page.getByRole('button',{name:'Retry verification',exact:true}).click();
      await page.getByText('Verification reached its time limit. Retry on a supported device.',{exact:true}).waitFor();
      assert.equal(await heading.evaluate(el=>el===document.activeElement),true);
      await capture('verify-timeout',feature,heading);
      await page.evaluate(()=>{window.__shortDeadline=false;});
      await page.getByRole('button',{name:'Retry verification',exact:true}).click();
      await page.locator('[data-result=crypto]').filter({hasText:/^Valid$/}).waitFor({timeout:180000});
      assert.equal(await heading.evaluate(el=>el===document.activeElement),true,'success announces its results heading');
      assert.equal(await page.locator('[data-result=explorer]').innerText(),'Unavailable');
      assert.equal(providerCalls,before,'offline failure/recovery causes no explorer access');
      await capture('verify-success',feature,heading);
      const workers=await page.evaluate(()=>({created:window.__resourceWorkers.created,terminated:window.__resourceWorkers.terminated,held:window.__resourceWorkers.held.length}));
      assert.equal(workers.created,workers.terminated); assert.equal(workers.held,0);
      console.log(JSON.stringify({engine:name,states:10,combinationsPerState:4,workers,physicalLowMemory:'unverified',screenReader:'not exercised',timeout:'test-only 50ms substitution for the five-minute deadline'}));
    } finally {
      releaseProvider?.();
      await page?.evaluate(()=>{window.__resourceWorkers.hold=false;for(const e of window.__resourceWorkers.held.splice(0))e.send();}).catch(()=>{});
      await page?.close(); await browser.close();
    }
  });
}
