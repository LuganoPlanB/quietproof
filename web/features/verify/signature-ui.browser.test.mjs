import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { chromium, webkit } from 'playwright';
import { workflows, providerResponse } from '../request/workflow-fixtures.mjs';
import { decodeInspection } from '../../wasm/codec.mjs';

const origin=process.env.QUIETPROOF_SITE_ORIGIN;
const disabledOrigin=process.env.QUIETPROOF_DISABLED_SITE_ORIGIN;
const output=process.env.QUIETPROOF_SIGNATURE_UI_ARTIFACTS;
const fixtureRoot=process.env.QUIETPROOF_VERIFY_FIXTURES;
assert(origin && disabledOrigin && output && fixtureRoot, 'Enabled/disabled sites, public fixtures and evidence directory are required.');
const proof=await readFile(resolve(fixtureRoot,'signature-mixed.qpf'));
const request=await readFile(resolve(fixtureRoot,'signature-mixed.qpr'));
// Change only the nonce: this is still a canonical, well-formed request, but
// it was independently issued for a different challenge.
const wrong=Buffer.from(request);
let nonceOffset=11;
for(let field=0;field<2;field++)nonceOffset+=2+wrong.readUInt16BE(nonceOffset);
wrong[nonceOffset]^=1;
const upload=(name,buffer)=>({ name,buffer,mimeType:'application/octet-stream' });
const layouts=[[375,812,100],[375,812,200],[1440,900,100],[1440,900,200]];
const digest=value=>createHash('sha256').update(value).digest('hex');

const engines=[['chromium',chromium],['webkit',webkit]].filter(([name])=>!process.env.QUIETPROOF_UI_ENGINE||process.env.QUIETPROOF_UI_ENGINE===name);
const chromiumPath=process.env.QUIETPROOF_CHROMIUM_EXECUTABLE;
for (const [name,engine] of engines) {
  test(`${name}: signature request/input/results and capability/error matrix`,{ timeout:900000 },async()=>{
    const browser=await engine.launch({ headless:true,...(name==='chromium'&&chromiumPath?{executablePath:chromiumPath}:{}),...(name==='webkit'&&process.env.QUIETPROOF_WEBKIT_EXECUTABLE?
      { executablePath:process.env.QUIETPROOF_WEBKIT_EXECUTABLE }:{}) });
    const directory=resolve(output,name);await mkdir(directory,{ recursive:true });
    const captures=[],downloads=[],errors=[];let page;
    async function zoom(layout) {
      const [width,height,scale]=layout;await page.setViewportSize({ width,height });
      await page.evaluate(scale=>{
        let style=document.querySelector('#signature-test-zoom');
        if(!style){style=document.createElement('style');style.id='signature-test-zoom';document.head.append(style);}
        style.textContent=`html, .quietproof-request, .quietproof-verify { font-size:${16*scale/100}px !important; line-height:1.6; }`;
      },scale);
    }
    async function capture(state,layout,section) {
      await zoom(layout);await page.evaluate(()=>scrollTo(0,0));await page.waitForTimeout(100);
      assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false,`${state} no page overflow`);
      const [width,height,scale]=layout,id=`${name}-${width}x${height}-${scale}-${state}`;
      const full=resolve(directory,id+'.png');await page.screenshot({ path:full,fullPage:true,animations:'disabled' });
      if(section){await section.evaluate(element=>element.scrollIntoView({block:'start'}));await page.screenshot({ path:resolve(directory,id+'-detail.png'),animations:'disabled' });}
      captures.push({ state,width,height,textZoom:scale,path:full,observedAt:new Date().toISOString() });
    }
    async function support(selector) {
      const button=page.getByRole('button',{ name:'Check signature support',exact:true });
      await button.focus();await page.keyboard.press('Enter');
      await page.locator(selector+' option[value="signature-possession"]').waitFor({ state:'attached' });
      await page.locator(selector).selectOption('signature-possession');
    }
    async function publicLookup(workflow) {
      await page.getByLabel('Bitcoin addresses').fill(workflow.claims.map(c=>c.address).join('\n'));
      await page.getByRole('button',{ name:'Look up outputs',exact:true }).click();
      const boxes=page.locator('.quietproof-claims').getByRole('checkbox');await boxes.first().waitFor();
      await boxes.first().focus();await page.keyboard.press('Space');
      for(let i=1;i<workflow.claims.length;i++)await boxes.nth(i).check();
      await page.getByLabel('Intended verifier').fill('signature-ui.example');
    }
    try {
      const workflow=workflows.find(w=>w.id==='mainnet-mixed-same-key');
      for(const layout of layouts){
        page=await browser.newPage({ viewport:{ width:layout[0],height:layout[1] },acceptDownloads:true });
        page.on('pageerror',e=>errors.push(e.message));
        let providerCalls=0;
        await page.route('https://blockstream.info/**',route=>{providerCalls++;return route.fulfill(providerResponse(workflow,route.request().url()));});
        await page.goto(origin+'/tool');await page.getByRole('button',{name:'Create request',exact:true}).waitFor();
        assert.equal(await page.locator('#qp-request-proof-mode').inputValue(),'signature-possession');
        assert.equal(await page.getByLabel('Purpose',{exact:true}).inputValue(),'proof-of-control');
        assert.equal(await page.getByLabel('Request lifetime').inputValue(),'300');
        assert.equal(await page.locator('#qp-request-proof-mode option[value="signature-possession"]').count(),1);
        await support('#qp-request-proof-mode');assert.equal(providerCalls,0,'capability lookup makes no explorer request');
        await publicLookup(workflow);
        assert.deepEqual(await page.getByLabel('Signing script kind').locator('option').evaluateAll(nodes=>nodes.map(n=>n.value)),['','p2wpkh','p2pkh']);
        assert.equal(await page.getByLabel('Signing script kind').inputValue(),'','mixed claims require an explicit signer');
        await page.getByLabel('Signing script kind').focus();await page.keyboard.press('ArrowDown');await page.keyboard.press('Enter');
        await page.getByLabel('Signing script kind').selectOption('p2wpkh');
        const create=page.getByRole('button',{name:'Create request',exact:true});await create.focus();await page.keyboard.press('Enter');
        const preview=page.getByRole('region',{name:'Canonical request preview'});await preview.waitFor();
        assert.match(await preview.innerText(),/Signature possession/);assert.match(await preview.innerText(),/does not establish signing time/);
        await capture('RequestForm',layout,preview);
        const event=page.waitForEvent('download');await page.getByRole('link',{name:'Download .qpr request',exact:true}).click();
        const file=await event;const bytes=await readFile(await file.path());assert.equal(bytes[4],4);
        const path=resolve(directory,`${name}-${layout[0]}-${layout[2]}.qpr`);await writeFile(path,bytes);
        const encodedInspection=new Uint8Array(61+bytes.length);encodedInspection.set(new TextEncoder().encode('QWI1'));encodedInspection.set(bytes,61);
        const inspected=decodeInspection(encodedInspection.buffer);
        assert.equal(inspected.statementVersion,4);assert.equal(inspected.proofMode,'signature-possession');
        assert.equal(inspected.signatureProfile,1);assert.equal(inspected.signingKind,'p2wpkh');
        assert.equal(inspected.verifier,'signature-ui.example');assert.equal(inspected.claims.length,2);
        assert.deepEqual(Buffer.from(inspected.requestBytes),bytes);
        downloads.push({ path,sha256:digest(bytes),inspected:{...inspected,requestBytes:undefined} });
        await page.getByLabel('Signing script kind').selectOption('p2pkh');assert.equal(await preview.count(),0,'mode-specific edits clear preview');
        const procedure=page.getByLabel('Signing procedure',{exact:true});
        assert.equal(await procedure.inputValue(),'2','P2PKH defaults to Bitcoin Signed Message');
        assert.equal(await procedure.locator('option').count(),2,'P2PKH exposes only two compatible procedures');
        await procedure.focus();await page.keyboard.press('Home');await page.keyboard.press('ArrowDown');await page.keyboard.press('Enter');
        await procedure.selectOption('1');
        await create.click();await preview.waitFor();
        assert.match(await preview.innerText(),/bip322-ecdsa-v1/);
        await capture('P2PKH-BIP322-alternative',layout,preview);
        await procedure.selectOption('2');assert.equal(await preview.count(),0,'profile edits clear preview');
        await create.click();await preview.waitFor();
        assert.match(await preview.innerText(),/Bitcoin Signed Message.*bitcoin-message-ecdsa-v1/s);
        await capture('P2PKH-legacy-default',layout,preview);
        await page.close();

        page=await browser.newPage({ viewport:{width:layout[0],height:layout[1]} });page.on('pageerror',e=>errors.push(e.message));
        await page.route('https://blockstream.info/**',route=>{throw new Error('Offline proof controls must not contact an explorer');});
        await page.goto(origin+'/verify');
        const inspect=page.getByRole('button',{name:'Inspect proof and policy',exact:true});await inspect.waitFor();
        const proofInput=page.getByLabel('Proof file (.qpf)',{exact:true});await proofInput.setInputFiles(upload('public.qpf',proof));
        assert.equal(await page.locator('#qp-verify-proof-mode').inputValue(),'signature-possession');
        await page.locator('#qp-verify-proof-mode').selectOption('key-knowledge');
        await page.getByLabel('Expected policy source').selectOption('none');
        await inspect.click();await page.getByRole('alert').filter({hasText:'Proof mode does not match'}).waitFor();
        await capture('mismatched-mode',layout);
        await support('#qp-verify-proof-mode');
        assert.equal(await page.getByLabel('Expected policy source').inputValue(),'request');
        assert.equal(await page.getByLabel('Expected policy source').locator('option').count(),1);
        await inspect.focus();await page.keyboard.press('Enter');await page.getByRole('alert').filter({hasText:'.qpr'}).waitFor();
        await capture('missing-request',layout);
        const expected=page.getByLabel('Expected request file (.qpr)',{exact:true});
        await expected.setInputFiles(upload('retained.qpr',request));
        await proofInput.setInputFiles(upload('private.qpa',Buffer.from('QPA1private fixture marker')));
        await inspect.click();await page.getByRole('alert').filter({hasText:'Private .qpa'}).waitFor();await capture('receipt-rejected',layout);
        await proofInput.setInputFiles(upload('renamed.qpf',Buffer.from('QPA1private fixture marker')));
        await inspect.click();await page.getByRole('alert').filter({hasText:'authorization receipt detected'}).waitFor();
        await proofInput.setInputFiles(upload('public.qpf',proof));
        await expected.focus();assert.equal(await page.evaluate(()=>document.activeElement.id),'qp-expected');
        await expected.setInputFiles(upload('wrong.qpr',wrong));await inspect.click();
        await page.getByRole('alert').filter({hasText:'Expected policy rejected'}).waitFor();await capture('mismatched-request',layout);
        await expected.setInputFiles(upload('retained.qpr',request));await inspect.click();
        await page.getByText('Expected policy matched at inspection time.',{exact:false}).waitFor();
        assert.equal(await page.getByLabel('Verification network (chosen independently)').inputValue(),'');
        const inspection=page.getByRole('region',{name:'Unverified inspection'});
        assert.match(await inspection.innerText(),/does not prove knowledge of the private key/);
        await capture('ProofInput',layout,inspection);
        if(layout!==layouts.at(-1))await page.close();
      }
      await page.getByLabel('Verification network (chosen independently)').selectOption('mainnet');
      await page.getByRole('button',{name:'Verify offline',exact:true}).click();
      await page.locator('[data-result=crypto]').filter({hasText:/^Valid$/}).waitFor({ timeout:240000 });
      const results=page.getByRole('region',{name:'Verification results'});
      assert.equal(await page.getByRole('heading',{name:'Separate verification results',exact:true}).evaluate(element=>element===document.activeElement),true,'completed results receive keyboard focus');
      assert.match(await results.innerText(),/Signature possession/);assert.match(await results.innerText(),/can be delegated/);
      assert.match(await results.innerText(),/does not prove knowledge of the private key/);
      assert.equal(await page.locator('[data-result=explorer]').innerText(),'Unavailable');
      for(const layout of layouts)await capture('results',layout,results);
      await page.close();
      for(const layout of layouts){
        page=await browser.newPage({viewport:{width:layout[0],height:layout[1]}});
        await page.goto(disabledOrigin+'/verify');await page.getByRole('button',{name:'Check signature support',exact:true}).click();
        await page.getByText('Signature possession is unavailable in this verifier build.',{exact:false}).waitFor();
        assert.equal(await page.locator('#qp-verify-proof-mode option[value="signature-possession"]').count(),1);
        assert.equal(await page.locator('#qp-verify-proof-mode').inputValue(),'signature-possession');
        await capture('disabled-capability',layout);await page.close();
        page=await browser.newPage({viewport:{width:layout[0],height:layout[1]}});
        await page.goto(disabledOrigin+'/tool');
        const check=page.getByRole('button',{name:'Check signature support',exact:true});await check.focus();await page.keyboard.press('Enter');
        await page.getByText('Signature possession is unavailable in this verifier build.',{exact:false}).waitFor();
        assert.equal(await page.locator('#qp-request-proof-mode option[value="signature-possession"]').count(),1);
        assert.equal(await page.locator('#qp-request-proof-mode').inputValue(),'signature-possession');
        await capture('RequestForm-disabled-capability',layout,page.locator('#qp-request-proof-mode').locator('..'));
        await page.close();
      }
      assert.deepEqual(errors,[]);
      await writeFile(resolve(directory,'matrix.json'),JSON.stringify({ engine:name,browserVersion:browser.version(),proofSha256:digest(proof),
        requestSha256:digest(request),captures,downloads,errors,realSignatureVerification:true,
        zoomMethod:'Repository text zoom: html and feature font size 16px/32px at fixed viewport; full-page and viewport detail captures.' },null,2));
      console.log(JSON.stringify({engine:name,captures:captures.length,downloads:downloads.length,realSignatureVerification:true}));
    } finally {await page?.close().catch(()=>{});await browser.close();}
  });
}

for (const [name,engine] of engines) {
  test(`${name}: single-kind defaults, profile refresh and native request summaries`,{timeout:180000},async()=>{
    const browser=await engine.launch({headless:true,...(name==='chromium'&&chromiumPath?{executablePath:chromiumPath}:{}),
      ...(name==='webkit'&&process.env.QUIETPROOF_WEBKIT_EXECUTABLE?{executablePath:process.env.QUIETPROOF_WEBKIT_EXECUTABLE}:{})});
    const workflow=workflows.find(w=>w.id==='mainnet-mixed-same-key'),records=[];
    try {
      for(const [width,height,scale] of layouts)for(const [kind,id] of [['p2pkh','2'],['p2wpkh','1']]){
        const page=await browser.newPage({viewport:{width,height},acceptDownloads:true});
        await page.route('https://blockstream.info/**',route=>route.fulfill(providerResponse(workflow,route.request().url())));
        await page.goto(origin+'/tool');await page.getByLabel('Bitcoin addresses').fill(workflow.claims.map(c=>c.address).join('\n'));
        await page.getByRole('button',{name:'Look up outputs',exact:true}).click();
        const row=page.locator('.quietproof-claims li').filter({hasText:new RegExp(kind.toUpperCase())});
        await row.getByRole('checkbox').check();await page.getByLabel('Intended verifier').fill('profile-parity.example');
        const procedure=page.getByLabel('Signing procedure',{exact:true});await procedure.waitFor();
        await page.waitForFunction(id=>document.querySelector('#qp-signing-profile').value===id,id);
        assert.equal(await page.getByLabel('Signing script kind').inputValue(),kind);
        assert.equal(await procedure.inputValue(),id);
        await page.addStyleTag({content:`html,.quietproof-request{font-size:${16*scale/100}px!important;line-height:1.6}`});
        for(const selected of kind==='p2pkh'?['2','1']:['1']){
          await procedure.selectOption(selected);await procedure.focus();assert.equal(await page.evaluate(()=>document.activeElement.id),'qp-signing-profile');
          await page.keyboard.press('Tab');assert.notEqual(await page.evaluate(()=>document.activeElement.id),'qp-signing-profile');
          await page.getByRole('button',{name:/^(Create|Regenerate) request$/}).click();
          const preview=page.getByRole('region',{name:'Canonical request preview'});await preview.waitFor();
          const profileName=selected==='2'?'bitcoin-message-ecdsa-v1':'bip322-ecdsa-v1';
          assert.match(await preview.innerText(),new RegExp(profileName));
          await page.getByRole('button',{name:'Check signature support',exact:true}).click();
          await page.waitForFunction(()=>!document.querySelector('#qp-signing-profile').disabled);
          assert.equal(await procedure.inputValue(),selected);assert.equal(await preview.count(),1,'capability refresh preserves an explicit compatible profile and preview');
          const event=page.waitForEvent('download');await page.getByRole('link',{name:'Download .qpr request',exact:true}).click();
          const downloaded=await event,publicPath=resolve(output,name,`${kind}-${selected}-${width}x${height}-${scale}.qpr`);
          await mkdir(resolve(output,name),{recursive:true});await downloaded.saveAs(publicPath);
          const native=JSON.parse(execFileSync(process.env.QUIETPROOF_NATIVE_CLI,['inspect',publicPath],{encoding:'utf8'}));
          assert.equal(native.request_version,4);assert.equal(native.profile_version,1);assert.equal(native.signing_profile,profileName);assert.equal(native.signing_kind,kind);
          assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);
          for(const [part,target] of [['selector',procedure],['summary',preview.locator('dt').filter({hasText:'Signing kind · procedure'})]]){
            await target.evaluate(el=>scrollTo(0,Math.max(0,scrollY+el.getBoundingClientRect().top-96)));
            await page.screenshot({path:publicPath.replace('.qpr',`-${part}.png`),animations:'disabled'});
          }
          records.push({width,height,scale,kind,profileName,native,publicPath,requestSha256:digest(await readFile(publicPath)),observedAt:new Date().toISOString()});
        }
        await page.close();
      }
      await writeFile(resolve(output,name,'native-request-parity.json'),JSON.stringify(records,null,2)+'\n');
      console.log(JSON.stringify({engine:name,nativeRequestParity:records.length}));
    }finally{await browser.close();}
  });
  test(`${name}: v3 and unknown-profile UI errors preserve expected request and selected mode`,{timeout:120000},async()=>{
    const browser=await engine.launch({headless:true,...(name==='chromium'&&chromiumPath?{executablePath:chromiumPath}:{}),
      ...(name==='webkit'&&process.env.QUIETPROOF_WEBKIT_EXECUTABLE?{executablePath:process.env.QUIETPROOF_WEBKIT_EXECUTABLE}:{})});
    try {
      const page=await browser.newPage();await page.goto(origin+'/verify');
      const input=page.getByLabel('Proof file (.qpf)',{exact:true});
      await page.getByLabel('Expected request file (.qpr)',{exact:true}).setInputFiles(upload('retained.qpr',request));
      const old=Buffer.from(proof);old[4]=3;
      const unknown=Buffer.from(proof);unknown[17]=255;unknown[9+request.length+10]=255;
      for(const [label,bytes,pattern] of [['v3',old,/v3.*unsupported.*fresh v4/],['unknown-profile',unknown,/profile.*unsupported/]]) {
        await input.setInputFiles(upload(label+'.qpf',bytes));await page.getByRole('button',{name:'Inspect proof and policy',exact:true}).click();
        const error=page.getByRole('alert');await error.waitFor();assert.match(await error.innerText(),pattern);
        assert.equal(await page.locator('#qp-verify-proof-mode').inputValue(),'signature-possession');
        assert.equal(await page.getByLabel('Expected request file (.qpr)',{exact:true}).evaluate(el=>el.files[0].name),'retained.qpr');
        for(const [width,height,scale] of layouts){
          await page.setViewportSize({width,height});await page.addStyleTag({content:`html,.quietproof-verify{font-size:${16*scale/100}px!important;line-height:1.6}`});
          assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);
          await error.scrollIntoViewIfNeeded();await mkdir(resolve(output,name),{recursive:true});
          await page.screenshot({path:resolve(output,name,`${label}-${width}x${height}-${scale}.png`),fullPage:true});
        }
      }
    }finally{await browser.close();}
  });
  test(`${name}: disabled default PoSC fails without fallback and explicit PoKC still creates requests`,{timeout:180000},async()=>{
    const browser=await engine.launch({headless:true,...(name==='chromium'&&chromiumPath?{executablePath:chromiumPath}:{}),...(name==='webkit'&&process.env.QUIETPROOF_WEBKIT_EXECUTABLE?
      {executablePath:process.env.QUIETPROOF_WEBKIT_EXECUTABLE}:{})});
    try {
      const page=await browser.newPage({acceptDownloads:true});
      const workflow=workflows.find(w=>w.id==='mainnet-mixed-same-key');let explorerCalls=0;
      await page.route('https://blockstream.info/**',route=>{explorerCalls++;return route.fulfill(providerResponse(workflow,route.request().url()));});
      await page.goto(disabledOrigin+'/tool');
      const mode=page.getByLabel('Proof mode',{exact:true});
      assert.equal(await mode.inputValue(),'signature-possession');
      await page.getByLabel('Bitcoin addresses').fill(workflow.claims.map(c=>c.address).join('\n'));
      await page.getByRole('button',{name:'Look up outputs',exact:true}).click();
      await page.locator('.quietproof-claims input[type=checkbox]').first().waitFor();
      for(const box of await page.locator('.quietproof-claims input[type=checkbox]').all())await box.check();
      await page.getByLabel('Intended verifier').fill('disabled-default.example');
      await page.getByText('Signature possession is unavailable in this verifier build.',{exact:false}).first().waitFor();
      assert.equal(await page.getByRole('button',{name:'Create request',exact:true}).isDisabled(),true);
      assert.equal(await mode.inputValue(),'signature-possession');
      assert.equal(await page.getByRole('link',{name:'Download .qpr request',exact:true}).count(),0);
      await mode.selectOption('key-knowledge');
      await page.getByRole('button',{name:'Create request',exact:true}).click();
      const download=page.waitForEvent('download');
      await page.getByRole('link',{name:'Download .qpr request',exact:true}).click();
      assert.equal((await readFile(await(await download).path()))[4],2,'explicit legacy mixed request retains v2');
      const before=explorerCalls;
      await page.goto(disabledOrigin+'/verify');
      const verificationMode=page.getByLabel('Proof mode (chosen independently)',{exact:true});
      assert.equal(await verificationMode.inputValue(),'signature-possession');
      await page.getByLabel('Proof file (.qpf)',{exact:true}).setInputFiles(upload('public.qpf',proof));
      await page.getByLabel('Expected request file (.qpr)',{exact:true}).setInputFiles(upload('retained.qpr',request));
      await page.getByLabel('Verification network (chosen independently)').selectOption('mainnet');
      await page.getByRole('button',{name:'Verify offline',exact:true}).click();
      const result=page.getByRole('region',{name:'Verification results'});await result.waitFor();
      assert.match(await result.innerText(),/unavailable|unsupported|not available/i);
      assert.equal(await page.locator('[data-result=crypto]').innerText(),'Not checked to completion');
      assert.equal(await verificationMode.inputValue(),'signature-possession');assert.equal(explorerCalls,before);
    } finally {await browser.close();}
  });
  test(`${name}: default PoSC verifies a retained request without a capability or mode selection`,{timeout:600000},async()=>{
    const browser=await engine.launch({headless:true,...(name==='chromium'&&chromiumPath?{executablePath:chromiumPath}:{}),...(name==='webkit'&&process.env.QUIETPROOF_WEBKIT_EXECUTABLE?
      {executablePath:process.env.QUIETPROOF_WEBKIT_EXECUTABLE}:{})});
    try {
      const page=await browser.newPage({viewport:{width:375,height:812}});
      await page.route('https://blockstream.info/**',()=>{throw new Error('Default offline verification must not contact an explorer');});
      await page.goto(origin+'/verify');
      const mode=page.getByLabel('Proof mode (chosen independently)',{exact:true});
      assert.equal(await mode.inputValue(),'signature-possession');
      assert.equal(await page.getByLabel('Expected policy source').inputValue(),'request');
      await page.getByLabel('Expected request file (.qpr)',{exact:true}).setInputFiles(upload('retained.qpr',request));
      const input=page.getByLabel('Proof file (.qpf)',{exact:true});
      const legacy=await readFile(new URL('../../../tests/wasm/fixtures/0.qpf',import.meta.url));
      await input.setInputFiles(upload('legacy.qpf',legacy));
      await page.getByRole('button',{name:'Inspect proof and policy',exact:true}).click();
      await page.getByRole('alert').filter({hasText:'Proof mode does not match'}).waitFor();
      assert.equal(await mode.inputValue(),'signature-possession','old proof versions never change the selected mode');
      for(const [family,profileName] of [['signature-p2pkh','bitcoin-message-ecdsa-v1'],['signature-p2wpkh','bip322-ecdsa-v1']]) {
        await input.setInputFiles(upload(family+'.qpf',await readFile(resolve(fixtureRoot,family+'.qpf'))));
        await page.getByLabel('Expected request file (.qpr)',{exact:true}).setInputFiles(upload(family+'.qpr',await readFile(resolve(fixtureRoot,family+'.qpr'))));
        await page.getByLabel('Verification network (chosen independently)').selectOption('mainnet');
        await page.getByRole('button',{name:'Verify offline',exact:true}).click();
        await page.locator('[data-result=crypto]').filter({hasText:/^Valid$/}).waitFor({timeout:240000});
        assert.equal(await mode.inputValue(),'signature-possession');
        assert.equal(await page.locator('[data-result=explorer]').innerText(),'Unavailable');
        assert.match(await page.locator('[data-result=profile]').innerText(),new RegExp('v4.*'+profileName));
        assert.match(await page.getByRole('region',{name:'Verification results'}).innerText(),/can be delegated/);
        await mkdir(resolve(output,name),{recursive:true});
        for(const [width,height,scale] of layouts) {
          await page.setViewportSize({width,height});
          await page.addStyleTag({content:`html,.quietproof-verify{font-size:${16*scale/100}px!important;line-height:1.6}`});
          assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);
          await page.locator('[data-result=profile]').scrollIntoViewIfNeeded();
          await page.screenshot({path:resolve(output,name,`${family}-${width}x${height}-${scale}-verified.png`),fullPage:true});
        }
        console.log(JSON.stringify({engine:name,family,profileName,version:browser.version(),defaultMode:'signature-possession',realSignatureVerification:true,manualCapabilityProbe:false}));
      }
    } finally {await browser.close();}
  });
}
