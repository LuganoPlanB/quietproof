import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { mkdir, readFile, writeFile, access, readdir } from 'node:fs/promises';
import { openSync, closeSync } from 'node:fs';
import { resolve } from 'node:path';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { chromium, webkit } from 'playwright';
import { roundtrips, observationResponse } from './fixtures.mjs';
import { RESOURCE_BUDGETS } from '../../tests/wasm/resources.mjs';

const origin=process.env.QUIETPROOF_SITE_ORIGIN || 'http://127.0.0.1:4178';
const cli=process.env.QUIETPROOF_NATIVE_CLI, output=process.env.QUIETPROOF_ROUNDTRIP_ARTIFACTS;
assert(cli && output,'Set current native CLI and a new roundtrip artifact directory.');
const directory=resolve(output,`${Date.now()}-${process.pid}`), materials=resolve(output,'materials');
const hash=bytes=>createHash('sha256').update(bytes).digest('hex');
const now=()=>new Date().toISOString();
const root=fileURLToPath(new URL('../../',import.meta.url));
const bindings={};
for (const path of ['package-lock.json','web/wasm/asset.mjs','web/wasm/runtime.mjs','web/wasm/codec.mjs','web/wasm/worker.mjs',
  'web/features/request/RequestForm.vue','web/features/request/download.mjs','web/features/verify/ProofInput.vue','web/features/verify/input.mjs',
  'web/features/verify/results.mjs','web/features/provider/discovery.mjs','web/features/provider/verification.mjs','web/features/provider/esplora.mjs',
  'docs/.vitepress/dist/tool.html','docs/.vitepress/dist/verify.html']) bindings[path]=hash(await readFile(resolve(root,path)));
const wasmPath=resolve(process.env.QUIETPROOF_WASM || resolve(root,'docs/public/wasm/quietproof.wasm'));
bindings[wasmPath]=hash(await readFile(wasmPath));
bindings.nativeCLI=hash(await readFile(cli));
const harnessSha256=hash(await readFile(new URL(import.meta.url)));
const engines=[['chromium',chromium],['webkit',webkit]];
const launch=(name,engine)=>engine.launch({headless:true,...(name==='webkit' && process.env.QUIETPROOF_WEBKIT_EXECUTABLE
  ? {executablePath:process.env.QUIETPROOF_WEBKIT_EXECUTABLE} : {})});

async function instrument(page) {
  await page.emulateMedia({reducedMotion:'reduce'});
  await page.addInitScript(()=>{
    const NativeWorker=Worker;
    window.__roundtrip={created:0,terminated:0,transfers:[],outcomes:[],maxGapMs:0,ticks:0};
    let last=performance.now();setInterval(()=>{const next=performance.now();window.__roundtrip.maxGapMs=Math.max(window.__roundtrip.maxGapMs,next-last);last=next;window.__roundtrip.ticks++;},20);
    window.__roundtrip.restartHeartbeat=()=>{last=performance.now();window.__roundtrip.maxGapMs=0;window.__roundtrip.ticks=0;};
    window.Worker=class extends NativeWorker {
      constructor(...args) {
        super(...args);window.__roundtrip.created++;let started,operation;
        const send=super.postMessage.bind(this);
        this.postMessage=(data,transfer)=>{
          const bytes=data.bytes,size=bytes?.byteLength??0;
          if(data.type==='verify'||data.type==='evaluate'){started=performance.now();operation=data.type;}
          send(data,transfer);
          if(size)window.__roundtrip.transfers.push({type:data.type,bytes:size,detached:bytes.byteLength===0});
        };
        this.addEventListener('message',({data})=>{
          if(data.cryptography && (data.phase==='verified'||data.phase==='finished')) window.__roundtrip.outcomes.push({
            operation,phase:data.phase,cryptography:data.cryptography,policy:data.policy,explorer:data.explorer,authorizes:data.authorizes,
            elapsedMs:performance.now()-started,linearMemoryBytes:data.linearMemoryBytes,receivedAt:Date.now()});
        });
      }
      terminate(){if(!this.closed){this.closed=true;window.__roundtrip.terminated++;}super.terminate();}
    };
  });
}

async function capture(page,label,detail) {
  const screenshots=[];
  for(const [width,height] of [[390,844],[1440,900]])for(const scale of [100,200]){
    await page.setViewportSize({width,height});
    await page.evaluate(scale=>{
      let style=document.querySelector('#qp-matrix-scale');if(!style){style=document.createElement('style');style.id='qp-matrix-scale';document.head.append(style);}
      style.textContent=`html,.quietproof-request,.quietproof-verify{font-size:${16*scale/100}px!important;line-height:1.6}`;
    },scale);
    await detail.scrollIntoViewIfNeeded();await page.waitForTimeout(350);
    assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false,label+' fits viewport');
    for(const full of [false,true]){
      const path=resolve(directory,`${label}-${width}-${scale}-${full?'full':'viewport'}.png`);
      await page.screenshot({path,fullPage:full,animations:'disabled'});screenshots.push(path);
    }
  }
  await page.setViewportSize({width:1440,height:900});await page.evaluate(()=>document.querySelector('#qp-matrix-scale')?.remove());
  return screenshots;
}

async function material(name,engine,workflow,lifetime=86400) {
  const folder=resolve(materials,name,lifetime===90?'expired':workflow.id);await mkdir(folder,{recursive:true});
  const recordPath=resolve(folder,'record.json');
  let existing=false;try{await access(recordPath);existing=true;}catch{}
  if(existing){
    const record=JSON.parse(await readFile(recordPath));assert.deepEqual(record.bindings,bindings,'Material source/artifact identity changed; use a new output directory.');
    assert.equal(hash(await readFile(record.qpr)),record.requestSha256);assert.equal(hash(await readFile(record.qpf)),record.proofSha256);
    assert.equal(record.selectedLifetime,lifetime);assert.deepEqual(record.workflow,workflow);
    return {...record,materialReused:true};
  }
  assert.equal((await readdir(folder)).length,0,'Incomplete material is retained; choose a new artifact root rather than overwrite it.');
  const browser=await launch(name,engine);let page;
  try{
    page=await browser.newPage({acceptDownloads:true});const requests=[];
    await page.route('https://blockstream.info/**',route=>{
      const r=route.request();requests.push({url:r.url(),method:r.method(),body:r.postData()});
      assert.equal(r.method(),'GET');assert.equal(r.postData(),null);
      return route.fulfill(observationResponse(workflow,r.url()));
    });
    await page.goto(origin+'/tool');
    const create=page.getByRole('button',{name:'Create request',exact:true});await create.waitFor();
    await page.getByLabel('Bitcoin network',{exact:true}).selectOption(workflow.network);
    await page.getByLabel('Bitcoin addresses').fill(workflow.claims.map(c=>c.address).join('\n'));assert.equal(requests.length,0);
    await page.getByRole('button',{name:'Look up outputs',exact:true}).click();
    await page.locator('.quietproof-claims').getByRole('checkbox').first().waitFor();
    assert.equal(await page.locator('.quietproof-claims').getByRole('checkbox').count(),workflow.claims.length);
    for(const box of await page.locator('.quietproof-claims').getByRole('checkbox').all())await box.check();
    await page.getByLabel('Intended verifier').fill('adversarial-roundtrip.example');
    await page.getByLabel('Purpose',{exact:true}).selectOption('proof-of-funds');
    await page.getByLabel('Message (optional').fill('Public disposable browser request/native proof/browser verification');
    assert.equal(await page.getByLabel('Request lifetime').inputValue(),'300');
    await page.getByLabel('Request lifetime').fill(String(lifetime));await create.click();
    const preview=page.getByRole('region',{name:'Canonical request preview'});await preview.waitFor();
    const qpr=resolve(folder,'request.qpr'),qpf=resolve(folder,'proof.qpf');
    const event=page.waitForEvent('download');await page.getByRole('link',{name:'Download .qpr request',exact:true}).click();await(await event).saveAs(qpr);
    const requestBytes=await readFile(qpr),inspected=JSON.parse(execFileSync(cli,['inspect',qpr],{encoding:'utf8'}));
    assert.equal(inspected.network,workflow.network);assert.equal(inspected.statement_version,workflow.version);
    assert.equal(inspected.claims,workflow.claims.length);assert.equal(inspected.expires_at-inspected.not_before,lifetime);
    assert.deepEqual(inspected.script_kinds,workflow.claims.map(c=>c.scriptKind));
    await page.screenshot({path:resolve(folder,'browser-request.png'),fullPage:true,animations:'disabled'});
    const command=[cli,'prove','--request',qpr,'--output',qpf,'--network',workflow.network];
    const log=resolve(folder,'native-prove.log'),fd=openSync(log,'w'),startedAt=now(),start=performance.now();let stdout;
    try{
      // Public disposable scalars are native stdin only; never page/worker/URL inputs.
      const input=workflow.publicDisposableScalars.map(n=>n.toString(16).padStart(64,'0')).join('\n')+'\n';
      stdout=execFileSync(command[0],command.slice(1),{input,encoding:'utf8',timeout:600000,stdio:['pipe','pipe',fd]});
    }finally{closeSync(fd);}
    const summary=JSON.parse(stdout);assert.equal(summary.result,'proof_created');assert(summary.proof_bytes>40*1024*1024);
    const proofBytes=await readFile(qpf);assert.equal(proofBytes.subarray(0,4).toString(),'QPE1');
    assert.deepEqual(proofBytes.subarray(9,9+proofBytes.readUInt32BE(5)),requestBytes,'Native proof embeds the exact browser download.');
    const record={workflow,engine:name,browserVersion:browser.version(),origin,bindings,harnessSha256,defaultLifetime:300,selectedLifetime:lifetime,
      qpr,qpf,requestSha256:hash(requestBytes),proofSha256:hash(proofBytes),requestBytes:requestBytes.length,proofBytes:proofBytes.length,
      inspected,discoveryRequests:requests,publicDisposableScalars:workflow.publicDisposableScalars,inputChannel:'native CLI stdin only',
      nativeProving:{command,cwd:process.cwd(),exit:0,observedAt:startedAt,completedAt:now(),elapsedSeconds:(performance.now()-start)/1000,log,summary},
      exactEmbeddedRequest:true,materialReused:false};
    await writeFile(recordPath,JSON.stringify(record,null,2)+'\n');console.log(`${name} ${workflow.id}: browser request natively proved (${lifetime}s explicit lifetime)`);
    return record;
  }finally{await page?.close();await browser.close();}
}

before(async()=>{await mkdir(directory,{recursive:true});await material('chromium',chromium,roundtrips[0],90);});

async function prepare(page,record) {
  await page.goto(origin+'/verify');
  await page.getByRole('button',{name:'Verify offline',exact:true}).waitFor();
  await page.waitForFunction(()=>!document.querySelector('.quietproof-verify button[type=submit]').disabled);
  assert.match(await page.locator('meta[http-equiv="Content-Security-Policy"]').getAttribute('content'),/script-src 'self' 'wasm-unsafe-eval'/);
  await page.getByLabel('Proof file (.qpf)',{exact:true}).setInputFiles(record.qpf);
  await page.getByLabel('Expected policy source').selectOption('request');
  await page.getByLabel('Expected request file (.qpr)',{exact:true}).setInputFiles(record.qpr);
  await page.getByLabel('Verification network (chosen independently)').selectOption(record.workflow.network);
}
async function metrics(page) {
  return page.evaluate(()=>{const r=window.__roundtrip;return {created:r.created,terminated:r.terminated,transfers:r.transfers,
    outcomes:r.outcomes,maxGapMs:r.maxGapMs,ticks:r.ticks};});
}
async function check(page,{crypto,policy='Matched at check time',explorer='Unavailable',button='Verify offline'}) {
  const observedAt=now();await page.evaluate(()=>window.__roundtrip.restartHeartbeat());
  await page.getByRole('button',{name:button,exact:true}).click();
  await page.locator('[data-result=crypto]').filter({hasText:new RegExp('^'+crypto+'$')}).waitFor({timeout:300000});
  assert.equal(await page.locator('[data-result=policy]').innerText(),policy);
  assert.equal(await page.locator('[data-result=explorer]').innerText(),explorer);
  const heading=page.getByRole('heading',{name:'Separate verification results'});
  assert.equal(await heading.evaluate(el=>el===document.activeElement),true);
  const measured=await metrics(page);
  assert.equal(measured.created,measured.terminated,'all operation workers are disposed');
  assert(measured.transfers.every(t=>t.detached),'binary transfer detaches every sender');
  return {observedAt,completedAt:now(),crypto,policy,explorer,metrics:measured};
}
function budgets(record) {
  const result=record.metrics.outcomes.filter(o=>o.operation==='verify').at(-1);
  assert(result && result.cryptography==='valid' && result.policy==='matched');
  assert.equal(result.authorizes,false);assert.equal(result.explorer,'unavailable');
  const limit=RESOURCE_BUDGETS.verifyMs['one-key'];
  assert(result.elapsedMs<=limit,`unchanged verification timing budget: ${result.elapsedMs}ms > ${limit}ms`);
  assert(result.linearMemoryBytes<=RESOURCE_BUDGETS.linearMemoryBytes,'linear-memory regression budget');
  assert(record.metrics.maxGapMs<=RESOURCE_BUDGETS.heartbeatGapMs,'computation leaves the main thread responsive');
}
async function failure(page,label,error) {
  const record={label,failedAt:now(),bindings,harnessSha256,error:{name:error.name,message:error.message,stack:error.stack},
    metrics:await metrics(page).catch(()=>null),source:'local',completeness:'failed'};
  await writeFile(resolve(directory,label+'-failed.json'),JSON.stringify(record,null,2)+'\n');
  await writeFile(resolve(directory,label+'-failed.txt'),await page.locator('body').innerText().catch(()=>'Page unavailable'));
  await page.screenshot({path:resolve(directory,label+'-failed.png'),fullPage:true,animations:'disabled'}).catch(()=>{});
}

for(const [name,engine] of engines){
  for(const workflow of roundtrips){
    test(`${name}: browser request/native prove/browser verify ${workflow.id}`,{timeout:900000},async()=>{
      const fixture=await material(name,engine,workflow),browser=await launch(name,engine);let page;
      const requests=[];
      try{
        page=await browser.newPage();await instrument(page);
        await page.route('https://blockstream.info/**',async route=>{
          const r=route.request();requests.push({url:r.url(),method:r.method(),body:r.postData()});
          assert.equal(r.method(),'GET');assert.equal(r.postData(),null);
          assert(r.url().startsWith(`https://blockstream.info/${workflow.network==='mainnet'?'api/':'signet/api/'}`));
          assert((await metrics(page)).outcomes.some(o=>o.operation==='verify'&&o.cryptography==='valid'),'real cryptography precedes explorer observations');
          return route.fulfill(observationResponse(workflow,r.url()));
        });
        await prepare(page,fixture);
        await page.getByRole('checkbox',{name:'After valid cryptography',exact:false}).check();assert.equal(requests.length,0);
        const result=await check(page,{crypto:'Valid',explorer:'Reported unspent under selected limits',button:'Verify and check explorer'});budgets(result);
        assert(requests.length>0);const evaluation=result.metrics.outcomes.at(-1);
        assert.equal(evaluation.operation,'evaluate');assert.equal(evaluation.authorizes,false);assert.equal(evaluation.explorer,'reported_unspent');
        assert.match(await page.getByRole('region',{name:'Verification results',exact:true}).innerText(),/does not authorize acceptance/);
        const screenshots=await capture(page,`${name}-${workflow.id}-valid`,page.getByRole('heading',{name:'Separate verification results'}));
        const record={scenario:workflow.id,engine:name,browserVersion:browser.version(),fixture,bindings,harnessSha256,result,screenshots,
          providerRequests:requests,source:'local',completeness:'complete'};
        await writeFile(resolve(directory,`${name}-${workflow.id}.json`),JSON.stringify(record,null,2)+'\n');
        console.log(JSON.stringify({engine:name,scenario:workflow.id,realCryptography:result.crypto,keys:workflow.keyCount,
          version:workflow.version,network:workflow.network,metrics:result.metrics.outcomes.at(-1),workers:[result.metrics.created,result.metrics.terminated]}));
      }catch(error){if(page)await failure(page,`${name}-${workflow.id}`,error);throw error;}
      finally{await page?.close();await browser.close();}
    });
  }
  test(`${name}: corrupt, wrong-context, naturally expired, provider failure and repeated real proof`,{timeout:900000},async()=>{
    const workflow=roundtrips[0],fixture=await material(name,engine,workflow),expired=await material('chromium',chromium,workflow,90);
    const browser=await launch(name,engine);let page,mode='deny',barrier=0;const requests=[],records=[];
    try{
      page=await browser.newPage();await instrument(page);
      await page.route('https://blockstream.info/**',async route=>{
        const r=route.request();requests.push({url:r.url(),method:r.method(),body:r.postData(),observedAt:now()});
        assert.equal(r.method(),'GET');assert.equal(r.postData(),null);assert(r.url().startsWith('https://blockstream.info/api/'));
        assert.equal(r.headers().authorization,undefined);assert.equal(r.headers().cookie,undefined);
        assert((await metrics(page)).outcomes.slice(barrier).some(o=>o.cryptography==='valid'),'current cryptography before provider access');
        return mode==='outage'?route.abort('failed'):route.fulfill(observationResponse(workflow,r.url()));
      });
      await prepare(page,fixture);
      const proofInput=page.getByLabel('Proof file (.qpf)',{exact:true}),expected=page.getByLabel('Expected request file (.qpr)',{exact:true});
      const online=page.getByRole('checkbox',{name:'After valid cryptography',exact:false});await online.check();assert.equal(requests.length,0);
      const corrupted=Buffer.from(await readFile(fixture.qpf));corrupted[corrupted.length-1]^=1;
      await proofInput.setInputFiles({name:'corrupted.qpf',buffer:corrupted,mimeType:'application/octet-stream'});
      const invalid=await check(page,{crypto:'Invalid — do not accept',button:'Verify and check explorer'});
      assert.equal(requests.length,0);records.push({scenario:'corrupt',...invalid,screenshots:await capture(page,`${name}-corrupt`,page.getByRole('heading',{name:'Separate verification results'}))});
      await proofInput.setInputFiles(fixture.qpf);
      const wrong=Buffer.from(await readFile(fixture.qpr));wrong[wrong.length-1]^=1;
      const wrongPath=resolve(directory,`${name}-wrong-context.qpr`);await writeFile(wrongPath,wrong);await expected.setInputFiles(wrongPath);
      const mismatch=await check(page,{crypto:'Not checked to completion',policy:'Rejected — do not accept',button:'Verify and check explorer'});
      assert.equal(requests.length,0);records.push({scenario:'wrong-context',...mismatch,screenshots:await capture(page,`${name}-wrong-context`,page.getByRole('heading',{name:'Separate verification results'}))});
      // This is the original native proof and original browser request. Wait
      // only if a focused diagnostic run reaches the negative case early.
      const deadline=Date.now()+95000;
      while(Math.floor(Date.now()/1000)<expired.inspected.expires_at){assert(Date.now()<deadline,'actual fixture expiry wait bounded');await new Promise(r=>setTimeout(r,250));}
      await proofInput.setInputFiles(expired.qpf);await expected.setInputFiles(expired.qpr);
      assert(await page.evaluate(expires=>Math.floor(Date.now()/1000)>=expires,expired.inspected.expires_at),'normal browser clock sees true expiry');
      const stale=await check(page,{crypto:'Not checked to completion',policy:'Rejected — do not accept',button:'Verify and check explorer'});
      assert.equal(requests.length,0);records.push({scenario:'naturally-expired',fixture:expired,...stale,screenshots:await capture(page,`${name}-expired`,page.getByRole('heading',{name:'Separate verification results'}))});
      await proofInput.setInputFiles(fixture.qpf);await expected.setInputFiles(fixture.qpr);mode='outage';barrier=(await metrics(page)).outcomes.length;
      const outage=await check(page,{crypto:'Valid',button:'Verify and check explorer'});budgets(outage);
      assert.equal(requests.length,1,'provider outage is bounded without retries');
      assert.match(await page.getByRole('region',{name:'Verification results',exact:true}).innerText(),/could not supply usable fresh observations/);
      records.push({scenario:'provider-outage',...outage,screenshots:await capture(page,`${name}-outage`,page.getByRole('heading',{name:'Separate verification results'}))});
      await online.uncheck();const before=requests.length;
      const repeated=await check(page,{crypto:'Valid'});budgets(repeated);assert.equal(requests.length,before);
      records.push({scenario:'repeated-offline-recovery',...repeated,screenshots:await capture(page,`${name}-repeated`,page.getByRole('heading',{name:'Separate verification results'}))});
      await writeFile(resolve(directory,`${name}-adversarial.json`),JSON.stringify({engine:name,browserVersion:browser.version(),fixture,
        bindings,harnessSha256,records,providerRequests:requests,source:'local',completeness:'complete'},null,2)+'\n');
      console.log(JSON.stringify({engine:name,adversarialScenarios:records.map(r=>r.scenario),outbound:requests,workers:(await metrics(page)).terminated}));
    }catch(error){if(page)await failure(page,`${name}-adversarial`,error);throw error;}
    finally{await page?.close();await browser.close();}
  });
}
