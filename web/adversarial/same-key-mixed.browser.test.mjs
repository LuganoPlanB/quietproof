import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { openSync, closeSync } from 'node:fs';
import { resolve } from 'node:path';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { chromium, webkit } from 'playwright';
import { workflows } from '../features/request/workflow-fixtures.mjs';
import { observationResponse } from './fixtures.mjs';
import { RESOURCE_BUDGETS } from '../../tests/wasm/resources.mjs';

const origin=process.env.QUIETPROOF_SITE_ORIGIN || 'http://127.0.0.1:4178';
const cli=process.env.QUIETPROOF_NATIVE_CLI,output=process.env.QUIETPROOF_ROUNDTRIP_ARTIFACTS;
assert(cli && output,'Supply the current native CLI and new artifact directory.');
const directory=resolve(output,`same-key-mixed-${Date.now()}-${process.pid}`);
const root=fileURLToPath(new URL('../../',import.meta.url)),hash=b=>createHash('sha256').update(b).digest('hex');
const bindings={nativeCLI:hash(await readFile(cli)),harness:hash(await readFile(new URL(import.meta.url)))};
for(const path of ['package-lock.json','docs/.vitepress/dist/tool.html','docs/.vitepress/dist/verify.html','docs/public/wasm/quietproof.wasm',
  'web/wasm/runtime.mjs','web/wasm/codec.mjs','web/wasm/worker.mjs','web/features/verify/ProofInput.vue','web/features/provider/verification.mjs'])
  bindings[path]=hash(await readFile(resolve(root,path)));
before(()=>mkdir(directory,{recursive:true}));

for(const [name,engine] of [['chromium',chromium],['webkit',webkit]])for(const network of ['mainnet','signet']){
  test(`${name}: one-key mixed P2WPKH/P2PKH real roundtrip ${network}`,{timeout:600000},async()=>{
    const first=workflows.find(w=>w.id===`${network}-p2wpkh`).claims[0];
    const second={...workflows.find(w=>w.id===`${network}-p2pkh`).claims[0],txid:'cd'.repeat(32),amountSats:'50001'};
    const workflow={id:`${network}-mixed-one-key`,network,version:2,claims:[first,second]};
    assert.equal(first.program,second.program);assert.notEqual(first.address,second.address);
    const browser=await engine.launch({headless:true,...(name==='webkit' && process.env.QUIETPROOF_WEBKIT_EXECUTABLE
      ? {executablePath:process.env.QUIETPROOF_WEBKIT_EXECUTABLE} : {})});
    const stem=resolve(directory,`${name}-${network}`),requests=[];let page,phase='discovery';
    try{
      page=await browser.newPage({acceptDownloads:true});await page.emulateMedia({reducedMotion:'reduce'});
      await page.addInitScript(()=>{
        const NativeWorker=Worker;window.__mixed={created:0,terminated:0,outcomes:[],transfers:[]};
        window.Worker=class extends NativeWorker{
          constructor(...args){
            super(...args);window.__mixed.created++;let started,operation;const send=super.postMessage.bind(this);
            this.postMessage=(data,transfer)=>{const bytes=data.bytes,size=bytes?.byteLength??0;
              if(data.type==='verify'||data.type==='evaluate'){operation=data.type;started=performance.now();}
              send(data,transfer);if(size)window.__mixed.transfers.push({type:data.type,bytes:size,detached:bytes.byteLength===0});};
            this.addEventListener('message',({data})=>{if(data.cryptography && ['verified','finished'].includes(data.phase))window.__mixed.outcomes.push({operation,
              cryptography:data.cryptography,policy:data.policy,explorer:data.explorer,authorizes:data.authorizes,totalSats:data.totalSats,
              elapsedMs:performance.now()-started,linearMemoryBytes:data.linearMemoryBytes});});
          }
          terminate(){if(!this.closed){this.closed=true;window.__mixed.terminated++;}super.terminate();}
        };
      });
      await page.route('https://blockstream.info/**',async route=>{
        const r=route.request();requests.push({phase,url:r.url(),method:r.method(),body:r.postData()});
        assert.equal(r.method(),'GET');assert.equal(r.postData(),null);
        assert(r.url().startsWith(`https://blockstream.info/${network==='mainnet'?'api/':'signet/api/'}`));
        if(phase==='verification')assert(await page.evaluate(()=>window.__mixed.outcomes.some(o=>o.operation==='verify'&&o.cryptography==='valid')));
        return route.fulfill(observationResponse(workflow,r.url()));
      });
      await page.goto(origin+'/tool');const create=page.getByRole('button',{name:'Create request',exact:true});await create.waitFor();
      await page.getByLabel('Bitcoin network',{exact:true}).selectOption(network);
      await page.getByLabel('Bitcoin addresses').fill([first.address,second.address].join('\n'));assert.equal(requests.length,0);
      await page.getByRole('button',{name:'Look up outputs',exact:true}).click();await page.locator('.quietproof-claims').getByRole('checkbox').first().waitFor();
      for(const box of await page.locator('.quietproof-claims').getByRole('checkbox').all())await box.check();
      assert.match(await page.locator('.quietproof-total').innerText(),/1\/2 key fingerprints/);
      await page.getByLabel('Intended verifier').fill('same-key-mixed.example');
      await page.getByLabel('Purpose',{exact:true}).selectOption('proof-of-funds');
      await page.getByLabel('Message (optional').fill('One public disposable spend key, two script kinds');
      assert.equal(await page.getByLabel('Request lifetime').inputValue(),'300');await page.getByLabel('Request lifetime').fill('86400');await create.click();
      await page.getByRole('region',{name:'Canonical request preview'}).waitFor();
      const qpr=stem+'.qpr',qpf=stem+'.qpf',download=page.waitForEvent('download');
      await page.getByRole('link',{name:'Download .qpr request',exact:true}).click();await(await download).saveAs(qpr);
      const qprBytes=await readFile(qpr),inspected=JSON.parse(execFileSync(cli,['inspect',qpr],{encoding:'utf8'}));
      assert.equal(inspected.statement_version,2);assert.equal(inspected.claims,2);assert.equal(inspected.network,network);
      assert.deepEqual(inspected.script_kinds,['p2wpkh','p2pkh']);assert.equal(inspected.expires_at-inspected.not_before,86400);
      const command=[cli,'prove','--request',qpr,'--output',qpf,'--network',network],log=stem+'-prove.log',fd=openSync(log,'w');
      const startedAt=new Date().toISOString();let stdout;
      try{stdout=execFileSync(command[0],command.slice(1),{input:'0'.repeat(63)+'1\n',encoding:'utf8',timeout:600000,stdio:['pipe','pipe',fd]});}
      finally{closeSync(fd);}
      const native={command,cwd:process.cwd(),exit:0,observedAt:startedAt,completedAt:new Date().toISOString(),log,summary:JSON.parse(stdout),
        publicDisposableScalars:[1],inputChannel:'native CLI stdin only'};assert.equal(native.summary.result,'proof_created');
      const qpfBytes=await readFile(qpf);assert(qpfBytes.length>40*1024*1024 && qpfBytes.length<60*1024*1024,'one-key proof family');
      assert.deepEqual(qpfBytes.subarray(9,9+qpfBytes.readUInt32BE(5)),qprBytes);
      phase='verification';await page.goto(origin+'/verify');await page.getByRole('button',{name:'Verify offline',exact:true}).waitFor();
      assert.match(await page.locator('meta[http-equiv="Content-Security-Policy"]').getAttribute('content'),/script-src 'self' 'wasm-unsafe-eval'/);
      await page.getByLabel('Proof file (.qpf)',{exact:true}).setInputFiles(qpf);await page.getByLabel('Expected policy source').selectOption('request');
      await page.getByLabel('Expected request file (.qpr)',{exact:true}).setInputFiles(qpr);
      await page.getByLabel('Verification network (chosen independently)').selectOption(network);
      await page.getByRole('checkbox',{name:'After valid cryptography',exact:false}).check();
      const observedAt=new Date().toISOString();await page.getByRole('button',{name:'Verify and check explorer',exact:true}).click();
      await page.locator('[data-result=crypto]').filter({hasText:/^Valid$/}).waitFor({timeout:300000});
      await page.locator('[data-result=explorer]').filter({hasText:/^Reported unspent under selected limits$/}).waitFor({timeout:300000});
      assert.equal(await page.locator('[data-result=policy]').innerText(),'Matched at check time');
      assert.equal(await page.locator('[data-result=explorer]').innerText(),'Reported unspent under selected limits');
      const metrics=await page.evaluate(()=>window.__mixed),verified=metrics.outcomes.find(o=>o.operation==='verify');
      assert.equal(metrics.created,metrics.terminated);assert(metrics.transfers.every(t=>t.detached));
      assert.equal(verified.authorizes,false);assert(verified.elapsedMs<=RESOURCE_BUDGETS.verifyMs['one-key']);assert(verified.linearMemoryBytes<=RESOURCE_BUDGETS.linearMemoryBytes);
      assert.equal(metrics.outcomes.at(-1).operation,'evaluate');assert.equal(metrics.outcomes.at(-1).authorizes,false);
      assert.equal(metrics.outcomes.at(-1).totalSats,'100001','both same-key script claims are included in WASM assessment');
      const screenshots=[];
      for(const [width,height] of [[390,844],[1440,900]])for(const scale of [100,200]){
        await page.setViewportSize({width,height});await page.evaluate(scale=>{let s=document.querySelector('#same-key-scale');if(!s){s=document.createElement('style');s.id='same-key-scale';document.head.append(s);}s.textContent=`html,.quietproof-verify{font-size:${16*scale/100}px!important;line-height:1.6}`;},scale);
        await page.getByRole('heading',{name:'Separate verification results'}).scrollIntoViewIfNeeded();await page.waitForTimeout(350);
        assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);
        const path=stem+`-${width}-${scale}.png`;await page.screenshot({path,animations:'disabled'});screenshots.push(path);
      }
      await writeFile(stem+'.json',JSON.stringify({scenario:workflow.id,keyCount:1,claimCount:2,engine:name,browserVersion:browser.version(),bindings,workflow,
        qpr,qpf,requestSha256:hash(qprBytes),proofSha256:hash(qpfBytes),requestBytes:qprBytes.length,proofBytes:qpfBytes.length,exactEmbeddedRequest:true,
        inspected,native,verification:{observedAt,completedAt:new Date().toISOString(),cryptography:'valid',policy:'matched',explorer:'reported_unspent',authorizes:false,metrics},requests,screenshots},null,2)+'\n');
      console.log(JSON.stringify({engine:name,network,scenario:workflow.id,keyCount:1,claimCount:2,verified,workers:[metrics.created,metrics.terminated]}));
    }catch(error){
      await writeFile(stem+'-failed.json',JSON.stringify({error:{message:error.message,stack:error.stack},metrics:await page?.evaluate(()=>window.__mixed).catch(()=>null)},null,2)+'\n');
      await page?.screenshot({path:stem+'-failed.png',fullPage:true}).catch(()=>{});throw error;
    }finally{await page?.close();await browser.close();}
  });
}
