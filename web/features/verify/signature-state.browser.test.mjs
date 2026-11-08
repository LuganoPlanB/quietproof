import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile, mkdir, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { chromium, webkit } from 'playwright';
import { decodeInspection } from '../../wasm/codec.mjs';
import { NETWORKS } from '../provider/esplora.mjs';
import { workflows, providerResponse } from '../request/workflow-fixtures.mjs';

const origin=process.env.QUIETPROOF_SITE_ORIGIN,disabledOrigin=process.env.QUIETPROOF_DISABLED_SITE_ORIGIN;
const directory=process.env.QUIETPROOF_SIGNATURE_STATE_ARTIFACTS,fixtures=process.env.QUIETPROOF_VERIFY_FIXTURES;
const signatureMode=process.env.QUIETPROOF_SIGNATURE_MODE==='1',subpath=process.env.QUIETPROOF_SIGNATURE_STATE_SUBPATH==='1';
assert(origin&&directory&&fixtures,'Site, public native fixtures and evidence directory required.');
const hash=bytes=>createHash('sha256').update(bytes).digest('hex');
const decode=bytes=>{const value=new Uint8Array(61+bytes.length);value.set(new TextEncoder().encode('QWI1'));value.set(bytes,61);return decodeInspection(value.buffer);};
const load=async name=>{
  const [proof,request,provenance]=await Promise.all(['qpf','qpr','json'].map(ext=>readFile(resolve(fixtures,name+'.'+ext))));
  assert(JSON.parse(provenance).nativeVerified);const metadata=decode(request);
  assert(BigInt(metadata.expiresAt)>BigInt(Math.floor(Date.now()/1000)+3600));
  return {name,proof,request,metadata,proofSha256:hash(proof),requestSha256:hash(request)};
};
const legacy=await load('one-key'),signature=signatureMode?await load('signature-max16'):null;
if(signature)assert.equal(signature.metadata.claims.length,16);
const layouts=[[390,844,100],[390,844,200],[1280,800,100],[1280,800,200]];
const upload=(name,buffer)=>({name,buffer,mimeType:'application/octet-stream'});
const marker='PRIVATE_BROWSER_RECEIPT_MARKER';
const consent='Keep future requests and completed check records locally';
const mixed=workflows.find(w=>w.id==='mainnet-mixed-same-key');
const workflow={...mixed,claims:signature?signature.metadata.claims.map(c=>({...mixed.claims.find(t=>t.scriptKind===c.scriptKind),...c})):mixed.claims};

async function storage(page){return page.evaluate(async()=>{
  const state=await new Promise((resolve,reject)=>{
    const open=indexedDB.open('quietproof-local-history-v1',1);
    open.onerror=()=>reject(new Error('History inspection failed'));
    open.onsuccess=()=>{const db=open.result;
      if(!db.objectStoreNames.contains('state')){db.close();resolve(null);return;}
      const tx=db.transaction('state','readonly'),get=tx.objectStore('state').get('local');
      get.onsuccess=()=>resolve(get.result??null);tx.oncomplete=()=>db.close();tx.onerror=()=>reject(new Error('History read failed'));
    };
  });
  return {localStorage:{...localStorage},sessionStorage:{...sessionStorage},
    state:state?{...state,requests:state.requests.map(row=>({...row,bytes:[...new Uint8Array(row.bytes)]}))}:null};
});}

for(const [engine,type] of [['chromium',chromium],['webkit',webkit]])test(`${engine}: public signature funds/export/history ${subpath?'subpath':'full root'} qualification`,{timeout:2400000},async()=>{
  const browser=await type.launch({headless:true,...(engine==='webkit'&&process.env.QUIETPROOF_WEBKIT_EXECUTABLE?
    {executablePath:process.env.QUIETPROOF_WEBKIT_EXECUTABLE}:{})});
  const out=resolve(directory,engine);await mkdir(out,{recursive:true});
  const records=[],screens=[],historyScreens=[],requests=[],errors=[];let page,context,mode='lookup',tipReads=0,active=signature??legacy;
  const position=locator=>locator.evaluate(element=>scrollTo(0,Math.max(0,scrollY+element.getBoundingClientRect().top-96)));
  async function capture(state){
    for(const [width,height,scale] of layouts){
      await page.setViewportSize({width,height});await page.evaluate(scale=>{
        let style=document.querySelector('#qp-state-zoom');if(!style){style=document.createElement('style');style.id='qp-state-zoom';document.head.append(style);}
        style.textContent=`html,.quietproof-request,.quietproof-verify{font-size:${16*scale/100}px!important;line-height:1.6}`;scrollTo(0,0);
      },scale);
      assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false,state+' fits viewport');
      const funds=page.locator('[data-result=funds]'),hasFunds=await funds.count();
      const primary=hasFunds?page.getByRole('heading',{name:'Separate verification results',exact:true}):page.getByRole('alert').first();
      await position(primary);
      // A max16 statement at 200% text zoom can exceed WebKit's 32767px
      // full-page image limit. Keep exact viewport images of the result,
      // qualification and trust limits; complete public claims remain in JSON.
      const path=resolve(out,`${engine}-${width}x${height}-${scale}-${state}.png`);await page.screenshot({path,animations:'disabled'});
      if(hasFunds){
        await funds.evaluate(element=>{const label=element.previousElementSibling;scrollTo(0,Math.max(0,scrollY+label.getBoundingClientRect().top-96));});
        await page.screenshot({path:path.replace('.png','-detail.png'),animations:'disabled'});
        await position(page.getByText(/^Cryptographic validity alone does not establish current funds\./));
        await page.screenshot({path:path.replace('.png','-limits.png'),animations:'disabled'});
      }
      screens.push({state,width,height,textZoom:scale,path,capture:'viewport; result plus qualification/trust detail images',
        documentHeight:await page.evaluate(()=>document.documentElement.scrollHeight),observedAt:new Date().toISOString()});
    }
    await page.setViewportSize({width:1280,height:800});await page.evaluate(()=>document.querySelector('#qp-state-zoom')?.remove());
  }
  async function support(){
    const button=page.getByRole('button',{name:'Check signature support',exact:true});await button.focus();await page.keyboard.press('Enter');
    await page.locator('#qp-verify-proof-mode option[value="signature-possession"]').waitFor({state:'attached'});
    await page.locator('#qp-verify-proof-mode').selectOption('signature-possession');
  }
  async function captureHistory(state){
    const panel=page.getByRole('region',{name:'Local request history',exact:true});
    await panel.locator('details').evaluate(element=>element.open=true);
    assert.match(await panel.innerText(),/proof files, private keys, signatures, public-key witnesses and \.qpa receipts are never stored/);
    for(const [width,height,scale] of layouts){
      await page.setViewportSize({width,height});
      await page.addStyleTag({content:`html,.quietproof-request,.quietproof-verify{font-size:${16*scale/100}px!important;line-height:1.6}`,id:'qp-history-zoom'});
      assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth),false);
      for(const [part,target] of [['limits',panel.getByRole('heading',{name:'Local request history',exact:true})],
        ['saved-request',panel.locator('li').filter({has:page.getByRole('button',{name:/Delete saved request/})}).first()],
        ...(state==='checked'?[['check-marker',panel.locator('li').filter({has:page.getByRole('button',{name:'Delete check marker',exact:true})}).first()]]:[])]){
        await position(target);const path=resolve(out,`${engine}-${width}x${height}-${scale}-history-${state}-${part}.png`);
        await page.screenshot({path,animations:'disabled'});historyScreens.push({state,part,width,height,textZoom:scale,path,observedAt:new Date().toISOString()});
      }
      await page.evaluate(()=>document.querySelectorAll('style').forEach(e=>{if(e.textContent.includes('font-size:')&&e.textContent.includes('!important;line-height:1.6'))e.remove();}));
    }
    await page.setViewportSize({width:1280,height:800});
  }
  async function importProof(site,fixture){
    active=fixture;await page.goto(site+'/verify');await page.getByRole('button',{name:'Inspect proof and policy',exact:true}).waitFor();
    if(fixture.metadata.proofMode==='signature-possession')await support();
    else {
      await page.locator('#qp-verify-proof-mode').selectOption('key-knowledge');
      await page.getByLabel('Expected policy source').selectOption('request');
    }
    await page.getByLabel('Proof file (.qpf)',{exact:true}).setInputFiles(upload(fixture.name+'.qpf',fixture.proof));
    await page.getByLabel('Expected request file (.qpr)',{exact:true}).setInputFiles(upload(fixture.name+'.qpr',fixture.request));
    await page.getByLabel('Verification network (chosen independently)').selectOption('mainnet');
  }
  async function check(state,providerMode,expected,{online=true,age='300'}={}){
    mode=providerMode;tipReads=0;
    await page.getByLabel('Maximum observation age').fill(age);
    await page.getByLabel('After valid cryptography, check fresh public explorer observations').setChecked(online);
    const before=requests.length,start=new Date().toISOString();
    await page.getByRole('button',{name:online?'Verify and check explorer':'Verify offline',exact:true}).click();
    await page.locator('[data-result=crypto]').filter({hasText:/^Valid$/}).waitFor({timeout:240000});
    await page.locator('[data-result=explorer]').filter({hasText:expected}).waitFor();
    const qualified=state==='qualified'||state==='changed-stable'||state==='disabled-key-qualified';
    assert.match(await page.locator('[data-result=funds]').innerText(),qualified?/Provider-qualified at check time/:/Not established/);
    if(!online)assert.equal(requests.length,before);
    await capture(state);
    const download=page.waitForEvent('download');const button=page.getByRole('button',{name:'Download public result report',exact:true});
    await button.focus();await page.keyboard.press('Enter');const file=await download;
    const path=resolve(out,state+'.json');await file.saveAs(path);const report=JSON.parse(await readFile(path));
    assert.equal(report.authorizes,false);assert.equal(report.fundsEvidence.validatedNode,false);
    assert.equal(report.fundsEvidence.qualifiedAtCheck,qualified);
    assert.equal(report.claim.proofMode,active.metadata.proofMode);assert.equal(report.claim.claims.length,active.metadata.claims.length);
    assert(!JSON.stringify(report).includes(marker));assert(!JSON.stringify(report).includes('requestBytes'));
    assert.match(report.limitations.join(' '),/global replay/);
    if(providerMode==='changed-stable')assert.equal(report.observations.attempts.length,2);
    if(providerMode==='changing-tip')assert.equal(report.observations.attempts.length,2);
    if(providerMode==='stale')assert(report.observations.attempts.at(-1).reasons.some(r=>r.code==='stale_observation'));
    records.push({state,start,completedAt:new Date().toISOString(),report:path,sha256:hash(await readFile(path)),providerRequests:requests.length-before,
      proofSha256:active.proofSha256,requestSha256:active.requestSha256});
  }
  try{
    context=await browser.newContext({viewport:{width:1280,height:800},acceptDownloads:true});
    await context.route('https://blockstream.info/**',async route=>{
      const request=route.request();assert.equal(request.method(),'GET');assert.equal(request.postData(),null);
      requests.push({url:request.url(),mode,observedAt:new Date().toISOString()});
      if(mode==='lookup'){
        const matches=workflow.claims.filter(c=>request.url().endsWith(`/address/${c.address}/utxo`));
        if(matches.length)return route.fulfill({json:matches.map(c=>({txid:c.txid,vout:c.vout,value:Number(c.amountSats),
          status:{confirmed:true,block_height:100,block_hash:'34'.repeat(32),block_time:1600000000}}))});
        return route.fulfill(providerResponse(workflow,request.url()));
      }
      const path=new URL(request.url()).pathname.replace('/api','');
      let body,contentType='application/json';
      if(mode==='outage')return route.fulfill({status:503,body:'Unavailable'});
      if(path==='/block-height/0'){body=NETWORKS.mainnet.genesis;contentType='text/plain';}
      else if(path==='/blocks/tip/hash'){
        tipReads++;if(mode==='stale'&&tipReads===2)await new Promise(resolve=>setTimeout(resolve,2200));
        body=(mode==='changing-tip'?(tipReads%2?'56':'78'):mode==='changed-stable'&&tipReads>1?'78':'56').repeat(32);contentType='text/plain';
      }else if(path==='/block-height/100'){body='34'.repeat(32);contentType='text/plain';}
      else{
        const found=active.metadata.claims.find(c=>path.startsWith('/tx/'+c.txid));
        const status={confirmed:true,block_height:100,block_hash:'34'.repeat(32),block_time:1600000000};
        if(found&&path.endsWith('/status'))body=mode==='conflict'?{confirmed:false}:status;
        else if(found&&path.includes('/outspend/'))body={spent:false};
        else if(found){
          const vout=Array.from({length:found.vout+1},()=>({value:1,scriptpubkey:'51'}));
          vout[found.vout]={value:Number(found.amountSats),scriptpubkey:found.scriptKind==='p2wpkh'?'0014'+found.program:'76a914'+found.program+'88ac'};
          body={txid:found.txid,vout,status};
        }else if(path.endsWith('/status'))body={in_best_chain:true};
        else body={id:path.split('/').at(-1),height:110};
      }
      return route.fulfill({status:200,contentType,body:typeof body==='string'?body:JSON.stringify(body),headers:{'cache-control':'no-store'}});
    });
    page=await context.newPage();page.on('pageerror',e=>errors.push(e.message));
    // Store an independently created public request, with consent. Native
    // receipt/signature inputs are never used by any page or worker.
    await page.goto(origin+'/tool');await page.getByRole('button',{name:'Create request',exact:true}).waitFor();
    await page.locator('.quietproof-history summary').click();await page.getByLabel(consent,{exact:true}).check();
    await page.getByLabel('Bitcoin addresses').fill([...new Set(workflow.claims.map(c=>c.address))].join('\n'));
    await page.getByRole('button',{name:'Look up outputs',exact:true}).click();
    await page.locator('.quietproof-claims input[type=checkbox]').first().waitFor();
    for(const box of await page.locator('.quietproof-claims input[type=checkbox]').all())await box.check();
    assert.equal(await page.locator('.quietproof-claims input[type=checkbox]:checked').count(),signatureMode?16:2);
    await page.getByLabel('Intended verifier').fill('public-history.example');
    await page.getByLabel('Request lifetime in seconds (1–86400)',{exact:true}).fill('21600');
    if(signatureMode){await page.getByRole('button',{name:'Check signature support',exact:true}).click();
      await page.locator('#qp-request-proof-mode option[value="signature-possession"]').waitFor({state:'attached'});
      await page.locator('#qp-request-proof-mode').selectOption('signature-possession');}
    else await page.locator('#qp-request-proof-mode').selectOption('key-knowledge');
    await page.getByRole('button',{name:'Create request',exact:true}).click();
    await page.getByText('1 saved requests; 0 completed check markers.',{exact:true}).waitFor();
    const publicDownload=page.waitForEvent('download');await page.getByRole('link',{name:'Download .qpr request',exact:true}).click();
    const publicPath=resolve(out,'issued-public.qpr');await(await publicDownload).saveAs(publicPath);
    const publicBytes=await readFile(publicPath),publicMetadata=decode(publicBytes);
    assert.equal(publicMetadata.claims.length,signatureMode?16:2);
    assert.deepEqual(publicMetadata.claims.map(c=>[c.txid,c.vout,c.amountSats,c.scriptKind,c.program]),
      workflow.claims.map(c=>[c.txid,c.vout,c.amountSats,c.scriptKind,c.program]));
    await writeFile(resolve(out,'issued-public-inspection.json'),JSON.stringify(publicMetadata,null,2));
    await captureHistory('saved');
    if(signatureMode){
      // Prove this exact GUI-created canonical request outside the browser.
      // The independent native helper deletes its owner-only receipt input;
      // only the public request/proof and provenance enter the page.
      assert(process.env.QUIETPROOF_NATIVE_CLI,'Native fixture driver location required');
      const nativeOut=resolve(out,'issued-native');await mkdir(nativeOut);
      const command=['python3','tests/wasm/signature_fixtures.py','--driver',resolve(process.env.QUIETPROOF_NATIVE_CLI,'../quietproof-browser-signature-test'),
        '--output',nativeOut,'--largest-only','--request-file',publicPath];
      const startedAt=new Date().toISOString(),result=spawnSync(command[0],command.slice(1),{encoding:'utf8',timeout:900000,maxBuffer:1024*1024});
      await writeFile(resolve(out,'native-generation.log'),(result.stdout??'')+(result.stderr??''));
      await writeFile(resolve(out,'native-generation.json'),JSON.stringify({command,cwd:process.cwd(),startedAt,completedAt:new Date().toISOString(),
        exit:result.status,error:result.error?.message??null,inputSha256:hash(publicBytes),witnessExported:false},null,2));
      assert.equal(result.status,0,result.stderr);
      const [proof,request,provenance]=await Promise.all(['qpf','qpr','json'].map(ext=>readFile(resolve(nativeOut,'signature-max16.'+ext))));
      assert(JSON.parse(provenance).nativeVerified);assert.deepEqual(request,publicBytes);
      active={name:'issued-max16',proof,request,metadata:publicMetadata,proofSha256:hash(proof),requestSha256:hash(request)};
    }
    await importProof(origin,active);mode='unspent';
    const inspect=page.getByRole('button',{name:'Inspect proof and policy',exact:true});
    await page.getByLabel('Proof file (.qpf)',{exact:true}).setInputFiles(upload('private.qpa',Buffer.from('QPA1'+marker)));
    await inspect.click();await page.getByRole('alert').filter({hasText:'Private .qpa'}).waitFor();await capture('receipt-rejected');
    assert.equal(await page.getByRole('button',{name:'Download public result report',exact:true}).count(),0);
    await page.getByLabel('Proof file (.qpf)',{exact:true}).setInputFiles(upload(active.name+'.qpf',active.proof));
    await page.getByLabel('Expected request file (.qpr)',{exact:true}).setInputFiles(upload('renamed.qpr',Buffer.from('QPA1'+marker)));
    await inspect.click();await page.getByRole('alert').filter({hasText:'authorization receipt detected'}).waitFor();
    if(signatureMode)await page.getByRole('button',{name:'Use saved request as explicit expectation',exact:true}).click();
    else await page.getByLabel('Expected request file (.qpr)',{exact:true}).setInputFiles(upload(active.name+'.qpr',active.request));
    await check('qualified','unspent',/Reported unspent/);
    if(!subpath){
      await check('provider-conflict','conflict',/Inconclusive/);
      await check('stale','stale',/Inconclusive/,{age:'1'});
      await check('changing-tip','changing-tip',/Inconclusive/);
      await check('provider-outage','outage',/^Unavailable$/);
      await check('changed-stable','changed-stable',/Reported unspent/);
      await check('offline','unspent',/^Unavailable$/,{online:false});
    }
    const stored=await storage(page);assert(!JSON.stringify(stored).includes(marker));
    assert.deepEqual(Object.keys(stored.state).sort(),['version','enabled','epoch','requests','checks'].sort());
    assert.equal(stored.state.requests.length,1);
    assert.deepEqual(Buffer.from(stored.state.requests[0].bytes),publicBytes);
    assert.equal(decode(Buffer.from(stored.state.requests[0].bytes)).claims.length,signatureMode?16:2);
    assert(stored.state.checks.length>0);assert(stored.state.checks.every(row=>row.proofMode===active.metadata.proofMode&&!('bytes'in row)));
    assert.equal(stored.state.checks.length,subpath?1:7);
    for(const row of stored.state.requests)assert.deepEqual(Object.keys(row).sort(),['id','hash','bytes','nonce','network','verifier','expiresAt','proofMode','time'].sort());
    for(const row of stored.state.checks){
      assert.deepEqual(Object.keys(row).sort(),['id','hash','nonce','network','time','cryptography','policy','explorer','proofMode','fundsQualifiedAtCheck'].sort());
      if(signatureMode){assert.equal(row.hash,hash(publicBytes));assert.equal(row.nonce,stored.state.requests[0].nonce);}
    }
    assert.equal(stored.state.requests[0].hash,hash(publicBytes));
    await writeFile(resolve(out,'storage.json'),JSON.stringify(stored,null,2));
    await page.getByText(`1 saved requests; ${stored.state.checks.length} completed check markers.`,{exact:true}).waitFor();
    await captureHistory('checked');
    if(signatureMode){
      assert(disabledOrigin,'Actual separately packaged disabled site required.');await importProof(disabledOrigin,legacy);
      await page.getByRole('button',{name:'Check signature support',exact:true}).click();
      await page.getByText('Signature possession is unavailable in this verifier build.',{exact:false}).waitFor();
      assert.equal(await page.locator('#qp-verify-proof-mode option[value="signature-possession"]').count(),1);
      await check('disabled-key-qualified','unspent',/Reported unspent/);
      const disabledStorage=await storage(page);assert.equal(disabledStorage.state?.checks.length??0,0);
      await writeFile(resolve(out,'disabled-storage.json'),JSON.stringify(disabledStorage,null,2));
    }
    assert.deepEqual(errors,[]);assert(requests.every(r=>r.url.startsWith('https://blockstream.info/api/')));
    await writeFile(resolve(out,'qualification.json'),JSON.stringify({engine,browserVersion:browser.version(),signatureMode,subpath,
      records,screens,historyScreens,requests,errors,zoomMethod:'Repository text zoom16/32px at fixed viewport; not page zoom.',
      privateInputs:'Native only; browser receipt markers are synthetic rejection fixtures.'},null,2));
    console.log(JSON.stringify({engine,signatureMode,subpath,states:records.length,screens:screens.length}));
  }catch(error){
    await writeFile(resolve(out,'qualification-failed.json'),JSON.stringify({engine,signatureMode,subpath,status:'failed',
      observedAt:new Date().toISOString(),mode,records,screens,requests,errors,
      error:{name:error.name,message:error.message,stack:error.stack}},null,2));
    throw error;
  }finally{await page?.close().catch(()=>{});await context?.close();await browser.close();}
});
