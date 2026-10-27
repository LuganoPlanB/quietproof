import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { openSync, closeSync } from 'node:fs';
import { resolve } from 'node:path';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { chromium, webkit } from 'playwright';
import { workflows, providerResponse } from '../request/workflow-fixtures.mjs';

const origin = process.env.QUIETPROOF_SITE_ORIGIN || 'http://127.0.0.1:4175';
const cli = process.env.QUIETPROOF_NATIVE_CLI;
const artifacts = process.env.QUIETPROOF_HISTORY_ARTIFACTS;
assert(cli && artifacts, 'Set QUIETPROOF_NATIVE_CLI and QUIETPROOF_HISTORY_ARTIFACTS.');
const directory = resolve(artifacts, `${Date.now()}-${process.pid}`);
const fixtures = new Map();
const digest = bytes => createHash('sha256').update(bytes).digest('hex');
const consentName = 'Keep future requests and completed check records locally';
async function ready(page) { await page.waitForFunction(() => { const button = document.querySelector('.quietproof-verify button[type=submit],.quietproof-request button[type=submit]'); return !!button && !button.disabled; }); }
async function manage(page) { const details = page.locator('.quietproof-history details'); if (!await details.evaluate(e => e.open)) await details.locator('summary').click(); }
async function capture(page, engine, state) {
  await mkdir(directory, { recursive: true });
  for (const [width, height] of [[390, 844], [1440, 900]]) for (const scale of [100, 200]) {
    await page.setViewportSize({ width, height });
    await page.evaluate(scale => {
      let style = document.querySelector('#qp-history-scale'); if (!style) { style = document.createElement('style'); style.id = 'qp-history-scale'; document.head.append(style); }
      style.textContent = `html,.quietproof-request,.quietproof-verify {font-size:${16 * scale / 100}px!important;line-height:1.6}`; scrollTo(0, 0);
    }, scale);
    await page.waitForTimeout(350);
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false, state+' fits viewport');
    await page.screenshot({ path: resolve(directory, `${engine}-${width}-${scale}-${state}.png`), fullPage: true, animations: 'disabled' });
  }
  await page.setViewportSize({ width: 1440, height: 900 }); await page.evaluate(() => document.querySelector('#qp-history-scale')?.remove());
}
async function requestForm(page, workflow) {
  await page.getByLabel('Bitcoin network', { exact: true }).selectOption(workflow.network);
  await page.getByLabel('Bitcoin addresses').fill(workflow.claims[0].address);
  await page.getByRole('button', { name: 'Look up outputs', exact: true }).click();
  await page.locator('.quietproof-claims').getByRole('checkbox').check();
  await page.getByLabel('Intended verifier').fill('history-roundtrip.example');
  await page.getByLabel('Purpose', { exact: true }).selectOption('proof-of-funds');
  await page.getByLabel('Message (optional').fill('Public disposable local history round trip');
}
async function prepareVerification(page, fixture, saved) {
  await page.getByLabel('Proof file (.qpf)', { exact: true }).setInputFiles(fixture.proof);
  if (saved) {
    await page.getByRole('button', { name: 'Use saved request as explicit expectation', exact: true }).click();
    assert.equal(await page.getByLabel('Expected request file (.qpr)', { exact: true }).inputValue(), '');
    await page.getByText('Using explicitly selected local request:', { exact: false }).waitFor();
  } else {
    await page.getByLabel('Expected policy source').selectOption('request');
    await page.getByLabel('Expected request file (.qpr)', { exact: true }).setInputFiles(fixture.qpr);
  }
  assert.equal(await page.getByLabel('Verification network (chosen independently)').inputValue(), '');
  await page.getByLabel('Verification network (chosen independently)').selectOption(fixture.network);
}
async function verify(page) { await page.getByRole('button', { name: 'Verify offline', exact: true }).click(); await page.locator('[data-result=crypto]').filter({ hasText: /^Valid$/ }).waitFor({ timeout: 180000 }); }
async function rawState(page) {
  return page.evaluate(() => new Promise((resolve, reject) => {
    const request = indexedDB.open('quietproof-local-history-v1', 1);
    request.onerror = () => reject(new Error('Cannot inspect test history'));
    request.onsuccess = () => {
      const db = request.result, tx = db.transaction('state', 'readonly'), get = tx.objectStore('state').get('local');
      get.onsuccess = () => resolve(get.result ? { enabled: get.result.enabled, requests: get.result.requests.map(r => ({ hash: r.hash, bytes: r.bytes.byteLength, keys: Object.keys(r) })), checks: get.result.checks.map(r => ({ hash: r.hash, keys: Object.keys(r) })) } : null);
      tx.oncomplete = () => db.close(); tx.onerror = () => { db.close(); reject(new Error('Cannot inspect history')); };
    };
  }));
}
for (const [name, engine] of [['chromium', chromium], ['webkit', webkit]]) {
  const launch = () => engine.launch({ headless: true, ...(name === 'webkit' && process.env.QUIETPROOF_WEBKIT_EXECUTABLE ? { executablePath: process.env.QUIETPROOF_WEBKIT_EXECUTABLE } : {}) });
  test(`${name}: storage-only opt-in, reload, explicit selection and cross-tab clear`, { timeout: 60000 }, async () => {
    const browser = await launch(); let context;
    try {
      context = await browser.newContext({ viewport: { width: 1440, height: 900 } });
      const workflow = workflows[0]; await context.route('https://blockstream.info/**', route => route.fulfill(providerResponse(workflow, route.request().url())));
      const page = await context.newPage(); await page.goto(origin+'/tool'); await ready(page); await manage(page);
      await page.getByLabel(consentName, { exact: true }).click();
      await page.getByText('0 saved requests; 0 completed check markers.', { exact: true }).waitFor();
      await requestForm(page, workflow); await page.getByRole('button', { name: 'Create request', exact: true }).click();
      await page.getByText('1 saved requests; 0 completed check markers.', { exact: true }).waitFor();
      await page.reload(); await ready(page); await page.getByText('1 saved requests; 0 completed check markers.', { exact: true }).waitFor();
      await page.goto(origin+'/verify'); await ready(page);
      await page.getByRole('button', { name: 'Use saved request as explicit expectation', exact: true }).click();
      assert.equal(await page.getByLabel('Expected policy source').inputValue(), 'request');
      assert.equal(await page.getByLabel('Verification network (chosen independently)').inputValue(), '');
      const second = await context.newPage(); await second.goto(origin+'/verify'); await ready(second);
      await second.getByText('1 saved requests; 0 completed check markers.', { exact: true }).waitFor();
      await second.getByRole('button', { name: 'Clear history and turn off', exact: true }).click();
      await page.getByText('Local history is off. Nothing new is saved.', { exact: true }).waitFor();
      assert.equal(await page.getByText('Using explicitly selected local request:', { exact: false }).count(), 0);
      assert.equal((await rawState(page)).requests.length, 0);
    } finally { await context?.close(); await browser.close(); }
  });
  test(`${name}: missed tab notifications cannot restore a deleted request through manual save`, { timeout: 60000 }, async () => {
    const browser = await launch(); let context;
    try {
      context = await browser.newContext();
      await context.addInitScript(() => {
        window.BroadcastChannel = undefined;
        const listen = window.addEventListener.bind(window);
        window.addEventListener = (kind, ...args) => { if (kind !== 'focus') listen(kind, ...args); };
      });
      const workflow = workflows[0]; await context.route('https://blockstream.info/**', route => route.fulfill(providerResponse(workflow, route.request().url())));
      const page = await context.newPage(); await page.goto(origin+'/tool'); await ready(page); await manage(page);
      await page.getByLabel(consentName, { exact: true }).click();
      await page.getByText('0 saved requests; 0 completed check markers.', { exact: true }).waitFor();
      await requestForm(page, workflow); await page.getByRole('button', { name: 'Create request', exact: true }).click();
      await page.getByText('1 saved requests; 0 completed check markers.', { exact: true }).waitFor();
      const second = await context.newPage(); await second.goto(origin+'/verify'); await ready(second);
      await second.getByRole('button', { name: /^Delete saved request / }).click();
      await second.getByText('0 saved requests; 0 completed check markers.', { exact: true }).waitFor();
      // With notifications and focus refresh disabled, this tab still holds its preview.
      await page.getByRole('button', { name: 'Save this request locally (opt-in required)', exact: true }).click();
      await page.getByText('Local history changed or was cleared.', { exact: false }).waitFor();
      assert.equal(await page.getByRole('region', { name: 'Canonical request preview' }).count(), 0);
      assert.equal((await rawState(page)).requests.length, 0);
    } finally { await context?.close(); await browser.close(); }
  });
  test(`${name}: downloaded request, native prove, real browser checks, reload/tabs/delete/clear`, { timeout: 900000 }, async () => {
    await mkdir(directory, { recursive: true }); const browser = await launch();
    const workflow = workflows.find(w => w.network === (name === 'chromium' ? 'mainnet' : 'signet') && w.claims.length === 1 && w.claims[0].scriptKind === (name === 'chromium' ? 'p2wpkh' : 'p2pkh'));
    let context;
    try {
      context = await browser.newContext({ viewport: { width: 1440, height: 900 }, acceptDownloads: true, reducedMotion: 'reduce' });
      await context.addInitScript(() => {
        const Native = window.Worker; window.__historyWorkers = { created: 0, terminated: 0 };
        window.Worker = class extends Native { constructor(...args) { super(...args); window.__historyWorkers.created++; } terminate() { if (!this.closed) { this.closed = true; window.__historyWorkers.terminated++; } super.terminate(); } };
      });
      let explorerRequests = 0;
      await context.route('https://blockstream.info/**', route => { explorerRequests++; assert.equal(route.request().method(), 'GET'); assert.equal(route.request().postData(), null); return route.fulfill(providerResponse(workflow, route.request().url())); });
      const page = await context.newPage(); await page.goto(origin+'/tool'); await ready(page);
      await page.getByText('Local history is off. Nothing new is saved.', { exact: true }).waitFor();
      assert.equal(explorerRequests, 0); await capture(page, name, 'request-history-off');
      await manage(page); await page.getByLabel(consentName, { exact: true }).click();
      await page.getByText('0 saved requests; 0 completed check markers.', { exact: true }).waitFor();
      await requestForm(page, workflow); assert.equal(await page.getByLabel('Request lifetime').inputValue(), '300');
      await page.getByLabel('Request lifetime').fill('1800'); // Explicit test choice for native prove and repeated serialized checks.
      await page.getByRole('button', { name: 'Create request', exact: true }).click();
      await page.getByRole('region', { name: 'Canonical request preview' }).waitFor();
      await page.getByText('1 saved requests; 0 completed check markers.', { exact: true }).waitFor();
      await capture(page, name, 'request-saved');
      const qpr = resolve(directory, name+'.qpr'), proof = resolve(directory, name+'.qpf');
      const download = page.waitForEvent('download'); await page.getByRole('link', { name: 'Download .qpr request', exact: true }).click(); await (await download).saveAs(qpr);
      const request = await readFile(qpr), inspected = JSON.parse(execFileSync(cli, ['inspect', qpr], { encoding: 'utf8' }));
      const proveCommand = [cli, 'prove', '--request', qpr, '--output', proof, '--network', workflow.network];
      const log = resolve(directory, name+'-prove.log'), fd = openSync(log, 'w'), observedAt = new Date().toISOString();
      let summary; try { summary = JSON.parse(execFileSync(cli, proveCommand.slice(1), { input: '1'.padStart(64, '0')+'\n', encoding: 'utf8', timeout: 600000, stdio: ['pipe','pipe',fd] })); } finally { closeSync(fd); }
      assert.equal(summary.result, 'proof_created'); const envelope = await readFile(proof); assert(envelope.length > 40*1024*1024);
      assert.deepEqual(envelope.subarray(9, 9+envelope.readUInt32BE(5)), request);
      const fixture = { qpr, proof, network: workflow.network, expiresAt: inspected.expires_at, qprSha256: digest(request), proofSha256: digest(envelope) }; fixtures.set(name, fixture);
      await writeFile(resolve(directory, name+'-provenance.json'), JSON.stringify({ ...fixture, engine: name, browserVersion: browser.version(), statementVersion: inspected.statement_version, proveCommand, cwd: process.cwd(), exit: 0, observedAt, completedAt: new Date().toISOString(), inputChannel: 'native stdin only; public disposable scalar1; never browser input', summary, requestInspection: inspected, exactEmbeddedRequest: true, log }, null, 2));
      await page.reload(); await ready(page); await page.getByText('1 saved requests; 0 completed check markers.', { exact: true }).waitFor();
      assert.equal(await page.getByLabel('Bitcoin addresses').inputValue(), '');
      await page.goto(origin+'/verify'); await ready(page); await prepareVerification(page, fixture, true);
      const beforeVerify = explorerRequests; await verify(page);
      await page.getByText('1 saved requests; 1 completed check markers.', { exact: true }).waitFor();
      assert.equal(explorerRequests, beforeVerify); await capture(page, name, 'first-offline-check');
      const stored = await rawState(page); assert.equal(stored.requests[0].hash, fixture.qprSha256); assert.equal(stored.requests[0].bytes, request.length);
      assert(stored.requests.every(r => !r.keys.some(k => /proof|secret/i.test(k)))); assert(stored.checks.every(r => !r.keys.includes('bytes')));
      const second = await context.newPage(); await second.goto(origin+'/verify'); await ready(second); await prepareVerification(second, fixture, true); await verify(second);
      await second.getByText('Local repeat warning: this request or nonce', { exact: false }).waitFor();
      await page.getByText('1 saved requests; 2 completed check markers.', { exact: true }).waitFor();
      await capture(second, name, 'cross-tab-repeat');
      await second.getByRole('button', { name: 'Inspect proof and policy', exact: true }).click();
      await second.getByRole('heading', { name: 'Inspection only · cryptography not checked' }).waitFor();
      assert.equal((await rawState(second)).checks.length, 2); await capture(second, name, 'reinspection');
      await second.getByRole('button', { name: 'Delete check marker', exact: true }).first().click();
      await second.getByText('1 saved requests; 1 completed check markers.', { exact: true }).waitFor();
      await second.getByRole('button', { name: /^Delete saved request / }).click();
      await second.getByText('0 saved requests; 0 completed check markers.', { exact: true }).waitFor();
      assert.equal(await second.getByText('Using explicitly selected local request:', { exact: false }).count(), 0);
      await second.getByLabel('Expected request file (.qpr)', { exact: true }).setInputFiles(qpr);
      await second.getByRole('button', { name: 'Verify offline', exact: true }).click();
      await second.getByText(/Checking proof cryptography…/).waitFor({ timeout: 30000 }); await second.waitForTimeout(100);
      await page.evaluate(() => localStorage.setItem('qp-history-test-unrelated', 'preserved'));
      await manage(page); await page.getByRole('button', { name: 'Clear history and turn off', exact: true }).click();
      await second.getByText('Local history is off. Nothing new is saved.', { exact: true }).waitFor();
      await second.waitForTimeout(100); assert.equal(await second.getByRole('region', { name: 'Verification results' }).count(), 0);
      assert.equal((await rawState(second)).checks.length, 0); assert.equal(await page.evaluate(() => localStorage.getItem('qp-history-test-unrelated')), 'preserved');
      await capture(second, name, 'clear-during-verification');
      await second.reload(); await ready(second); await second.getByText('Local history is off. Nothing new is saved.', { exact: true }).waitFor();
      const otherOrigin = await context.newPage(); await otherOrigin.goto(origin.replace('127.0.0.1','localhost')+'/verify'); await ready(otherOrigin);
      await otherOrigin.getByText('Local history is off. Nothing new is saved.', { exact: true }).waitFor();
      for (const tab of [page, second]) { const count = await tab.evaluate(() => window.__historyWorkers); assert.equal(count.created, count.terminated); }
      console.log(JSON.stringify({ engine: name, network: workflow.network, version: workflow.version, publicNativeProof: fixture, nativeCliSha256: digest(await readFile(cli)), explorerRequestsBeforeOfflineChecks: beforeVerify, explorerRequestsAfter: explorerRequests, crossTabClearFenced: true, screenshotStates: 6, observedAt: new Date().toISOString() }));
    } finally { await context?.close(); await browser.close(); }
  });

  test(`${name}: denied private storage leaves real verification and request download available`, { timeout: 300000 }, async () => {
    const fixture = fixtures.get(name); assert(fixture && fixture.expiresAt > Math.floor(Date.now()/1000)+180);
    assert.equal(digest(await readFile(fixture.proof)), fixture.proofSha256); assert.equal(digest(await readFile(fixture.qpr)), fixture.qprSha256);
    const browser = await launch(); let context;
    try {
      context = await browser.newContext({ viewport: { width: 1440, height: 900 }, acceptDownloads: true, reducedMotion: 'reduce' });
      await context.addInitScript(() => Object.defineProperty(window, 'indexedDB', { configurable: true, get() { throw new DOMException('Denied test storage', 'SecurityError'); } }));
      const page = await context.newPage(); let calls = 0;
      const workflow = workflows.find(w => w.network === fixture.network && w.claims.length === 1 && w.version === (name==='chromium'?1:2));
      await context.route('https://blockstream.info/**', route => { calls++; return route.fulfill(providerResponse(workflow, route.request().url())); });
      await page.goto(origin+'/verify'); await ready(page);
      await page.getByRole('alert').filter({ hasText: 'Local history is unavailable.' }).waitFor(); await prepareVerification(page, fixture, false); await verify(page);
      assert.equal(calls, 0); await capture(page, name, 'storage-unavailable-result');
      await page.goto(origin+'/tool'); await ready(page); await requestForm(page, workflow); await page.getByRole('button', { name: 'Create request', exact: true }).click();
      await page.getByRole('link', { name: 'Download .qpr request', exact: true }).waitFor();
      const downloading = page.waitForEvent('download'); await page.getByRole('link', { name: 'Download .qpr request', exact: true }).click();
      const downloaded = await (await downloading).path(); assert.equal(JSON.parse(execFileSync(cli, ['inspect', downloaded], { encoding: 'utf8' })).network, fixture.network);
      await page.getByRole('alert').filter({ hasText: 'Local history is unavailable.' }).waitFor(); await capture(page, name, 'storage-unavailable-request');
      console.log(`${name}: denied storage did not prevent actual crypto or canonical download`);
    } finally { await context?.close(); await browser.close(); }
  });

  test(`${name}: failed writes never claim opt-in or clear success; corrupt history can be cleared`, { timeout: 60000 }, async () => {
    const browser = await launch(); let quota, corrupt;
    try {
      quota = await browser.newContext({ viewport: { width: 1440, height: 900 }, reducedMotion: 'reduce' });
      await quota.addInitScript(() => { const put = IDBObjectStore.prototype.put; IDBObjectStore.prototype.put = function(...args) { if (this.name === 'state') throw new DOMException('Test quota', 'QuotaExceededError'); return put.apply(this,args); }; });
      const page = await quota.newPage(); await page.goto(origin+'/verify'); await ready(page); await manage(page);
      await page.getByLabel(consentName, { exact: true }).click();
      await page.getByRole('alert').filter({ hasText: 'Local history is unavailable.' }).waitFor();
      assert.equal(await page.getByLabel(consentName, { exact: true }).isChecked(), false);
      await page.getByRole('button', { name: 'Clear history and turn off', exact: true }).click();
      assert.equal(await page.getByText('Local history cleared and turned off.', { exact: true }).count(), 0); await capture(page, name, 'quota-failure');
      corrupt = await browser.newContext({ viewport: { width: 1440, height: 900 }, reducedMotion: 'reduce' });
      const broken = await corrupt.newPage(); await broken.goto(origin+'/verify'); await ready(broken);
      await broken.waitForFunction(() => { const checkbox = document.querySelector('.quietproof-history input'); return !!checkbox && !checkbox.disabled; });
      await broken.evaluate(() => new Promise((resolve,reject) => { const open = indexedDB.open('quietproof-local-history-v1',1); open.onerror=reject; open.onsuccess=()=>{const db=open.result,tx=db.transaction('state','readwrite');tx.objectStore('state').put({version:99},'local');tx.oncomplete=()=>{db.close();resolve()};tx.onerror=reject;}; }));
      await broken.reload(); await ready(broken); await broken.getByRole('alert').filter({ hasText: 'Local history is unavailable.' }).waitFor();
      await manage(broken); await broken.getByRole('button', { name: 'Clear history and turn off', exact: true }).click();
      await broken.getByText('Local history cleared and turned off.', { exact: true }).waitFor(); assert.equal((await rawState(broken)).enabled, false);
    } finally { await quota?.close(); await corrupt?.close(); await browser.close(); }
  });
}
