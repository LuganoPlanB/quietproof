import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fixtures } from './fixtures.mjs';

import { verificationHarness as harness } from './verification-fixtures.mjs';

for (const network of ['mainnet', 'signet']) test(`${network}: verified manifest receives fresh bounded evidence`, async () => {
  const h = harness({ network }), result = await h.run();
  assert.equal(result.cryptography, 'valid'); assert.equal(result.explorer, 'reported_unspent');
  assert.equal(result.authorizes, false); assert.equal(result.provenance.atomic, false);
  assert.equal(result.provenance.network, network); assert.equal(result.provenance.attempts.length, 1);
  assert.equal(h.evidence[0].claims[0].confirmations, 11);
  assert.notEqual(h.evidence[0].tipBefore.block, fixtures.block);
  assert.equal(h.evidence[0].provider, h.provider.endpoint);
  assert.equal(h.requests.length, 10); assert.ok(h.workers[0].terminated);
  for (const { options, url } of h.requests) {
    assert.equal(options.cache, 'no-store'); assert.equal(options.credentials, 'omit');
    assert.ok(url.startsWith(h.provider.endpoint + '/')); assert.equal(options.method, 'GET');
    assert.equal(options.body, undefined);
  }
});
test('invalid cryptography never fetches, despite caller validation boolean', async () => {
  const h = harness({ invalid: true }); const result = await h.run({ validated: true });
  assert.equal(result.cryptography, 'invalid'); assert.equal(result.explorer, 'unavailable');
  assert.equal(h.requests.length, 0); assert.equal(h.evidence.length, 0); assert.ok(h.workers[0].terminated);
});
test('policy rejection never fetches', async () => {
  const h = harness({ policyError: true }); await assert.rejects(h.run(), { code: 'policy_rejected' });
  assert.equal(h.requests.length, 0);
});
test('caller boolean without binary proof cannot authorize network access', async () => {
  const h = harness(); await assert.rejects(h.verify({ validated: true, policy: h.policy }), { code: 'invalid_binary' });
  assert.equal(h.requests.length, 0); assert.equal(h.workers.length, 0);
});
test('provider policy mismatch fails before worker or network access', async () => {
  const h = harness(); h.policy.provider = 'another-provider';
  await assert.rejects(h.run(), { code: 'provider_mismatch' }); assert.equal(h.requests.length, 0); assert.equal(h.workers.length, 0);
});
test('offline cryptography remains possible without explorer requests', async () => {
  const h = harness(); h.policy.provider = '';
  const result = await h.run({ online: false });
  assert.equal(result.cryptography, 'valid'); assert.equal(result.explorer, 'unavailable'); assert.equal(h.requests.length, 0);
});
for (const [name, options, expected, reason] of [
  ['spent', { respond: url => url.includes('/outspend/') ? new Response(JSON.stringify({ spent: true, txid: '78'.repeat(32), vin: 0, status: { confirmed: false } })) : undefined }, 'reported_spent'],
  ['missing transaction', { respond: url => url.endsWith(`/tx/${fixtures.txid}`) ? new Response('', { status: 404 }) : undefined }, 'inconclusive', 'http_404'],
  ['missing vout', { change: d => { d.tx.vout = [{ value: 99, scriptpubkey: '00' }]; } }, 'inconclusive', 'output_mismatch'],
  ['wrong amount', { change: d => { d.tx.vout[0].value++; } }, 'inconclusive', 'output_mismatch'],
  ['wrong script', { change: d => { d.tx.vout[0].scriptpubkey = '51'; } }, 'inconclusive', 'output_mismatch'],
  ['reorged funding', { respond: url => url.endsWith(`/block/${fixtures.block}/status`) ? new Response('{"in_best_chain":false}') : undefined }, 'inconclusive', 'funding_not_in_best_chain'],
  ['wrong funding height mapping', { respond: url => url.endsWith('/block-height/100') ? new Response('ab'.repeat(32)) : undefined }, 'inconclusive', 'funding_not_in_best_chain'],
  ['conflicting status', { respond: url => url.endsWith(`/tx/${fixtures.txid}/status`) ? new Response('{"confirmed":false}') : undefined }, 'inconclusive', 'conflicting_status'],
  ['conflicting outspend', { respond: url => url.includes('/outspend/') ? new Response('{"spent":false,"vin":0}') : undefined }, 'inconclusive', 'conflicting_outspend'],
  ['cached funding status', { respond: url => url.endsWith(`/tx/${fixtures.txid}/status`) ? new Response('{"confirmed":false}', { headers: { age: '1' } }) : undefined }, 'inconclusive', 'cached_response'],
  ['malformed outspend', { respond: url => url.includes('/outspend/') ? new Response('{"spent":"false"}') : undefined }, 'inconclusive', 'invalid_outspend'],
  ['provider rate limit', { respond: url => url.includes('/outspend/') ? new Response('', { status: 429 }) : undefined }, 'inconclusive', 'http_429'],
  ['unconfirmed funding', { change: d => { d.tx.status = { confirmed: false }; } }, 'inconclusive', 'funding_not_in_best_chain']
]) test(`${name} stays separate from cryptography`, async () => {
  const h = harness(options), result = await h.run();
  assert.equal(result.cryptography, 'valid'); assert.equal(result.explorer, expected);
  if (reason) assert.ok(result.provenance.attempts[0].reasons.some(r => r.code === reason));
});
test('insufficient confirmations are passed accurately to policy assessment', async () => {
  const h = harness(); h.policy.minConfirmations = 12;
  assert.equal((await h.run()).explorer, 'inconclusive'); assert.equal(h.evidence[0].claims[0].confirmations, 11);
});
test('missing output index produces a missing observation', async () => {
  const h = harness();
  // Keep a valid array but remove index zero to exercise the actual vout lookup.
  h.data.tx.vout = [null];
  assert.equal((await h.run()).explorer, 'inconclusive'); assert.equal(h.evidence[0].claims[0].status, 'missing');
});
test('changed tip triggers one complete refetch then accepts only new stable observations', async () => {
  let reads = 0;
  const h = harness({ respond: url => url.endsWith('/blocks/tip/hash') ? new Response((++reads === 1 ? '56' : '78').repeat(32)) : undefined });
  assert.equal((await h.run()).explorer, 'reported_unspent');
  assert.equal(reads, 4); assert.equal(h.requests.filter(r => r.url.endsWith(`/tx/${fixtures.txid}`)).length, 2);
  assert.equal(h.evidence[0].tipBefore.block, '78'.repeat(32)); assert.equal(h.evidence.length, 1);
});
test('persistent tip changes exhaust exactly two attempts and stay inconclusive', async () => {
  let reads = 0;
  const h = harness({ respond: url => url.endsWith('/blocks/tip/hash') ? new Response((++reads % 2 ? '56' : '78').repeat(32)) : undefined });
  const result = await h.run(); assert.equal(result.explorer, 'inconclusive');
  assert.equal(reads, 4); assert.equal(result.provenance.attempts.length, 2);
});
test('aged observations retain original start time and become inconclusive', async () => {
  const realNow = Date.now; let time = realNow(), reads = 0;
  Date.now = () => time;
  try {
    const h = harness({ respond: url => {
      if (url.endsWith('/blocks/tip/hash') && ++reads === 2) time += 61000;
    } });
    const result = await h.run(); assert.equal(result.explorer, 'inconclusive');
    assert.ok(result.provenance.attempts[0].reasons.some(r => r.code === 'stale_observation'));
  } finally { Date.now = realNow; }
});
for (const code of ['network_or_cors', 'wrong_genesis', 'timeout']) test(`whole-provider ${code} preserves valid cryptography`, async () => {
  const h = harness({ timeoutMs: code === 'timeout' ? 10 : undefined, respond: () => {
    if (code === 'timeout') return new Promise(() => {});
    if (code === 'wrong_genesis') return new Response(fixtures.signet.genesis);
    throw new TypeError('CORS');
  } });
  const result = await h.run(); assert.equal(result.cryptography, 'valid'); assert.equal(result.explorer, 'unavailable');
  assert.equal(result.providerError, code); assert.equal(h.evidence.length, 0);
});
test('binary buffers and expected policy are captured before initialization yields', async () => {
  const h = harness(), proof = new ArrayBuffer(1), wasmBytes = new ArrayBuffer(1);
  const result = h.run({ proof, wasmBytes }); h.policy.verifier = 'changed';
  assert.equal(proof.byteLength, 0); assert.equal(wasmBytes.byteLength, 0);
  await result; assert.equal(h.workers[0].messages.find(m => m.type === 'prepare').policy.verifier, 'test');
});
test('abort during worker computation terminates it without chain fetch', async () => {
  const controller = new AbortController();
  const h = harness({ holdWorker: message => { if (message.type === 'verify') { queueMicrotask(() => controller.abort()); return true; } } });
  await assert.rejects(h.run({ signal: controller.signal }), { code: 'aborted' });
  assert.equal(h.requests.length, 0); assert.ok(h.workers[0].terminated);
});
test('a newer operation consumes an older operation and rejects late provider results', async () => {
  let started, release, first = true;
  const ready = new Promise(resolve => { started = resolve; });
  const h = harness({ respond: () => { if (first) { first = false; started(); return new Promise(resolve => { release = resolve; }); } } });
  const previous = h.run(); const rejected = assert.rejects(previous, { code: 'superseded' }); await ready;
  const next = h.run(); await rejected; release(new Response(fixtures.mainnet.genesis));
  assert.equal((await next).explorer, 'reported_unspent'); assert.equal(h.evidence.length, 1);
});
test('disposing a provider selection invalidates pending evidence and future operations', async () => {
  let started; const ready = new Promise(resolve => { started = resolve; });
  const h = harness({ respond: () => { started(); return new Promise(() => {}); } });
  const pending = h.run(); const rejected = assert.rejects(pending, { code: 'superseded' }); await ready; h.dispose();
  await rejected; await assert.rejects(h.run(), { code: 'disposed_provider' }); assert.equal(h.evidence.length, 0);
});
