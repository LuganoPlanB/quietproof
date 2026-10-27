import { test } from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { setupProvider } from './discovery.mjs';
import { fixtures, outputFixture } from './fixtures.mjs';
import { verificationHarness as harness } from './verification-fixtures.mjs';

function discoveryHarness() {
  let release, started, first = true;
  const ready = new Promise(resolve => { started = resolve; }), requests = [], data = outputFixture();
  const adapter = setupProvider({ network: 'mainnet', crypto: webcrypto, fetch: async url => {
    requests.push(url);
    if (first) { first = false; started(); return new Promise(resolve => { release = resolve; }); }
    return new Response(url.endsWith('/block-height/0') ? fixtures.mainnet.genesis
      : JSON.stringify(url.includes('/address/') ? data.utxos : data.tx));
  } });
  return { ...adapter, ready, requests, release: () => release(new Response(fixtures.mainnet.genesis)),
    run: () => adapter.discover({ addresses: [fixtures.mainnet.p2wpkh] }) };
}
test('selection disposal rejects pending discovery and all future discovery', async () => {
  const h = discoveryHarness(), pending = h.run();
  const rejected = assert.rejects(pending, { code: 'superseded' }); await h.ready;
  h.dispose(); await rejected; h.release();
  await assert.rejects(h.run(), { code: 'disposed_provider' });
  assert.equal(h.requests.length, 1); // Late genesis cannot trigger address upload.
});
test('a new discovery supersedes old results even when the old fetch ignores cancellation', async () => {
  const h = discoveryHarness(), pending = h.run();
  const rejected = assert.rejects(pending, { code: 'superseded' }); await h.ready;
  const next = h.run(); await rejected; h.release();
  assert.equal((await next).claims.length, 1);
  assert.equal(h.requests.filter(url => url.includes('/address/')).length, 1);
});
test('an invalid replacement lookup also invalidates the old result', async () => {
  const h = discoveryHarness(), pending = h.run();
  const rejected = assert.rejects(pending, { code: 'superseded' }); await h.ready;
  await assert.rejects(h.discover({ addresses: [] }), { code: 'address_limit' });
  await rejected; h.release(); assert.equal(h.requests.length, 1);
});
test('disposal during funding fetch cannot return already-discovered claims', async () => {
  let release, started; const ready = new Promise(resolve => { started = resolve; }), data = outputFixture();
  const adapter = setupProvider({ network: 'mainnet', crypto: webcrypto, fetch: async url => {
    if (url.includes('/tx/')) { started(); return new Promise(resolve => { release = resolve; }); }
    return new Response(url.endsWith('/block-height/0') ? fixtures.mainnet.genesis : JSON.stringify(data.utxos));
  } });
  const pending = adapter.discover({ addresses: [fixtures.mainnet.p2wpkh] });
  const rejected = assert.rejects(pending, { code: 'superseded' }); await ready; adapter.dispose(); await rejected;
  release(new Response(JSON.stringify(data.tx)));
});
for (const [name, status, headers] of [['HTTP rejection', 429, {}], ['oversized Content-Length', 200, { 'content-length': '129' }]]) {
  test(`${name} cancels the unread response body`, async () => {
    let cancelled = false;
    const adapter = setupProvider({ network: 'mainnet', crypto: webcrypto, fetch: async () =>
      new Response(new ReadableStream({ start() {}, cancel() { cancelled = true; } }), { status, headers }) });
    await assert.rejects(adapter.discover({ addresses: [fixtures.mainnet.p2wpkh] }),
      { code: status === 429 ? 'http_429' : 'response_limit' });
    assert.equal(cancelled, true);
  });
}
test('disposing while legacy address checksum is pending prevents every fetch', async () => {
  let release, started;
  const ready = new Promise(resolve => { started = resolve; }), calls = [];
  const gate = new Promise(resolve => { release = resolve; });
  const adapter = setupProvider({ network: 'mainnet', crypto: { subtle: { digest: async (...args) => {
    started(); await gate; return webcrypto.subtle.digest(...args);
  } } }, fetch: async url => { calls.push(url); return new Response(''); } });
  const pending = adapter.discover({ addresses: [fixtures.mainnet.p2pkh] }); await ready; adapter.dispose();
  release(); await assert.rejects(pending, { code: 'superseded' });
  assert.equal(calls.length, 0);
});

const claims = [0, 1].map(vout => ({ txid: fixtures.txid, vout, amountSats: '12345',
  scriptKind: 'p2wpkh', program: fixtures.program }));
function twoClaims(options = {}) {
  return harness({ ...options, claims, change: data => {
    data.tx.vout.push({ ...data.tx.vout[0] }); options.change?.(data);
  } });
}
test('same-transaction claims deduplicate funding/status/membership but fetch each exact outspend', async () => {
  const h = twoClaims(), result = await h.run(); assert.equal(result.explorer, 'reported_unspent');
  const urls = h.requests.map(r => r.url);
  for (const suffix of [`/tx/${fixtures.txid}`, `/tx/${fixtures.txid}/status`, `/block/${fixtures.block}/status`, '/block-height/100',
    `/tx/${fixtures.txid}/outspend/0`, `/tx/${fixtures.txid}/outspend/1`])
    assert.equal(urls.filter(url => url.endsWith(suffix)).length, 1, suffix);
  assert.deepEqual(h.evidence[0].claims.map(c => c.vout), [0, 1]); assert.equal(urls.length, 11);
});
for (const [name, suffix] of [['transaction', `/tx/${fixtures.txid}`], ['membership', `/block/${fixtures.block}/status`]]) {
  test(`failed ${name} responses are also deduplicated within an attempt`, async () => {
    const h = twoClaims({ respond: url => url.endsWith(suffix) ? new Response('', { status: 503 }) : undefined });
    assert.equal((await h.run()).explorer, 'inconclusive');
    assert.equal(h.requests.filter(r => r.url.endsWith(suffix)).length, 1);
    assert.equal(h.evidence[0].claims.length, 2);
  });
}
test('changed-tip retry discards even rejected funding caches and does not exceed its budget', async () => {
  let tips = 0, tx = 0;
  const h = twoClaims({ respond: url => {
    if (url.endsWith('/blocks/tip/hash')) return new Response((++tips === 1 ? '56' : '78').repeat(32));
    if (url.endsWith(`/tx/${fixtures.txid}`) && ++tx === 1) return new Response('', { status: 503 });
  } });
  assert.equal((await h.run()).explorer, 'reported_unspent'); assert.equal(tx, 2); assert.equal(tips, 4);
  assert.equal(h.evidence.length, 1);
});
test('response-selected transaction IDs cannot redirect claim fetching or change the WASM evidence binding', async () => {
  const malicious = 'ab'.repeat(32), h = harness({ change: data => { data.tx.txid = malicious; } });
  assert.equal((await h.run()).explorer, 'inconclusive');
  assert.ok(h.requests.every(r => !r.url.includes(malicious)));
  assert.equal(h.evidence[0].claims[0].txid, fixtures.txid);
});
test('verification transmits only a pinned GET path allowlist, excluding proof/policy/secrets/addresses', async () => {
  const marker = 'sensitive-payload-marker', unrelatedAddress = fixtures.signet.p2pkh;
  const h = harness(); h.policy.message = marker; h.policy.verifier = unrelatedAddress;
  const proof = new TextEncoder().encode(marker + unrelatedAddress).buffer;
  await h.run({ proof, privateKey: marker, addresses: [unrelatedAddress] });
  const allowed = new Set(['/block-height/0', '/blocks/tip/hash', '/block/' + '56'.repeat(32),
    `/tx/${fixtures.txid}`, `/tx/${fixtures.txid}/status`, `/tx/${fixtures.txid}/outspend/0`,
    `/block/${fixtures.block}/status`, '/block-height/100']);
  for (const { url, options } of h.requests) {
    assert.ok(url.startsWith(h.provider.endpoint + '/'));
    const suffix = url.slice(h.provider.endpoint.length); assert.ok(allowed.has(suffix));
    assert.equal(options.body, undefined); assert.equal(options.headers, undefined); assert.equal(options.method, 'GET');
    assert.equal(options.credentials, 'omit'); assert.equal(options.referrerPolicy, 'no-referrer');
    assert.ok(!url.includes(marker) && !url.includes(unrelatedAddress));
  }
});
test('provider outage does not retry or silently switch endpoints', async () => {
  const h = harness({ respond: () => new Response('', { status: 429, headers: { 'retry-after': '3600' } }) });
  const result = await h.run(); assert.equal(result.explorer, 'unavailable'); assert.equal(result.providerError, 'http_429');
  assert.equal(h.requests.length, 1); assert.ok(h.requests[0].url.startsWith(h.provider.endpoint));
});
test('provider selection replacement cannot reuse pending observations from another network', async () => {
  let started; const ready = new Promise(resolve => { started = resolve; });
  const previous = harness({ respond: () => { started(); return new Promise(() => {}); } });
  const pending = previous.run(), rejected = assert.rejects(pending, { code: 'superseded' });
  await ready; previous.dispose(); const next = harness({ network: 'signet' });
  assert.equal((await next.run()).provenance.network, 'signet'); await rejected;
  assert.equal(previous.evidence.length, 0);
  assert.ok(next.requests.every(r => r.url.startsWith('https://blockstream.info/signet/api/')));
});
