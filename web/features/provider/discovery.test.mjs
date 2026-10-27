import { test } from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { setupProvider } from './discovery.mjs';
import { fixtures, outputFixture } from './fixtures.mjs';
import { encodeRequestOptions } from '../../wasm/codec.mjs';

function harness({ network = 'mainnet', kind = 'p2wpkh', change, response, timeoutMs } = {}) {
  const data = outputFixture(kind); change?.(data);
  const requests = [];
  const adapter = setupProvider({ network, crypto: webcrypto, timeoutMs,
    fetch: async (url, options) => {
      requests.push({ url, options });
      if (response) { const custom = await response(url, options); if (custom !== undefined) return custom; }
      const body = url.endsWith('/block-height/0') ? fixtures[network].genesis
        : url.includes('/address/') ? JSON.stringify(data.utxos) : JSON.stringify(data.tx);
      return new Response(body);
    } });
  return { ...adapter, data, requests, lookup: (options = {}) => adapter.discover({ addresses: [fixtures[network][kind]], ...options }) };
}
for (const network of ['mainnet', 'signet']) for (const kind of ['p2wpkh', 'p2pkh']) {
  test(`${network} ${kind}: exact claim is consumable by WASM transport`, async () => {
    const h = harness({ network, kind });
    assert.equal(h.requests.length, 0);
    const result = await h.lookup();
    assert.equal(result.claims[0].program, fixtures.program);
    assert.equal(result.claims[0].amountSats, '12345');
    assert.equal(result.claims[0].scriptKind, kind);
    assert.equal(result.chainStatus, 'unavailable');
    assert.equal(result.requiresFreshVerification, true);
    assert.match(result.provider.trust, /non-atomic/);
    assert.equal(h.requests.length, 3);
    assert.ok(encodeRequestOptions({ network, claims: result.claims, lifetimeSeconds: 60,
      verifier: 'test', purpose: 'test', message: '' }).byteLength);
    for (const { url, options } of h.requests) {
      assert.ok(url.startsWith(h.provider.endpoint + '/'));
      assert.deepEqual({ ...options, signal: null }, { method: 'GET', mode: 'cors', credentials: 'omit',
        cache: 'no-store', redirect: 'error', referrerPolicy: 'no-referrer', signal: null });
    }
    assert.ok(Object.isFrozen(result.claims[0]));
  });
}
test('provider and network configuration fail before fetch', () => {
  for (const network of ['testnet', 'regtest', '__proto__', '', undefined])
    assert.throws(() => setupProvider({ network }), { code: 'unsupported_network' });
  assert.throws(() => setupProvider({ network: 'mainnet', timeoutMs: 30001 }), { code: 'invalid_integer' });
});
for (const [label, address, code] of [
  ['wrong witness network', fixtures.signet.p2wpkh, 'wrong_network'],
  ['wrong legacy network', fixtures.signet.p2pkh, 'wrong_network'],
  ['mixed witness case', 'bC' + fixtures.mainnet.p2wpkh.slice(2), 'invalid_address'],
  ['witness checksum', fixtures.mainnet.p2wpkh.slice(0, -1) + 'q', 'invalid_address'],
  ['legacy checksum', fixtures.mainnet.p2pkh.slice(0, -1) + '1', 'invalid_address'],
  ['P2SH', '3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy', 'unsupported_script'],
  ['P2WSH', 'bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3', 'unsupported_script'],
  ['Taproot', 'bc1p' + 'q'.repeat(58), 'unsupported_script'],
  ['URL', 'https://evil.example/a', 'invalid_address'],
  ['whitespace', ' ' + fixtures.mainnet.p2pkh, 'invalid_address'],
  ['oversized', '1'.repeat(91), 'invalid_address']
]) test(`reject ${label} without address disclosure`, async () => {
  const h = harness(); await assert.rejects(h.lookup({ addresses: [address] }), { code });
  assert.equal(h.requests.length, 0);
});
test('all addresses validated before network access; duplicate and mixed lists rejected', async () => {
  const h = harness();
  await assert.rejects(h.lookup({ addresses: [fixtures.mainnet.p2wpkh, fixtures.signet.p2pkh] }), { code: 'wrong_network' });
  await assert.rejects(h.lookup({ addresses: [fixtures.mainnet.p2wpkh, fixtures.mainnet.p2wpkh.toUpperCase()] }), { code: 'duplicate_address' });
  for (const addresses of [[], Array(3).fill(fixtures.mainnet.p2pkh), 'x'])
    await assert.rejects(h.lookup({ addresses }), { code: 'address_limit' });
  assert.equal(h.requests.length, 0);
});
test('uppercase witness address normalizes', async () => {
  const h = harness(); const result = await h.lookup({ addresses: [fixtures.mainnet.p2wpkh.toUpperCase()] });
  assert.equal(result.claims[0].address, fixtures.mainnet.p2wpkh);
});
test('empty response is an empty discovery, without funding requests', async () => {
  const h = harness({ change: d => { d.utxos = []; } });
  assert.deepEqual((await h.lookup()).claims, []); assert.equal(h.requests.length, 2);
});
for (const [label, change, code] of [
  ['fraction', d => { d.utxos[0].value = 1.5; }, 'invalid_integer'],
  ['unsafe integer', d => { d.utxos[0].value = Number.MAX_SAFE_INTEGER + 1; }, 'invalid_integer'],
  ['supply overflow', d => { d.utxos[0].value = 2100000000000001; }, 'invalid_integer'],
  ['string sats', d => { d.utxos[0].value = '12345'; }, 'invalid_integer'],
  ['negative sats', d => { d.utxos[0].value = -1; }, 'invalid_integer'],
  ['zero sats', d => { d.utxos[0].value = 0; }, 'invalid_integer'],
  ['fraction vout', d => { d.utxos[0].vout = 0.5; }, 'invalid_integer'],
  ['vout overflow', d => { d.utxos[0].vout = 2 ** 32; }, 'invalid_integer'],
  ['bad hash', d => { d.utxos[0].txid = '../a'; }, 'invalid_hash'],
  ['bad status', d => { d.utxos[0].status.confirmed = 'true'; }, 'invalid_status'],
  ['bad height', d => { d.utxos[0].status.block_height = -1; }, 'invalid_integer'],
  ['unconfirmed with block', d => { d.utxos[0].status.confirmed = false; }, 'invalid_status'],
  ['missing funding output', d => { d.utxos[0].vout = 5; }, 'output_mismatch'],
  ['wrong funding amount', d => { d.tx.vout[0].value++; }, 'output_mismatch'],
  ['wrong funding script', d => { d.tx.vout[0].scriptpubkey = '0014' + '00'.repeat(20); }, 'output_mismatch'],
  ['wrong transaction', d => { d.tx.txid = '56'.repeat(32); }, 'invalid_transaction'],
  ['empty transaction', d => { d.tx.vout = []; }, 'invalid_transaction'],
  ['conflicting status', d => { d.tx.status.block_height++; }, 'conflicting_status'],
  ['duplicate outputs', d => { d.utxos.push({ ...d.utxos[0] }); }, 'duplicate_outpoint'],
  ['too many outputs', d => { d.utxos = Array(257).fill(d.utxos[0]); }, 'output_limit'],
  ['too many transaction outputs', d => { d.tx.vout = Array(20001).fill(d.tx.vout[0]); }, 'invalid_transaction'],
  ['non-array discovery', d => { d.utxos = {}; }, 'malformed_utxos'],
  ['null output', d => { d.utxos = [null]; }, 'malformed_utxos']
]) test(`reject ${label}`, async () => { await assert.rejects(harness({ change }).lookup(), { code }); });

test('maximum bounded results and transaction deduplication', async () => {
  const h = harness({ change: d => {
    d.tx.vout = Array.from({ length: 256 }, () => ({ ...d.tx.vout[0] }));
    d.utxos = Array.from({ length: 256 }, (_, vout) => ({ ...d.utxos[0], vout }));
  } });
  assert.equal((await h.lookup()).claims.length, 256);
  assert.equal(h.requests.length, 3);
});
test('two supported addresses share one exact funding transaction fetch', async () => {
  const witness = outputFixture(), legacy = outputFixture('p2pkh');
  legacy.utxos[0].vout = 1;
  const tx = { ...witness.tx, vout: [...witness.tx.vout, ...legacy.tx.vout] }, requests = [];
  const h = setupProvider({ network: 'mainnet', crypto: webcrypto, fetch: async url => {
    requests.push(url);
    return new Response(url.endsWith('/block-height/0') ? fixtures.mainnet.genesis
      : JSON.stringify(url.includes('/tx/') ? tx
        : url.includes(fixtures.mainnet.p2pkh) ? legacy.utxos : witness.utxos));
  } });
  const result = await h.discover({ addresses: [fixtures.mainnet.p2wpkh, fixtures.mainnet.p2pkh] });
  assert.deepEqual(result.claims.map(c => c.scriptKind), ['p2wpkh', 'p2pkh']);
  assert.equal(requests.length, 4);
});
test('unconfirmed exact outputs remain discovery only', async () => {
  const h = harness({ change: d => { d.utxos[0].status = d.tx.status = { confirmed: false }; } });
  assert.deepEqual((await h.lookup()).claims[0].funding, { confirmed: false });
});
test('duplicate outpoint across two addresses is rejected', async () => {
  const h = harness();
  await assert.rejects(h.lookup({ addresses: [fixtures.mainnet.p2wpkh, fixtures.mainnet.p2pkh] }), { code: 'duplicate_outpoint' });
});
for (const code of [404, 429, 503]) test(`HTTP ${code} fails without fallback or retry`, async () => {
  const h = harness({ response: () => new Response('', { status: code }) });
  await assert.rejects(h.lookup(), { code: `http_${code}` }); assert.equal(h.requests.length, 1);
});
test('network/CORS failure is bounded and sanitized', async () => {
  const h = harness({ response: () => { throw new TypeError('private provider details'); } });
  await assert.rejects(h.lookup(), { code: 'network_or_cors', message: 'Explorer discovery: network_or_cors.' });
});
test('wrong genesis prevents address disclosure', async () => {
  const h = harness({ response: () => new Response(fixtures.signet.genesis) });
  await assert.rejects(h.lookup(), { code: 'wrong_genesis' }); assert.equal(h.requests.length, 1);
});
for (const [body, code] of [['{', 'malformed_json'], ['[{"value":1.0000000000000001}]', 'invalid_integer'],
  ['[{"value":1e0}]', 'invalid_integer'], ['[{"value":9007199254740993}]', 'invalid_integer']]) {
  test(`original JSON numeric/malformed lexemes: ${body}`, async () => {
    const h = harness({ response: url => url.includes('/address/') ? new Response(body) : undefined });
    await assert.rejects(h.lookup(), { code });
  });
}
test('response byte bounds with and without Content-Length', async () => {
  for (const headers of [{}, { 'content-length': '2097153' }]) {
    const h = harness({ response: url => url.includes('/address/') ? new Response(' '.repeat(2097153), { headers }) : undefined });
    await assert.rejects(h.lookup(), { code: 'response_limit' });
  }
});
test('strict UTF-8 response validation', async () => {
  const h = harness({ response: url => url.includes('/address/') ? new Response(new Uint8Array([255])) : undefined });
  await assert.rejects(h.lookup(), { code: 'malformed_response' });
});
test('entire operation timeout also bounds a fetch ignoring abort', async () => {
  const h = harness({ timeoutMs: 10, response: () => new Promise(() => {}) });
  await assert.rejects(h.lookup(), { code: 'timeout' });
});
test('timeout bounds a response body ignoring abort', async () => {
  let cancelled = false;
  const h = harness({ timeoutMs: 10, response: () => new Response(new ReadableStream({ start() {}, cancel() { cancelled = true; } })) });
  await assert.rejects(h.lookup(), { code: 'timeout' });
  assert.equal(cancelled, true);
});
test('abort before lookup discloses nothing', async () => {
  const h = harness(), controller = new AbortController(); controller.abort();
  await assert.rejects(h.lookup({ signal: controller.signal }), { code: 'aborted' }); assert.equal(h.requests.length, 0);
});
test('in-flight cancellation rejects late response and preserves pinning', async () => {
  let release, started;
  const ready = new Promise(resolve => { started = resolve; });
  const h = harness({ response: () => { started(); return new Promise(resolve => { release = resolve; }); } });
  const controller = new AbortController(), addresses = [fixtures.mainnet.p2wpkh];
  const result = h.lookup({ addresses, signal: controller.signal }); addresses[0] = fixtures.signet.p2wpkh;
  await ready; controller.abort();
  await assert.rejects(result, { code: 'aborted' }); release(new Response(fixtures.mainnet.genesis));
  assert.ok(Object.isFrozen(h.provider)); assert.equal(h.provider.network, 'mainnet');
});
