import { test } from 'node:test';
import assert from 'node:assert/strict';
import { setupProofInput, expectedPolicy } from './input.mjs';
import { failureResult, observationReasons } from './results.mjs';
const options = { mode: 'explicit', network: 'mainnet', verifier: 'Independent', purpose: 'proof-of-control', message: '', confirmed: true };
const proof = { name: 'proof.qpf', size: 1, arrayBuffer: async () => new ArrayBuffer(1) };
const args = { proof, options, selectedNetwork: 'mainnet' };
const asset = async () => new Response(new Uint8Array([1]));

test('verification requires independent policy/network and bounded observation limits before proof reads', async () => {
  let reads = 0;
  const tools = setupProofInput({ fetch: asset });
  const unread = { ...proof, arrayBuffer() { reads++; } };
  await assert.rejects(tools.verify({ ...args, proof: unread, options: { mode: 'none' } }), /independent expected policy/);
  await assert.rejects(tools.verify({ ...args, proof: unread, selectedNetwork: '' }), /network independently/);
  for (const change of [{ maxObservationAgeSeconds: '0' }, { maxObservationAgeSeconds: '301' }, { minimumTotalSats: '2100000000000001' }])
    await assert.rejects(tools.verify({ ...args, proof: unread, options: { ...options, ...change } }));
  assert.equal(reads, 0); tools.dispose();
});

for (const online of [false, true]) test(`${online ? 'online' : 'offline'} verification delegates binary ownership and independent policy then disposes adapter`, async () => {
  let disposed = 0, seen;
  const progress = [];
  const tools = setupProofInput({ fetch: asset, providerFactory({ network }) {
    assert.equal(network, 'mainnet');
    return { provider: { endpoint: 'https://blockstream.info/api' }, dispose() { disposed++; }, async verify(input) {
      seen = input; input.onProgress({ phase: 'verifying', policy: 'matched', cryptography: 'not_checked' });
      return { cryptography: 'valid', policy: 'matched', explorer: 'unavailable', manifest: { expiresAt: '9999999999' } };
    } };
  } });
  const result = await tools.verify({ ...args, online, onProgress: p => progress.push(p.phase) });
  assert.equal(seen.proof.byteLength, 1); assert.equal(seen.wasmBytes.byteLength, 1);
  assert.equal(seen.policy.verifier, 'Independent'); assert.equal(seen.policy.provider, online ? 'https://blockstream.info/api' : '');
  assert.equal(seen.online, online); assert.equal(result.online, online); assert.equal(result.cryptography, 'valid');
  assert.equal(result.expected.minConfirmations, '1'); assert.deepEqual(progress, ['reading', 'verifying']);
  assert.equal(disposed, 1); tools.dispose();
});

test('a second verification disposes the first adapter and rejects its late result', async () => {
  let firstStarted, release, readyTimer, disposed = 0, count = 0;
  const ready = new Promise(r => { firstStarted = r; });
  const tools = setupProofInput({ fetch: asset, providerFactory() {
    const first = ++count === 1;
    return { provider: { endpoint: 'https://blockstream.info/api' }, dispose() { disposed++; }, async verify() {
      if (first) { firstStarted(); await new Promise(r => { release = r; }); }
      return { cryptography: 'valid', policy: 'matched', explorer: 'unavailable', manifest: {} };
    } };
  } });
  const old = tools.verify(args), rejected = assert.rejects(old, { name: 'AbortError' });
  try {
    await Promise.race([ready, new Promise((_, reject) => {
      readyTimer = setTimeout(() => reject(new Error('First verification did not reach its owned gate.')), 5000);
    })]);
    const next = tools.verify(args); release();
    await rejected; assert.equal((await next).cryptography, 'valid'); assert(disposed >= 2);
  } finally { clearTimeout(readyTimer); release?.(); tools.dispose(); await rejected; }
});

test('failure reporting preserves known crypto while clearing unfinished policy and chain assessment', () => {
  assert.equal(failureResult(new Error('Choose independent expectations.'), null).reason, 'Choose independent expectations.');
  const failed = failureResult({ code: 'policy_rejected' }, { cryptography: 'valid', policy: 'matched' });
  assert.equal(failed.cryptography, 'valid'); assert.equal(failed.policy, 'rejected'); assert.equal(failed.explorer, 'unavailable');
  assert.equal(failureResult({ code: 'verification_failed' }, { policy: 'matched' }).policy, 'not_checked');
  assert.match(observationReasons(failed)[0], /expected request or policy/);
});
test('outer verification timeout retains its timeout reason when adapter disposal races abort', async () => {
  let disposed = 0;
  const tools = setupProofInput({ fetch: asset, verificationTimeoutMs: 10, providerFactory() {
    return { provider: { endpoint: 'https://blockstream.info/api' }, dispose() { disposed++; }, verify({ signal }) {
      return new Promise((_, reject) => signal.addEventListener('abort', () => reject(Object.assign(new Error('Disposed'), { code: 'superseded' })), { once: true }));
    } };
  } });
  await assert.rejects(tools.verify(args), { name: 'AbortError', code: 'timeout' });
  assert(disposed >= 1); tools.dispose();
});

test('offline, outages, reorgs, spent outputs and insufficient confirmations have separate reasons', () => {
  assert.match(observationReasons({ cryptography: 'valid', online: false })[0], /Offline/);
  assert.match(observationReasons({ cryptography: 'valid', online: true, providerError: 'network_or_cors' })[0], /could not supply/);
  const observation = { cryptography: 'valid', online: true, explorer: 'inconclusive', provenance: { attempts: [{ reasons: [{ code: 'funding_not_in_best_chain' }] }] } };
  assert.match(observationReasons(observation)[0], /best chain/);
  assert.match(observationReasons({ ...observation, explorer: 'reported_spent' }).at(-1), /spent/);
  assert.match(observationReasons({ ...observation, provenance: { attempts: [{ reasons: [] }] } })[0], /confirmation, amount or freshness/);
  assert.equal(expectedPolicy(options).minConfirmations, '1');
});
