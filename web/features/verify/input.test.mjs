import { test } from 'node:test';
import assert from 'node:assert/strict';
import { MAX_ENVELOPE_BYTES } from '../../wasm/codec.mjs';
import { expectedPolicy, preflight, setupProofInput } from './input.mjs';
const options = { mode: 'explicit', network: 'signet', verifier: 'Auditor', purpose: 'proof-of-control', message: '', confirmed: true };
const proof = { name: 'proof.qpf', size: 3, arrayBuffer: async () => new ArrayBuffer(3) };

test('size, extension and absent inputs fail before file reads or asset fetch', async () => {
  let reads = 0, fetches = 0;
  const tools = setupProofInput({ fetch() { fetches++; } });
  for (const size of [0, -1, 1.5, MAX_ENVELOPE_BYTES + 1]) {
    await assert.rejects(tools.inspect({ proof: { ...proof, size, arrayBuffer() { reads++; } }, options }), /size/);
  }
  await assert.rejects(tools.inspect({ proof: { ...proof, name: 'file.txt' }, options }), /\.qpf/);
  await assert.rejects(tools.inspect({ proof, options: { mode: 'request' } }), /\.qpr/);
  await assert.rejects(tools.inspect({ proof, request: { name: 'oversized.qpr', size: 4097, arrayBuffer() { reads++; } }, options: { mode: 'request' } }), /Request size/);
  assert.equal(reads, 0); assert.equal(fetches, 0);
  preflight({ name: 'EXACT.QPF', size: MAX_ENVELOPE_BYTES }, 'proof');
  assert.throws(() => preflight({ name: 'file.qpr', size: 4097 }, 'request'), /size/);
});

test('independent expectations require explicit context and preserve empty message', () => {
  assert.equal(expectedPolicy({ mode: 'none' }), undefined);
  for (const change of [{ verifier: '' }, { network: '' }, { purpose: 'bridge-authorization' }, { confirmed: false }])
    assert.throws(() => expectedPolicy({ ...options, ...change }));
  assert.throws(() => expectedPolicy({ mode: 'request' }), /independent/);
  const policy = expectedPolicy(options);
  assert.equal(policy.message, ''); assert.equal(policy.network, 'signet');
  assert.equal(policy.expectedRequest, undefined);
});

test('invalid explicit policy fails before proof read; oversized stream fails before worker', async () => {
  let reads = 0, workers = 0;
  const tools = setupProofInput({ fetch: async () => new Response('', { headers: { 'content-length': '99999999' } }), workerFactory() { workers++; } });
  await assert.rejects(tools.inspect({ proof: { ...proof, arrayBuffer() { reads++; } }, options: { ...options, network: '' } }));
  assert.equal(reads, 0);
  await assert.rejects(tools.inspect({ proof, options }), /load proof tools/);
  assert.equal(workers, 0);
  const streamTools = setupProofInput({ fetch: async () => new Response(new Uint8Array(8 * 1024 * 1024 + 1)), workerFactory() { workers++; } });
  await assert.rejects(streamTools.inspect({ proof, options }), /download size/);
  assert.equal(workers, 0);
});

test('cancellation fences late reads, terminates worker and permits retry; dispose closes entry', async () => {
  let release, workers = 0, terminated = 0, worker;
  const tools = setupProofInput({ fetch: async () => new Response(new Uint8Array([1])), workerFactory() {
    workers++; worker = { terminate() { terminated++; }, postMessage() {} }; return worker;
  } });
  const reading = tools.inspect({ proof: { ...proof, arrayBuffer: () => new Promise(r => { release = r; }) }, options });
  tools.cancel(); await assert.rejects(reading, { name: 'AbortError' }); release(new ArrayBuffer(3));
  assert.equal(workers, 0);
  const pending = tools.inspect({ proof, options });
  while (!worker) await new Promise(r => setImmediate(r));
  tools.cancel(); await assert.rejects(pending, { name: 'AbortError' }); assert(terminated >= 1);
  worker = undefined;
  const retry = tools.inspect({ proof, options });
  while (!worker) await new Promise(r => setImmediate(r));
  worker.onmessage({ data: { id: 1, type: 'error' } });
  await assert.rejects(retry, /Cannot decode/);
  tools.dispose(); await assert.rejects(tools.inspect({ proof, options }), /closed/);
  const timed = setupProofInput({ timeoutMs: 10, workerFactory() { throw new Error('No worker should start'); } });
  await assert.rejects(timed.inspect({ proof: { ...proof, arrayBuffer: () => new Promise(() => {}) }, options }), { name: 'AbortError' });
  timed.dispose();
});

test('owned worker receives transferred binary proof and independent policy, then disposes', async () => {
  let terminated = 0;
  const tools = setupProofInput({ fetch: async () => new Response(new Uint8Array([1])), workerFactory() {
    return { terminate() { terminated++; }, postMessage(data, transfer) {
      assert(transfer.includes(data.bytes));
      if (data.type === 'inspectProofInput') {
        assert.equal(data.policy.verifier, 'Auditor');
        assert.equal(data.policy.network, 'signet');
        assert.equal(data.bytes.byteLength, 3);
      }
      queueMicrotask(() => this.onmessage({ data: { id: data.id, type: 'result', metadata: { verified: false }, binding: 'matched' } }));
    } };
  } });
  const result = await tools.inspect({ proof, options });
  assert.equal(result.cryptography, 'not_checked'); assert.equal(result.explorer, 'unavailable');
  assert.equal(terminated, 1);
});
