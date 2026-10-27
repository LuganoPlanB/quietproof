import { test } from 'node:test';
import assert from 'node:assert/strict';
import { setupRequest, setupDownload } from './download.mjs';
const options = { network: 'mainnet', verifier: 'Auditor', purpose: 'proof-of-control', message: '', lifetimeSeconds: '300',
  claims: [{ txid: '11'.repeat(32), vout: 0, amountSats: '123', scriptKind: 'p2wpkh', program: '22'.repeat(20) }] };
const fetcher = async () => new Response(new Uint8Array([1]));

test('invalid form and oversized asset fail before a worker exists', async () => {
  let fetches = 0, workers = 0;
  const tools = setupRequest({ wasmUrl: '/reactor.wasm', fetch: async () => { fetches++; return new Response('', { headers: { 'content-length': '999999999' } }); }, workerFactory: () => { workers++; } });
  await assert.rejects(tools.create({ ...options, claims: [] }), /Select at least/);
  assert.equal(fetches, 0);
  await assert.rejects(tools.create(options), /Could not load/);
  assert.equal(workers, 0); tools.dispose();
});

test('worker failure and cancellation terminate the owned worker and allow a fresh retry', async () => {
  let current, terminated = 0;
  const tools = setupRequest({ wasmUrl: '/reactor.wasm', fetch: fetcher, workerFactory: () => {
    current = { terminate() { terminated++; }, postMessage() {} }; return current;
  } });
  const work = tools.create(options);
  while (!current) await new Promise(r => setImmediate(r));
  tools.cancel(); await assert.rejects(work, { name: 'AbortError' });
  assert(terminated >= 1);
  current = undefined;
  const retry = tools.create(options);
  while (!current) await new Promise(r => setImmediate(r));
  current.onmessage({ data: { id: 1, type: 'error', message: 'test failure' } });
  await assert.rejects(retry, /Request creation failed/);
  tools.dispose(); await assert.rejects(tools.create(options), /closed/);
});

test('download URL retains exact binary bytes and revokes on replacement and clear', async () => {
  const blobs = [], revoked = [];
  const download = setupDownload({ createObjectURL(blob) { blobs.push(blob); return `blob:${blobs.length}`; }, revokeObjectURL(url) { revoked.push(url); } });
  const bytes = new Uint8Array([0, 255, 128, 1]);
  const metadata = { network: 'signet', nonce: '12'.repeat(32) };
  assert.deepEqual(download.replace(bytes.buffer, metadata), { url: 'blob:1', filename: 'quietproof-signet-1212121212121212.qpr' });
  assert.deepEqual(new Uint8Array(await blobs[0].arrayBuffer()), bytes);
  download.replace(bytes.buffer, metadata); assert.deepEqual(revoked, ['blob:1']);
  download.clear(); download.clear(); assert.deepEqual(revoked, ['blob:1', 'blob:2']);
});
